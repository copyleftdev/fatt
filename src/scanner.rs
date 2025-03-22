use anyhow::{Context, Result};
use reqwest::Client;
use rusqlite::Connection;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::ScanConfig;
use crate::db;
use crate::logger;
use crate::resolver::DnsResolver;
use crate::rules::RuleSet;
use crate::utils;

/// Create an optimized HTTP client
pub fn create_http_client(timeout_secs: u64, connect_timeout_secs: u64) -> Result<Client> {
    let timeout = Duration::from_secs(timeout_secs);
    let connect_timeout = Duration::from_secs(connect_timeout_secs);

    // Create a connection pool using reqwest's connection manager
    let client = Client::builder()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .tcp_nodelay(true)
        .pool_idle_timeout(Some(Duration::from_secs(90)))
        .pool_max_idle_per_host(10) // Allow up to 10 idle connections per host
        .use_rustls_tls() // Use RustTLS for better performance
        .user_agent("FATT Security Scanner") // Set a user agent
        .redirect(reqwest::redirect::Policy::limited(3)) // Limit redirects
        .build()
        .context("Failed to build HTTP client")?;

    debug!("📡 Created optimized HTTP client");

    Ok(client)
}

/// Run a scanning session
pub async fn run_scan(config: ScanConfig) -> Result<()> {
    // Validate configuration
    config.validate()?;
    config.log_config();

    let start_time = Instant::now();

    // Load rules
    let ruleset = crate::rules::load_rules(&config.rules_file).context("Failed to load rules")?;

    if ruleset.rules.is_empty() {
        warn!("⚠️ No rules loaded from {}", config.rules_file);
        return Ok(());
    }

    // Initialize database
    let db_conn = Arc::new(Mutex::new(
        db::init_db(&config.db_path).context("Failed to initialize database")?,
    ));

    // Initialize DNS resolver
    let resolver = Arc::new(
        DnsResolver::new("cache", config.dns_cache_size)
            .await
            .context("Failed to initialize DNS resolver")?,
    );

    // Load domains
    let domains = utils::read_domains(&config.input_file).context("Failed to read domains")?;

    if domains.is_empty() {
        warn!("⚠️ No domains loaded from {}", config.input_file);
        return Ok(());
    }

    // Create high-performance HTTP client
    let client = create_http_client(config.http_timeout, config.connect_timeout)?;

    // Counter for matches found
    let matches_found = Arc::new(AtomicUsize::new(0));
    let domains_processed = Arc::new(AtomicUsize::new(0));
    let tasks_completed = Arc::new(AtomicUsize::new(0));

    // Chunk domains for batch processing
    let batch_size = 100; // Default batch size if not specified
    let domain_chunks = utils::chunk_vector(domains, batch_size);
    let total_domains = domain_chunks.iter().map(|chunk| chunk.len()).sum::<usize>();
    let total_tasks = total_domains * ruleset.rules.len();

    info!(
        "🚀 Starting scan of {} domains with {} rules ({} total checks)",
        total_domains,
        ruleset.rules.len(),
        total_tasks
    );

    // Status update task
    let status_interval = Duration::from_secs(3);
    let domains_processed_clone = domains_processed.clone();
    let tasks_completed_clone = tasks_completed.clone();
    let total_domains_clone = total_domains;
    let total_tasks_clone = total_tasks;

    // Spawn status update task
    let status_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(status_interval);
        loop {
            interval.tick().await;
            let domains_done = domains_processed_clone.load(Ordering::Relaxed);
            let tasks_done = tasks_completed_clone.load(Ordering::Relaxed);
            let domains_percent =
                (domains_done as f64 / total_domains_clone as f64 * 100.0) as usize;
            let tasks_percent = (tasks_done as f64 / total_tasks_clone as f64 * 100.0) as usize;

            info!(
                "📊 Status: {}/{} domains ({}%), {}/{} tasks ({}%)",
                domains_done,
                total_domains_clone,
                domains_percent,
                tasks_done,
                total_tasks_clone,
                tasks_percent
            );

            if domains_done >= total_domains_clone && tasks_done >= total_tasks_clone {
                break;
            }
        }
    });

    // Process domains in batches
    for (i, chunk) in domain_chunks.iter().enumerate() {
        info!(
            "📦 Processing batch {}/{} ({} domains)",
            i + 1,
            domain_chunks.len(),
            chunk.len()
        );

        // Process each domain in the batch concurrently
        let client_clone = client.clone();
        let ruleset_clone = ruleset.clone();
        let resolver_clone = resolver.clone();
        let db_conn_clone = db_conn.clone();
        let tasks_completed_clone = tasks_completed.clone();
        let matches_found_clone = matches_found.clone();
        let domains_processed_clone = domains_processed.clone();

        // Create a stream of futures for concurrent processing
        let mut handles = Vec::with_capacity(chunk.len());

        // Create tasks for each domain
        for domain in chunk {
            let domain = domain.clone();
            let client = client_clone.clone();
            let ruleset = ruleset_clone.clone();
            let resolver = resolver_clone.clone();
            let db_conn = db_conn_clone.clone();
            let tasks_completed = tasks_completed_clone.clone();
            let matches_found = matches_found_clone.clone();
            let domains_processed = domains_processed_clone.clone();

            // Spawn a task for each domain
            let handle = tokio::spawn(async move {
                let result = scan_domain(
                    &domain,
                    &client,
                    &ruleset,
                    &resolver,
                    db_conn,
                    tasks_completed,
                    matches_found,
                )
                .await;

                // Always increment domain counter
                domains_processed.fetch_add(1, Ordering::Relaxed);

                result
            });

            handles.push(handle);
        }

        // Wait for all futures to complete
        let results = futures::future::join_all(handles).await;

        // Count errors
        let error_count = results
            .iter()
            .filter(|r| r.is_err() || r.as_ref().ok().is_none_or(|r| r.is_err()))
            .count();
        if error_count > 0 {
            debug!("⚠️ Batch completed with {} errors", error_count);
        }
    }

    // Cancel the status update task once all work is done
    status_handle.abort();

    // Calculate stats
    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let matches = matches_found.load(Ordering::Relaxed);

    // Log stats
    logger::log_scan_stats(total_domains, total_tasks, matches, elapsed_secs);

    Ok(())
}

/// Scan a domain with all rules in the ruleset
pub async fn scan_domain(
    domain: &str,
    client: &Client,
    ruleset: &RuleSet,
    resolver: &DnsResolver,
    db_conn: Arc<Mutex<Connection>>,
    tasks_completed: Arc<AtomicUsize>,
    matches_found: Arc<AtomicUsize>,
) -> Result<()> {
    // Resolve domain to IP
    match resolver.lookup(domain).await {
        Ok(ip) => {
            debug!(
                "🔍 Scanning domain: {} ({})",
                domain,
                ip.unwrap_or_else(|| "unresolved".to_string())
            );

            // Create a vector of futures for parallel rule checking
            let mut rule_futures = Vec::with_capacity(ruleset.rules.len());

            // Process each rule in parallel
            for rule in &ruleset.rules {
                let domain = domain.to_string();
                let client = client.clone();
                let rule = rule.clone();
                let db_conn = db_conn.clone();
                let matches_found = matches_found.clone();

                // Create a future for this rule check
                let rule_future = async move {
                    // Construct target URL from rule path
                    let url = format!("http://{}{}", domain, rule.path);

                    // Check if path exists
                    match check_path(&client, &url).await {
                        Ok(true) => {
                            // Check if it matches the signature
                            match check_signature(&client, &url, &rule.signature).await {
                                Ok(true) => {
                                    info!(
                                        "🔴 Match found: {} - {} ({})",
                                        domain, rule.name, rule.path
                                    );
                                    logger::log_success(&domain, &rule.name, &rule.path);

                                    // Store in database
                                    let conn = db_conn.lock().await;
                                    if let Err(e) = db::insert_finding(
                                        &conn, &domain, &rule.name, &rule.path, true,
                                    ) {
                                        error!("Failed to insert finding: {}", e);
                                    }

                                    // Increment match counter
                                    matches_found.fetch_add(1, Ordering::Relaxed);

                                    Ok(())
                                }
                                Ok(false) => {
                                    // No match, but path exists
                                    let conn = db_conn.lock().await;
                                    if let Err(e) = db::insert_finding(
                                        &conn, &domain, &rule.name, &rule.path, false,
                                    ) {
                                        error!("Failed to insert finding: {}", e);
                                    }

                                    Ok(())
                                }
                                Err(e) => {
                                    debug!(
                                        "🔶 Error checking signature for {} - {}: {}",
                                        domain, rule.path, e
                                    );
                                    Err(e)
                                }
                            }
                        }
                        Ok(false) => {
                            // Path doesn't exist, nothing to do
                            debug!("❌ Path not found: {} - {}", domain, rule.path);
                            Ok(())
                        }
                        Err(e) => {
                            debug!("🔶 Error checking path: {} - {}: {}", domain, rule.path, e);
                            Err(e)
                        }
                    }
                };

                rule_futures.push(rule_future);
            }

            // Execute all rule checks in parallel with a concurrency limit
            let results = futures::future::join_all(rule_futures).await;

            // Increment task counter for all completed tasks
            tasks_completed.fetch_add(ruleset.rules.len(), Ordering::Relaxed);

            // Check if any errors occurred
            let errors: Vec<_> = results.into_iter().filter_map(|r| r.err()).collect();
            if !errors.is_empty() {
                debug!(
                    "❌ Some rule checks failed for {}: {} errors",
                    domain,
                    errors.len()
                );
            }

            Ok(())
        }
        Err(e) => {
            debug!("❌ Failed to resolve domain: {}: {}", domain, e);

            // Increment task counter for all rules that would have been checked
            tasks_completed.fetch_add(ruleset.rules.len(), Ordering::Relaxed);

            Err(anyhow::anyhow!("Failed to resolve domain: {}", domain))
        }
    }
}

/// Check if a path exists by making a HEAD request
pub async fn check_path(client: &Client, url: &str) -> Result<bool> {
    // First try a HEAD request to see if the path exists without downloading content
    match client.head(url).send().await {
        Ok(response) => Ok(response.status().is_success()),
        Err(e) => {
            debug!("HEAD request failed for {}: {}", url, e);
            // Fall back to a GET if HEAD fails, some servers don't support HEAD
            match client.get(url).send().await {
                Ok(response) => Ok(response.status().is_success()),
                Err(e) => {
                    debug!("GET request also failed for {}: {}", url, e);
                    Err(anyhow::anyhow!("Failed to check path: {}", e))
                }
            }
        }
    }
}

/// Check if a signature exists in the response body
pub async fn check_signature(client: &Client, url: &str, signature: &str) -> Result<bool> {
    // Get the path content
    match client.get(url).send().await {
        Ok(response) => {
            // Check if the response is successful
            if response.status().is_success() {
                // Get the response text and check for signature
                let body = response.text().await?;
                Ok(body.contains(signature))
            } else {
                Ok(false)
            }
        }
        Err(e) => {
            debug!("Error checking signature: {}", e);
            Err(anyhow::anyhow!("Failed to check signature: {}", e))
        }
    }
}
