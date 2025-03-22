use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use reqwest::Client;
use rusqlite::Connection;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::ScanConfig;
use crate::db;
use crate::logger;
use crate::resolver::DnsResolver;
use crate::rules::RuleSet;
use crate::utils;

/// Run a scanning session
pub async fn run_scan(config: ScanConfig) -> Result<()> {
    // Validate configuration
    config.validate()?;
    config.log_config();
    
    let start_time = Instant::now();
    
    // Load rules
    let ruleset = crate::rules::load_rules(&config.rules_file)
        .context("Failed to load rules")?;
    
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
        DnsResolver::new("cache/dns_cache", config.concurrency, config.dns_timeout as u64)
            .await
            .context("Failed to initialize DNS resolver")?,
    );
    
    // Load domains
    let domains = utils::read_domains(&config.input_file)
        .context("Failed to read domains")?;
    
    if domains.is_empty() {
        warn!("⚠️ No domains loaded from {}", config.input_file);
        return Ok(());
    }
    
    // Initialize HTTP client with timeout
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(config.http_timeout))
        .connect_timeout(std::time::Duration::from_secs(config.connect_timeout))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
        .build()
        .context("Failed to build HTTP client")?;
    
    // Counter for matches found
    let matches_found = Arc::new(AtomicUsize::new(0));
    let domains_processed = Arc::new(AtomicUsize::new(0));
    let tasks_completed = Arc::new(AtomicUsize::new(0));
    
    // Chunk domains for batch processing
    let batch_size = 100; // Default batch size if not specified
    let domain_chunks = utils::chunk_vector(domains, batch_size);
    let total_domains = domain_chunks.iter().map(|chunk| chunk.len()).sum::<usize>();
    let total_tasks = total_domains * ruleset.rules.len();
    
    info!("🚀 Starting scan of {} domains with {} rules ({} total checks)", 
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
            let domains_percent = (domains_done as f64 / total_domains_clone as f64 * 100.0) as usize;
            let tasks_percent = (tasks_done as f64 / total_tasks_clone as f64 * 100.0) as usize;
            
            info!("📊 Status: {}/{} domains ({}%), {}/{} tasks ({}%)", 
                domains_done, total_domains_clone, domains_percent,
                tasks_done, total_tasks_clone, tasks_percent
            );
            
            if domains_done >= total_domains_clone && tasks_done >= total_tasks_clone {
                break;
            }
        }
    });
    
    // Process domain chunks
    for (chunk_idx, chunk) in domain_chunks.iter().enumerate() {
        info!("📦 Processing batch {}/{} ({} domains)", 
            chunk_idx + 1, 
            domain_chunks.len(), 
            chunk.len()
        );
        
        // Create a stream of futures for concurrent processing
        let results = stream::iter(chunk)
            .map(|domain| {
                let client = client.clone();
                let ruleset = ruleset.clone();
                let resolver = resolver.clone();
                let db_conn = db_conn.clone();
                let matches_found = matches_found.clone();
                let domains_processed = domains_processed.clone();
                let tasks_completed = tasks_completed.clone();
                
                async move {
                    // Call scan_domain which will increment scan_pb for each rule
                    let result = scan_domain(
                        domain,
                        &client,
                        &ruleset,
                        resolver.as_ref(),
                        db_conn,
                        tasks_completed,
                        matches_found,
                    ).await;
                    
                    // Always increment domain counter
                    domains_processed.fetch_add(1, Ordering::Relaxed);
                    
                    result
                }
            })
            .buffer_unordered(config.concurrency);
        
        // Wait for all futures to complete
        results.for_each(|result| async {
            if let Err(e) = result {
                error!("Error processing domain: {}", e);
            }
        }).await;
    }
    
    // Cancel the status update task once all work is done
    status_handle.abort();
    
    // Calculate stats
    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let matches = matches_found.load(Ordering::Relaxed);
    
    // Log stats
    logger::log_scan_stats(
        total_domains,
        total_tasks,
        matches,
        elapsed_secs,
    );
    
    Ok(())
}

/// Scan a single domain against all rules
async fn scan_domain(
    domain: &str,
    client: &Client,
    ruleset: &RuleSet,
    resolver: &DnsResolver,
    db_conn: Arc<Mutex<Connection>>,
    tasks_completed: Arc<AtomicUsize>,
    matches_found: Arc<AtomicUsize>,
) -> Result<()> {
    // Resolve domain to IP
    match resolver.resolve(domain).await {
        Ok(ip) => {
            debug!("🔍 Scanning domain: {} ({})", domain, ip.unwrap_or_else(|| "unresolved".to_string()));
            
            // Check each rule
            for rule in &ruleset.rules {
                // Construct target URL from rule path
                let url = format!("http://{}{}", domain, rule.path);
                
                // Check if path exists
                match check_path(client, &url).await {
                    Ok(true) => {
                        // Check if it matches the signature
                        if check_signature(client, &url, &rule.signature).await? {
                            info!("🔴 Match found: {} - {} ({})", domain, rule.name, rule.path);
                            logger::log_success(domain, &rule.name, &rule.path);
                            
                            // Store in database
                            let mut conn = db_conn.lock().await;
                            db::insert_finding(&conn, domain, &rule.name, &rule.path, true)?;
                            
                            // Increment match counter
                            matches_found.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // No match, but path exists
                            let mut conn = db_conn.lock().await;
                            db::insert_finding(&conn, domain, &rule.name, &rule.path, false)?;
                        }
                    }
                    Ok(false) => {
                        // Path doesn't exist, nothing to do
                        debug!("❌ Path not found: {} - {}", domain, rule.path);
                    }
                    Err(e) => {
                        debug!("🔶 Error checking path: {} - {}: {}", domain, rule.path, e);
                    }
                }
                
                // Increment task counter
                tasks_completed.fetch_add(1, Ordering::Relaxed);
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

/// Check if a path exists
async fn check_path(client: &Client, url: &str) -> Result<bool> {
    match client.get(url).send().await {
        Ok(response) => {
            // Check if the response is successful
            if response.status().is_success() {
                return Ok(true);
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}

/// Check if a path matches a signature
async fn check_signature(client: &Client, url: &str, signature: &str) -> Result<bool> {
    match client.get(url).send().await {
        Ok(response) => {
            // Check if the response is successful
            if response.status().is_success() {
                // Get the response body and check for signature
                if let Ok(body) = response.text().await {
                    return Ok(body.contains(signature));
                }
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}
