use anyhow::{Context, Result};
use futures::{stream, StreamExt};
use indicatif::{MultiProgress, ProgressBar};
use reqwest::{Client, StatusCode};
use rusqlite::Connection;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::config::ScanConfig;
use crate::db;
use crate::logger;
use crate::resolver::DnsResolver;
use crate::rules::{Rule, RuleSet};
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
    
    // Create a multi-progress for tracking
    let multi_pb = MultiProgress::new();
    
    // Add domain progress bar
    let domain_pb = utils::create_progress_bar(
        domains.len() as u64,
        "Scanning domains",
        &multi_pb,
    );
    
    // Total scan calculations
    let total_scans = domains.len() * ruleset.rules.len();
    let scan_pb = utils::create_progress_bar(
        total_scans as u64,
        "Running scan tasks",
        &multi_pb,
    );
    
    // Counter for matches found
    let matches_found = Arc::new(Mutex::new(0));
    
    // Chunk domains for batch processing
    let batch_size = 100; // Default batch size if not specified
    let domain_chunks = utils::chunk_vector(domains, batch_size);
    info!("🚀 Starting scan of {} domains with {} rules ({} total checks)", 
        domain_chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
        ruleset.rules.len(), 
        total_scans
    );
    
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
                let domain_pb = domain_pb.clone();
                let scan_pb = scan_pb.clone();
                let matches_found = matches_found.clone();
                
                async move {
                    scan_domain(
                        domain,
                        &client,
                        &ruleset,
                        resolver.as_ref(),
                        db_conn,
                        scan_pb,
                        matches_found,
                    )
                    .await?;
                    
                    domain_pb.inc(1);
                    Ok::<_, anyhow::Error>(())
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
    
    // Finish progress bars
    domain_pb.finish_with_message("All domains processed");
    scan_pb.finish_with_message("All scan tasks completed");
    
    // Calculate stats
    let elapsed = start_time.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let matches = *matches_found.lock().await;
    
    // Log stats
    logger::log_scan_stats(
        domain_chunks.iter().map(|chunk| chunk.len()).sum::<usize>(),
        domain_chunks.iter().map(|chunk| chunk.len()).sum::<usize>() * ruleset.rules.len(),
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
    scan_pb: ProgressBar,
    matches_found: Arc<Mutex<usize>>,
) -> Result<()> {
    // Resolve domain to IP
    let ip_opt = resolver.resolve(domain).await?;
    
    if ip_opt.is_none() {
        // Domain doesn't resolve, skip
        debug!("🔍 Domain doesn't resolve: {}", domain);
        scan_pb.inc(ruleset.rules.len() as u64);
        return Ok(());
    }
    
    // Scan each rule for this domain
    for rule in &ruleset.rules {
        scan_rule(
            domain,
            rule,
            client,
            db_conn.clone(),
            matches_found.clone(),
        )
        .await?;
        
        scan_pb.inc(1);
    }
    
    Ok(())
}

/// Check a single domain against a single rule
async fn scan_rule(
    domain: &str,
    rule: &Rule,
    client: &Client,
    db_conn: Arc<Mutex<Connection>>,
    matches_found: Arc<Mutex<usize>>,
) -> Result<()> {
    // Build the URL
    let url = utils::build_url(domain, &rule.path);
    
    // Make request
    match client.get(&url).send().await {
        Ok(response) => {
            let status = response.status();
            
            // Only process successful responses or redirection responses
            if status.is_success() || status.is_redirection() {
                // Get response body
                match response.text().await {
                    Ok(body) => {
                        // Check if response matches rule signature
                        let detected = body.contains(&rule.signature);
                        
                        if detected {
                            // Found a match!
                            *matches_found.lock().await += 1;
                            
                            // Log the finding
                            logger::log_success(domain, &rule.name, &rule.path);
                            
                            // Store in database
                            let conn = db_conn.lock().await;
                            db::insert_finding(&conn, domain, &rule.name, &rule.path, true)?;
                        } else {
                            // No match, but path exists
                            let conn = db_conn.lock().await;
                            db::insert_finding(&conn, domain, &rule.name, &rule.path, false)?;
                        }
                    }
                    Err(e) => {
                        debug!("❌ Failed to get response body for {}{}: {}", domain, rule.path, e);
                    }
                }
            } else if status == StatusCode::TOO_MANY_REQUESTS {
                // Rate limited, back off
                debug!("⚠️ Rate limited for {}, backing off", domain);
                utils::random_backoff(1000, 5000).await;
            }
        }
        Err(e) => {
            // Request failed
            debug!("❌ Request failed for {}{}: {}", domain, rule.path, e);
        }
    }
    
    Ok(())
}

/// Check for a security issue, returning true if found
async fn check_security_issue(
    domain: &str,
    path: &str,
    signature: &str,
    client: &Client,
) -> Result<bool> {
    let url = utils::build_url(domain, path);
    
    match client.get(&url).send().await {
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
