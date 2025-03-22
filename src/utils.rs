use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use tracing::{debug, info};
use url::Url;
use rand::prelude::*;

/// Read domains from a file, one domain per line
pub fn read_domains(file_path: &str) -> Result<Vec<String>> {
    let lines = read_lines(file_path)?;
    
    // Deduplicate the domains
    let mut unique_domains = Vec::new();
    for domain in lines {
        if !unique_domains.contains(&domain) {
            unique_domains.push(domain);
        }
    }
    
    Ok(unique_domains)
}

/// Normalize a domain name by removing leading/trailing whitespace
/// and converting to lowercase
pub fn normalize_domain(domain: &str) -> String {
    domain.trim().to_lowercase()
}

/// Check if a string is a valid domain name
pub fn is_valid_domain(domain: &str) -> bool {
    // Basic domain validation
    // More sophisticated validation might use regex or DNS libraries
    
    // Check for leading/trailing whitespace - fail immediately
    if domain != domain.trim() {
        return false;
    }
    
    // Check if empty
    if domain.is_empty() {
        return false;
    }
    
    // Check length constraints
    if domain.len() > 253 {
        return false;
    }
    
    // Split into labels and validate each
    let labels: Vec<&str> = domain.split('.').collect();
    
    // Domain must have at least one dot (two labels)
    if labels.len() < 2 {
        return false;
    }
    
    // Check each label
    for label in labels {
        // Each label must be 1-63 characters
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        
        // Labels must start and end with alphanumeric
        let chars: Vec<char> = label.chars().collect();
        if !chars[0].is_alphanumeric() || !chars[chars.len() - 1].is_alphanumeric() {
            // Special case for IDN (punycode) domains
            if !label.starts_with("xn--") {
                return false;
            }
        }
        
        // Labels can only contain alphanumeric and hyphen
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
    }
    
    true
}

/// Build a URL with optional HTTP/HTTPS scheme
pub fn build_url(domain: &str, path: &str) -> String {
    let domain = normalize_domain(domain);
    let base_url = if domain.starts_with("http://") || domain.starts_with("https://") {
        domain
    } else {
        format!("https://{}", domain)
    };
    
    // Ensure path starts with / if non-empty
    let path = if path.is_empty() || path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    
    // Combine and normalize URL
    let mut url = format!("{}{}", base_url, path);
    if let Ok(parsed_url) = Url::parse(&url) {
        url = parsed_url.to_string();
    }
    
    url
}

/// Split a vector into chunks of a specified size
pub fn chunk_vector<T: Clone>(vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    if chunk_size == 0 {
        return vec![vec];
    }
    
    let chunks = vec.len() / chunk_size + if vec.len() % chunk_size > 0 { 1 } else { 0 };
    let mut result = Vec::with_capacity(chunks);
    
    for i in 0..chunks {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, vec.len());
        let chunk = vec[start..end].to_vec();
        result.push(chunk);
    }
    
    result
}

/// Format duration in seconds to a human-readable string
pub fn format_duration(seconds: f64) -> String {
    let hours = (seconds / 3600.0).floor();
    let minutes = ((seconds - hours * 3600.0) / 60.0).floor();
    let remaining_seconds = seconds - hours * 3600.0 - minutes * 60.0;
    
    if hours > 0.0 {
        format!("{}h {}m {:.1}s", hours, minutes, remaining_seconds)
    } else if minutes > 0.0 {
        format!("{}m {:.1}s", minutes, remaining_seconds)
    } else {
        format!("{:.1}s", remaining_seconds)
    }
}

/// Create a random backoff delay between min_ms and max_ms
pub async fn random_backoff(min_ms: u64, max_ms: u64) {
    let mut rng = rand::thread_rng();
    let backoff_ms = rng.gen_range(min_ms..=max_ms);
    debug!(" Backing off for {}ms", backoff_ms);
    sleep(Duration::from_millis(backoff_ms)).await;
}

/// Process a batch of items with bounded concurrency
pub async fn process_batch<T, F, Fut>(items: Vec<T>, concurrency: usize, process_fn: F) -> Result<Vec<Fut::Output>>
where
    T: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: futures::Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let process_fn = std::sync::Arc::new(process_fn);
    
    let start = Instant::now();
    debug!("Starting batch processing with concurrency: {}", concurrency);
    
    let tasks: Vec<_> = items
        .into_iter()
        .map(|item| {
            let semaphore = Arc::clone(&semaphore);
            let process_fn = Arc::clone(&process_fn);
            
            tokio::spawn(async move {
                let _permit = semaphore.acquire_owned().await.unwrap();
                process_fn(item).await
            })
        })
        .collect();
    
    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(result) = task.await {
            results.push(result);
        }
    }
    
    let elapsed = start.elapsed();
    debug!("Batch processing completed in {}", format_duration(elapsed.as_secs_f64()));
    
    Ok(results)
}

/// Read lines from a file
pub fn read_lines(file_path: &str) -> Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    
    let mut lines = Vec::new();
    let mut line_count = 0;
    
    for line in reader.lines() {
        line_count += 1;
        let line = line?;
        let line = line.trim();
        
        if !line.is_empty() && !line.starts_with('#') {
            lines.push(line.to_string());
        }
    }
    
    info!(" Read {} lines from {}", lines.len(), file_path);
    debug!("  Total lines: {}, valid lines: {}", line_count, lines.len());
    
    Ok(lines)
}
