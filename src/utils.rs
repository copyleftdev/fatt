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
    read_lines(file_path)
}

/// Normalize a domain name
pub fn normalize_domain(domain: &str) -> String {
    // Remove protocol if present
    let domain = if let Some(domain_part) = domain.strip_prefix("http://") {
        domain_part
    } else if let Some(domain_part) = domain.strip_prefix("https://") {
        domain_part
    } else {
        domain
    };
    
    // Remove path and parameters
    let domain = domain.split('/').next().unwrap_or(domain);
    let domain = domain.split('?').next().unwrap_or(domain);
    let domain = domain.split('#').next().unwrap_or(domain);
    
    // Remove ports
    let domain = domain.split(':').next().unwrap_or(domain);
    
    // Handle edge cases
    let domain = domain.trim().to_lowercase();
    
    domain.to_string()
}

/// Build a URL from a domain and path
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

/// Create a random backoff delay between min_ms and max_ms
pub async fn random_backoff(min_ms: u64, max_ms: u64) {
    let mut rng = rand::thread_rng();
    let backoff_ms = rng.gen_range(min_ms..=max_ms);
    debug!("🕒 Backing off for {}ms", backoff_ms);
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
    debug!("Batch processing completed in {:?}", elapsed);
    
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
    
    info!("📋 Read {} lines from {}", lines.len(), file_path);
    debug!("  Total lines: {}, valid lines: {}", line_count, lines.len());
    
    Ok(lines)
}
