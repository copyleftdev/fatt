use anyhow::{Context, Result};
use sled::Db;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::sync::{Arc, RwLock, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info};
use chrono::Utc;
use bincode::{config, Encode, Decode};
use once_cell::sync::Lazy;

/// Statistics for DNS resolution
#[derive(Debug, Clone, Default)]
pub struct DnsStats {
    pub resolved: usize,
    pub failed: usize,
    pub cached: usize,
    pub total: usize,
}

/// Result of DNS resolution
#[derive(Debug, Clone, Encode, Decode)]
pub struct ResolverResult {
    pub domain: String,
    pub ip: Option<String>,
    pub error: Option<String>,
    pub timestamp: u64,
}

/// DNS resolver with persistent caching
pub struct DnsResolver {
    cache: Db,
    stats: Arc<RwLock<DnsStats>>,
    semaphore: Arc<Semaphore>,
    ttl: Duration,
}

impl DnsResolver {
    /// Create a new DNS resolver with caching
    pub async fn new(cache_path: &str, concurrency: usize, ttl_secs: u64) -> Result<Self> {
        // Create cache directory if it doesn't exist
        if let Some(parent) = Path::new(cache_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .context(format!("Failed to create cache directory: {:?}", parent))?;
            }
        }
        
        // Open or create the cache database
        let cache = sled::open(cache_path)
            .context(format!("Failed to open DNS cache database: {}", cache_path))?;
        
        let ttl = Duration::from_secs(ttl_secs);
        let semaphore = Arc::new(Semaphore::new(concurrency));
        
        info!("📡 DNS resolver initialized with cache at: {}", cache_path);
        
        Ok(Self {
            cache,
            stats: Arc::new(RwLock::new(DnsStats::default())),
            semaphore,
            ttl,
        })
    }
    
    /// Resolve a domain to IP address with caching
    pub async fn resolve(&self, domain: &str) -> Result<Option<String>> {
        // Get a permit from the semaphore to limit concurrency
        let _permit = self.semaphore.clone().acquire_owned().await?;
        
        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total += 1;
        }
        
        // Check cache first
        if let Some(cached_result) = self.get_from_cache(domain)? {
            // Update stats
            {
                let mut stats = self.stats.write().unwrap();
                stats.cached += 1;
            }
            
            debug!("🔍 Cache hit for domain: {}", domain);
            return Ok(cached_result.ip);
        }
        
        // Perform actual DNS resolution
        debug!("🔍 Resolving domain: {}", domain);
        let lookup_result = match format!("{}:80", domain).to_socket_addrs() {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    Some(addr.ip().to_string())
                } else {
                    None
                }
            }
            Err(e) => {
                debug!("❌ Failed to resolve domain {}: {}", domain, e);
                // Update stats
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.failed += 1;
                }
                
                // Cache the failure too
                let result = ResolverResult {
                    domain: domain.to_string(),
                    ip: None,
                    error: Some(e.to_string()),
                    timestamp: Utc::now().timestamp() as u64,
                };
                
                self.add_to_cache(domain, &result)?;
                
                return Ok(None);
            }
        };
        
        // Update stats for successful resolution
        {
            let mut stats = self.stats.write().unwrap();
            stats.resolved += 1;
        }
        
        // Cache the result
        let result = ResolverResult {
            domain: domain.to_string(),
            ip: lookup_result.clone(),
            error: None,
            timestamp: Utc::now().timestamp() as u64,
        };
        
        self.add_to_cache(domain, &result)?;
        
        Ok(lookup_result)
    }
    
    /// Add a resolver result to the cache
    fn add_to_cache(&self, domain: &str, result: &ResolverResult) -> Result<()> {
        // Use standard configuration for bincode 2.0
        let config = config::standard();
        let serialized = bincode::encode_to_vec(result, config)
            .context("Failed to serialize resolver result")?;
            
        self.cache
            .insert(domain.as_bytes(), serialized)
            .context("Failed to write to cache")?;
            
        Ok(())
    }
    
    /// Get a resolver result from the cache if valid
    fn get_from_cache(&self, domain: &str) -> Result<Option<ResolverResult>> {
        if let Some(cached_bytes) = self.cache.get(domain.as_bytes())? {
            // Use standard configuration for bincode 2.0
            let config = config::standard();
            let (result, _): (ResolverResult, _) = bincode::decode_from_slice(&cached_bytes, config)
                .context("Failed to deserialize cached resolver result")?;
                
            let now = Utc::now().timestamp() as u64;
            let age = now - result.timestamp;
            
            // Check if cache entry is still valid based on TTL
            if Duration::from_secs(age) < self.ttl {
                return Ok(Some(result));
            }
        }
        
        Ok(None)
    }
    
    /// Get a copy of the current DNS resolution statistics
    pub fn get_stats(&self) -> DnsStats {
        let stats = self.stats.read().unwrap();
        stats.clone()
    }
    
    /// Clear the DNS cache
    pub fn clear_cache(&self) -> Result<usize> {
        self.cache.clear()?;
        
        // Reset stats
        let mut stats = self.stats.write().unwrap();
        *stats = DnsStats::default();
        
        // The count from clear() is (), not a number, so just return estimated count
        let estimated_count = self.cache.len();
        
        Ok(estimated_count)
    }
}

/// Global resolver instance
static RESOLVER: Lazy<Mutex<Option<Arc<DnsResolver>>>> = Lazy::new(|| Mutex::new(None));

/// Initialize global resolver
pub async fn init_resolver(cache_path: &str, concurrency: usize, ttl_secs: u64) -> Result<()> {
    let resolver = DnsResolver::new(cache_path, concurrency, ttl_secs).await?;
    let resolver_arc = Arc::new(resolver);
    
    // Store in global instance
    *RESOLVER.lock().unwrap() = Some(resolver_arc);
    
    Ok(())
}

/// Flush the DNS cache
pub async fn flush_cache() -> Result<()> {
    if let Some(resolver) = RESOLVER.lock().unwrap().clone() {
        let cache_size_before = resolver.cache.len();
        resolver.cache.clear()?;
        info!("🧹 Flushed DNS cache: {} entries removed", cache_size_before);
        Ok(())
    } else {
        anyhow::bail!("DNS resolver not initialized")
    }
}

/// Show cache status
pub async fn show_cache_status() -> Result<()> {
    if let Some(resolver) = RESOLVER.lock().unwrap().clone() {
        let stats = resolver.stats.read().unwrap().clone();
        let cache_size = resolver.cache.len();
        
        info!("📊 DNS Cache Status:");
        info!("  Cache entries: {}", cache_size);
        info!("  Total lookups: {}", stats.total);
        info!("  Cache hits: {} ({:.1}%)", 
            stats.cached, 
            if stats.total > 0 { (stats.cached as f64 / stats.total as f64) * 100.0 } else { 0.0 }
        );
        info!("  Successful resolutions: {}", stats.resolved);
        info!("  Failed resolutions: {}", stats.failed);
        
        Ok(())
    } else {
        anyhow::bail!("DNS resolver not initialized")
    }
}
