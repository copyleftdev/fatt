use anyhow::{Context as AnyhowContext, Result};
use chrono::Utc;
use std::{
    net::IpAddr,
    sync::Arc,
};
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use tracing::{debug, warn};

/// DNS resolver for domain name resolution with caching
#[derive(Debug, Clone)]
pub struct DnsResolver {
    resolver: Arc<TokioAsyncResolver>,
    cache: sled::Tree,
    cache_hits: Arc<Mutex<u64>>,
    cache_misses: Arc<Mutex<u64>>,
    is_test: bool,
}

/// Result of a DNS resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverResult {
    /// IPs resolved from the domain
    pub ips: Vec<IpAddr>,
    /// Timestamp when this result was created
    pub timestamp: u64,
    /// Time to live in seconds
    pub ttl: u64,
}

impl DnsResolver {
    /// Create a new DNS resolver with caching
    pub async fn new(cache_dir: &str, cache_size: usize) -> Result<Self> {
        // Create DNS resolver
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default()
        );
        
        // Open or create cache
        let db = sled::Config::new()
            .path(format!("{}/dns_cache", cache_dir))
            .cache_capacity((cache_size * 1024 * 1024) as u64) // Convert to MB and to u64
            .mode(sled::Mode::HighThroughput)
            .open()
            .context("Failed to open DNS cache database")?;
            
        let cache = db.open_tree("dns_cache")
            .context("Failed to open DNS cache tree")?;
            
        Ok(Self {
            resolver: Arc::new(resolver),
            cache,
            cache_hits: Arc::new(Mutex::new(0)),
            cache_misses: Arc::new(Mutex::new(0)),
            is_test: false,
        })
    }
    
    /// Create a new resolver for testing (no caching)
    pub fn new_for_testing() -> Result<Self> {
        // Create in-memory database for testing
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .context("Failed to create temporary DNS cache database")?;
            
        let cache = db.open_tree("dns_cache")
            .context("Failed to open DNS cache tree")?;
            
        // For testing, use system resolver
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .context("Failed to create DNS resolver from system configuration")?;
        
        Ok(Self {
            resolver: Arc::new(resolver),
            cache,
            cache_hits: Arc::new(Mutex::new(0)),
            cache_misses: Arc::new(Mutex::new(0)),
            is_test: true,
        })
    }
    
    /// Check if this is a test resolver
    pub fn is_test_resolver(&self) -> bool {
        self.is_test
    }
    
    /// Lookup a domain name and return its IP address if found
    pub async fn lookup(&self, domain: &str) -> Result<Option<String>> {
        // Check cache first
        if let Some(cached_result) = self.get_from_cache(domain)? {
            // Increment cache hits
            let mut hits = self.cache_hits.lock().await;
            *hits += 1;
            
            debug!("🔍 Cache hit for domain: {}", domain);
            return Ok(cached_result.ips.first().map(|ip| ip.to_string()));
        }
        
        // Perform actual DNS resolution
        debug!("🔍 Resolving domain: {}", domain);
        let mut hits = self.cache_misses.lock().await;
        *hits += 1;
        
        // For test resolvers, return a predictable IP
        if self.is_test {
            let test_ip = "192.0.2.1"; // TEST-NET-1 address for testing
            debug!("🔍 Test resolver returning {} for {}", test_ip, domain);
            
            // Cache the result
            let result = ResolverResult {
                ips: vec![test_ip.parse().unwrap()],
                timestamp: Utc::now().timestamp() as u64,
                ttl: 3600, // 1 hour
            };
            
            self.add_to_cache(domain, &result)?;
            return Ok(Some(test_ip.to_string()));
        }
        
        // Attempt to lookup the A record first
        let lookup_result = match self.resolver.lookup_ip(domain).await {
            Ok(lookup) => {
                if let Some(addr) = lookup.iter().next() {
                    Some(addr.to_string())
                } else {
                    None
                }
            },
            Err(e) => {
                warn!("❌ Failed to resolve domain {}: {}", domain, e);
                
                // Cache the failure too
                let result = ResolverResult {
                    ips: vec![],
                    timestamp: Utc::now().timestamp() as u64,
                    ttl: 0,
                };
                
                self.add_to_cache(domain, &result)?;
                
                None
            }
        };
        
        debug!("🔍 Resolved domain {} to {:?}", domain, lookup_result);
        
        if let Some(ip) = &lookup_result {
            // Cache the result
            let result = ResolverResult {
                ips: vec![ip.parse().unwrap()],
                timestamp: Utc::now().timestamp() as u64,
                ttl: 3600, // default TTL of 1 hour
            };
            
            self.add_to_cache(domain, &result)?;
        }
        
        Ok(lookup_result)
    }
    
    /// Add a resolver result to the cache
    fn add_to_cache(&self, domain: &str, result: &ResolverResult) -> Result<()> {
        // Serialize with serde_json instead of bincode
        let serialized = serde_json::to_vec(result)
            .context("Failed to serialize resolver result")?;
            
        self.cache
            .insert(domain.as_bytes(), serialized)
            .context("Failed to write to cache")?;
            
        Ok(())
    }
    
    /// Get a resolver result from the cache if valid
    fn get_from_cache(&self, domain: &str) -> Result<Option<ResolverResult>> {
        if let Some(cached_bytes) = self.cache.get(domain.as_bytes())? {
            // Deserialize with serde_json instead of bincode
            let result: ResolverResult = serde_json::from_slice(&cached_bytes)
                .context("Failed to deserialize cached resolver result")?;
                
            let now = Utc::now().timestamp() as u64;
            let age = now - result.timestamp;
            
            // Check if cache entry is still valid based on TTL
            if age < result.ttl {
                return Ok(Some(result));
            }
        }
        
        Ok(None)
    }

    /// Flush the DNS cache
    pub async fn flush_cache(&self) -> Result<()> {
        // Clear the cache by removing all items
        self.cache.clear().context("Failed to clear DNS cache")?;
        
        debug!("🧹 DNS cache flushed");
        
        Ok(())
    }

    /// Show DNS cache status
    pub async fn show_cache_status(&self) -> Result<()> {
        // Get cache size
        let count = self.cache.len();
        
        debug!("📊 DNS cache contains {} entries", count);
        
        Ok(())
    }
}

/// Flush the DNS cache
pub async fn flush_cache() -> Result<()> {
    // Use system configuration for resolver
    let _resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("Failed to create DNS resolver from system configuration")?;
        
    // Open cache
    let db = sled::Config::new()
        .path("./cache/dns_cache") // Default path
        .open()
        .context("Failed to open DNS cache database")?;
        
    let cache = db.open_tree("dns_cache")
        .context("Failed to open DNS cache tree")?;
        
    // Clear the cache by removing all items
    cache.clear().context("Failed to clear DNS cache")?;
    
    debug!("🧹 DNS cache flushed");
    
    Ok(())
}

/// Show DNS cache status
pub async fn show_cache_status() -> Result<()> {
    // Use system configuration for resolver
    let _resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("Failed to create DNS resolver from system configuration")?;
        
    // Open cache
    let db = sled::Config::new()
        .path("./cache/dns_cache") // Default path
        .open()
        .context("Failed to open DNS cache database")?;
        
    let cache = db.open_tree("dns_cache")
        .context("Failed to open DNS cache tree")?;
        
    // Get cache size
    let count = cache.len();
    
    debug!("📊 DNS cache contains {} entries", count);
    
    Ok(())
}
