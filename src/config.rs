use anyhow::Result;
use std::path::Path;
use tracing::{debug, info};

/// Configuration for scanning
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Path to input file with domains, one per line
    pub input_file: String,
    
    /// Path to rules file
    pub rules_file: String,
    
    /// Number of concurrent scanners
    pub concurrency: usize,
    
    /// Verbosity level: 0=error, 1=warn, 2=info, 3=debug, 4=trace
    pub verbosity: u8,
    
    /// Whether to use distributed mode
    pub distributed: bool,
    
    /// Path to output file
    pub output_file: Option<String>,

    /// Path to database file
    pub db_path: String,

    /// DNS timeout in seconds
    pub dns_timeout: u64,

    /// HTTP timeout in seconds
    pub http_timeout: u64,

    /// TCP connection timeout in seconds
    pub connect_timeout: u64,

    /// Size of DNS cache
    pub dns_cache_size: usize,

    /// Run in quiet mode (minimal output)
    pub quiet: bool,

    /// Only perform DNS resolution (no HTTP requests)
    pub dns_only: bool,
}

impl ScanConfig {
    /// Create a new scan configuration with default values
    pub fn new(input_file: String, rules_file: String) -> Self {
        Self {
            input_file,
            rules_file,
            concurrency: 50,
            verbosity: 2, // info level
            distributed: false,
            output_file: None,
            db_path: "data/fatt.db".to_string(),
            dns_timeout: 5,
            http_timeout: 10,
            connect_timeout: 5,
            dns_cache_size: 10000,
            quiet: false,
            dns_only: false,
        }
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check if input file exists
        if !Path::new(&self.input_file).exists() {
            anyhow::bail!("Input file does not exist: {}", self.input_file);
        }
        
        // Check if rules file exists
        if !Path::new(&self.rules_file).exists() {
            anyhow::bail!("Rules file does not exist: {}", self.rules_file);
        }
        
        Ok(())
    }
    
    /// Log the configuration
    pub fn log_config(&self) {
        info!("📋 Configuration:");
        info!("  ⏩ Input file: {}", self.input_file);
        info!("  ⏩ Rules file: {}", self.rules_file);
        info!("  ⏩ Concurrency: {}", self.concurrency);
        info!("  ⏩ Verbosity: {}", self.verbosity);
        info!("  ⏩ Distributed: {}", self.distributed);
        info!("  ⏩ Output file: {:?}", self.output_file);
        info!("  ⏩ Database path: {}", self.db_path);
        info!("  ⏩ DNS timeout: {}s", self.dns_timeout);
        info!("  ⏩ HTTP timeout: {}s", self.http_timeout);
        info!("  ⏩ Connect timeout: {}s", self.connect_timeout);
        info!("  ⏩ DNS cache size: {}", self.dns_cache_size);
        info!("  ⏩ Quiet mode: {}", self.quiet);
        info!("  ⏩ DNS only: {}", self.dns_only);
        
        debug!("Configuration validated successfully");
    }
}
