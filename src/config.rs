use anyhow::Result;
use std::path::Path;

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

    /// Verbose mode
    pub verbose: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            input_file: "domains.txt".to_string(),
            rules_file: "rules.yaml".to_string(),
            concurrency: 10,
            verbosity: 0,
            distributed: false,
            output_file: Some("output.txt".to_string()),
            db_path: "results.sqlite".to_string(),
            dns_timeout: 5,
            http_timeout: 10,
            connect_timeout: 5,
            dns_cache_size: 10000,
            quiet: false,
            dns_only: false,
            verbose: false,
        }
    }
}

impl ScanConfig {
    /// Create a new scan configuration with default values
    #[allow(dead_code)]
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
            verbose: false,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check if input file exists
        if !Path::new(&self.input_file).exists() {
            anyhow::bail!("input file does not exist: {}", self.input_file);
        }

        // Check if rules file exists
        if !Path::new(&self.rules_file).exists() {
            anyhow::bail!("Rules file does not exist: {}", self.rules_file);
        }

        // Check concurrency value
        if self.concurrency == 0 {
            anyhow::bail!("Invalid concurrency value: must be greater than 0");
        }

        Ok(())
    }

    /// Log the configuration
    pub fn log_config(&self) {
        // Use event-based tracing which is more reliably captured by test infrastructure
        tracing::event!(tracing::Level::INFO, message = "Configuration:");

        // Log each configuration value as a separate event for better test capturing
        tracing::event!(
            tracing::Level::INFO,
            input_file = %self.input_file,
            message = format!("  input file: {}", self.input_file)
        );
        tracing::event!(
            tracing::Level::INFO,
            rules_file = %self.rules_file,
            message = format!("  rules file: {}", self.rules_file)
        );
        tracing::event!(
            tracing::Level::INFO,
            concurrency = self.concurrency,
            message = format!("  concurrency: {}", self.concurrency)
        );
        tracing::event!(
            tracing::Level::INFO,
            dns_timeout = self.dns_timeout,
            message = format!("  DNS timeout: {}s", self.dns_timeout)
        );
        tracing::event!(
            tracing::Level::INFO,
            http_timeout = self.http_timeout,
            message = format!("  HTTP timeout: {}s", self.http_timeout)
        );
        tracing::event!(
            tracing::Level::INFO,
            connect_timeout = self.connect_timeout,
            message = format!("  connect timeout: {}s", self.connect_timeout)
        );
        tracing::event!(
            tracing::Level::INFO,
            verbosity = self.verbosity,
            message = format!("  verbosity: {}", self.verbosity)
        );
        tracing::event!(
            tracing::Level::INFO,
            distributed = self.distributed,
            message = format!("  distributed: {}", self.distributed)
        );
        tracing::event!(
            tracing::Level::INFO,
            output_file = ?self.output_file,
            message = format!("  output file: {:?}", self.output_file)
        );
        tracing::event!(
            tracing::Level::INFO,
            db_path = %self.db_path,
            message = format!("  database: {}", self.db_path)
        );
        tracing::event!(
            tracing::Level::INFO,
            dns_cache_size = self.dns_cache_size,
            message = format!("  DNS cache size: {}", self.dns_cache_size)
        );
        tracing::event!(
            tracing::Level::INFO,
            quiet = self.quiet,
            message = format!("  quiet mode: {}", self.quiet)
        );
        tracing::event!(
            tracing::Level::INFO,
            dns_only = self.dns_only,
            message = format!("  DNS only: {}", self.dns_only)
        );
        tracing::event!(
            tracing::Level::INFO,
            verbose = self.verbose,
            message = format!("  verbose: {}", self.verbose)
        );

        tracing::event!(
            tracing::Level::DEBUG,
            message = "Configuration validated successfully"
        );
    }
}
