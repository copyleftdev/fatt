use fatt::config::ScanConfig;
use tempfile::tempdir;
use tracing;
mod test_helpers;
use test_helpers::LogCapture;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_config_defaults() {
        // Test default configuration values
        let config = ScanConfig::default();

        // Verify default values
        assert_eq!(config.concurrency, 10);
        assert_eq!(config.http_timeout, 10);
        assert_eq!(config.connect_timeout, 5);
        assert_eq!(config.dns_timeout, 5);
        assert_eq!(config.input_file, "domains.txt");
        assert_eq!(config.rules_file, "rules.yaml");
        assert_eq!(config.db_path, "results.sqlite");
        assert!(!config.verbose);
        assert_eq!(config.verbosity, 0);
        assert!(!config.distributed);
        assert_eq!(config.output_file, Some("output.txt".to_string()));
        assert_eq!(config.dns_cache_size, 10000);
        assert!(!config.quiet);
        assert!(!config.dns_only);
    }

    #[test]
    fn test_scan_config_custom() {
        // Create a custom configuration
        let mut config = ScanConfig::default();
        config.concurrency = 20;
        config.http_timeout = 15;
        config.connect_timeout = 8;
        config.dns_timeout = 10;
        config.input_file = "custom-domains.txt".to_string();
        config.rules_file = "custom-rules.yaml".to_string();
        config.db_path = "custom-results.sqlite".to_string();
        config.verbose = true;
        config.verbosity = 2;
        config.distributed = true;
        config.output_file = Some("custom-output.txt".to_string());
        config.dns_cache_size = 5000;
        config.quiet = false;
        config.dns_only = false;

        // Verify custom values
        assert_eq!(config.concurrency, 20);
        assert_eq!(config.http_timeout, 15);
        assert_eq!(config.connect_timeout, 8);
        assert_eq!(config.dns_timeout, 10);
        assert_eq!(config.input_file, "custom-domains.txt");
        assert_eq!(config.rules_file, "custom-rules.yaml");
        assert_eq!(config.db_path, "custom-results.sqlite");
        assert!(config.verbose);
        assert_eq!(config.verbosity, 2);
        assert!(config.distributed);
        assert_eq!(config.output_file, Some("custom-output.txt".to_string()));
        assert_eq!(config.dns_cache_size, 5000);
        assert!(!config.quiet);
        assert!(!config.dns_only);
    }

    #[test]
    fn test_scan_config_validation() {
        // Test configuration with invalid values
        let mut config = ScanConfig::default();
        config.concurrency = 0; // Invalid concurrency

        let validation_result = config.validate();
        assert!(validation_result.is_err());
        assert!(validation_result
            .unwrap_err()
            .to_string()
            .contains("concurrency"));

        // Test with missing input file
        let mut config = ScanConfig::default();
        config.input_file = "nonexistent-file.txt".to_string();

        let validation_result = config.validate();
        assert!(validation_result.is_err());
        assert!(validation_result
            .unwrap_err()
            .to_string()
            .contains("input file"));

        // Test with valid temporary input file
        let temp_dir = tempdir().unwrap();
        let temp_file = temp_dir.path().join("test-domains.txt");
        std::fs::write(&temp_file, "example.com\ntest.com").unwrap();

        let mut config = ScanConfig::default();
        config.input_file = temp_file.to_string_lossy().to_string();

        let validation_result = config.validate();
        assert!(validation_result.is_ok());
    }

    // A more direct test approach for logging
    #[test]
    fn test_config_log_output() {
        // Create a log capture instance
        let log_capture = LogCapture::new();

        // Run the test with log capturing
        log_capture.capture_logs(|| {
            // Create a test configuration with known values
            let mut config = ScanConfig::default();
            config.concurrency = 15;
            config.http_timeout = 20;
            config.input_file = "test-domains.txt".to_string();
            config.db_path = "test-results.sqlite".to_string();

            // Log a simple test message
            tracing::info!("Simple log test");

            // Log the configuration
            config.log_config();
        });

        // Print all captured logs for debugging
        log_capture.print_logs();

        // Assert logs contain expected content
        assert!(log_capture.contains("Simple log test"));
        assert!(log_capture.contains("Configuration:"));
        assert!(log_capture.contains("input file: test-domains.txt"));
        assert!(log_capture.contains("concurrency: 15"));
        assert!(log_capture.contains("HTTP timeout: 20s"));
        assert!(log_capture.contains("database: test-results.sqlite"));
    }
}
