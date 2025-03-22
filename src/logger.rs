use std::path::Path;
use tracing::{debug, info, warn, Level};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, prelude::*, EnvFilter, Registry};

/// Initialize logger with file and console output
pub fn init_logger(debug_mode: bool, log_file: Option<&str>) -> anyhow::Result<()> {
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| {
            if debug_mode {
                EnvFilter::try_new("debug")
            } else {
                EnvFilter::try_new("info")
            }
        })
        .unwrap();

    // Create a stdout logger
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_file(true)
        .with_line_number(true);

    // Build our subscriber
    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);

    // Add file logging if specified
    if let Some(log_path) = log_file {
        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(log_path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Create rolling file appender
        let file_appender = RollingFileAppender::new(
            Rotation::DAILY,
            Path::new(log_path).parent().unwrap_or(Path::new(".")),
            Path::new(log_path).file_name().unwrap_or_default(),
        );

        let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = fmt::layer().with_ansi(false).with_writer(non_blocking);

        tracing::subscriber::set_global_default(subscriber.with(file_layer))
            .expect("Failed to set global default subscriber");
    } else {
        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set global default subscriber");
    }

    Ok(())
}

/// Set the logging verbosity level
pub fn set_verbosity(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    debug!("Setting log level to {:?}", level);
}

/// Log scan statistics
pub fn log_scan_stats(
    domain_count: usize,
    checks_count: usize,
    findings_count: usize,
    elapsed_secs: f64,
) {
    // Calculate scan rate
    let scan_rate = domain_count as f64 / elapsed_secs;

    info!("📊 Scan Statistics: Scanned {}/{} domains in {:.1}s ({:.1} domains/sec), Found {} findings", 
        checks_count,
        domain_count,
        elapsed_secs,
        scan_rate,
        findings_count
    );

    // Add a more detailed summary if findings were found
    if findings_count > 0 {
        info!(
            "🔍 Summary: Found {} security issues across {} domains",
            findings_count, domain_count
        );
        info!("📝 Run 'fatt results list' to see detailed findings");
        info!("📊 Run 'fatt results export -o findings.csv' to export results");
    } else {
        info!(
            "✅ No security issues found across {} domains",
            domain_count
        );
    }

    // Print a separator line for clarity
    info!("────────────────────────────────────────────────────────────────");
}

/// Log a successful finding
pub fn log_success(domain: &str, rule_name: &str, matched_path: &str) {
    info!(
        "✅ Found {} in {} at path {}",
        rule_name, domain, matched_path
    );
}

/// Log when a rule is loaded
pub fn log_rule_loaded(rule_name: &str, patterns: usize) {
    debug!("📋 Loaded rule '{}' with {} patterns", rule_name, patterns);
}

/// Log DNS resolution
#[allow(dead_code)]
pub fn log_dns_resolution(domain: &str, ip: &str, cached: bool) {
    if cached {
        debug!("🔍 DNS Resolution (cached): {} -> {}", domain, ip);
    } else {
        debug!("🔍 DNS Resolution: {} -> {}", domain, ip);
    }
}

/// Log a scan result
#[allow(dead_code)]
pub fn log_scan_result(domain: &str, rule_name: &str, path: &str, detected: bool) {
    if detected {
        info!("✅ Found: {} - {} - {}", domain, rule_name, path);
    } else {
        debug!("❌ Not found: {} - {} - {}", domain, rule_name, path);
    }
}

/// Log worker status
#[allow(dead_code)]
pub fn log_worker_status(worker_id: &str, active: usize, completed: usize, findings: usize) {
    info!(
        "👷 Worker {}: Active={}, Completed={}, Findings={}",
        worker_id, active, completed, findings
    );
}

/// Log an HTTP request result
#[allow(dead_code)]
pub fn log_http_request(url: &str, status: u16, elapsed_ms: u64) {
    match status {
        200..=299 => debug!("🌐 HTTP {}ms: {} ({})", elapsed_ms, url, status),
        300..=399 => debug!("🔄 HTTP {}ms: {} ({})", elapsed_ms, url, status),
        400..=499 => debug!("🚫 HTTP {}ms: {} ({})", elapsed_ms, url, status),
        500..=599 => warn!("⚠️ HTTP {}ms: {} ({})", elapsed_ms, url, status),
        _ => warn!("❓ HTTP {}ms: {} ({})", elapsed_ms, url, status),
    }
}

/// Log a database operation
#[allow(dead_code)]
pub fn log_db_operation(operation: &str, rows_affected: usize) {
    debug!("💾 DB {}: {} rows affected", operation, rows_affected);
}

/// Log distributed processing statistics
#[allow(dead_code)]
pub fn log_distributed_stats(workers: usize, active_scans: usize, domains_processed: usize) {
    info!(
        "🌐 Distributed: Workers={}, Active={}, Processed={}",
        workers, active_scans, domains_processed
    );
}
