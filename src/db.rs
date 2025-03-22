use anyhow::{Context, Result};
use chrono::{DateTime, Local, NaiveDateTime, Utc};
use rusqlite::{params, Connection, Row};
use serde::Serialize;
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Represents a finding from a scan
#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: i64,
    pub domain: String,
    pub rule_name: String,
    pub matched_path: String,
    pub detected: bool,
    pub scanned_at: DateTime<Utc>,
}

impl Finding {
    fn from_row(row: &Row) -> Result<Self, rusqlite::Error> {
        let scanned_at: String = row.get(5)?;
        let naive_dt = NaiveDateTime::parse_from_str(&scanned_at, "%Y-%m-%d %H:%M:%S")
            .unwrap_or_else(|_| Local::now().naive_local());
        
        Ok(Finding {
            id: row.get(0)?,
            domain: row.get(1)?,
            rule_name: row.get(2)?,
            matched_path: row.get(3)?,
            detected: row.get::<_, i64>(4)? != 0,
            scanned_at: DateTime::from_naive_utc_and_offset(naive_dt, Utc),
        })
    }
}

/// Initialize the SQLite database
pub fn init_db(db_file: &str) -> Result<Connection> {
    // Ensure parent directory exists
    if let Some(parent) = Path::new(db_file).parent() {
        if !parent.exists() {
            create_dir_all(parent).context("Failed to create database parent directory")?;
        }
    }
    
    // Open or create the database
    let conn = Connection::open(db_file)
        .context(format!("Failed to open database: {}", db_file))?;
    
    // Create necessary tables if they don't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            domain TEXT,
            rule_name TEXT,
            matched_path TEXT,
            detected INTEGER,
            scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(domain, rule_name)
        )",
        [],
    )
    .context("Failed to create findings table")?;
    
    // Create index for faster lookups
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings (domain)",
        [],
    )
    .context("Failed to create domain index")?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings (rule_name)",
        [],
    )
    .context("Failed to create rule_name index")?;
    
    debug!("Database initialized: {}", db_file);
    
    Ok(conn)
}

/// Insert a new finding into the database
pub fn insert_finding(
    conn: &Connection,
    domain: &str,
    rule_name: &str,
    matched_path: &str,
    detected: bool,
) -> Result<i64> {
    // Use upsert pattern to update if exists, insert if not
    let detected_int = if detected { 1 } else { 0 };
    
    conn.execute(
        "INSERT INTO findings (domain, rule_name, matched_path, detected, scanned_at)
         VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
         ON CONFLICT(domain, rule_name) 
         DO UPDATE SET 
            matched_path = excluded.matched_path,
            detected = excluded.detected,
            scanned_at = CURRENT_TIMESTAMP",
        params![domain, rule_name, matched_path, detected_int],
    )
    .context("Failed to insert finding")?;
    
    // Return the ID of the inserted or updated row
    let id = conn.last_insert_rowid();
    
    Ok(id)
}

/// Get findings by domain pattern
pub fn get_findings_by_domain(
    conn: &Connection,
    domain_pattern: Option<&str>,
    limit: usize,
) -> Result<Vec<Finding>> {
    let mut stmt;
    let findings = if let Some(pattern) = domain_pattern {
        let pattern = format!("%{}%", pattern);
        stmt = conn.prepare(
            "SELECT id, domain, rule_name, matched_path, detected, scanned_at 
             FROM findings 
             WHERE domain LIKE ? 
             ORDER BY scanned_at DESC 
             LIMIT ?",
        )?;
        
        stmt.query_map(params![pattern, limit as i64], |row| Finding::from_row(row))?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect findings")?
    } else {
        stmt = conn.prepare(
            "SELECT id, domain, rule_name, matched_path, detected, scanned_at 
             FROM findings 
             ORDER BY scanned_at DESC 
             LIMIT ?",
        )?;
        
        stmt.query_map(params![limit as i64], |row| Finding::from_row(row))?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect findings")?
    };
    
    Ok(findings)
}

/// Get findings by rule name pattern
pub fn get_findings_by_rule(
    conn: &Connection,
    rule_pattern: Option<&str>,
    limit: usize,
) -> Result<Vec<Finding>> {
    let mut stmt;
    let findings = if let Some(pattern) = rule_pattern {
        let pattern = format!("%{}%", pattern);
        stmt = conn.prepare(
            "SELECT id, domain, rule_name, matched_path, detected, scanned_at 
             FROM findings 
             WHERE rule_name LIKE ? 
             ORDER BY scanned_at DESC 
             LIMIT ?",
        )?;
        
        stmt.query_map(params![pattern, limit as i64], |row| Finding::from_row(row))?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect findings")?
    } else {
        stmt = conn.prepare(
            "SELECT id, domain, rule_name, matched_path, detected, scanned_at 
             FROM findings 
             ORDER BY scanned_at DESC 
             LIMIT ?",
        )?;
        
        stmt.query_map(params![limit as i64], |row| Finding::from_row(row))?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect findings")?
    };
    
    Ok(findings)
}

/// List findings in the database with optional filtering
pub fn list_results(
    db_file: &str,
    domain_pattern: Option<&str>,
    rule_pattern: Option<&str>,
    limit: usize,
) -> Result<()> {
    let conn = Connection::open(db_file)
        .context(format!("Failed to open database: {}", db_file))?;
    
    let findings = if domain_pattern.is_some() {
        get_findings_by_domain(&conn, domain_pattern, limit)?
    } else if rule_pattern.is_some() {
        get_findings_by_rule(&conn, rule_pattern, limit)?
    } else {
        // No specific filter, get latest results
        let mut stmt = conn.prepare(
            "SELECT id, domain, rule_name, matched_path, detected, scanned_at 
             FROM findings 
             ORDER BY scanned_at DESC 
             LIMIT ?",
        )?;
        
        let result = stmt.query_map(params![limit as i64], |row| Finding::from_row(row))?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to collect findings")?;
            
        result
    };
    
    // Print results in a table format
    println!("📋 Scan Results:");
    println!(
        "{:<5} {:<30} {:<25} {:<30} {:<10} {:<20}",
        "ID", "Domain", "Rule", "Path", "Detected", "Scanned At"
    );
    println!("{:-<120}", "");
    
    for finding in &findings {
        println!(
            "{:<5} {:<30} {:<25} {:<30} {:<10} {:<20}",
            finding.id,
            truncate_string(&finding.domain, 29),
            truncate_string(&finding.rule_name, 24),
            truncate_string(&finding.matched_path, 29),
            if finding.detected { "✅ Yes" } else { "❌ No" },
            finding.scanned_at.format("%Y-%m-%d %H:%M:%S").to_string()
        );
    }
    
    println!("\nTotal results: {}", findings.len());
    
    Ok(())
}

/// Export findings to a file
pub fn export_results(db_file: &str, output_file: &str, format: &str) -> Result<()> {
    let conn = Connection::open(db_file)
        .context(format!("Failed to open database: {}", db_file))?;
    
    // Get all findings
    let mut stmt = conn.prepare(
        "SELECT id, domain, rule_name, matched_path, detected, scanned_at 
         FROM findings 
         ORDER BY domain, rule_name",
    )?;
    
    let findings = stmt
        .query_map([], |row| Finding::from_row(row))?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to collect findings")?;
    
    // Ensure parent directory exists
    if let Some(parent) = Path::new(output_file).parent() {
        if !parent.exists() {
            create_dir_all(parent).context("Failed to create output directory")?;
        }
    }
    
    match format.to_lowercase().as_str() {
        "csv" => export_to_csv(&findings, output_file)?,
        "json" => export_to_json(&findings, output_file)?,
        _ => anyhow::bail!("Unsupported export format: {}", format),
    }
    
    info!("✅ Exported {} findings to {}", findings.len(), output_file);
    
    Ok(())
}

/// Export findings to CSV format
fn export_to_csv(findings: &[Finding], output_file: &str) -> Result<()> {
    let path = PathBuf::from(output_file);
    let mut writer = csv::Writer::from_path(path)?;
    
    // Write header
    writer.write_record(&[
        "ID",
        "Domain",
        "Rule",
        "Path",
        "Detected",
        "Scanned At",
    ])?;
    
    // Write findings
    for finding in findings {
        writer.write_record(&[
            finding.id.to_string(),
            finding.domain.clone(),
            finding.rule_name.clone(),
            finding.matched_path.clone(),
            finding.detected.to_string(),
            finding.scanned_at.to_rfc3339(),
        ])?;
    }
    
    writer.flush()?;
    
    Ok(())
}

/// Export findings to JSON format
fn export_to_json(findings: &[Finding], output_file: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    std::fs::write(output_file, json)?;
    
    Ok(())
}

/// Helper to truncate a string to max_length with ellipsis if needed
fn truncate_string(s: &str, max_length: usize) -> String {
    if s.len() <= max_length {
        s.to_string()
    } else {
        format!("{}...", &s[0..max_length - 3])
    }
}
