use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, prelude::*};
use std::path::Path;
use tracing::{info, debug};

use crate::logger;

/// Severity levels for rules
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Convert severity to a numeric value for ordering
    pub fn to_value(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.to_value().cmp(&other.to_value()))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_value().cmp(&other.to_value())
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

/// A scanning rule definition
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub name: String,
    pub path: String,
    pub signature: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
}

impl Rule {
    /// Create a new rule
    pub fn new(name: &str, path: &str, signature: &str, description: &str, severity: Severity) -> Self {
        Self {
            name: name.to_string(),
            path: path.to_string(),
            signature: signature.to_string(),
            description: Some(description.to_string()),
            severity: Some(severity),
        }
    }
}

/// Collection of rules from a rules file
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    /// Load rules from a YAML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .context(format!("Failed to open rules file: {}", path.as_ref().display()))?;
        
        let reader = BufReader::new(file);
        let mut ruleset: RuleSet = serde_yaml::from_reader(reader)
            .context(format!("Failed to parse rules file: {}", path.as_ref().display()))?;
        
        // Sort rules by severity (highest first)
        ruleset.sort_by_severity();
        
        info!("📋 Loaded {} rules from {}", ruleset.rules.len(), path.as_ref().display());
        
        for rule in &ruleset.rules {
            logger::log_rule_loaded(&rule.name, 1); // Just count the signature as 1 pattern
        }
        
        Ok(ruleset)
    }
    
    /// Sort rules by severity (highest first)
    pub fn sort_by_severity(&mut self) {
        self.rules.sort_by(|a, b| {
            // Use Option::cmp to handle None values
            match (&a.severity, &b.severity) {
                (Some(a_sev), Some(b_sev)) => b_sev.cmp(a_sev), // Highest severity first
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        });
    }
}

/// Load rules from a YAML file
pub fn load_rules(rules_file: &str) -> Result<RuleSet> {
    RuleSet::from_file(rules_file)
}

/// Add a new rule to the rules file
pub fn add_rule(yaml_file: &str) -> Result<()> {
    // This function would parse the provided YAML file and add the rules
    // to the main rules file, avoiding duplicates
    
    // Load the existing rules
    let existing_rules_path = "rules.yaml";
    let mut existing_ruleset = load_rules(existing_rules_path)?;
    
    // Load the new rules
    let new_ruleset = load_rules(yaml_file)?;
    
    // Track number of new rules added
    let original_count = existing_ruleset.rules.len();
    
    // Add new rules, avoiding duplicates by name
    for new_rule in new_ruleset.rules {
        if !existing_ruleset.rules.iter().any(|r| r.name == new_rule.name) {
            existing_ruleset.rules.push(new_rule);
        } else {
            debug!("Rule '{}' already exists, skipping", new_rule.name);
        }
    }
    
    // Calculate how many new rules were added
    let added_count = existing_ruleset.rules.len() - original_count;
    
    // Write the updated rules back to the file
    let yaml = serde_yaml::to_string(&existing_ruleset)
        .context("Failed to serialize rules to YAML")?;
    
    let mut file = File::create(existing_rules_path)
        .context(format!("Failed to open rules file for writing: {}", existing_rules_path))?;
    
    file.write_all(yaml.as_bytes())
        .context(format!("Failed to write to rules file: {}", existing_rules_path))?;
    
    info!("✅ Added {} new rules to {}", added_count, existing_rules_path);
    
    Ok(())
}

/// Remove a rule from the rules file
pub fn remove_rule(rule_name: &str) -> Result<()> {
    // Load existing rules
    let existing_rules_path = "rules.yaml";
    let mut ruleset = load_rules(existing_rules_path)?;
    
    // Check if the rule exists
    let original_count = ruleset.rules.len();
    ruleset.rules.retain(|rule| rule.name != rule_name);
    
    if ruleset.rules.len() == original_count {
        info!("⚠️ Rule '{}' not found in {}", rule_name, existing_rules_path);
        return Ok(());
    }
    
    // Write the updated rules back to the file
    let yaml = serde_yaml::to_string(&ruleset)
        .context("Failed to serialize rules to YAML")?;
    
    let mut file = File::create(existing_rules_path)
        .context(format!("Failed to open rules file for writing: {}", existing_rules_path))?;
    
    file.write_all(yaml.as_bytes())
        .context(format!("Failed to write to rules file: {}", existing_rules_path))?;
    
    info!("✅ Removed rule '{}' from {}", rule_name, existing_rules_path);
    
    Ok(())
}

/// List all rules in the rules file
pub fn list_rules(rules_file: &str) -> Result<()> {
    let ruleset = load_rules(rules_file)?;
    
    println!("📋 Rules in {}:", rules_file);
    println!("{:<30} {:<15} {:<}", "Name", "Severity", "Description");
    println!("{:-<60}", "");
    
    for rule in &ruleset.rules {
        let severity = match &rule.severity {
            Some(s) => s.to_string(),
            None => "N/A".to_string(),
        };
        let description = rule.description.as_deref().unwrap_or("N/A");
        println!("{:<30} {:<15} {:<}", rule.name, severity, description);
    }
    
    println!("\nTotal rules: {}", ruleset.rules.len());
    
    Ok(())
}
