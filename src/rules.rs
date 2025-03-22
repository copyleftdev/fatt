use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use tracing::{info, debug};

use crate::logger;

/// Severity level for rules
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// A scanning rule definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub name: String,
    pub path: String,
    pub signature: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
}

/// Collection of rules from a rules file
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

/// Load rules from a YAML file
pub fn load_rules(rules_file: &str) -> Result<RuleSet> {
    let path = Path::new(rules_file);
    let mut file = File::open(path).context(format!("Failed to open rules file: {}", rules_file))?;
    
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .context(format!("Failed to read rules file: {}", rules_file))?;
    
    let ruleset: RuleSet = serde_yaml::from_str(&contents)
        .context(format!("Failed to parse rules file: {}", rules_file))?;
    
    info!("📋 Loaded {} rules from {}", ruleset.rules.len(), rules_file);
    
    for rule in &ruleset.rules {
        logger::log_rule_loaded(&rule.name, 1); // Just count the signature as 1 pattern
    }
    
    Ok(ruleset)
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
