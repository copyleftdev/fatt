use anyhow::Result;
use std::path::PathBuf;
use fatt::rules::{Rule, RuleSet, Severity};

#[test]
fn test_severity_ordering() {
    // Test that severities are ordered correctly
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
    
    // Test to_value() conversion
    assert_eq!(Severity::Critical.to_value(), 5);
    assert_eq!(Severity::High.to_value(), 4);
    assert_eq!(Severity::Medium.to_value(), 3);
    assert_eq!(Severity::Low.to_value(), 2);
    assert_eq!(Severity::Info.to_value(), 1);
}

#[test]
fn test_rule_creation() {
    // Test rule constructor
    let rule = Rule::new(
        "Test Rule", 
        "/test-path", 
        "test-signature", 
        "Test description", 
        Severity::High
    );
    
    assert_eq!(rule.name, "Test Rule");
    assert_eq!(rule.path, "/test-path");
    assert_eq!(rule.signature, "test-signature");
    assert_eq!(rule.description, Some("Test description".to_string()));
    assert_eq!(rule.severity, Some(Severity::High));
}

#[test]
fn test_load_rules_from_file() -> Result<()> {
    // Path to test rules file
    let test_rules_path = PathBuf::from("tests/data/rules/test-rules.yaml");
    
    // Load rules
    let ruleset = fatt::rules::load_rules(test_rules_path.to_str().unwrap())?;
    
    // Verify ruleset content
    assert_eq!(ruleset.rules.len(), 4);
    
    // Verify rule properties
    let first_rule = &ruleset.rules[0];
    assert_eq!(first_rule.name, "Test Rule 1");
    assert_eq!(first_rule.path, "/admin");
    assert_eq!(first_rule.signature, "<title>Admin Panel</title>");
    assert_eq!(first_rule.description, Some("Admin panel detection".to_string()));
    assert_eq!(first_rule.severity, Some(Severity::Critical));

    // Verify sorting
    assert_eq!(ruleset.rules[0].severity, Some(Severity::Critical));
    assert_eq!(ruleset.rules[1].severity, Some(Severity::Medium));
    assert_eq!(ruleset.rules[2].severity, Some(Severity::Low));
    assert!(ruleset.rules[3].severity.is_none());
    
    Ok(())
}

#[test]
fn test_ruleset_sort_by_severity() {
    // Create a ruleset with unsorted rules
    let mut ruleset = RuleSet {
        rules: vec![
            Rule::new("Info Rule", "/path1", "sig1", "desc1", Severity::Info),
            Rule::new("Critical Rule", "/path2", "sig2", "desc2", Severity::Critical),
            Rule::new("Medium Rule", "/path3", "sig3", "desc3", Severity::Medium),
            Rule::new("High Rule", "/path4", "sig4", "desc4", Severity::High),
        ],
    };
    
    // Sort the ruleset
    ruleset.sort_by_severity();
    
    // Verify sorting order (highest to lowest)
    assert_eq!(ruleset.rules[0].severity, Some(Severity::Critical));
    assert_eq!(ruleset.rules[1].severity, Some(Severity::High));
    assert_eq!(ruleset.rules[2].severity, Some(Severity::Medium));
    assert_eq!(ruleset.rules[3].severity, Some(Severity::Info));
}
