use fatt::utils;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_read_domains() -> anyhow::Result<()> {
    // Create a temporary directory
    let temp_dir = tempdir()?;
    let file_path = temp_dir.path().join("test_domains.txt");

    // Create a test domains file
    let domains = vec![
        "example.com",
        "test.com",
        "security.io",
        "   example.org  ",    // With whitespace to test trimming
        "# This is a comment", // Should be skipped
        "",                    // Empty line should be skipped
        "duplicate.com",
        "duplicate.com", // Duplicate should only be counted once
    ];

    let mut file = File::create(&file_path)?;
    for domain in &domains {
        writeln!(file, "{}", domain)?;
    }

    // Test reading domains
    let result = utils::read_domains(file_path.to_str().unwrap())?;

    // Verify the result
    assert_eq!(result.len(), 5); // 5 unique domains (excluding comments, empty lines, and duplicates)
    assert!(result.contains(&"example.com".to_string()));
    assert!(result.contains(&"test.com".to_string()));
    assert!(result.contains(&"security.io".to_string()));
    assert!(result.contains(&"example.org".to_string())); // Should be trimmed
    assert!(result.contains(&"duplicate.com".to_string()));
    assert!(!result.contains(&"# This is a comment".to_string())); // Comment should be excluded

    Ok(())
}

#[test]
fn test_chunk_vector() {
    // Create test data
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    // Test with chunk size of 3
    let chunks = utils::chunk_vector(data.clone(), 3);
    assert_eq!(chunks.len(), 4);
    assert_eq!(chunks[0], vec![1, 2, 3]);
    assert_eq!(chunks[1], vec![4, 5, 6]);
    assert_eq!(chunks[2], vec![7, 8, 9]);
    assert_eq!(chunks[3], vec![10]);

    // Test with chunk size equal to vector length
    let chunks = utils::chunk_vector(data.clone(), 10);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0], data);

    // Test with chunk size larger than vector length
    let chunks = utils::chunk_vector(data.clone(), 20);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0], data);

    // Test with empty vector
    let empty: Vec<i32> = Vec::new();
    let chunks = utils::chunk_vector(empty, 5);
    assert_eq!(chunks.len(), 0);
}

#[test]
fn test_is_valid_domain() {
    // Valid domains
    assert!(utils::is_valid_domain("example.com"));
    assert!(utils::is_valid_domain("sub.example.com"));
    assert!(utils::is_valid_domain("sub-domain.example.co.uk"));
    assert!(utils::is_valid_domain("xn--bcher-kva.example")); // IDN
    assert!(utils::is_valid_domain("123.example.com"));

    // Invalid domains
    assert!(!utils::is_valid_domain(""));
    assert!(!utils::is_valid_domain("example"));
    assert!(!utils::is_valid_domain(".com"));
    assert!(!utils::is_valid_domain("example..com"));
    assert!(!utils::is_valid_domain("example.com."));
    assert!(!utils::is_valid_domain("http://example.com"));
    assert!(!utils::is_valid_domain("example.com/path"));
    assert!(!utils::is_valid_domain("user@example.com"));
    assert!(!utils::is_valid_domain(" example.com "));
}

#[test]
fn test_format_duration() {
    // Test various durations
    assert_eq!(utils::format_duration(0.5), "0.5s");
    assert_eq!(utils::format_duration(1.0), "1.0s");
    assert_eq!(utils::format_duration(59.5), "59.5s");
    assert_eq!(utils::format_duration(60.0), "1m 0.0s");
    assert_eq!(utils::format_duration(90.5), "1m 30.5s");
    assert_eq!(utils::format_duration(3600.0), "1h 0m 0.0s");
    assert_eq!(utils::format_duration(3661.5), "1h 1m 1.5s");
    assert_eq!(utils::format_duration(86400.0), "24h 0m 0.0s");
    assert_eq!(utils::format_duration(90061.5), "25h 1m 1.5s");
}
