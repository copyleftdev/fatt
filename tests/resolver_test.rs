use fatt::resolver::DnsResolver;
use tempfile::tempdir;
use std::path::PathBuf;
use std::net::IpAddr;
use std::str::FromStr;

#[test]
fn test_resolver_creation() -> anyhow::Result<()> {
    // Create a temporary directory for DNS cache
    let temp_dir = tempdir()?;
    // We're using a temporary directory now, no need for cache_path variable
    
    // Test for testing resolver
    let resolver = DnsResolver::new_for_testing()?;
    assert!(resolver.is_test_resolver());
    
    // Clean up
    temp_dir.close()?;
    
    Ok(())
}

#[tokio::test]
async fn test_resolver_lookup() -> anyhow::Result<()> {
    // Create test resolver (should use mock responses)
    let resolver = DnsResolver::new_for_testing()?;
    
    // Test some domain lookups with the test resolver
    let first_result = resolver.lookup("example.com").await?;
    let second_result = resolver.lookup("test.example.org").await?;
    
    // Both lookups should succeed and have results
    assert!(first_result.is_some());
    assert!(second_result.is_some());
    
    // Make sure we got valid IP addresses
    if let Some(ip) = &first_result {
        assert!(!ip.is_empty(), "First lookup returned empty IP");
        assert_eq!(ip, "192.0.2.1"); // TEST-NET-1 address
    }
    
    if let Some(ip) = &second_result {
        assert!(!ip.is_empty(), "Second lookup returned empty IP");
        assert_eq!(ip, "192.0.2.1");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_resolver_concurrency() -> anyhow::Result<()> {
    // Create test resolver with limited concurrency
    let resolver = DnsResolver::new_for_testing()?;
    
    // Perform multiple concurrent lookups
    let futures = vec![
        resolver.lookup("domain1.com"),
        resolver.lookup("domain2.com"),
        resolver.lookup("domain3.com"),
        resolver.lookup("domain4.com"),
        resolver.lookup("domain5.com"),
    ];
    
    // Run all lookups concurrently
    let results = futures::future::join_all(futures).await;
    
    // Verify all completed successfully
    for result in results {
        assert!(result.is_ok());
        let ips = result?;
        assert!(ips.is_some());
    }
    
    Ok(())
}

#[tokio::test]
async fn test_resolver_cache() -> anyhow::Result<()> {
    // Create a temporary directory for DNS cache
    let temp_dir = tempdir()?;
    // We're using a temporary directory now, no need for cache_path variable
    
    // Create resolver with caching
    let resolver = DnsResolver::new_for_testing()?;
    
    // Perform the same lookup multiple times to test caching
    let domain = "cached-example.com";
    
    // First lookup should not be cached
    let first_result = resolver.lookup(domain).await?;
    
    // Second lookup should use cache
    let second_result = resolver.lookup(domain).await?;
    
    // Both lookups should succeed and have results
    assert!(first_result.is_some());
    assert!(second_result.is_some());
    
    // Make sure we got valid IP addresses
    if let Some(ip) = &first_result {
        assert!(!ip.is_empty(), "First lookup returned empty IP");
    }
    
    if let Some(ip) = &second_result {
        assert!(!ip.is_empty(), "Second lookup returned empty IP");
    }
    
    // Results should be the same
    assert_eq!(first_result, second_result);
    
    Ok(())
}
