use anyhow::Result;
use fatt::rules::{Rule, RuleSet, Severity};
use fatt::scanner;
use rusqlite::Connection;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_http_client_creation() -> Result<()> {
    // Test client creation with various timeout settings
    let client = scanner::create_http_client(10, 5)?;

    // Basic functionality test - verify client can make a request
    let mock_server = MockServer::start().await;

    // Set up a mock endpoint
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200).set_body_string("test response"))
        .mount(&mock_server)
        .await;

    // Make a request to test the client
    let response = client
        .get(&format!("{}/test", mock_server.uri()))
        .send()
        .await?;

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await?, "test response");

    Ok(())
}

#[tokio::test]
async fn test_check_path() -> Result<()> {
    // Start a mock server
    let mock_server = MockServer::start().await;

    // Set up mock endpoints for HEAD requests
    Mock::given(method("HEAD"))
        .and(path("/exists"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/not-exists"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Set up fallback mock endpoints for GET requests
    Mock::given(method("GET"))
        .and(path("/exists"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/not-exists"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Create HTTP client
    let client = scanner::create_http_client(5, 2)?;

    // Test path that exists
    let exists_url = format!("{}/exists", mock_server.uri());
    let exists_result = scanner::check_path(&client, &exists_url).await?;
    assert!(exists_result);

    // Test path that doesn't exist
    let not_exists_url = format!("{}/not-exists", mock_server.uri());
    let not_exists_result = scanner::check_path(&client, &not_exists_url).await?;
    assert!(!not_exists_result);

    Ok(())
}

#[tokio::test]
async fn test_check_signature() -> Result<()> {
    // Start a mock server
    let mock_server = MockServer::start().await;

    // Set up a mock endpoint with a specific signature
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><title>Admin Panel</title></html>"),
        )
        .mount(&mock_server)
        .await;

    // Create HTTP client
    let client = scanner::create_http_client(5, 2)?;

    // Test matching signature
    let admin_url = format!("{}/admin", mock_server.uri());
    let matching_result =
        scanner::check_signature(&client, &admin_url, "<title>Admin Panel</title>").await?;
    assert!(matching_result);

    // Test non-matching signature
    let non_matching_result = scanner::check_signature(&client, &admin_url, "login form").await?;
    assert!(!non_matching_result);

    Ok(())
}

#[tokio::test]
async fn test_scan_domain() -> Result<()> {
    // Start a mock server
    let mock_server = MockServer::start().await;

    // Set up two mock endpoints with different content
    Mock::given(method("GET"))
        .and(path("/admin"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<html><title>Admin Panel</title></html>"),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/admin"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><form><input name='username'><input name='password'></form></html>",
        ))
        .mount(&mock_server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/login"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/not-found"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/not-found"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // Create ruleset for testing
    let ruleset = RuleSet {
        rules: vec![
            Rule::new(
                "Admin Panel",
                "/admin",
                "<title>Admin Panel</title>",
                "Admin panel detection",
                Severity::High,
            ),
            Rule::new(
                "Login Form",
                "/login",
                "username.*password",
                "Login form detection",
                Severity::Medium,
            ),
            Rule::new(
                "Not Found",
                "/not-found",
                "should-not-match",
                "Should not be found",
                Severity::Low,
            ),
        ],
    };

    // Setup test DB in memory
    let db_conn = Arc::new(Mutex::new(Connection::open_in_memory()?));

    // Initialize schema with correct columns to match the actual implementation
    {
        let conn = db_conn.lock().await;
        conn.execute(
            "CREATE TABLE findings (
                id INTEGER PRIMARY KEY,
                domain TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                matched_path TEXT NOT NULL,
                detected INTEGER NOT NULL,
                scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(domain, rule_name)
            )",
            [],
        )?;
    }

    // Counters
    let tasks_completed = Arc::new(AtomicUsize::new(0));
    let matches_found = Arc::new(AtomicUsize::new(0));

    // Extract hostname from mock server URL
    let server_url = mock_server.uri();
    let hostname = server_url.strip_prefix("http://").unwrap_or(&server_url);

    // Scan the mock domain
    scanner::scan_domain(
        &hostname,
        &scanner::create_http_client(5, 2)?,
        &ruleset,
        &fatt::resolver::DnsResolver::new_for_testing()?,
        db_conn.clone(),
        tasks_completed.clone(),
        matches_found.clone(),
    )
    .await?;

    // Verify results
    assert_eq!(tasks_completed.load(Ordering::Relaxed), 3); // 3 rules tested
    assert_eq!(matches_found.load(Ordering::Relaxed), 1); // 1 match found (Admin Panel)

    // Verify database entries
    let conn = db_conn.lock().await;
    let mut stmt =
        conn.prepare("SELECT domain, matched_path, rule_name, detected FROM findings")?;
    let findings = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?, // domain
            row.get::<_, String>(1)?, // matched_path
            row.get::<_, String>(2)?, // rule_name
            row.get::<_, i64>(3)?,    // detected
        ))
    })?;

    let mut findings_vec = Vec::new();
    for finding in findings {
        let f = finding?;
        findings_vec.push(f);
    }

    // We should have 2 findings in total
    assert_eq!(findings_vec.len(), 2);

    // But only 1 should be detected (detected=1)
    let detected_findings = findings_vec.iter().filter(|f| f.3 == 1).count();
    assert_eq!(detected_findings, 1);

    // Check we have findings for both Admin Panel and Login Form
    let admin_finding = findings_vec.iter().find(|f| f.2 == "Admin Panel");
    let login_finding = findings_vec.iter().find(|f| f.2 == "Login Form");

    assert!(admin_finding.is_some());
    assert!(login_finding.is_some());

    // Verify Admin Panel was detected
    assert_eq!(admin_finding.unwrap().3, 1);

    // Verify Login Form was not detected (exists but signature didn't match)
    assert_eq!(login_finding.unwrap().3, 0);

    Ok(())
}
