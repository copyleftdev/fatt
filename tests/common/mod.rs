use std::sync::Once;

// Setup function that is only run once for all tests
static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        // Initialize logging for tests
        if std::env::var("TEST_LOG").is_ok() {
            let subscriber = tracing_subscriber::FmtSubscriber::builder()
                .with_max_level(tracing::Level::DEBUG)
                .with_test_writer()
                .finish();
            
            tracing::subscriber::set_global_default(subscriber)
                .expect("Failed to set subscriber");
        }
    });
}
