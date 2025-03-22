use std::sync::{Arc, Mutex};
use tracing;
use tracing_subscriber::prelude::*;

/// A test utility for capturing and testing log output
pub struct LogCapture {
    lines: Arc<Mutex<Vec<String>>>,
}

impl LogCapture {
    /// Create a new log capture utility
    pub fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Run a function with log capturing enabled
    pub fn capture_logs<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let test_layer = TestLayer {
            lines: Arc::clone(&self.lines),
        };

        // Install our test layer for the duration of the function
        tracing::subscriber::with_default(tracing_subscriber::registry().with(test_layer), f)
    }

    /// Get all captured log lines
    pub fn logs(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    /// Print all captured logs for debugging
    pub fn print_logs(&self) {
        let logs = self.lines.lock().unwrap();
        println!("Captured {} log lines:", logs.len());
        for (i, line) in logs.iter().enumerate() {
            println!("{}: {}", i + 1, line);
        }
    }

    /// Check if any log line contains the given text
    pub fn contains(&self, text: &str) -> bool {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains(text))
    }
}

// The actual tracing layer implementation
struct TestLayer {
    lines: Arc<Mutex<Vec<String>>>,
}

impl<S> tracing_subscriber::layer::Layer<S> for TestLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        use tracing::field::{Field, Visit};
        struct StringVisitor {
            result: String,
        }

        impl Visit for StringVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                // Capture message field
                if field.name() == "message" {
                    self.result = format!("{:?}", value).replace("\"", "");
                }
            }
        }

        let mut visitor = StringVisitor {
            result: String::new(),
        };
        event.record(&mut visitor);

        if !visitor.result.is_empty() {
            self.lines.lock().unwrap().push(visitor.result);
        }
    }
}
