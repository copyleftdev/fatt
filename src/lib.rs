// Export internal modules for testing
pub mod config;
pub mod db;
pub mod distributed;
pub mod logger;
pub mod resolver;
pub mod rules;
pub mod scanner;
pub mod utils;

// Re-export common types for easier access
pub use config::ScanConfig;
pub use rules::{Rule, RuleSet, Severity};
