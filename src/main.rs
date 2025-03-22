use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::info;
use uuid::Uuid;

mod config;
mod db;
mod distributed;
mod logger;
mod resolver;
mod rules;
mod scanner;
mod utils;

#[derive(Parser)]
#[command(
    name = "fatt",
    author = "FATT Development Team",
    version,
    about = "Find All The Things - A high-performance, distributed security scanning tool",
    long_about = "FATT (Find All The Things) is a high-performance, modular, asynchronous, and distributed security scanning CLI tool designed to rapidly identify sensitive or exposed files and directories across millions of domains."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan domains for sensitive files and directories
    Scan {
        /// Input file containing domains to scan (one per line)
        #[arg(short, long, value_name = "FILE")]
        input: String,
        
        /// Rules file in YAML format
        #[arg(short, long, value_name = "FILE", default_value = "rules.yaml")]
        rules: String,
        
        /// Output database file for results
        #[arg(short, long, value_name = "FILE", default_value = "results.sqlite")]
        database: String,
        
        /// Concurrency level (number of simultaneous requests)
        #[arg(short, long, default_value = "100")]
        concurrency: usize,
        
        /// Batch size for domain processing
        #[arg(short, long, default_value = "1000")]
        batch_size: usize,
        
        /// Connect timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
        
        /// Number of worker threads
        #[arg(short, long, default_value = "0")]
        threads: usize,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Manage scanning rules
    Rules {
        #[command(subcommand)]
        action: RulesCommands,
    },
    
    /// Query and export scan results
    Results {
        #[command(subcommand)]
        action: ResultsCommands,
    },
    
    /// Manage DNS cache
    Dns {
        #[command(subcommand)]
        action: DnsCommands,
    },
    
    /// Control distributed worker nodes
    Worker {
        #[command(subcommand)]
        action: WorkerCommands,
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// Add a new rule
    Add {
        /// Rules YAML file
        #[arg(short, long, value_name = "FILE")]
        file: String,
    },
    
    /// Remove a rule
    Remove {
        /// Rule name to remove
        #[arg(short, long)]
        name: String,
    },
    
    /// List available rules
    List {
        /// Rules YAML file
        #[arg(short, long, value_name = "FILE", default_value = "rules.yaml")]
        file: String,
    },
}

#[derive(Subcommand)]
enum ResultsCommands {
    /// Export results to a file
    Export {
        /// Output file for results
        #[arg(short, long, value_name = "FILE")]
        output: String,
        
        /// Database file containing results
        #[arg(short, long, value_name = "FILE", default_value = "results.sqlite")]
        database: String,
        
        /// Export format (csv, json)
        #[arg(short, long, default_value = "csv")]
        format: String,
    },
    
    /// List scan results
    List {
        /// Database file containing results
        #[arg(short, long, value_name = "FILE", default_value = "results.sqlite")]
        database: String,
        
        /// Filter by domain pattern
        #[arg(short, long)]
        domain: Option<String>,
        
        /// Filter by rule name pattern
        #[arg(short, long)]
        rule: Option<String>,
        
        /// Limit number of results
        #[arg(short, long, default_value = "100")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum DnsCommands {
    /// Flush the DNS cache
    Flush,
    
    /// Show DNS cache status
    Status,
}

#[derive(Subcommand)]
enum WorkerCommands {
    /// Start a worker node
    Start {
        /// Master node address
        #[arg(short, long, value_name = "HOST:PORT")]
        master: String,
        
        /// Worker node identifier
        #[arg(short, long)]
        id: Option<String>,
        
        /// Listen port for worker
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    
    /// Stop a worker node
    Stop {
        /// Worker ID or 'all'
        #[arg(short, long, default_value = "all")]
        id: String,
    },
    
    /// Show worker node status
    Status,
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args = Cli::parse();
    
    // Initialize logger
    logger::init_logger(false, None)?;
    
    // Run command based on subcommand
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        match args.command {
            Commands::Scan {
                input,
                rules,
                database,
                concurrency,
                batch_size,
                timeout,
                threads,
                verbose,
            } => {
                logger::set_verbosity(verbose);
                
                let scan_config = config::ScanConfig {
                    input_file: input,
                    rules_file: rules,
                    concurrency,
                    verbosity: if verbose { 3 } else { 2 }, // 3 for debug, 2 for info
                    distributed: false,
                    output_file: None,
                    db_path: database,
                    dns_timeout: 5, // default value
                    http_timeout: timeout,
                    connect_timeout: timeout,
                    dns_cache_size: 10000, // default value
                    quiet: false,
                    dns_only: false,
                };
                
                scanner::run_scan(scan_config).await
            }
            
            Commands::Rules { action } => match action {
                RulesCommands::Add { file } => {
                    rules::add_rule(&file)
                }
                RulesCommands::Remove { name } => {
                    rules::remove_rule(&name)
                }
                RulesCommands::List { file } => {
                    rules::list_rules(&file)
                }
            },
            
            Commands::Results { action } => match action {
                ResultsCommands::Export {
                    output,
                    database,
                    format,
                } => {
                    db::export_results(&database, &output, &format)
                }
                ResultsCommands::List {
                    database,
                    domain,
                    rule,
                    limit,
                } => {
                    db::list_results(&database, domain.as_deref(), rule.as_deref(), limit)
                }
            },
            
            Commands::Dns { action } => match action {
                DnsCommands::Flush => {
                    resolver::flush_cache().await.context("Failed to flush DNS cache")
                }
                DnsCommands::Status => {
                    resolver::show_cache_status().await.context("Failed to show DNS cache status")
                }
            },
            
            Commands::Worker { action } => match action {
                WorkerCommands::Start { master, id, port } => {
                    let worker_id = id.unwrap_or_else(|| Uuid::new_v4().to_string());
                    info!("Starting worker with ID: {}", worker_id);
                    
                    let worker_config = distributed::WorkerConfig {
                        worker_id,
                        master: format!("{}:{}", master, port),
                        concurrency: 10, // Default concurrency
                    };
                    
                    distributed::start_worker(&worker_config).await
                        .context("Failed to start worker")
                }
                WorkerCommands::Stop { id } => {
                    distributed::stop_worker(&id).await.context("Failed to stop worker")
                }
                WorkerCommands::Status => {
                    distributed::worker_status().await.context("Failed to get worker status")
                }
            },
        }
    })?;

    Ok(())
}
