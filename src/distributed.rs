use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tracing::{debug, error, info};
use bincode::{Encode, Decode, config};
use std::collections::HashMap;
use lazy_static::lazy_static;

/// Configuration for a worker node
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Worker ID
    pub worker_id: String,
    
    /// Master node address
    pub master: String,
    
    /// Maximum concurrency
    pub concurrency: usize,
}

/// Message types for worker-master communication
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub enum WorkerMessage {
    /// Worker registration
    Register {
        worker_id: String,
        capabilities: WorkerCapabilities,
    },
    
    /// Worker heartbeat
    Heartbeat {
        worker_id: String,
        status: WorkerStatus,
    },
    
    /// Domain scan request
    ScanRequest {
        domains: Vec<String>,
        batch_id: String,
    },
    
    /// Domain scan result
    ScanResult {
        worker_id: String,
        batch_id: String,
        findings: Vec<ScanFinding>,
    },
    
    /// Shutdown request
    Shutdown {
        worker_id: String,
    },
}

/// Worker capabilities
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct WorkerCapabilities {
    /// Maximum concurrent scans
    pub max_concurrency: usize,
    
    /// Worker version
    pub version: String,
}

/// Worker status
#[derive(Debug, Clone, Serialize, Deserialize, Default, Encode, Decode)]
pub struct WorkerStatus {
    /// Number of active scans
    pub active_scans: usize,
    
    /// Number of completed scans
    pub completed_scans: usize,
    
    /// Number of findings
    pub findings: usize,
    
    /// Uptime in seconds
    pub uptime_seconds: u64,
}

/// Scan finding
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct ScanFinding {
    /// Domain
    pub domain: String,
    
    /// Rule name
    pub rule_name: String,
    
    /// Matched path
    pub matched_path: String,
    
    /// Whether the target was detected
    pub detected: bool,
}

/// Connected worker information
pub struct ConnectedWorker {
    /// Worker ID
    pub id: String,
    
    /// Worker capabilities
    pub capabilities: WorkerCapabilities,
    
    /// Write half of the TCP stream
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
    
    /// Worker status
    pub status: WorkerStatus,
}

lazy_static! {
    static ref WORKERS: Mutex<HashMap<String, Arc<ConnectedWorker>>> = Mutex::new(HashMap::new());
}

/// Stop a worker by ID
pub async fn stop_worker(worker_id: &str) -> Result<()> {
    let workers = WORKERS.lock().await;
    
    if let Some(worker) = workers.get(worker_id) {
        let shutdown_msg = WorkerMessage::Shutdown {
            worker_id: worker_id.to_string(),
        };
        
        send_message(&worker.writer, &shutdown_msg).await
            .context(format!("Failed to send shutdown message to worker {}", worker_id))?;
        
        info!("⏹️ Sent shutdown request to worker: {}", worker_id);
        Ok(())
    } else {
        anyhow::bail!("Worker not found: {}", worker_id)
    }
}

/// Get status of all workers
pub async fn worker_status() -> Result<()> {
    let workers = WORKERS.lock().await;
    
    if workers.is_empty() {
        info!("🔍 No workers connected");
        return Ok(());
    }
    
    info!("🔍 Connected Workers: {}", workers.len());
    
    for (id, worker) in workers.iter() {
        info!(
            "👷 Worker {}: Active={}, Completed={}, Findings={}, MaxConcurrency={}",
            id,
            worker.status.active_scans,
            worker.status.completed_scans,
            worker.status.findings,
            worker.capabilities.max_concurrency
        );
    }
    
    Ok(())
}

/// Start a worker node
pub async fn start_worker(config: &WorkerConfig) -> Result<()> {
    info!("🚀 Starting worker node with ID: {}", config.worker_id);
    
    // Connect to master
    let stream = TcpStream::connect(&config.master)
        .await
        .context(format!("Failed to connect to master at {}", config.master))?;
    
    // Split the stream
    let (mut reader, write_half) = stream.into_split();
    let writer = Arc::new(Mutex::new(write_half));
    
    // Register with master
    let capabilities = WorkerCapabilities {
        max_concurrency: config.concurrency,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    
    let register_msg = WorkerMessage::Register {
        worker_id: config.worker_id.clone(),
        capabilities: capabilities.clone(),
    };
    
    send_message(&writer, &register_msg).await
        .context("Failed to register with master")?;
    
    info!("✅ Registered with master at {}", config.master);
    
    // Handle messages
    loop {
        // Read message length (4 bytes)
        let mut len_bytes = [0u8; 4];
        reader.read_exact(&mut len_bytes).await
            .context("Failed to read message length")?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        
        // Read message
        let mut buffer = vec![0u8; len];
        reader.read_exact(&mut buffer).await
            .context("Failed to read message")?;
        
        // Deserialize message
        let message: WorkerMessage = bincode::decode_from_slice(&buffer, bincode::config::standard())
            .context("Failed to deserialize message")?.0;
            
        debug!("📩 Received message: {:?}", message);
        
        // Handle message
        match message {
            WorkerMessage::ScanRequest { domains, batch_id } => {
                info!("🔍 Received scan request for {} domains (batch: {})", domains.len(), batch_id);
                
                // TODO: Implement scan logic
                let _scan_config = config.clone();
                
                // For now, just send back empty results
                let result_msg = WorkerMessage::ScanResult {
                    worker_id: config.worker_id.clone(),
                    batch_id,
                    findings: vec![],
                };
                
                send_message(&writer, &result_msg).await
                    .context("Failed to send scan results")?;
            },
            WorkerMessage::Shutdown { .. } => {
                info!("⏹️ Received shutdown request, stopping worker");
                break;
            },
            _ => {
                error!("❓ Received unexpected message type");
            }
        }
    }
    
    Ok(())
}

/// Send a message to a worker
async fn send_message(writer: &Arc<Mutex<OwnedWriteHalf>>, message: &WorkerMessage) -> Result<()> {
    let mut writer_guard = writer.lock().await;
    
    // Serialize the message using bincode
    let config = config::standard();
    let encoded = bincode::encode_to_vec(message, config)?;
    
    // Write the message length as u32 first
    let msg_len = encoded.len() as u32;
    writer_guard.write_all(&msg_len.to_be_bytes()).await?;
    
    // Then write the actual message
    writer_guard.write_all(&encoded).await?;
    writer_guard.flush().await?;
    
    Ok(())
}

/// Read a message from a stream
async fn read_message(stream: &mut TcpStream) -> Result<WorkerMessage> {
    // Read message length
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let msg_len = u32::from_be_bytes(len_bytes) as usize;
    
    // Read the actual message
    let mut buffer = vec![0u8; msg_len];
    stream.read_exact(&mut buffer).await?;
    
    // Deserialize using bincode
    let config = config::standard();
    let (message, _): (WorkerMessage, _) = bincode::decode_from_slice(&buffer, config)?;
    
    Ok(message)
}

/// Start a master node for distributed scanning
pub async fn start_master(
    listen_addr: &str,
    _scan_config: crate::config::ScanConfig,
) -> Result<()> {
    info!("🌐 Starting master node on {}", listen_addr);
    
    // Create our TCP listener
    let listener = TcpListener::bind(listen_addr).await
        .context(format!("Failed to bind to {}", listen_addr))?;
    
    info!("✅ Master node started, waiting for workers to connect");
    
    // Create a shared list of connected workers
    let workers = Arc::new(Mutex::new(Vec::new()));
    
    loop {
        // Accept connections
        let (socket, addr) = listener.accept().await
            .context("Failed to accept connection")?;
        
        info!("✅ New connection from: {}", addr);
        
        // Clone the workers for this connection
        let workers_clone = workers.clone();
        
        // Handle connection in separate task
        tokio::spawn(async move {
            if let Err(e) = handle_worker_connection(socket, workers_clone).await {
                error!("❌ Error handling worker connection: {}", e);
            }
        });
    }
}

/// Handle a worker connection
async fn handle_worker_connection(
    mut stream: TcpStream,
    _workers: Arc<Mutex<Vec<ConnectedWorker>>>,
) -> Result<()> {
    info!("🔌 Worker connected from: {}", stream.peer_addr()?);
    
    // Read initial message
    let message = read_message(&mut stream).await?;
    
    match message {
        WorkerMessage::Register { worker_id, capabilities } => {
            info!(
                "👷 Worker registered: {} (concurrency={})",
                worker_id, capabilities.max_concurrency
            );
            
            // Split the stream and store the write half for sending messages
            let (_read_half, write_half) = stream.into_split();
            
            // Create the connected worker
            let worker = Arc::new(ConnectedWorker {
                id: worker_id.clone(),
                capabilities,
                writer: Arc::new(Mutex::new(write_half)),
                status: WorkerStatus::default(),
            });
            
            // Store in global workers map
            {
                let mut workers = WORKERS.lock().await;
                workers.insert(worker_id.clone(), worker.clone());
            }
            
            // Send a heartbeat request
            let heartbeat = WorkerMessage::Heartbeat {
                worker_id: worker_id.clone(),
                status: WorkerStatus::default(),
            };
            
            send_message(&worker.writer, &heartbeat).await?;
            
            Ok(())
        }
        _ => {
            error!("❌ Expected Register message from worker, got something else");
            anyhow::bail!("Invalid initial message from worker")
        }
    }
}

/// Message types for master-worker communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MasterMessage {
    /// Registration response
    RegisterResponse {
        accepted: bool,
        message: Option<String>,
    },
    
    /// Work assignment
    WorkAssignment {
        batch_id: String,
        domains: Vec<String>,
        rules: Vec<ScanRule>,
    },
    
    /// No work available
    NoWorkAvailable,
    
    /// Shutdown worker command
    Shutdown {
        reason: Option<String>,
    },
}

/// Simplified rule representation for distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRule {
    pub name: String,
    pub paths: Vec<String>,
    pub severity: String,
}
