use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::fs::{DirEntry, File};
use std::io::{self, Read, Write};
use std::thread;
use crossbeam::channel::{self, Sender, Receiver};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNone
};
use aes_gcm_siv::{
    aead::{Aead as AesAead, KeyInit as AesKeyInit},
    Aes256GcmSiv, Key as AesKey, Nonce as AesNonce
};
use tar::{Archive, Builder};
use rayon::prelude::*;
use std::collections::BTreeMap;
use argon2::Argon2;
use rand::Rng;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, Mutex};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize, serialize_into, deserialize_from};
use log::{info, error, debug};
use num_cpus;
use std::process::Command;
use fuser::{MountOption, Filesystem};
use std::sync::LazyLock;
use whoami;
use anyhow::{Context, Result, anyhow};

use crate::locker::try_cleanup_mount;

const CHUNK_SIZE: usize = 256 * 1024; // 256KB chunks
const NONCE_SIZE: usize = 12; // ChaCha20Poly1305 nonce size
const AES_NONCE_SIZE: usize = 12; // AES-GCM-SIV nonce size
const SALT_SIZE: usize = 16; // Argon2 salt size
const VERSION: u8 = 1;
const LAST_CHECKED_INTERVAL: Duration = Duration::from_millis(10);
const TIMEOUT_INTERVAL: Duration = Duration::from_millis(5);

// File identifier for Locker AI files (64 bytes)
const LOCKER_ID: [u8; 64] = [
    0x4C, 0x6F, 0x63, 0x6B, 0x65, 0x72, 0x20, 0x41, 0x49, 0x20, 0x46, 0x69, 0x6C, 0x65, 0x20, 0x49,
    0x64, 0x65, 0x6E, 0x74, 0x69, 0x66, 0x69, 0x65, 0x72, 0x20, 0x2D, 0x20, 0x54, 0x68, 0x69, 0x73,
    0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x73, 0x74, 0x6F,
    0x72, 0x61, 0x67, 0x65, 0x20, 0x66, 0x69, 0x6C, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74
];

static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct LazyShutdown {
    shutdown: Arc<AtomicBool>,
    error_message: Arc<Mutex<Vec<String>>>,
    last_checked: Instant,
}

impl LazyShutdown {
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
            error_message: Arc::new(Mutex::new(Vec::new())),
            last_checked: Instant::now(),
        }
    }

    pub fn request_shutdown(&self, message: &str) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Ok(mut error_msg) = self.error_message.lock() {
            error_msg.push(message.to_string());
        }
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    pub fn get_error_message(&self) -> String {
        self.error_message.lock()
            .map(|msgs| msgs.join(" "))
            .unwrap_or_else(|_| "Failed to get error message".to_string())
    }
    pub fn should_shutdown(&mut self) -> Option<String> {
        if self.last_checked.elapsed() >= Duration::from_millis(10) {
            self.last_checked = Instant::now();
            if self.is_shutdown() {
                return Some(self.get_error_message());
            }
        }
        None
    }
    pub fn err_is_shutdown<T, E: std::fmt::Display>(&self, result: Result<T, E>) -> bool {
        match result {
            Ok(_) => false,
            Err(e) => {
                self.request_shutdown(&e.to_string());
                true
            }
        }
    }
}

impl Clone for LazyShutdown {
    fn clone(&self) -> Self {
        Self {
            shutdown: Arc::clone(&self.shutdown),
            error_message: Arc::clone(&self.error_message),
            last_checked: Instant::now(),
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    ChaCha20Poly1305,
    Aes256GcmSiv,
}

impl EncryptionAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::ChaCha20Poly1305 => "chacha20poly1305".to_string(),
            Self::Aes256GcmSiv => "aes256-gcm-siv".to_string(),
        }
    }

    fn from_string(s: &str) -> Option<Self> {
        match s {
            "chacha20poly1305" => Some(Self::ChaCha20Poly1305),
            "aes256-gcm-siv" => Some(Self::Aes256GcmSiv),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Header {
    version: u32,
    salt: [u8; 32],
    pub algorithm: EncryptionAlgorithm,
}

#[derive(Serialize, Deserialize)]
struct EncryptedChunk {
    sequence_id: usize,
    nonce: [u8; 12],
    data: Vec<u8>,
}

#[derive(Clone)]
struct StreamEncrypter {
    algorithm: EncryptionAlgorithm,
    key: Vec<u8>,
}

impl StreamEncrypter {
    fn new(algorithm: EncryptionAlgorithm, key: &[u8]) -> Self {
        Self {
            algorithm,
            key: key.to_vec(),
        }
    }

    fn encrypt(&self, sequence_id: usize, data: &[u8]) -> io::Result<EncryptedChunk> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill(&mut nonce_bytes);
        
        let encrypted_data = if self.algorithm == EncryptionAlgorithm::ChaCha20Poly1305 {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&self.key));
            let nonce = ChaChaNone::from(nonce_bytes);
            cipher.encrypt(&nonce, data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ChaCha encryption error: {:?}", e)))?
        } else {
            let cipher = Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(&self.key));
            let nonce = AesNonce::from(nonce_bytes);
            cipher.encrypt(&nonce, data)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES encryption error: {:?}", e)))?
        };
        
        Ok(EncryptedChunk {
            sequence_id,
            nonce: nonce_bytes,
            data: encrypted_data,
        })
    }
}

#[derive(Clone)]
struct StreamDecrypter {
    algorithm: EncryptionAlgorithm,
    key: Vec<u8>,
}

impl StreamDecrypter {
    fn new(algorithm: EncryptionAlgorithm, key: &[u8]) -> Self {
        Self {
            algorithm,
            key: key.to_vec(),
        }
    }

    fn decrypt(&self, chunk: &EncryptedChunk) -> io::Result<Vec<u8>> {
        if self.algorithm == EncryptionAlgorithm::ChaCha20Poly1305 {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(&self.key));
            let nonce = ChaChaNone::from(chunk.nonce);
            cipher.decrypt(&nonce, chunk.data.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ChaCha decryption error: {:?}", e)))
        } else {
            let cipher = Aes256GcmSiv::new(AesKey::<Aes256GcmSiv>::from_slice(&self.key));
            let nonce = AesNonce::from(chunk.nonce);
            cipher.decrypt(&nonce, chunk.data.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("AES decryption error: {:?}", e)))
        }
    }
}

fn send_chunk<T>(sender: &Sender<T>, data: T) -> Result<()> {
    sender.send(data)
        .map_err(|_| anyhow!("Channel send error"))
}

#[derive(Debug)]
struct Chunk {
    sequence_id: usize,
    data: Vec<u8>,
}

fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Failed to derive key");
    key.to_vec()
}

pub fn init_logger() {
    if LOGGER_INITIALIZED.compare_and_swap(false, true, Ordering::SeqCst) {
        return;
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
    info!("Logger initialized");
}

fn get_max_threads() -> usize {
    num_cpus::get()
}

fn stream_tar(
    folder_path: &Path,
    data_sender: Sender<Chunk>,
    mut shutdown: LazyShutdown,
) -> Result<()> {
    let mut builder = Builder::new(Vec::new());

    let folder_path = get_relative_path(folder_path)
        .context("Failed to get relative path for tar creation")?;

    debug!("Starting tar creation for {}", folder_path.display());
    let mut builder = Builder::new(Vec::new());

    add_directory_to_tar(&mut builder, folder_path.as_path())
        .context("Failed to add directory to tar")?;

        //builder.append_dir_all(".", src_path)

    let tar_data = builder.into_inner()
        .context("Failed to finalize tar archive")?;
    for (i, chunk) in tar_data.chunks(CHUNK_SIZE).enumerate() {
        if let Some(msg) = shutdown.should_shutdown() {
            return Err(anyhow!(msg));
        }
        debug!("Sending chunk {} of size {}", i, chunk.len());
        send_chunk(&data_sender, Chunk {
            sequence_id: i,
            data: chunk.to_vec(),
        })?;
    }
    info!("Tar creation completed for {}", folder_path.display());
    Ok(())
}

fn stream_encrypter(
    data_receiver: Receiver<Chunk>,
    encrypted_sender: Sender<Chunk>,
    encrypter: StreamEncrypter,
    shutdown: LazyShutdown,
) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_max_threads())
        .build()
        .context("Failed to create thread pool")?;
    for _ in 0..get_max_threads() {
        let mut shutdown = shutdown.clone();
        let encrypter = encrypter.clone();
        let encrypted_sender = encrypted_sender.clone();
        let data_receiver = data_receiver.clone();
        pool.spawn(move || {
            loop {
                match data_receiver.recv_timeout(TIMEOUT_INTERVAL) {
                    Ok(chunk) => {
                        if let Some(_) = shutdown.should_shutdown() {
                            return;
                        }

                        debug!("Encrypting chunk {}", chunk.sequence_id);
                        let encrypted = match encrypter.encrypt(chunk.sequence_id, &chunk.data) {
                            Ok(enc) => enc,
                            Err(e) => {
                                error!("Error encrypting chunk {}: {:?}", chunk.sequence_id, e);
                                shutdown.request_shutdown(&format!("Encryption failed: {}", e));
                                return;
                            }
                        };

                        let serialized = match serialize(&encrypted) {
                            Ok(serialized) => serialized,
                            Err(e) => {
                                error!("Error serializing encrypted chunk: {:?}", e);
                                shutdown.request_shutdown(&format!("Serialization failed: {}", e));
                                return;
                            }
                        };

                        if let Err(e) = send_chunk(&encrypted_sender, Chunk {
                            sequence_id: chunk.sequence_id,
                            data: serialized,
                        }) {
                            error!("Error sending encrypted chunk: {:?}", e);
                            shutdown.request_shutdown(&format!("Failed to send encrypted chunk: {}", e));
                            return;
                        }
                    }
                    Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                        if let Some(_) = shutdown.should_shutdown() {
                            return;
                        }
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });
    }
    Ok(())
}

fn stream_reorderer(
    decrypted_receiver: Receiver<Chunk>,
    ordered_sender: Sender<Vec<u8>>,
    mut shutdown: LazyShutdown,
) -> Result<()> {
    debug!("Starting reordering");
    let mut next_sequence = 0;
    let mut buffer = BTreeMap::new();
    loop {
        match decrypted_receiver.recv_timeout(TIMEOUT_INTERVAL) {
            Ok(chunk) => {
                if let Some(msg) = shutdown.should_shutdown() {
                    return Err(anyhow!(msg));
                }
                buffer.insert(chunk.sequence_id, chunk.data);
                while let Some(data) = buffer.remove(&next_sequence) {
                    match ordered_sender.send(data) {
                        Ok(_) => next_sequence += 1,
                        Err(e) => {
                            shutdown.request_shutdown(&format!("Failed to send ordered chunk: {}", e));
                            return Err(anyhow!("Failed to send ordered chunk: {}", e));
                        }
                    }
                }
            }
            Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                if let Some(msg) = shutdown.should_shutdown() {
                    return Err(anyhow!(msg));
                }
                continue;
            }
            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
    Ok(())
}

fn stream_writer(
    mut output_file: File,
    ordered_receiver: Receiver<Vec<u8>>,
    mut shutdown: LazyShutdown,
) -> Result<()> {
    loop {
        match ordered_receiver.recv_timeout(TIMEOUT_INTERVAL) {
            Ok(chunk) => {
                if let Some(msg) = shutdown.should_shutdown() {
                    return Err(anyhow!(msg));
                }
                let size = chunk.len() as u64;
                output_file.write_all(&size.to_le_bytes())
                    .context("Failed to write chunk size")?;
                output_file.write_all(&chunk)
                    .context("Failed to write chunk data")?;
            }
            Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                if let Some(msg) = shutdown.should_shutdown() {
                    return Err(anyhow!(msg));
                }
                continue;
            }
            Err(_) => break,
        }
    }
    Ok(())
}

fn stream_reader(
    mut encrypted_file: File,
    encrypted_sender: Sender<Vec<u8>>,
    mut shutdown: LazyShutdown,
) -> Result<()> {
    let mut size_buffer = [0u8; 8];
    loop {
        if let Some(msg) = shutdown.should_shutdown() {
            return Err(anyhow!(msg));
        }
        match encrypted_file.read_exact(&mut size_buffer) {
            Ok(_) => {
                let size = u64::from_le_bytes(size_buffer) as usize;
                let mut chunk = vec![0u8; size];
                encrypted_file.read_exact(&mut chunk)
                    .context("Failed to read chunk data")?;
                send_chunk(&encrypted_sender, chunk)
                    .context("Failed to send chunk")?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                shutdown.request_shutdown(&format!("Error reading encrypted file: {}", e));
                return Err(anyhow!("Error reading encrypted file: {}", e));
            }
        }
    }
    Ok(())
}

fn stream_decrypter(
    encrypted_receiver: Receiver<Vec<u8>>,
    decrypted_sender: Sender<Chunk>,
    decrypter: StreamDecrypter,
    shutdown: LazyShutdown,
) -> Result<()> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_max_threads())
        .build()
        .context("Failed to create thread pool")?;
    for _ in 0..get_max_threads() {
        let mut shutdown = shutdown.clone();
        let decrypter = decrypter.clone();
        let decrypted_sender = decrypted_sender.clone();
        let encrypted_receiver = encrypted_receiver.clone();
        pool.spawn(move || {
            loop {
                match encrypted_receiver.recv_timeout(TIMEOUT_INTERVAL) {
                    Ok(chunk) => {
                        if let Some(_) = shutdown.should_shutdown() {
                            break;
                        }

                        if shutdown.err_is_shutdown( 
                            (|| {
                                debug!("Decrypting chunk of size {}", chunk.len());
                                let encrypted_chunk = match deserialize::<EncryptedChunk>(&chunk) {
                                    Ok(enc) => enc,
                                    Err(e) => {
                                        return Err(anyhow!("Failed to deserialize chunk: {}", e));
                                    }
                                };

                                let decrypted = match decrypter.decrypt(&encrypted_chunk) {
                                    Ok(dec) => dec,
                                    Err(e) => {
                                        return Err(anyhow!("Failed to decrypt chunk: {}", e));
                                    }
                                };

                                match send_chunk(&decrypted_sender, Chunk {
                                    sequence_id: encrypted_chunk.sequence_id,
                                    data: decrypted,
                                }) {
                                    Ok(_) => Ok(()),
                                    Err(e) => {
                                        return Err(anyhow!("Failed to send decrypted chunk: {}", e));
                                    }
                                }
                            })()
                        ) {
                            break;
                        }
                    }
                    Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                        if let Some(_) = shutdown.should_shutdown() {
                            break;
                        }
                        continue;
                    }
                    Err(_) => break,
                };
            }
        });
    }
    Ok(())
}

fn stream_extractor(
    output_path: &Path,
    decrypted_receiver: Receiver<Vec<u8>>,
    mut shutdown: LazyShutdown,
) -> Result<()> {
    let file_name = output_path.iter().last()
        .context("Failed to get file name from path")?;
    let temp_tar = "/tmp/".to_string() + file_name.to_str()
        .context("Failed to convert file name to string")?;
    {
        let mut tar_file = File::create(&temp_tar)
            .context("Failed to create temporary tar file")?;
        loop {
            match decrypted_receiver.recv_timeout(TIMEOUT_INTERVAL) {
                Ok(chunk) => {
                    if let Some(msg) = shutdown.should_shutdown() {
                        return Err(anyhow!(msg));
                    }

                    tar_file.write_all(&chunk)
                        .context("Failed to write chunk to tar file")?;
                }
                Err(crossbeam::channel::RecvTimeoutError::Timeout) => {
                    if let Some(msg) = shutdown.should_shutdown() {
                        return Err(anyhow!(msg));
                    }
                    continue;
                }
                Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
        tar_file.flush()
            .context("Failed to flush tar file")?;
    }

    let mut archive = Archive::new(File::open(&temp_tar)
        .context("Failed to open temporary tar file")?);
    std::fs::create_dir_all(output_path)
        .context("Failed to create output directory")?;
    let mut entries = archive.entries()
        .context("Failed to get archive entries")?;
    let extraction_result = (|| {
        while let Some(entry) = entries.next() {
            if let Some(msg) = shutdown.should_shutdown() {
                return Err(anyhow!(msg));
            }
            let mut entry = entry?;
            let path = entry.path()?;
            
            // Get the file name without any parent directory components
            let file_name = path.file_name()
                .ok_or_else(|| anyhow!("Invalid path: no file name"))?;
            
            // Create the target path by joining the output directory with just the file name
            let target_path = output_path.join(file_name);
            
            // Create parent directories if they don't exist
            if let Some(parent) = target_path.parent() {
                std::fs::create_dir_all(parent)
                    .context("Failed to create parent directory")?;
            }

            // Unpack the entry to the target path
            entry.unpack(&target_path)
                .context("Failed to unpack entry")?;
        }
        Ok(())
    })();
    if let Err(e) = extraction_result {
        shutdown.request_shutdown(&format!("Failed to extract tar: {}", e));
        return Err(e);
    }
    std::fs::remove_file(temp_tar)
        .context("Failed to remove temporary tar file")?;
    Ok(())
}

pub fn encrypt_folder(folder_path: &Path, output_path: &Path, password: &str, algorithm: EncryptionAlgorithm, shutdown: LazyShutdown) -> Result<()> {
    info!("Starting encryption of {} to {} using {}", folder_path.display(), output_path.display(), algorithm.to_string());
    
    // Create output file with better error handling
    let mut output_file = match File::create(output_path) {
        Ok(file) => file,
        Err(e) => {
            let error_msg = format!(
                "Failed to create output file at {}: {}. Make sure you have write permissions to the directory.",
                output_path.display(),
                e
            );
            error!("{}", error_msg);
            return Err(anyhow!(error_msg));
        }
    };
    debug!("Created output file: {}", output_path.display());

    // Write Locker ID
    output_file.write_all(&LOCKER_ID)
        .context("Failed to write Locker ID")?;
    debug!("Wrote Locker ID");

    // Generate salt
    let mut salt = [0u8; 32];
    OsRng.fill(&mut salt);
    debug!("Generated salt");

    // Create header
    let header = Header {
        version: 1,
        salt,
        algorithm: algorithm,
    };
    debug!("Encrypting with algorithm: {}", header.algorithm.to_string());

    // Write header
    serialize_into(&mut output_file, &header)
        .context("Failed to serialize header")?;
    debug!("Wrote header");

    // Create channels for streaming
    let (data_sender, data_receiver) = channel::bounded(10);
    let (encrypted_sender, encrypted_receiver) = channel::bounded(10);
    let (ordered_sender, ordered_receiver) = channel::bounded(10);

    // Create encrypter
    let key = derive_key(password, &salt);
    let encrypter = StreamEncrypter::new(algorithm, &key);
    debug!("Created encrypter");

    // Spawn threads
    let folder_path = folder_path.to_path_buf();
    let shutdown_clone = shutdown.clone();
    let tar_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_tar(&folder_path, data_sender, shutdown_clone.clone())));
    
    let shutdown_clone = shutdown.clone();
    let encrypt_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_encrypter(data_receiver, encrypted_sender, encrypter, shutdown_clone.clone())));
    
    let shutdown_clone = shutdown.clone();
    let reorder_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_reorderer(encrypted_receiver, ordered_sender, shutdown_clone.clone())));

    let shutdown_clone = shutdown.clone();
    let write_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_writer(output_file, ordered_receiver, shutdown_clone.clone())));

    // Wait for all threads to complete
    tar_thread.join().unwrap();
    encrypt_thread.join().unwrap();
    reorder_thread.join().unwrap();
    write_thread.join().unwrap();

    // Check if any errors occurred
    if shutdown.is_shutdown() {
        return Err(anyhow!(shutdown.get_error_message()));
    }

    info!("Encryption completed successfully");
    Ok(())
}

pub fn decrypt_folder(encrypted_path: &Path, output_path: &Path, password: &str, shutdown: LazyShutdown) -> Result<Header> {
    info!("Starting decryption of {} to {}", encrypted_path.display(), output_path.display());
    
    // Open encrypted file
    let mut encrypted_file = File::open(encrypted_path)
        .context("Failed to open encrypted file")?;
    debug!("Opened encrypted file");

    // Verify Locker ID
    let mut id_buffer = [0u8; 64];
    encrypted_file.read_exact(&mut id_buffer)
        .context("Failed to read Locker ID")?;
    if id_buffer != LOCKER_ID {
        error!("Invalid file format: Not a Locker AI encrypted file");
        return Err(anyhow!("Invalid file format: Not a Locker AI encrypted file"));
    }
    debug!("Verified Locker ID");

    // Read and verify header
    let header: Header = if let Ok(header) = deserialize_from(&mut encrypted_file) {
        header
    } else {
        error!("Invalid file format: Could not deserialize header");
        return Err(anyhow!("Invalid file format: Could not deserialize header"));
    };

    debug!("Decrypting with algorithm: {}", header.algorithm.to_string());
    
    // Create channels for streaming
    let (encrypted_sender, encrypted_receiver) = channel::bounded(10);
    let (decrypted_sender, decrypted_receiver) = channel::bounded(10);
    let (ordered_sender, ordered_receiver) = channel::bounded(10);

    // Create decrypter
    let key = derive_key(password, &header.salt);
    let decrypter = StreamDecrypter::new(header.algorithm, &key);
    debug!("Created decrypter");

    // Spawn threads
    let output_path = output_path.to_path_buf();
    let shutdown_clone = shutdown.clone();
    let read_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_reader(encrypted_file, encrypted_sender, shutdown_clone.clone())));
    
    let shutdown_clone = shutdown.clone();
    let decrypt_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_decrypter(encrypted_receiver, decrypted_sender, decrypter, shutdown_clone.clone())));
    
    let shutdown_clone = shutdown.clone();
    let reorder_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_reorderer(decrypted_receiver, ordered_sender, shutdown_clone.clone())));

    let shutdown_clone = shutdown.clone();
    let extract_thread = thread::spawn(move || shutdown_clone.err_is_shutdown(stream_extractor(&output_path, ordered_receiver, shutdown_clone.clone())));

    // Wait for all threads to complete
    read_thread.join().unwrap();
    decrypt_thread.join().unwrap();
    reorder_thread.join().unwrap();
    extract_thread.join().unwrap();

    // Check if any errors occurred
    if shutdown.is_shutdown() {
        return Err(anyhow!(shutdown.get_error_message()));
    }

    info!("Decryption completed successfully");
    Ok(header)
}

/// Adds a directory and its contents to a tar archive, maintaining relative paths
///
/// This function recursively adds a directory and all its contents to a tar archive.
/// The paths in the archive will be relative to the input directory.
///
/// # Arguments
/// * `builder` - The tar archive builder to add files to
/// * `path` - The directory path to add. Must be relative to the current directory.
///
/// # Returns
/// * `Ok(())` if the directory was added successfully
/// * `Err(io::Error)` if any step fails
///
/// # Note
/// The path must be relative to the current directory. Absolute paths will cause errors
/// in the tar archive.
///
/// # Example
/// ```
/// use tar::Builder;
/// use std::path::Path;
/// 
/// let mut archive = Builder::new(Vec::new());
/// let dir_path = Path::new("./my_directory");
/// add_directory_to_tar(&mut archive, dir_path).unwrap();
/// ```

fn add_directory_to_tar(builder: &mut Builder<Vec<u8>>, path: &Path) -> io::Result<()> {
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Path is not a directory: {}", path.display()),
        ));
    }

    // Get the absolute path of the input directory
    let base_path = std::fs::canonicalize(path)?;
    
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        
        if entry_path.is_dir() {
            add_directory_to_tar(builder, &entry_path)?;
        } else {
            // Get the absolute path of the file
            let abs_path = std::fs::canonicalize(&entry_path)?;
            
            // Create a relative path by stripping the base path prefix
            let relative_path = abs_path.strip_prefix(&base_path)
                .map_err(|e| io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Failed to create relative path: {}", e)
                ))?;
            
            // Add the file to the archive with its relative path
            match builder.append_path_with_name(&abs_path, relative_path) {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to add file to tar: {}", e);
                    return Err(e);
                }
            }
        }
    }
    
    Ok(())
}

/// Converts a path to be relative to the current directory
/// 
/// # Arguments
/// * `path` - The path to convert to a relative path
/// 
/// # Returns
/// * `Ok(PathBuf)` containing the relative path if successful
/// * `Err(io::Error)` if the path cannot be converted to a relative path
/// 
/// # Example
/// ```
/// use std::path::Path;
/// 
/// let absolute_path = Path::new("/home/user/documents/file.txt");
/// let relative_path = get_relative_path(absolute_path).unwrap();
/// ```
pub fn get_relative_path(path: &Path) -> io::Result<PathBuf> {
    // If path is already relative, return it as is
    if !path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let current_dir = std::env::current_dir()?;
    
    // Get the components of both paths
    let mut path_components = path.components();
    let mut current_components = current_dir.components();
    
    // Skip common prefix
    while let (Some(p), Some(c)) = (path_components.next(), current_components.next()) {
        if p != c {
            // Found a difference, need to rebuild the path
            let mut result = PathBuf::new();
            
            // Add ".." for the current component where difference was found
            result.push("..");
            
            // Add ".." for each remaining component in current_dir
            for _ in current_components {
                result.push("..");
            }
            
            // Add the remaining components from the input path
            result.push(p);
            for component in path_components {
                result.push(component);
            }
            
            return Ok(result);
        }
    }
    
    // If we get here, the path is a subpath of current_dir
    let mut result = PathBuf::new();
    for component in path_components {
        result.push(component);
    }
    
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn setup_test_files(structure: &str) -> (PathBuf, PathBuf) {
        let test_dir = Path::new("test_encrypt");
        let decrypted_dir = Path::new("test_decrypt");
        
        // Create test directory structure
        fs::create_dir_all(test_dir).unwrap();
        
        match structure {
            "empty" => {
                // Just create empty directory
            },
            "single_file" => {
                fs::write(test_dir.join("file.txt"), "Single file content").unwrap();
            },
            "nested_dirs" => {
                fs::create_dir_all(test_dir.join("dir1/dir2/dir3")).unwrap();
            },
            "mixed" => {
                // Create a complex structure with files and directories
                fs::create_dir_all(test_dir.join("dir1/dir2")).unwrap();
                fs::create_dir_all(test_dir.join("dir3")).unwrap();
                fs::write(test_dir.join("root_file.txt"), "Root file content").unwrap();
                fs::write(test_dir.join("dir1/file1.txt"), "Dir1 file content").unwrap();
                fs::write(test_dir.join("dir1/dir2/file2.txt"), "Dir2 file content").unwrap();
                fs::write(test_dir.join("dir3/file3.txt"), "Dir3 file content").unwrap();
            },
            "large_files" => {
                // Create some larger files
                let large_content = "x".repeat(1024 * 1024); // 1MB
                fs::write(test_dir.join("large1.txt"), &large_content).unwrap();
                fs::write(test_dir.join("large2.txt"), &large_content).unwrap();
            },
            _ => panic!("Unknown test structure: {}", structure),
        }

        (test_dir.to_path_buf(), decrypted_dir.to_path_buf())
    }

    fn cleanup_test_files(test_dir: &Path, decrypted_dir: &Path) {
        if test_dir.exists() {
            fs::remove_dir_all(test_dir).unwrap();
        }
        if decrypted_dir.exists() {
            fs::remove_dir_all(decrypted_dir).unwrap();
        }
        let encrypted_file = test_dir.with_extension("encrypted");
        if encrypted_file.exists() {
            fs::remove_file(encrypted_file).unwrap();
        }
    }

    fn verify_decrypted_files(decrypted_dir: &Path, structure: &str) {
        let original_dir = Path::new("test_encrypt");

        // Helper function to gather absolute file paths recursively
        fn gather_file_paths(dir: &Path) -> io::Result<Vec<PathBuf>> {
            let mut paths = Vec::new();
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    paths.extend(gather_file_paths(&path)?);
                } else {
                    paths.push(path);
                }
            }
            Ok(paths)
        }

        // Gather and sort file paths
        let original_paths = gather_file_paths(original_dir).unwrap();
        let decrypted_paths = gather_file_paths(decrypted_dir).unwrap();

        // Sort paths for consistent comparison
        let mut original_paths = original_paths;
        let mut decrypted_paths = decrypted_paths;
        original_paths.sort();
        decrypted_paths.sort();

        // Compare each file path and size
        for (orig_path, dec_path) in original_paths.iter().zip(decrypted_paths.iter()) {
            let orig_name = orig_path.file_name().unwrap();
            let dec_name = dec_path.file_name().unwrap();

            assert_eq!(
                orig_name,
                dec_name,
                "Entry names don't match: original={}, decrypted={}",
                orig_path.display(),
                dec_path.display()
            );

            let orig_size = fs::metadata(orig_path).unwrap().len();
            let dec_size = fs::metadata(dec_path).unwrap().len();

            assert_eq!(
                orig_size,
                dec_size,
                "File {} has different size (original: {} bytes, decrypted: {} bytes)",
                orig_name.to_string_lossy(),
                orig_size,
                dec_size
            );
        }
    }

    fn run_encryption_test(structure: &str, algorithm: EncryptionAlgorithm) -> io::Result<()> {
        let (test_dir, decrypted_dir) = setup_test_files(structure);
        
        // Encrypt
        encrypt_folder(&test_dir, &test_dir.with_extension("encrypted"), "testpassword", algorithm, LazyShutdown::new()).unwrap();

        // Verify encrypted file
        let encrypted_file = test_dir.with_extension("encrypted");
        assert!(encrypted_file.exists(), "Encrypted file was not created");
        assert!(fs::metadata(&encrypted_file)?.len() > 0, "Encrypted file is empty");

        // Decrypt
        decrypt_folder(&encrypted_file, &decrypted_dir, "testpassword", LazyShutdown::new()).unwrap();

        // Verify decrypted files
        verify_decrypted_files(&decrypted_dir, structure);

        // Cleanup
        cleanup_test_files(&test_dir, &decrypted_dir);
        Ok(())
    }

    #[test]
    fn test_empty_folder_chacha() -> io::Result<()> {
        init_logger();
        run_encryption_test("empty", EncryptionAlgorithm::ChaCha20Poly1305)
    }

    #[test]
    fn test_empty_folder_aes() -> io::Result<()> {
        init_logger();
        run_encryption_test("empty", EncryptionAlgorithm::Aes256GcmSiv)
    }

    #[test]
    fn test_single_file_chacha() -> io::Result<()> {
        init_logger();
        run_encryption_test("single_file", EncryptionAlgorithm::ChaCha20Poly1305)
    }

    #[test]
    fn test_single_file_aes() -> io::Result<()> {
        init_logger();
        run_encryption_test("single_file", EncryptionAlgorithm::Aes256GcmSiv)
    }

    #[test]
    fn test_nested_dirs_chacha() -> io::Result<()> {
        init_logger();
        run_encryption_test("nested_dirs", EncryptionAlgorithm::ChaCha20Poly1305)
    }

    #[test]
    fn test_nested_dirs_aes() -> io::Result<()> {
        init_logger();
        run_encryption_test("nested_dirs", EncryptionAlgorithm::Aes256GcmSiv)
    }

    #[test]
    fn test_mixed_structure_chacha() -> io::Result<()> {
        init_logger();
        run_encryption_test("mixed", EncryptionAlgorithm::ChaCha20Poly1305)
    }

    #[test]
    fn test_mixed_structure_aes() -> io::Result<()> {
        init_logger();
        run_encryption_test("mixed", EncryptionAlgorithm::Aes256GcmSiv)
    }

    #[test]
    fn test_large_files_chacha() -> io::Result<()> {
        init_logger();
        run_encryption_test("large_files", EncryptionAlgorithm::ChaCha20Poly1305)
    }

    #[test]
    fn test_large_files_aes() -> io::Result<()> {
        init_logger();
        run_encryption_test("large_files", EncryptionAlgorithm::Aes256GcmSiv)
    }

    #[test]
    fn test_wrong_password() -> io::Result<()> {
        init_logger();
        let (test_dir, decrypted_dir) = setup_test_files("mixed");
        
        // Encrypt using ChaCha20Poly1305
        encrypt_folder(&test_dir, &test_dir.with_extension("encrypted"), "correct_password", EncryptionAlgorithm::ChaCha20Poly1305, LazyShutdown::new()).unwrap();

        // Try to decrypt with wrong password
        let encrypted_file = test_dir.with_extension("encrypted");
        let result = decrypt_folder(&encrypted_file, &decrypted_dir, "wrong_password", LazyShutdown::new());
        assert!(result.is_err(), "Decryption with wrong password should fail");

        // Cleanup
        cleanup_test_files(&test_dir, &decrypted_dir);
        Ok(())
    }

    #[test]
    fn test_corrupted_file() -> io::Result<()> {
        init_logger();
        let (test_dir, decrypted_dir) = setup_test_files("mixed");
        // Encrypt using AES-GCM-SIV
        encrypt_folder(&test_dir, &test_dir.with_extension("encrypted"), "testpassword", EncryptionAlgorithm::Aes256GcmSiv, LazyShutdown::new()).unwrap();
        // Corrupt the encrypted file
        let encrypted_file = test_dir.with_extension("encrypted");
        let mut content = fs::read(&encrypted_file)?;
        content[100] = content[100].wrapping_add(1); // Modify one byte
        fs::write(&encrypted_file, content)?;
        // Try to decrypt corrupted file
        let result = decrypt_folder(&encrypted_file, &decrypted_dir, "testpassword", LazyShutdown::new());
        assert!(result.is_err(), "Decryption of corrupted file should fail");
        // Cleanup
        cleanup_test_files(&test_dir, &decrypted_dir);
        Ok(())
    }

    #[test]
    fn test_tar() -> io::Result<()> {
        init_logger();
        let file = File::create("test.tar")?;
        let mut builder = tar::Builder::new(file);
        builder.append_dir_all(".", "/media/tg")?;
        builder.finish()?;
        Ok(())
    }
} 