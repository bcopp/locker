use std::collections::BTreeMap;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::process::Command;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::io;
use log::{info, error, debug};
use fuser::{FileAttr, Filesystem, MountOption};
use whoami;
use anyhow::{Context, Result, anyhow};
use crate::core::{decrypt_folder, encrypt_folder, EncryptionAlgorithm, LazyShutdown, CTRL_C, RUNTIME_CTX};
use crate::fusefs::{Inode, MemFile, MemFilesystem};

/// Creates a new blank encrypted locker at the specified path
/// 
/// This function creates a new encrypted locker file that can be mounted as a virtual filesystem.
/// The process involves:
/// 1. Creating an empty mount point
/// 2. Mounting a virtual filesystem
/// 3. Encrypting the empty filesystem
/// 4. Cleaning up the mount point
///
/// # Arguments
/// * `output_path` - The path where the encrypted locker file will be created. Example: ${HOME}/locker.encrypted
/// * `fs_path` - The path where the virtual filesystem will be mounted. Example: /media/my-locker
/// * `password` - The password used to decrypt the locker. Example: "my_secure_password"
/// * `algorithm` - The encryption algorithm to use. Example: EncryptionAlgorithm::ChaCha20Poly1305
///
/// # Returns
/// * `Ok(())` if the locker was created successfully
/// * `Err(io::Error)` if any step of the process fails
///
/// # Example
/// ```
/// use std::path::Path;
/// use locker_core::core::EncryptionAlgorithm;
///
/// let output_path = Path::new("/path/to/locker.encrypted");
/// let fs_path = Path::new("/media/my-locker");
/// let password = "my_secure_password".to_string();
/// let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
///
/// match new(output_path, fs_path, password, algorithm) {
///     Ok(()) => println!("Locker created successfully"),
///     Err(e) => eprintln!("Failed to create locker: {}", e),
/// }
/// ```

pub fn new(output_path: &Path, fs_path: &Path, password: String, algorithm: EncryptionAlgorithm) -> Result<()> {
    info!("Creating new locker at mount point {}", fs_path.display());

    // Create empty mount point
    create_mount_point(&fs_path)?;

    let fs = mount_and_recover_filesystem(fs_path)?;
    // USER HAS EJECTED THE DRIVE

    // Re-mount the filesystem
    let mut session = fuser::Session::new(fs, &fs_path, &[MountOption::RW, MountOption::FSName(fs_path.file_name().unwrap().to_string_lossy().to_string())])
        .context("Failed to create FUSE session")?;
    let mut unmount = session.unmount_callable();

    // Use re-mounted filesystem for re-encryption
    let fs_path_clone = fs_path.to_path_buf();
    let output_path_clone = output_path.to_path_buf();
    let password_clone = password.clone();
    let algorithm_clone = algorithm.clone();
    std::thread::spawn(move || {
        wait_for_mount(&fs_path_clone).unwrap();
        encrypt_folder(&fs_path_clone, &output_path_clone, &password_clone, algorithm_clone, CTRL_C.get_shutdown()).unwrap();

        match unmount.unmount() {
            Ok(_) => {
                info!("Unmounted filesystem at {}", fs_path_clone.display());
            }
            Err(e) => {
                error!("Failed to unmount filesystem at {}: {}", fs_path_clone.display(), e);
            }
        }
    });

    // Run the session
    match session.run() {
        Ok(_) => {
            info!("Session run successfully");
        }
        Err(e) => {
            error!("Session run failed: {}", e);
            return Err(anyhow!("Session run failed: {}", e));
        }
    }

    // Clean up the mount point
    try_cleanup_mount(&fs_path);

    Ok(())
}

/// Opens an encrypted locker file, mounting it at the specified mount point
/// 
/// This function opens an existing encrypted locker file and mounts it as a virtual filesystem.
/// The process involves:
/// 1. Creating an empty mount point
/// 2. Decrypting and mounting the filesystem
/// 3. Waiting for user interaction (eject or CTRL+C)
/// 4. Re-encrypting and cleaning up when done
///
/// The function will block until the user ejects the drive or sends a CTRL+C signal.
/// When the function returns, the filesystem will be unmounted and re-encrypted.
///
/// # Arguments
/// * `encrypted_path` - The path to the encrypted locker file. Example: ${HOME}/locker.encrypted
/// * `fs_path` - The path where the virtual filesystem will be mounted. Example: /media/my-locker
/// * `password` - The password used to decrypt the locker. Example: "my_secure_password"
///
/// # Returns
/// * `Ok(())` if the locker was opened and closed successfully
/// * `Err(io::Error)` if any step of the process fails
///
/// # Example
/// ```
/// use std::path::Path;
///
/// let encrypted_path = Path::new("/path/to/locker.encrypted");
/// let fs_path = Path::new("/path/to/mount");
/// let password = "my_secure_password".to_string();
///
/// match open(encrypted_path, fs_path, password) {
///     Ok(()) => println!("Locker closed successfully"),
///     Err(e) => eprintln!("Failed to handle locker: {}", e),
/// }
/// ```
pub fn open(encrypted_path: &Path, fs_path: &Path, password: String) -> Result<()> {
    info!("Opening locker at {} with mount point {}", encrypted_path.display(), fs_path.display());

    let tmp_encrypted_path= encrypted_path.with_extension("part");

    // Create empty mount point
    create_mount_point(&fs_path)?;

    // Keep sudo alive to avoid timeout
    sudo_keep_alive()?;

    // Setup the thread to decrypt the filesystem
    let encrypted_path_clone = encrypted_path.to_path_buf();
    let password_clone = password.clone();
    let shutdown_clone = CTRL_C.get_shutdown().clone();
    let fs_path_clone = fs_path.to_path_buf();
    let decrypt_thread = std::thread::spawn(move || {
        match wait_for_mount(&fs_path_clone) {
            Ok(()) => {
                if let Err(e) = decrypt_folder(&encrypted_path_clone, &fs_path_clone, &password_clone, shutdown_clone) {
                    error!("Decrypt thread failed to mount and decrypt: {}", e);
                }
            }
            Err(e) => {
                error!("Decrypt thread failed to mount and decrypt: {}", e);
            }
        }
    });

    // Mount the filesystem
    let fs = mount_and_recover_filesystem(fs_path)?;
    decrypt_thread.join().unwrap();

    // Re-mount the filesystem
    let mut session = fuser::Session::new(fs, &fs_path, &[MountOption::RW, MountOption::FSName(fs_path.file_name().unwrap().to_string_lossy().to_string())])
        .context("Failed to create FUSE session")?;
    let mut unmount = session.unmount_callable();

    // Use re-mounted filesystem for re-encryption
    let fs_path_clone = fs_path.to_path_buf();
    let tmp_encrypted_path_clone = tmp_encrypted_path.to_path_buf();
    let password_clone = password.clone();
    let algorithm_clone = RUNTIME_CTX.get_algorithm().clone();

    info!("Re-encrypting locker at {}", encrypted_path.display());
    std::thread::spawn(move || {
        wait_for_mount(&fs_path_clone).unwrap();
        encrypt_folder(&fs_path_clone, &tmp_encrypted_path_clone, &password_clone, algorithm_clone, CTRL_C.get_shutdown()).unwrap();

        match unmount.unmount() {
            Ok(_) => {
                info!("Unmounted filesystem at {}", fs_path_clone.display());
            }
            Err(e) => {
                error!("Failed to unmount filesystem at {}: {}", fs_path_clone.display(), e);
            }
        }
    });

    // Run the session
    match session.run() {
        Ok(_) => {
            info!("Session run successfully");
        }
        Err(e) => {
            error!("Session run failed: {}", e);
            return Err(anyhow!("Session run failed: {}", e));
        }
    }

    // Rename temporary .part file to encrypted file
    fs::rename(tmp_encrypted_path, encrypted_path)?;

    try_cleanup_mount(&fs_path);

    Ok(())
}

/// Encrypts an existing folder into a locker file
/// 
/// This function takes an existing folder and encrypts its contents into a locker file.
/// The process involves:
/// 1. Creating a new encrypted file at the output path
/// 2. Encrypting all contents of the source folder into the output file
/// 3. Using the specified encryption algorithm for the encryption
///
/// # Arguments
/// * `folder_path` - The path to the folder that will be encrypted. Example: /path/to/my-folder
/// * `output_path` - The path where the encrypted locker file will be created. Example: /path/to/my-folder.locker
/// * `password` - The password used to encrypt the locker. Example: "my_secure_password"
/// * `algorithm` - The encryption algorithm to use. Example: EncryptionAlgorithm::ChaCha20Poly1305
///
/// # Returns
/// * `Ok(())` if the folder was encrypted successfully
/// * `Err(io::Error)` if any step of the process fails
///
/// # Example
/// ```
/// use std::path::Path;
/// use locker_core::core::EncryptionAlgorithm;
///
/// let folder_path = Path::new("/path/to/my-folder");
/// let output_path = Path::new("/path/to/my-folder.locker");
/// let password = "my_secure_password".to_string();
/// let algorithm = EncryptionAlgorithm::ChaCha20Poly1305;
///
/// match encrypt(folder_path, output_path, password, algorithm) {
///     Ok(()) => println!("Folder encrypted successfully"),
///     Err(e) => eprintln!("Failed to encrypt folder: {}", e),
/// }
/// ```
pub fn encrypt(folder_path: &Path, output_path: &Path, password: String, algorithm: EncryptionAlgorithm) -> Result<()> {
    info!("Encrypting folder {} to {}", folder_path.display(), output_path.display());
    
    // Create output file
    debug!("Created output file: {}", output_path.display());

    // Write Locker ID
    debug!("Wrote Locker ID");
    encrypt_folder(
        folder_path,
        &output_path,
        &password,
        algorithm,
        CTRL_C.get_shutdown()
    )?;
    
    Ok(())
}

fn mount_and_recover_filesystem(fs_path: &Path) -> Result<MemFilesystem> {
    let mut fs = MemFilesystem::new();

    // Recover the filesystem state after the session is closed
    let (on_destroy_sender, on_destroy_receiver) = crossbeam::channel::bounded::<(BTreeMap<u64, MemFile>, BTreeMap<u64, FileAttr>, BTreeMap<u64, Inode>, u64)>(1);
    fs.on_destroy = Some(Box::new(move |m: &mut MemFilesystem| {
        info!("On destroy triggered");
        on_destroy_sender.send((m.files.clone(), m.attrs.clone(), m.inodes.clone(), m.next_inode)).unwrap();
    }));

    // Mount the filesystem
    fuser::mount2(fs, &fs_path, &[MountOption::RW, MountOption::FSName(fs_path.file_name().unwrap().to_string_lossy().to_string())])
        .context("Failed to mount filesystem")?;
    // FILE SYSTEM IS EJECTED

    // Recover the filesystem state
    info!("Waiting for channel to receive filesystem state");
    let (files, attrs, inodes, next_inode) = on_destroy_receiver.recv()
        .context("Failed to receive filesystem state")?;

    // Reconstruct the filesystem
    let mut fs = MemFilesystem::new();
    fs.files = files;
    fs.attrs = attrs;
    fs.inodes = inodes;
    fs.next_inode = next_inode;

    return Ok(fs);
}

/// Mounts and decrypts an encrypted locker file
fn mount_and_decrypt(encrypted_path: &Path, fs_path: &Path, password: &String, mut fs: crate::fusefs::MemFilesystem, shutdown: LazyShutdown) -> Result<()> {
    let encrypted_path_clone = encrypted_path.to_path_buf();
    let password_clone = password.clone();
    let shutdown_clone = shutdown.clone();
    let fs_path_clone = fs_path.to_path_buf();
    let decrypt_thread = std::thread::spawn(move || {
        match wait_for_mount(&fs_path_clone) {
            Ok(()) => {
                let _ = decrypt_folder(&encrypted_path_clone, &fs_path_clone, &password_clone, shutdown_clone);
            }
            Err(e) => {
                error!("Failed to mount and decrypt: {}", e);
            }
        }
    });

    fuser::mount2(fs, fs_path, &[MountOption::RW, MountOption::FSName(fs_path.file_name().unwrap().to_string_lossy().to_string())])
        .context("Failed to mount filesystem")?;
    decrypt_thread.join().unwrap();

    info!("Mount and decrypt completed successfully");
    Ok(())
}

/// Unmounts and re-encrypts a locker file
fn unmount_and_encrypt(encrypted_path: &Path, fs_path: &Path, password: &String, algorithm: EncryptionAlgorithm, shutdown: LazyShutdown) -> std::io::Result<()> {
    let temp_encrypted_path = encrypted_path.with_extension("part");

    info!("Encrypting contents to temporary file {}...", temp_encrypted_path.display());
    
    // Encrypt the contents to the temporary file using AES-GCM-SIV
    if let Err(e) = encrypt_folder(fs_path, &temp_encrypted_path, password, algorithm, shutdown) {
        error!("Failed to encrypt folder: {}", e);
        std::fs::remove_file(temp_encrypted_path)?; // remove temp file if encryption fails
        return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
    }

    info!("Replacing original encrypted file...");
    
    // Remove the original file and rename the temporary file
    std::fs::remove_file(encrypted_path)?;
    std::fs::rename(&temp_encrypted_path, encrypted_path)?;

    try_cleanup_mount(fs_path);

    info!("Unmount and re-encryption completed successfully");
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
fn get_relative_path(path: &Path) -> io::Result<PathBuf> {
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

fn create_mount_point(fs_path: &Path) -> Result<()> {
    info!("Requesting sudo to mount file system at {}...", fs_path.display());
    Command::new("sudo").arg("-v").status()
        .context("Failed to verify sudo access")?;
    Command::new("sudo").arg("mkdir").arg("-p").arg(fs_path).status()
        .context("Failed to create mount point directory")?;
    Command::new("sudo").arg("chown").arg(format!("{}:{}", whoami::username(), whoami::username())).arg(fs_path).status()
        .context("Failed to set mount point ownership")?;
    Command::new("sudo").arg("chmod").arg("777").arg(fs_path).status()
        .context("Failed to set mount point permissions")?;
    Ok(())
}

/// Waits for a path to become a mount point
fn wait_for_mount(fs_path: &Path) -> Result<()> {
    info!("Waiting for mount at {}", fs_path.display());

    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(1);
    let check_interval = Duration::from_millis(5);

    while start.elapsed() < timeout {
        // Check if the path exists and is a directory
        if !fs_path.exists() || !fs_path.is_dir() {
            thread::sleep(check_interval);
            continue;
        }

        let parent = fs_path.parent().unwrap_or(fs_path); // handle `/`
    
        if fs_path == parent { // root is always a mount point
            return Ok(()); // root is always a mount point
        }

        let fs_path_meta = std::fs::metadata(fs_path)
            .context("Failed to get mount point metadata")?;
        let parent_meta = std::fs::metadata(parent)
            .context("Failed to get parent directory metadata")?;
        let is_mount = fs_path_meta.dev() != parent_meta.dev();
        if is_mount {
            return Ok(());
        }

        thread::sleep(check_interval);
    }

    Err(anyhow!("Timeout waiting for mount at {}", fs_path.display()))
}

/// Keeps sudo alive to avoid timeout
fn sudo_keep_alive() -> Result<()> {
    // Initial sudo check
    Command::new("sudo").arg("-v").status()
        .context("Failed to verify sudo access")?;

    // Spawn thread to keep sudo alive
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(120)); // 2 minutes
            let _ = Command::new("sudo").arg("-v").status();
        }
    });

    Ok(())
}

/// Attempts to clean up a mount point
pub fn try_cleanup_mount(fs_path: &Path) {
    // Unmount the filesystem
    info!("Unmounting filesystem at {}...", fs_path.display());
    match Command::new("sudo")
        .arg("umount")
        .arg(&fs_path)
        .status()
    {
        Ok(_) => {
            info!("Unmounted filesystem at {}...", &fs_path.display());
        }
        Err(e) => {
            error!("Failed to unmount filesystem at {}: {}", &fs_path.display(), e);
        }
    }

    // Clean up the mount point
    info!("Cleaning filesystem at {}...", &fs_path.display());
    match Command::new("sudo")
        .arg("rmdir")
        .arg(&fs_path)
        .status()
    {
        Ok(_) => {
            info!("Cleaned filesystem at {}...", &fs_path.display());
        }
        Err(e) => {
            error!("Failed to clean filesystem at {}: {}", &fs_path.display(), e);
        }
    }
} 