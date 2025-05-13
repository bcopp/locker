mod core;
mod fusefs;
use core::{init_logger, LazyShutdown, CTRL_C, sudo_keep_alive};
use std::path::Path;
use std::fs;

fn main() -> std::io::Result<()> {
    init_logger();
    // Create a test directory with some files
    let test_dir = Path::new("test_folder");
    fs::create_dir_all(test_dir.join("subdir"))?;
    
    fs::write(test_dir.join("file1.txt"), "Content of file 1")?;
    fs::write(test_dir.join("file2.txt"), "Content of file 2")?;
    fs::write(test_dir.join("subdir/file3.txt"), "Content of file 3")?;

    // Start sudo keep-alive thread
    sudo_keep_alive()?;

    // Get shutdown state from CTRL_C
    let shutdown = CTRL_C.get_shutdown();

    // Encrypt the folder
    println!("Encrypting folder...");
    let output_path = Path::new("test_folder").with_extension("locker");
    core::encrypt_folder(test_dir, &output_path, "mysecretpassword", core::EncryptionAlgorithm::Aes256GcmSiv, shutdown)?;
    println!("Encryption complete!");

    // Mount and decrypt the folder using FUSE
    println!("Mounting and decrypting folder...");
    core::mount_and_decrypt(&output_path, "mysecretpassword")?;
    println!("Mount and decrypt complete!");

    Ok(())
}
