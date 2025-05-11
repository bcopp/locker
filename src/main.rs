mod core;

use std::path::Path;
use std::fs;

fn main() -> std::io::Result<()> {
    // Create a test directory with some files
    let test_dir = Path::new("test_folder");
    fs::create_dir_all(test_dir.join("subdir"))?;
    
    fs::write(test_dir.join("file1.txt"), "Content of file 1")?;
    fs::write(test_dir.join("file2.txt"), "Content of file 2")?;
    fs::write(test_dir.join("subdir/file3.txt"), "Content of file 3")?;

    // Encrypt the folder
    println!("Encrypting folder...");
    core::encrypt_folder(test_dir, "mysecretpassword", core::EncryptionAlgorithm::Aes256GcmSiv)?;
    println!("Encryption complete!");

    Ok(())
}
