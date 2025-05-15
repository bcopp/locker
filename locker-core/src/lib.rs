//! Locker Core Library
//! 
//! This library provides secure file encryption and mounting capabilities with FUSE integration.
//! It allows you to create encrypted mounts and access encrypted files through a virtual filesystem.

pub mod core;
pub mod fusefs;
pub mod locker;

// Re-export public types and functions
pub use core::{
    EncryptionAlgorithm,
    init_logger,
    encrypt_folder,
    decrypt_folder,
};

// Re-export locker functionality
pub use locker::{
    new,
    open,
    encrypt,
};
