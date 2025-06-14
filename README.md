# Locker

A secure file encryption and virtual filesystem tool that allows you to create encrypted containers that can be mounted as virtual drives.

## Features

- Create encrypted containers that can be mounted as virtual drives
- Support for multiple encryption algorithms (ChaCha20Poly1305 and AES-256-GCM-SIV)
- Secure password-based encryption with Argon2 key derivation
- Virtual filesystem support using FUSE
- Streaming encryption/decryption for efficient memory usage
- Parallel processing for better performance

## Installation

```bash
cargo install --path .
```

## Usage

### Creating a New Locker

```bash
locker new /path/to/locker.encrypted /media/my-locker "your-password" [--algorithm chacha20poly1305|aes256-gcm-siv]
```

This command will:
1. Create a new encrypted container at `/path/to/locker.encrypted`
2. Mount it as a virtual drive at `/media/my-locker`
3. Use the specified password for encryption
4. Optionally specify the encryption algorithm (defaults to ChaCha20Poly1305)

### Opening a Locker

```bash
locker open /path/to/locker.encrypted /media/my-locker "your-password"
```

This command will:
1. Mount the encrypted container at `/media/my-locker`
2. Decrypt the contents on-the-fly
3. Allow you to access the files normally
4. Re-encrypt when you're done

### Encrypting an Existing Folder

```bash
locker encrypt /path/to/folder /path/to/output.encrypted "your-password" [--algorithm chacha20poly1305|aes256-gcm-siv]
```

This command will:
1. Take an existing folder
2. Encrypt its contents into a locker file
3. Use the specified password and algorithm

## File Format

The locker file format consists of the following sections:

1. **Locker ID** (64 bytes)
   - Fixed identifier to verify the file is a valid locker file
   - Helps prevent accidental decryption of non-locker files

2. **Header** (Variable size)
   - Version number (u32)
   - Salt (32 bytes) for Argon2 key derivation
   - Encryption algorithm identifier

3. **Encrypted Data**
   - Stream of encrypted chunks
   - Each chunk contains:
     - Sequence ID (for ordering)
     - Nonce (12 bytes)
     - Encrypted data
   - Chunks are encrypted using either:
     - ChaCha20Poly1305
     - AES-256-GCM-SIV

### Security Features

- **Key Derivation**: Uses Argon2 for secure password-based key derivation
- **Encryption**: Supports two modern encryption algorithms:
  - ChaCha20Poly1305: Fast, secure, and widely used
  - AES-256-GCM-SIV: High-security option with authentication
- **Authentication**: All encrypted data is authenticated to prevent tampering
- **Salt**: Unique salt for each file prevents rainbow table attacks
- **Nonce**: Unique nonce for each chunk prevents replay attacks

### Performance Features

- **Streaming**: Files are processed in chunks to minimize memory usage
- **Parallel Processing**: Uses multiple threads for encryption/decryption
- **Efficient Storage**: Minimal overhead in the file format
- **On-the-fly Decryption**: Files are decrypted as they are accessed

## Requirements

- Linux operating system (uses FUSE)
- Sudo access (for mounting filesystems)
- Rust toolchain (for building from source)

## Building from Source

```bash
git clone https://github.com/yourusername/locker.git
cd locker
cargo build --release
```

## Roadmap

[X] - Core Library
[X] - CLI Interface
[] - GUI
[X] - Linux Support
[] - MacOS Support

## License

MIT
