use clap::{Parser, Subcommand, ValueEnum};
use locker_core::{init_logger, new, open, encrypt, EncryptionAlgorithm};
use std::path::{PathBuf, Path};
use std::env;
use std::io::{self, Write, BufRead};
use std::fs;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(ValueEnum, Clone, Debug)]
enum Algorithm {
    #[value(name = "chacha20poly1305")]
    ChaCha20Poly1305,
    #[value(name = "aes256gcmsiv")]
    Aes256GcmSiv,
}

impl From<Algorithm> for EncryptionAlgorithm {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::ChaCha20Poly1305 => EncryptionAlgorithm::ChaCha20Poly1305,
            Algorithm::Aes256GcmSiv => EncryptionAlgorithm::Aes256GcmSiv,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new blank encrypted locker
    /// 
    /// Example:
    ///   locker new my-folder
    /// 
    /// Example:
    ///   locker new my-folder -o ~/path/my-folder.locker -m ~/media/my-locker -a chacha20poly1305
    New {
        /// Name for the new locker
        #[arg(value_parser)]
        name: PathBuf,

        /// Path where the encrypted locker file will be created
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Path where the virtual filesystem will be mounted
        #[arg(short = 'm', long)]
        fs_path: Option<PathBuf>,
        
        /// Encryption algorithm to use
        #[arg(short, long, value_enum, default_value = "chacha20poly1305")]
        algorithm: Algorithm,
    },
    
    /// Open an existing encrypted locker
    /// 
    /// Example:
    ///   locker open my-folder.locker
    /// 
    /// Example:
    ///   locker open ~/my-folder.locker -m ~/media/my-folder
    Open {
        /// Path to the encrypted locker file
        #[arg(value_parser)]
        path: PathBuf,
        
        /// Path where the virtual filesystem will be mounted
        #[arg(short = 'm', long)]
        fs_path: Option<PathBuf>,
    },
    
    /// Encrypt an existing folder into a locker file
    /// 
    /// Example:
    ///   locker encrypt my-folder
    /// 
    /// Example:
    ///   locker encrypt ~/my-folder -o ~/my-folder.locker -a chacha20poly1305
    Encrypt {
        /// Path to the folder that will be encrypted
        #[arg(value_parser)]
        path: PathBuf,
        
        /// Path where the encrypted locker file will be created
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Encryption algorithm to use
        #[arg(short, long, value_enum, default_value = "chacha20poly1305")]
        algorithm: Algorithm,
    },
}

fn to_absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        // First try to canonicalize the path
        match fs::canonicalize(path) {
            Ok(canonical) => Ok(canonical),
            Err(_) => {
                // If canonicalization fails (e.g., path doesn't exist yet),
                // resolve relative to current directory
                let current_dir = env::current_dir()?;
                Ok(current_dir.join(path))
            }
        }
    }
}

fn get_password_from_stdin() -> std::io::Result<String> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    lines.next()
        .transpose()?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No password provided via stdin"))
}

fn prompt_for_password() -> std::io::Result<String> {
    let password = rpassword::prompt_password("Enter password: ")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    let confirm = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    if password != confirm {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Passwords do not match"
        ));
    }
    
    Ok(password)
}

fn get_password() -> std::io::Result<String> {
    if atty::is(atty::Stream::Stdin) {
        prompt_for_password()
    } else {
        get_password_from_stdin()
    }
}

fn main() -> std::io::Result<()> {
    // Initialize logger
    init_logger();
    
    let cli = Cli::parse();
    
    match cli.command {
        Commands::New { name, output, fs_path, algorithm } => {

            let output = if let Some(output) = output {
                output
            } else {
                if name.extension().is_none() {
                    name.clone().with_extension("locker")
                } else {
                    name.clone()
                }
            };

            let fs_path = if let Some(fs_path) = fs_path {
                fs_path
            } else {
                Path::new("/media").join(name.file_name().unwrap())
            };

            let output = to_absolute_path(&output)?;
            let fs_path = to_absolute_path(&fs_path)?;
            let password = get_password()?;

            new(&output, &fs_path, password, algorithm.into()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }
        
        Commands::Open { path, fs_path } => {
            let path = to_absolute_path(&path)?;

            let fs_path = if let Some(fs_path) = fs_path {
                fs_path
            } else {
                Path::new("/media").join(path.file_name().unwrap())
            };
            let fs_path = to_absolute_path(&fs_path)?;
            let password = get_password()?;

            open(&path, &fs_path, password).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }
        
        Commands::Encrypt { path, output, algorithm } => {
            let path = to_absolute_path(&path)?;
            let output = if let Some(output) = output {
                output
            } else {
                path.clone().with_extension("locker")
            };
            let output = to_absolute_path(&output)?;
            
            let password = get_password()?;
            encrypt(&path, &output, password, algorithm.into()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }
    }
} 