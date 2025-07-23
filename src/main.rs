mod about; 
mod wordlist;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use clap::{Parser, Subcommand};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use rand::seq::SliceRandom;
use about::DEMON_ABOUT;
use wordlist::DICEWARE_WORDS;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn key_from_words(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    let key = key_from_words(passphrase);
    let iv: [u8; 16] = rand::thread_rng().gen();

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext);

    let mut full = iv.to_vec();
    full.extend_from_slice(&ciphertext);
    full
}

fn decrypt_bytes(full_data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if full_data.len() < 16 {
        return Err("Data too short to contain IV.".to_string());
    }
    
    let (iv, ciphertext) = full_data.split_at(16);
    let key = key_from_words(passphrase);
    let cipher = Aes256Cbc::new_from_slices(&key, iv)
        .map_err(|_| "Invalid key or IV length.".to_string())?;
    cipher.decrypt_vec(ciphertext)
        .map_err(|_| "Decryption failed: possibly wrong key or corrupted data.".to_string())
}
#[derive(Parser)]
#[command(name = "AESus", version = "0.1", author = "Andrew Garcia", about = "CLI for AES-256 encryption")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypt a message or file
    Encrypt {
        #[arg()]
        #[clap(required_unless_present = "file")]
        message: Option<String>,

        #[arg(long)]
        key: String,

        #[arg(long)]
        file: Option<String>,
    },
    /// Decrypt a message or file (IV is embedded)
    Decrypt {
        #[arg(long)]
        hex: Option<String>,

        #[arg(long)]
        key: String,

        #[arg(long)]
        file: Option<String>,
    },
    /// Generate a secure Diceware-style passphrase
    Generate {
        #[arg(long, default_value_t = 6)]
        words: usize,
    },
    /// Show custom help message
    About,

}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Generate { words } => {
            let mut rng = rand::thread_rng();
            let passphrase: Vec<_> = (0..words)
                .map(|_| *DICEWARE_WORDS.choose(&mut rng).unwrap())
                .collect();
            let joined = passphrase.join("-");
            println!("Generated passphrase:\n{}", joined);
        }

        Command::Encrypt { message, key, file } => {
            let key = key.trim();

            if let Some(path) = file {
                let input = fs::read(&path)?;
                let encrypted = encrypt_bytes(&input, key);

                let out_path = format!("{}.aesus", path);
                let mut out_file = File::create(&out_path)?;
                out_file.write_all(&encrypted)?;

                println!("Encrypted to file: {}", out_path);
            } else if let Some(msg) = message {
                let encrypted = encrypt_bytes(msg.as_bytes(), key);
                println!("Encrypted (IV + ciphertext) hex:\n{}", hex::encode(&encrypted));

                println!(
                    "\nTo decrypt, run:\naesus decrypt --hex {} --key {}",
                    hex::encode(&encrypted), 
                    key
                );
            }
        }

        Command::Decrypt { hex, key, file } => {
            if let Some(path) = file {
                let full_data = fs::read(&path)?;
                let decrypted = decrypt_bytes(&full_data, &key)?;
                
                // Try UTF-8, fallback to writing file
                match String::from_utf8(decrypted.clone()) {
                    Ok(text) => println!("Decrypted contents:\n{}", text),
                    Err(_) => {
                        let out_path = if let Some(stripped) = path.strip_suffix(".aesus") {
                            stripped
                        } else {
                            &format!("{}.decrypted", path)
                        };
                        fs::write(out_path, &decrypted)?;
                        println!("Decrypted binary to file: {}", out_path);
                    }
                }
            } else if let Some(hex_data) = hex {
                let full_bytes = hex::decode(hex_data.trim())?;
                let decrypted = decrypt_bytes(&full_bytes, &key)?;
                match String::from_utf8(decrypted.clone()) {
                    Ok(text) => println!("Decrypted message:\n{}", text),
                    Err(_) => {
                        println!("Decrypted non-UTF8 bytes (output suppressed; 
                        save to file if needed).");
                    }
                }
            } else {
                eprintln!("Either --hex or --file must be provided for decryption.");
            }
        }

        Command::About => {
            println!("{}", DEMON_ABOUT);
        }
    }

    Ok(())
}
