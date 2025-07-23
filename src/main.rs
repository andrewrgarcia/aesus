mod about; 
mod wordlist;

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use clap::{Parser, Subcommand};
use rand::{Rng, seq::SliceRandom};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{self, Write};
use pbkdf2::pbkdf2_hmac;
use hmac::Hmac;
use about::DEMON_ABOUT;
use wordlist::DICEWARE_WORDS;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// constant salt for demo
const PBKDF2_SALT: &[u8] = b"AESus_Salt";
const PBKDF2_ITERS: u32 = 100_000;

fn key_from_words(passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Hmac<Sha256>>(passphrase.as_bytes(), PBKDF2_SALT, PBKDF2_ITERS, &mut key);
    key
}

fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let key = key_from_words(passphrase);
    let iv: [u8; 16] = rand::thread_rng().gen();
    let cipher = Aes256Cbc::new_from_slices(&key, &iv)
        .map_err(|e| format!("Cipher init failed: {e}"))?;
    let ciphertext = cipher.encrypt_vec(plaintext);

    let mut full = iv.to_vec();
    full.extend_from_slice(&ciphertext);
    Ok(full)
}

fn decrypt_bytes(full_data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if full_data.len() < 16 {
        return Err("Data too short to contain IV.".to_string());
    }
    let (iv, ciphertext) = full_data.split_at(16);
    let key = key_from_words(passphrase);
    let cipher = Aes256Cbc::new_from_slices(&key, iv)
        .map_err(|e| format!("Cipher init failed: {e}"))?;
    cipher.decrypt_vec(ciphertext)
        .map_err(|_| "Decryption failed: wrong key, corrupted data, or wrong file.".to_string())
}

#[derive(Parser)]
#[command(name = "AESus", version = "0.2", author = "Andrew Garcia", about = "CLI for AES-256 encryption")]
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
                let encrypted = encrypt_bytes(&input, key)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                let out_path = format!("{}.aesus", path);
                let mut out_file = File::create(&out_path)?;
                out_file.write_all(&encrypted)?;
                println!("Encrypted to file: {}", out_path);
            } else if let Some(msg) = message {
                let encrypted = encrypt_bytes(msg.as_bytes(), key)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                let hexstr = hex::encode(&encrypted);
                println!("Encrypted (IV + ciphertext) hex:\n{}", hexstr);
                println!(
                    "\nTo decrypt, run:\naesus decrypt --hex {} --key {}",
                    hexstr,
                    key
                );
            }
        }

        Command::Decrypt { hex, key, file } => {
            if let Some(path) = file {
                let full_data = fs::read(&path)?;
                let decrypted = decrypt_bytes(&full_data, &key)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                // Try to guess output file name
                let out_path = if let Some(stripped) = path.strip_suffix(".aesus") {
                    stripped.to_string()
                } else {
                    format!("{}.decrypted", path)
                };

                if fs::metadata(&out_path).is_ok() {
                    println!(
                        "Warning: {} already exists. Overwrite? [y/N]: ",
                        out_path
                    );
                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    if !answer.trim().eq_ignore_ascii_case("y") {
                        println!("Aborted.");
                        return Ok(());
                    }
                }

                // If decrypted is valid UTF-8, print it; else, write as binary
                match std::str::from_utf8(&decrypted) {
                    Ok(text) => println!("Decrypted contents:\n{}", text),
                    Err(_) => {
                        fs::write(&out_path, &decrypted)?;
                        println!("Decrypted binary to file: {}", out_path);
                    }
                }
            } else if let Some(hex_data) = hex {
                let full_bytes = hex::decode(hex_data.trim())?;
                let decrypted = decrypt_bytes(&full_bytes, &key)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                match std::str::from_utf8(&decrypted) {
                    Ok(text) => println!("Decrypted message:\n{}", text),
                    Err(_) => {
                        println!("Decrypted non-UTF8 bytes (output suppressed; use --file for binary output).");
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
