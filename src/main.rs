mod about; 
mod wordlist;
use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng as RandOsRng, seq::SliceRandom};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;

use std::fs::{self, File};
use std::io::{self, Write};
use about::DEMON_ABOUT;
use wordlist::DICEWARE_WORDS;

// External
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12; // AES-GCM nonce
// const PBKDF2_ITERS: u32 = 100_000;

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, 100_000, &mut key);
    key
}


fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; SALT_LEN];
    RandOsRng.fill_bytes(&mut salt);
    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

    let mut nonce = [0u8; NONCE_LEN];
    RandOsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), plaintext)
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ciphertext.len());
    output.push(VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_bytes(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if data.len() < 1 + SALT_LEN + NONCE_LEN {
        return Err("Ciphertext too short.".into());
    }

    let version = data[0];
    if version != VERSION {
        return Err(format!("Unsupported version: {}", version));
    }

    let salt = &data[1..1 + SALT_LEN];
    let nonce = &data[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[1 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(passphrase, salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)
        .map_err(|_| "Decryption failed: invalid key or corrupted data.".into())
}

#[derive(Parser)]
#[command(name = "AESus", version = "0.2", author = "Andrew Garcia", about = "CLI for AES-GCM encryption")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Encrypt {
        #[arg()] message: Option<String>,
        #[arg(long)] key: String,
        #[arg(long)] file: Option<String>,
        #[arg(long)] out: Option<String>,
    },
    Decrypt {
        #[arg(long)] hex: Option<String>,
        #[arg(long)] key: String,
        #[arg(long)] file: Option<String>,
        #[arg(long)] out: Option<String>,
    },
    Generate {
        #[arg(long, default_value_t = 6)] words: usize,
    },
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
        },
        Command::Encrypt { message, key, file, out } => {
            let key = key.trim();
            if let Some(path) = file {
                let input = fs::read(&path)?;
                let encrypted = encrypt_bytes(&input, key)?;
                let out_path = out.unwrap_or_else(|| format!("{}.aesus", path));
                File::create(&out_path)?.write_all(&encrypted)?;

                println!("Encrypted to file: {}", out_path);
            } else if let Some(msg) = message {
                let encrypted = encrypt_bytes(msg.as_bytes(), key)?;
                let hexstr = hex::encode(&encrypted);
                println!("Encrypted hex:\n{}", hexstr);
                println!(
                    "\nTo decrypt, run:\naesus decrypt --hex {} --key {}",
                    hexstr,
                    key
                );
            }
        },

        Command::Decrypt { hex, key, file, out } => {
            if let Some(path) = file {
                let full_data = fs::read(&path)?;
                let decrypted = decrypt_bytes(&full_data, &key)?;
                let out_path = out.unwrap_or_else(|| {
                    path.strip_suffix(".aesus")
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("{}.decrypted", path))
                });

                if fs::metadata(&out_path).is_ok() {
                    println!("{} exists. Overwrite? [y/N]:", out_path);
                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    if !answer.trim().eq_ignore_ascii_case("y") {
                        println!("Aborted.");
                        return Ok(());
                    }
                }

                // If decrypted is valid UTF-8, print it; else, write as binary
                match std::str::from_utf8(&decrypted) {
                    Ok(text) => println!("{}", text),
                    Err(_) => {
                        fs::write(&out_path, &decrypted)?;
                        println!("Wrote binary output to {}", out_path);
                    }
                }
            } else if let Some(hex_data) = hex {
                let full_bytes = hex::decode(hex_data.trim())?;
                let decrypted = decrypt_bytes(&full_bytes, &key)?;
                match std::str::from_utf8(&decrypted) {
                    Ok(text) => println!("{}", text),
                    Err(_) => println!("Decrypted binary (non-UTF8), consider using --file to save it.")
                }
            }
        },
        Command::About => println!("{}", DEMON_ABOUT),
    }
    Ok(())
}
