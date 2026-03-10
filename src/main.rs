mod about;
mod wordlist;

use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
use clap::{Parser, Subcommand};
use rand::{RngCore, rngs::OsRng as RandOsRng, seq::SliceRandom};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use argon2::{Argon2, Params};
use zeroize::Zeroize;

use std::fs::{self, File};
use std::io::{Write};

use about::DEMON_ABOUT;
use wordlist::get_words;

/* ------------------------------- */
/* Constants */
/* ------------------------------- */

const VERSION: u8 = 2;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

const PBKDF2_ITERS: u32 = 100_000;

/* ------------------------------- */
/* KDF */
/* ------------------------------- */

fn derive_key_pbkdf2(passphrase: &str, salt: &[u8]) -> [u8; 32] {

    let mut key = [0u8; 32];

    pbkdf2::<Hmac<Sha256>>(
        passphrase.as_bytes(),
        salt,
        PBKDF2_ITERS,
        &mut key
    );

    key
}

fn derive_key_argon2(passphrase: &str, salt: &[u8]) -> [u8; 32] {

    let params = Params::new(
        128 * 1024, // 128 MB memory
        3,         // iterations
        1,         // parallelism
        Some(32)
    ).unwrap();

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params
    );

    let mut key = [0u8; 32];

    argon2.hash_password_into(
        passphrase.as_bytes(),
        salt,
        &mut key
    ).unwrap();

    key
}

/* ------------------------------- */
/* Encryption */
/* ------------------------------- */

fn encrypt_bytes(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {

    let mut salt = [0u8; SALT_LEN];
    RandOsRng.fill_bytes(&mut salt);

    let mut key = derive_key_argon2(passphrase, &salt);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| e.to_string())?;

    key.zeroize();

    let mut nonce = [0u8; NONCE_LEN];
    RandOsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(
        GenericArray::from_slice(&nonce),
        plaintext
    ).map_err(|e| format!("Encryption failed: {e}"))?;

    let mut output =
        Vec::with_capacity(
            1 + SALT_LEN + NONCE_LEN + ciphertext.len()
        );

    output.push(VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/* ------------------------------- */
/* Decryption */
/* ------------------------------- */

fn decrypt_bytes(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {

    if data.len() < 1 + SALT_LEN + NONCE_LEN {
        return Err("Ciphertext too short.".into());
    }

    let version = data[0];

    let salt =
        &data[1..1 + SALT_LEN];

    let nonce =
        &data[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN];

    let ciphertext =
        &data[1 + SALT_LEN + NONCE_LEN..];

    let mut key = match version {

        1 => derive_key_pbkdf2(passphrase, salt),

        2 => derive_key_argon2(passphrase, salt),

        _ => return Err(format!(
            "Unsupported version: {}",
            version
        ))
    };

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| e.to_string())?;

    key.zeroize();

    cipher.decrypt(
        GenericArray::from_slice(nonce),
        ciphertext
    ).map_err(|_| "Decryption failed: invalid key or corrupted data.".into())
}

/* ------------------------------- */
/* CLI */
/* ------------------------------- */

#[derive(Parser)]
#[command(
    name = "AESus",
    version = "0.3",
    author = "Andrew Garcia",
    about = "CLI for AES-256-GCM encryption"
)]
struct Cli {

    #[command(subcommand)]
    command: Command
}

#[derive(Subcommand)]
enum Command {

    Encrypt {
        #[arg()]
        message: Option<String>,

        #[arg(long)]
        key: String,

        #[arg(long)]
        file: Option<String>,

        #[arg(long)]
        out: Option<String>,
    },

    Decrypt {
        #[arg(long)]
        hex: Option<String>,

        #[arg(long)]
        key: String,

        #[arg(long)]
        file: Option<String>,

        #[arg(long)]
        out: Option<String>,
    },

    Generate {
        #[arg(long, default_value_t = 6)]
        words: usize,
    },

    Inspect {
        file: String
    },

    About
}

/* ------------------------------- */
/* Main */
/* ------------------------------- */

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let cli = Cli::parse();

    match cli.command {

        Command::Generate { words } => {

            let mut rng = rand::thread_rng();

            let wordlist = get_words();

            let passphrase: Vec<_> =
                (0..words)
                .map(|_| *wordlist.choose(&mut rng).unwrap())
                .collect();

            let joined =
                passphrase.join("-");

            println!("\nGenerated passphrase:\n{}\n", joined);

            let entropy =
                (wordlist.len() as f64).log2() *
                words as f64;

            println!(
                "Entropy ≈ {:.1} bits\n",
                entropy
            );
        }

        Command::Encrypt { message, key, file, out } => {

            let key = key.trim();

            if let Some(path) = file {

                let input = fs::read(&path)?;

                let encrypted =
                    encrypt_bytes(&input, key)?;

                let out_path =
                    out.unwrap_or_else(
                        || format!("{}.aesus", path)
                    );

                File::create(&out_path)?
                    .write_all(&encrypted)?;

                println!("Encrypted to file: {}", out_path);

            } else if let Some(msg) = message {

                let encrypted =
                    encrypt_bytes(msg.as_bytes(), key)?;

                let hexstr =
                    hex::encode(&encrypted);

                println!(
                    "Encrypted hex:\n{}\n",
                    hexstr
                );
            }
            else {
                return Err("Provide either a message or --file".into());
            }
        }

        Command::Decrypt { hex, key, file, out } => {

            if let Some(path) = file {

                let full_data =
                    fs::read(&path)?;

                let decrypted =
                    decrypt_bytes(&full_data, &key)?;

                let out_path =
                    out.unwrap_or_else(|| {

                        path.strip_suffix(".aesus")
                        .map(|s| s.to_string())
                        .unwrap_or_else(
                            || format!("{}.decrypted", path)
                        )
                    });

                fs::write(&out_path, &decrypted)?;

                println!(
                    "Decrypted file written to {}",
                    out_path
                );

            } else if let Some(hex_data) = hex {

                let full_bytes =
                    hex::decode(hex_data.trim())?;

                let decrypted =
                    decrypt_bytes(&full_bytes, &key)?;

                match std::str::from_utf8(&decrypted) {

                    Ok(text) => println!("{}", text),

                    Err(_) =>
                        println!(
                            "Binary output. Use --file to save."
                        )
                }
            }
            else {
                return Err("Provide either --hex or --file".into());
            }
        }

        Command::Inspect { file } => {

            let data = fs::read(file)?;

            if data.len() < 1 + SALT_LEN + NONCE_LEN {
                println!("Invalid AESus file");
                return Ok(())
            }

            let version = data[0];

            println!("\nAESus file info\n");

            println!("version: {}", version);

            match version {
                1 => println!("kdf: PBKDF2-SHA256"),
                2 => {
                    println!("kdf: Argon2id");
                    println!("memory: 128 MB");
                    println!("iterations: 3");
                }
                _ => println!("kdf: unknown"),
            }

            println!("cipher: AES-256-GCM");
            println!("salt length: {}", SALT_LEN);
            println!("nonce length: {}", NONCE_LEN);
        },

        Command::About =>
            println!("{}", DEMON_ABOUT)
    }

    Ok(())
}