use clap::{Parser, Subcommand};
use aes::Aes256;
use block_modes::{Cbc, BlockMode};
use block_modes::block_padding::Pkcs7;
use sha2::{Sha256, Digest};
use rand::Rng;
use std::str;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// CLI for AESus
#[derive(Parser)]
#[command(name = "AESus")]
#[command(about = "Word-based AES-256 encryption for the faithful and paranoid", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a message
    Encrypt {
        message: String,
        #[arg(short, long)]
        key: String,
    },
    /// Decrypt a message
    Decrypt {
        #[arg(long)]
        hex: String,
        #[arg(long)]
        iv: String,
        #[arg(short, long)]
        key: String,
    },
}

// Convert passphrase to 32-byte key
fn key_from_words(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

fn encrypt(plaintext: &str, passphrase: &str) -> (Vec<u8>, Vec<u8>) {
    let key = key_from_words(passphrase);
    let iv: [u8; 16] = rand::thread_rng().gen();

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext.as_bytes());

    (ciphertext, iv.to_vec())
}

fn decrypt(ciphertext: &[u8], iv: &[u8], passphrase: &str) -> Result<String, String> {
    let key = key_from_words(passphrase);
    let cipher = Aes256Cbc::new_from_slices(&key, iv)
        .map_err(|_| "Invalid key or IV format".to_string())?;

    let decrypted_data = cipher
        .decrypt_vec(ciphertext)
        .map_err(|_| "Decryption failed. Possibly wrong key or corrupted data.".to_string())?;

    String::from_utf8(decrypted_data).map_err(|_| "Decrypted data is not valid UTF-8.".to_string())
}


fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { message, key } => {
            let (ciphertext, iv) = encrypt(message, key);
            println!("Ciphertext (hex): {}", hex::encode(&ciphertext));
            println!("IV (hex):         {}", hex::encode(&iv));

            println!("\nTo decrypt, run:\ncargo run -- decrypt --hex {} --iv {} --key \"{}\"",
                hex::encode(&ciphertext),
                hex::encode(&iv),
                key
            );
        }
        Commands::Decrypt { hex: hex_msg, iv, key } => {
            let ciphertext = hex::decode(hex_msg).expect("Invalid ciphertext hex");
            let iv_bytes = hex::decode(iv).expect("Invalid IV hex");
            match decrypt(&ciphertext, &iv_bytes, key) {
                Ok(plaintext) => println!("Decrypted message:\n{}", plaintext),
                Err(err) => eprintln!("❌ Error: {}", err),
            }

        }
    }
}
