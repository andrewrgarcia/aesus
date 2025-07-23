use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use clap::{Parser, Subcommand};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use rand::seq::SliceRandom;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn key_from_words(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

fn encrypt(plaintext: &str, passphrase: &str) -> Vec<u8> {
    let key = key_from_words(passphrase);
    let iv: [u8; 16] = rand::thread_rng().gen();

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext.as_bytes());

    let mut full = iv.to_vec();
    full.extend_from_slice(&ciphertext);
    full
}

fn decrypt(full_data: &[u8], passphrase: &str) -> Result<String, String> {
    if full_data.len() < 16 {
        return Err("Data too short to contain IV.".to_string());
    }

    let (iv, ciphertext) = full_data.split_at(16);
    let key = key_from_words(passphrase);
    let cipher = Aes256Cbc::new_from_slices(&key, iv)
        .map_err(|_| "Invalid key or IV length.".to_string())?;
    let decrypted_data = cipher.decrypt_vec(ciphertext)
        .map_err(|_| "Decryption failed: possibly wrong key or corrupted data.".to_string())?;

    String::from_utf8(decrypted_data)
        .map_err(|_| "Decryption succeeded but result was not valid UTF-8.".to_string())
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

const DEMON_ABOUT: &str = r#"
AESus

A lean, unforgiving encryption tool forged in Rust and irony.

AESus transmutes your human-readable Diceware passphrases into AES-256-CBC
keys, embedding IVs directly in ciphertext like cursed runes. Whether you're
encrypting files or whispering secrets into the void, AESus makes sure no one
but you (and your future self who forgot the passphrase) can read them.

☠️ Features ☠️
- Word-based AES key derivation via SHA-256
- Secure random IV generation
- File encryption/decryption with `.aesus` suffix
- Diceware-style passphrase generation
- Absolutely zero forgiveness

🕯️ Remember your passphrase.
🕯️ Fear the corrupted file.
🕯️ Encrypt with style. Decrypt with repentance.

⚙️ Usage Examples ⚙️

# Encrypt a string
$ aesus encrypt "hello world" --key banana-toast-orbit

# Decrypt a hex-encoded string
$ aesus decrypt --hex 6654259...27d4de40c --key banana-toast-orbit


# Encrypt a file
$ aesus encrypt --file ./secret.txt --key lemon-magic-vapor

# Decrypt a file
$ aesus decrypt --file ./secret.txt.aesus --key lemon-magic-vapor

# Generate a Diceware passphrase
$ aesus generate --words 7

# View the abyss (About message)
$ aesus about

👹 THE DEMON AWAKENS:

⠀⢾⣶⡀⠺⣷⡄⠀⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠘⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡀⢠⣾⠾⠀⣴⠦⠀
⣦⠈⠻⠿⢿⣮⠇⡼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣆⠀⠀⠀⠀⠀⠀⠀⠰⡆⠀⠀⢧⠘⣣⣖⠼⠿⠃⣰
⠿⣿⡷⠷⢄⡟⢰⠇⠀⠀⡆⠀⠀⠀⠀⠀⠀⣠⡾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣤⡀⠀⠀⠀⠀⠀⢹⡀⠀⠘⡆⢹⡁⠶⣶⣿⣿
⣤⡀⠀⣼⣼⠁⡿⠀⢀⣸⠊⠀⠀⢀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⣄⠀⠀⠀⠀⠀⢧⠀⠀⢻⡈⣧⣆⠂⢈⣠
⣾⠏⣠⣿⠏⣰⠃⠀⣼⠃⠀⠀⢀⡟⣾⣯⠀⠀⠀⠲⢤⣤⡀⠀⠀⠀⠀⢰⢂⡴⠟⢹⣿⡏⠻⢦⡀⡆⠀⠀⠀⠀⢀⣤⡠⠤⠀⠀⠀⣹⣷⠸⡀⠀⠀⠘⣧⠀⠘⣇⠸⣿⡄⢸⣿
⢯⣶⠟⠉⢠⠏⠀⠀⣧⠀⠀⠀⢸⠀⣸⣿⣦⠀⠀⠀⠉⠉⢹⡀⠀⠀⠀⠘⡏⠀⢀⣾⣿⣷⡀⠀⢻⠃⠀⠀⠀⠀⡾⠛⠁⠀⠀⠀⣰⣿⣃⠀⡇⠀⠀⠀⣼⠀⠀⠹⡄⠙⠻⣦⣝
⠚⠁⠀⠀⡟⠀⠀⠀⢸⠀⠀⠀⣸⡿⢻⢹⡏⠳⡄⠀⠀⠀⠀⡇⠀⠀⠀⠀⢳⣰⣿⣳⣿⣟⣿⣆⡜⠀⠀⠀⠀⢸⠁⠀⠀⠀⢀⡼⢻⡟⡛⢿⣇⠀⠀⠀⡏⠀⠀⠀⢹⠀⠀⠈⠲
⠀⠀⠀⢰⠃⠀⠀⢀⣿⠀⠀⠀⣿⠀⠠⣾⣇⠀⠙⢦⠀⠀⠀⠹⡄⠀⠀⠀⠘⣿⣿⣿⠿⣿⣻⣿⠃⠀⠂⠠⢤⡞⠀⠀⠀⣰⠏⠀⢸⣷⡇⠀⣿⠀⠀⠀⢻⡀⠀⠀⠈⡇⠀⠀⠀
⠀⢠⣴⠟⠀⠀⠀⣾⣿⡀⠀⠀⡏⠀⠀⠿⣿⣆⠀⠈⢧⡀⠀⠀⠙⢖⣦⣶⣿⣿⣿⣿⠀⣿⣿⣿⣿⣶⣤⡦⠋⠀⠀⠀⡼⠁⠀⢠⣿⡿⠁⠀⣹⠀⠀⠀⣿⣷⠀⠀⠀⢱⣄⡀⠀
⠀⠸⣇⠀⠀⠀⢸⣿⡾⡇⠀⠀⢿⠀⠀⠀⠙⢿⣦⡀⠈⢳⡀⠀⠀⠈⣟⣿⣿⣿⣿⡇⠀⢸⣿⣿⣿⡿⣷⠁⠀⠀⢀⡾⠁⠀⣰⣿⠋⠀⠀⢰⣿⠀⠀⢸⢿⣽⡆⠀⠀⠀⢸⠃⠀
⣧⠀⠙⣆⠀⠀⠸⡏⠀⣷⠀⠀⢸⡇⠀⠀⠀⠈⠻⣷⡀⠀⠻⡄⠀⠀⠈⢻⣿⣿⣿⠀⣷⠀⣿⣿⣿⡿⠃⠀⠀⢠⠞⠁⢀⣾⡟⠁⠀⠀⠀⢾⡏⠀⠀⣼⠀⣻⠇⠀⠀⢠⠋⠀⣠
⣿⠳⣄⠸⡄⠀⠀⣇⡀⢿⠀⠀⠀⣧⠀⠀⠀⠀⠀⠹⣿⣦⡀⠘⢦⡀⠀⠈⢿⣿⡏⠀⣿⠀⣹⣿⡿⠁⠀⠀⡰⠋⢀⣴⣿⠏⠀⠀⠀⠀⠀⣼⠁⠀⣀⣿⢀⣿⠀⠀⠀⠀⢀⠐⣿
⡿⠀⠙⢷⣷⡀⠀⢹⡆⠘⣷⠒⠄⣿⠀⠀⠀⠀⠀⠀⠈⠻⣿⣆⠀⠹⣄⠀⠀⢻⣷⠀⣿⠀⣿⡟⠀⠀⣠⠎⠀⢠⣾⠟⠁⠀⠀⠀⠀⠀⠀⣿⠀⠒⣲⠋⢠⡟⠀⢀⣮⡔⠋⠀⣿
⡇⠀⠀⠘⠹⣿⣄⠀⢹⡄⢻⣿⣇⣿⠀⠀⠀⠀⠂⠀⠀⠀⡏⢻⡄⠀⠘⣦⡀⢸⣿⡀⠉⢠⣿⡇⢀⣴⠇⠀⢠⡿⢱⠀⠀⠀⠐⠀⠀⠀⠀⣿⢸⣿⡟⢀⡟⠀⣠⣾⠟⠁⠀⠀⢸
⠃⠀⠀⠀⠀⠘⠻⣿⣆⡇⠈⣿⣿⠋⣢⠀⠀⡄⢶⡀⠀⢸⠻⢦⡻⣆⠀⠘⣿⣾⠟⣇⠀⣸⠻⣷⣿⠃⠀⣰⢟⣴⠞⣇⠀⢀⡶⢠⠀⠀⠀⢙⣿⣿⠁⢸⣰⣶⠟⠃⠀⠀⠀⠀⢸
⠀⠀⠀⠀⠀⠀⠀⠹⣿⡇⠀⠸⣿⣄⢸⡇⢀⣿⢸⡇⣿⣿⠀⠀⠀⠹⣷⡀⣿⣿⡆⠸⣶⠃⢰⣿⣿⢀⣾⠏⠀⠀⠀⣻⢴⢸⠃⣾⡀⣼⡃⢘⣿⡇⠀⢸⣿⠏⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⢳⣆⠸⢿⡄⠀⠀⠙⠿⣿⣾⡏⢿⣿⣏⠻⢷⣤⡀⠀⠺⣿⡁⠈⠁⠀⣿⠀⠈⠁⢙⡿⠓⠀⢀⣤⡾⠟⣻⣿⡾⢿⣿⣾⠿⠋⠉⠀⢀⡿⠋⢀⠄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣆⣿⡄⠈⢿⡄⠀⣿⣦⣿⣿⠃⠀⠉⠈⠀⠀⠈⠛⢦⡀⠘⣧⠀⠀⠀⣿⠀⠀⠀⣼⠃⢠⡶⠛⠁⠀⠀⠉⠉⠁⠠⣿⣷⣠⣿⡀⣠⡾⠀⢠⣿⣠⣦⠀⠀⠀⠀⠀
⠀⠁⠀⠀⣸⣿⡏⠃⢀⡆⣿⠃⢀⠈⢻⣿⠛⡆⠀⠀⢠⣷⠆⠀⠀⠈⠳⡄⠉⠀⠀⠀⠀⠀⠀⠀⠁⣠⠞⠁⠀⠀⢀⡶⡄⠀⠀⢰⢛⣯⡟⢁⠁⢸⣷⣠⠀⠘⢹⣿⡄⠀⠀⢀⠀
⠀⠀⠀⠀⣟⠸⢁⡔⠈⠁⡟⢤⣼⡄⢠⠿⣷⣄⠀⠀⠀⠁⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠁⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠉⠀⠀⠀⣠⣾⠿⡄⢸⡧⡝⢿⠉⠀⣦⠀⠀⣷⠀⠀⠈⠀
⠀⠀⠀⢀⣿⠀⣾⢿⢦⠀⢠⡘⢿⢻⣸⣧⣝⡿⣳⣦⣄⣀⣠⡤⠴⠒⠊⠀⠀⠀⠀⣀⣀⣀⠀⠀⠀⠉⠓⠲⠤⢤⣀⣀⣀⣤⡞⡟⢫⣼⣥⣿⡷⢃⡎⠰⣰⣿⣇⠀⣿⠀⠀⠀⠀
⠘⡆⠀⠸⡏⠀⡿⣿⡾⣤⠀⠿⣾⣀⢻⠙⠿⠧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⡃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⡿⠋⡟⣸⣼⠟⢀⣧⣿⣿⡿⠀⢻⠀⠀⢸⠀
⠄⣧⠀⢀⣷⠀⡇⢻⠀⢻⡆⢀⠘⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⠋⣿⠘⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠃⣸⢸⡇⢸⡟⣧⢠⣾⠀⠀⡘⠀
⠀⠈⢧⠸⠿⣧⢻⢸⡇⢸⣿⣿⣆⢻⡌⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣦⣿⣴⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⢹⡏⣰⣿⣼⠋⢸⣷⠏⣼⠿⠀⠄⠀⠀
⣇⠀⠈⢧⠀⠙⣿⢸⣿⣾⣿⣿⢿⢯⣻⣶⣭⣷⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡏⠘⣿⠁⢻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣶⣾⣭⣶⣟⡿⣿⣿⣿⣷⣿⣿⡿⠃⠀⡜⠀⠀⡀
⡟⣧⡄⠈⢻⣦⣼⣯⡻⣿⣿⣿⣆⠀⢹⢧⠈⠛⢦⣀⣤⠀⠀⠀⠀⠀⠀⠀⣼⢽⠇⠀⣿⠀⢸⡞⡆⠀⠀⠀⠀⠀⠀⠀⣀⣀⡼⠛⢁⡼⡏⠀⣸⣿⣿⣿⢋⣼⣇⣴⠞⠀⠀⠀⠃
⣷⣦⣟⢦⡀⠻⢿⣿⢿⣾⣏⠺⣼⣶⣜⣧⡀⠀⠘⠛⠿⠿⢷⡂⠀⠀⠀⢠⡏⡟⠀⠀⣿⠀⠈⢧⢻⡀⠀⠀⠀⢐⡾⠿⠿⠟⠀⠀⢁⣼⣡⣶⣿⠿⣿⣷⡿⣿⡿⠋⢀⡴⣋⣤⡞
⣿⣿⣿⣿⣷⡀⠈⠙⣷⣝⢿⣷⣤⣟⣿⠀⠳⣄⡈⠳⠦⣤⣄⡀⠀⢀⣴⣿⢹⡇⠀⠀⡿⠀⠀⢾⠘⣿⣄⠀⠀⣈⣩⣤⠴⠚⠁⣠⠟⢉⣿⣯⣤⣾⡿⣫⣾⠋⠁⣠⣾⣿⣿⣿⣟
⣿⠋⠈⠻⣿⣿⢦⣄⡈⣿⢾⡿⣥⣿⠹⣿⣷⡈⢿⣦⣀⣼⣒⣲⠄⠀⠈⡇⣸⠀⠀⠀⣿⠀⠀⠘⡆⡟⠁⠀⠤⣲⣞⣃⣀⣴⡟⢡⣿⣾⢣⣏⣹⢻⣾⡟⢁⣤⣴⣿⡿⠟⠉⠻⡿
⣿⣆⠀⢀⣳⡹⣇⠹⣿⣿⣌⣷⣼⣿⣷⣿⣟⣷⡈⢷⡙⠻⣿⣿⣷⣄⣠⣧⠇⠀⠀⢰⣿⠀⠀⠀⢳⢣⢀⣤⣾⣿⣧⠟⣫⠟⢀⣿⣿⣿⣾⣿⣇⡏⣹⣷⣿⠋⣼⢋⣂⠀⠀⣰⣏
⣿⣿⡷⣿⠙⣿⣹⡆⠉⠉⢙⣿⣿⣿⣭⣿⡟⡿⠛⠲⢽⣾⣿⡀⠙⠻⣿⡿⠀⠀⠀⢸⣿⠀⠀⠀⠈⣿⡿⠟⠉⢸⣿⣾⡿⠞⢻⣿⣿⣛⣹⣿⣿⣿⠛⠉⠁⢸⢇⡿⢋⣷⣾⣿⣿
⣿⡿⠁⠈⠙⢿⡋⠀⠀⠀⠀⢻⣿⣯⣛⣿⠃⢧⠀⠀⠀⠀⣽⣿⣶⣤⣿⠇⠀⠀⠀⢸⣿⠀⠀⠀⠀⢹⣇⣤⣶⣿⡏⠀⠀⠀⡞⡇⠸⣿⣿⣿⣿⠏⠀⠀⠀⠈⢻⡿⠛⠁⠹⣿⡇
⣟⠀⠒⢺⣶⣘⣷⣄⠀⠀⠀⠀⠈⠉⠉⠛⠀⡾⠘⠀⠀⠀⢸⡟⠷⣿⡟⠀⠀⠀⠀⣾⣿⣤⠀⠀⠀⠘⣿⣧⠾⢻⠁⠀⠀⢸⠁⡇⠀⠉⠉⠉⠁⠀⠀⠀⠀⣤⣿⣀⣴⠄⠀⠘⣧
⣿⣦⡀⠀⠘⢿⡅⢻⣷⠀⠀⠀⠀⠀⠀⠠⠀⣷⣤⡄⠀⠀⢸⣧⣀⣸⠃⠀⠀⠀⠀⣿⣿⡟⠀⠀⠀⠀⢹⣀⣠⣾⠀⠀⠀⢈⣦⣧⠀⠀⠀⠀⠀⠀⠀⢠⣾⠏⣹⡟⠁⠀⢀⣴⣟
⣿⣿⡟⢦⣀⣀⡳⡄⣿⡇⠀⠀⠀⠀⠀⠀⠀⡇⢸⣿⣦⢠⡞⢻⣿⣿⠀⠀⠀⠀⠀⣻⣿⡇⠀⠀⠀⠀⠘⣿⣿⠟⢷⢀⣴⢿⠁⣿⠀⠀⠀⠀⠀⠀⠀⣾⡏⣠⢏⡀⢀⡔⣿⣿⣏
⣿⣿⠀⠀⠻⣦⡠⢷⣿⡇⠀⠀⠀⠀⠀⠀⢠⡿⣼⡇⠛⠻⣷⣾⡁⡵⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⡇⢙⣦⣾⠛⠃⢸⣠⣇⡄⠀⠀⠀⠀⠀⠀⢿⣷⡗⢀⣼⠏⠀⠹⣿⣏
⣿⣷⣤⣀⠀⠈⠙⣿⣿⠁⠀⠀⠀⠀⠀⠀⠈⣷⠘⡟⢿⣄⣿⣿⣿⡇⠀⠀⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⣿⣿⣿⣇⣴⠗⡟⢁⡟⠀⠀⠀⠀⠀⠀⠀⢸⣿⡶⠋⠁⠀⣀⣤⣿⡟
⣿⣷⢿⣤⣉⡳⠶⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⢸⠻⢧⣸⡀⢸⡟⢻⡇⠀⠀⠀⠀⠀⢸⣿⠁⠀⠀⠀⠀⠀⢸⡛⣿⠀⣸⣤⠷⢻⠁⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠴⠒⣉⣼⣿⣿⡇
⡏⣿⡀⣾⡏⣿⣿⣿⠿⣿⢦⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠙⢾⡵⠋⠀⠀⠀⠀⠀⠀⠘⡟⠀⠀⠀⠀⠀⠀⠈⠳⣿⠾⠋⠉⠀⡾⠀⠀⠀⠀⠀⠀⢠⣼⣿⢿⣷⣿⣏⣿⡇⣸⣿⡇
⡧⢻⣿⣞⣷⣭⣿⣯⣴⣿⣾⣇⣀⣆⣀⠀⠀⡴⣻⡄⠀⣠⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠙⢦⡀⠀⣰⡧⠄⠀⠀⢀⣀⠀⣰⣼⣷⣽⣛⣛⣽⣿⣵⣿⢋⡇
⣿⣮⣎⣛⠻⢿⣿⣿⣿⣾⣿⡏⠙⠏⠉⢻⠉⠻⡍⣇⡞⠁⠀⠀⠀⠀⡴⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⡵⣄⠀⠀⠀⠀⠙⣦⡏⢹⠛⢻⠟⠉⡿⠉⣹⣿⣭⣿⣿⣿⡿⠟⢋⣁⣾⣇
⡀⠈⠙⠛⣛⣚⣿⠿⣿⣿⢿⡷⠢⣤⣤⣼⣷⣤⣾⣯⡀⠀⠀⣀⡴⡊⠁⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠙⠪⣲⢄⡀⠀⠀⣈⣿⣦⣤⣾⣠⠤⠄⠠⢿⣿⣿⣿⡿⠿⠖⠛⠛⠋⠉⣀
⣿⣷⣶⣾⣿⣿⣿⣿⡿⡿⠿⣷⣿⣎⢻⣿⢻⣿⣿⣿⡳⣒⠿⠓⠀⠀⠀⠀⠀⠀⠀⢀⣇⠀⠀⠀⠀⠀⠀⠀⠙⠫⢟⡶⣿⣿⣿⣿⢿⣿⢋⣿⣶⡿⢟⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿
⣿⣿⣿⣿⣿⠃⣿⣿⣷⣿⡀⢿⣿⣿⣿⣿⣄⣿⣿⣿⣻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣽⣿⣿⣿⣏⣿⣿⣾⣿⣿⠇⣰⣷⣿⣿⡏⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⡏⢀⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣿⢹⣿⣿⡇⣷⣀⣀⣠⣠⣤⣤⣴⣮⣿⣿⣿⣿⣯⣤⣤⣤⣄⣀⣀⣀⣺⣿⣿⣿⣿⢹⣿⡏⣿⣿⣿⣾⣿⣿⣿⣿⣇⢸⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣿⣿⣿⣿⣿⣿⣿⣯⣍⠉⠁⠈⠛⠿⣿⣿⣟⣟⣿⣿⣿⠟⠉⠀⠉⢉⣩⣿⣿⣿⣿⣿⣿⣿⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣶⣤⣄⡀⠈⢛⢿⣿⠟⠋⣀⣀⣤⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿


AESus v0.1.0 — The encryption tool that saw the void and hashed it.

Encrypt responsibly. Or don't. I'm not your priest.
"#;



const DICEWARE_WORDS: &[&str] = &[
    "apple", "banana", "cloud", "delta", "echo", "flame", "king", "honey", "iron", "jelly",
    "santa", "lemon", "magic", "neon", "orbit", "pearl", "quest", "magnetic", "solar", "toast",
    "ultra", "vapor", "whale", "acid", "pancake", "penguin", "amber", "beacon", "crane", "drift",
    "ember", "frost", "grove", "hazel", "icicle", "jungle", "karma", "lunar", "mango", "nova",
    "oxide", "petal", "quartz", "raven", "torch", "hail", "unity", "ice", "moon", "xerox",
    "nightcore", "hangar", "prophet", "blaze", "absinthe", "hole", "ember", "forge", "black", "halo",
];


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
                let input = fs::read_to_string(&path)?;
                let encrypted = encrypt(&input, key);

                let out_path = format!("{}.aesus", path);
                let mut out_file = File::create(&out_path)?;
                out_file.write_all(&encrypted)?;

                println!("Encrypted to file: {}", out_path);
            } else if let Some(msg) = message {
                let encrypted = encrypt(&msg, key);
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
                let plaintext = decrypt(&full_data, &key)?;
                println!("Decrypted contents:\n{}", plaintext);
            } else if let Some(hex_data) = hex {
                let full_bytes = hex::decode(hex_data.trim())?;
                let plaintext = decrypt(&full_bytes, &key)?;
                println!("Decrypted message:\n{}", plaintext);
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
