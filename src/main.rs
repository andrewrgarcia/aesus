mod about;

use aesus::{
    encrypt_bytes,
    decrypt_bytes,
    generate_passphrase, 
    passphrase_entropy,
    CipherBlob,
    SALT_LEN,
    NONCE_LEN
};

use clap::{Parser, Subcommand};

use std::fs::{self, File};
use std::io::Write;

use about::DEMON_ABOUT;

/* ------------------------------- */
/* CLI */
/* ------------------------------- */

#[derive(Parser)]
#[command(
    name = "AESus",
    version = env!("CARGO_PKG_VERSION"),
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

            let phrase = generate_passphrase(words);

            println!("\nGenerated passphrase:\n{}\n", phrase);

            println!(
                "Entropy ≈ {:.1} bits\n",
                passphrase_entropy(words)
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

            } else {

                return Err(
                    "Provide either a message or --file".into()
                );
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

                    Ok(text) =>
                        println!("{}", text),

                    Err(_) =>
                        println!(
                            "Binary output. Use --file to save."
                        )
                }

            } else {

                return Err(
                    "Provide either --hex or --file".into()
                );
            }
        }

        Command::Inspect { file } => {

            let data = fs::read(file)?;

            if data.len() < 1 + SALT_LEN + NONCE_LEN {
                println!("Invalid AESus file");
                return Ok(());
            }

            let blob =
                CipherBlob::from_bytes(&data)?;

            println!("\nAESus file info\n");

            println!("version: {}", blob.version);

            match blob.version {
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
        }

        Command::About =>
            println!("{}", DEMON_ABOUT)
    }

    Ok(())
}