use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use sha2::{Sha256, Digest};
use rand::Rng;
use std::str;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Convert a wordy passphrase into a 32-byte key using SHA-256
fn key_from_words(passphrase: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

// Encrypt a message
fn encrypt(plaintext: &str, passphrase: &str) -> (Vec<u8>, Vec<u8>) {
    let key = key_from_words(passphrase);
    let iv: [u8; 16] = rand::thread_rng().gen();

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_vec(plaintext.as_bytes());

    (ciphertext, iv.to_vec())
}

// Decrypt a message
fn decrypt(ciphertext: &[u8], iv: &[u8], passphrase: &str) -> String {
    let key = key_from_words(passphrase);
    let cipher = Aes256Cbc::new_from_slices(&key, iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(ciphertext).unwrap();
    String::from_utf8(decrypted_data).unwrap()
}

fn main() {
    let passphrase = "watermelon-sun-bus-taxi";
    let message = "This is a secret message.";

    let (ciphertext, iv) = encrypt(message, passphrase);

    println!("Ciphertext (hex): {}", hex::encode(&ciphertext));
    println!("IV (hex):         {}", hex::encode(&iv));

    let decrypted = decrypt(&ciphertext, &iv, passphrase);
    println!("Decrypted:        {}", decrypted);
}
