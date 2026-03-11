pub mod wordlist;

use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, generic_array::GenericArray}};
use rand::{RngCore, rngs::OsRng};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use argon2::{Argon2, Params};
use zeroize::Zeroize;
use rand::seq::SliceRandom;
use rand::thread_rng;

pub const VERSION: u8 = 2;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

const PBKDF2_ITERS: u32 = 100_000;

#[derive(Debug, Clone)]
pub struct CipherBlob {
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl CipherBlob {

    pub fn to_bytes(&self) -> Vec<u8> {

        let mut out =
            Vec::with_capacity(
                1 + SALT_LEN + NONCE_LEN + self.ciphertext.len()
            );

        out.push(self.version);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);

        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {

        if data.len() < 1 + SALT_LEN + NONCE_LEN {
            return Err("Ciphertext too short.".into());
        }

        let version = data[0];

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[1..1 + SALT_LEN]);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(
            &data[1 + SALT_LEN..1 + SALT_LEN + NONCE_LEN]
        );

        let ciphertext =
            data[1 + SALT_LEN + NONCE_LEN..].to_vec();

        Ok(Self {
            version,
            salt,
            nonce,
            ciphertext
        })
    }
}


pub fn generate_passphrase(words: usize) -> String {

    let mut rng = thread_rng();

    let wordlist = crate::wordlist::get_words();

    let passphrase: Vec<_> =
        (0..words)
        .map(|_| *wordlist.choose(&mut rng).unwrap())
        .collect();

    passphrase.join("-")
}

pub fn passphrase_entropy(words: usize) -> f64 {

    let wordlist = crate::wordlist::get_words();

    (wordlist.len() as f64).log2() * words as f64
}

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
        128 * 1024,
        3,
        1,
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
pub fn encrypt(
    plaintext: &[u8],
    passphrase: &str
) -> Result<CipherBlob, String> {

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut key = derive_key_argon2(passphrase, &salt);

    let cipher =
        Aes256Gcm::new_from_slice(&key)
        .map_err(|e| e.to_string())?;

    key.zeroize();

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(
        GenericArray::from_slice(&nonce),
        plaintext
    ).map_err(|e| format!("Encryption failed: {e}"))?;

    Ok(CipherBlob {
        version: VERSION,
        salt,
        nonce,
        ciphertext
    })
}

pub fn encrypt_bytes(
    plaintext: &[u8],
    passphrase: &str
) -> Result<Vec<u8>, String> {

    let blob = encrypt(plaintext, passphrase)?;

    Ok(blob.to_bytes())
}

/* ------------------------------- */
/* Decryption */
/* ------------------------------- */
pub fn decrypt(
    blob: &CipherBlob,
    passphrase: &str
) -> Result<Vec<u8>, String> {

    let mut key = match blob.version {

        1 => derive_key_pbkdf2(passphrase, &blob.salt),

        2 => derive_key_argon2(passphrase, &blob.salt),

        _ => return Err(format!(
            "Unsupported version: {}",
            blob.version
        ))
    };

    let cipher =
        Aes256Gcm::new_from_slice(&key)
        .map_err(|e| e.to_string())?;

    key.zeroize();

    cipher.decrypt(
        GenericArray::from_slice(&blob.nonce),
        blob.ciphertext.as_ref()
    ).map_err(|_| "Decryption failed: invalid key or corrupted data.".into())
}


pub fn decrypt_bytes(
    data: &[u8],
    passphrase: &str
) -> Result<Vec<u8>, String> {

    let blob = CipherBlob::from_bytes(data)?;

    decrypt(&blob, passphrase)
}