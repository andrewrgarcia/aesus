<!-- LOGO -->
<p align="center">
  <img width="240" height="240" alt="logo2" src="https://github.com/user-attachments/assets/3eb4f6f6-15e2-45d6-a1ef-e9ac13967f3a" />
</p>

<h1 align="center">AESus</h1>

<p align="center">
  <i>Because your secrets deserve more than earthly protection.</i>
</p>

<p align="center">
  <a href="https://crates.io/crates/aesus"><img src="https://img.shields.io/crates/v/aesus.svg" /></a>
  <a href="#"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue" /></a>
</p>

---

# What is AESus?

**AESus** is a lean AES-256 encryption tool written in Rust with just a hint of divine mischief.

It converts **memorable Diceware passphrases** into hardened cryptographic keys and allows you to encrypt files or messages without juggling random keyfiles or 32-character gibberish.

AESus is both:

* 🔐 a **command-line encryption tool**
* 🦀 a **reusable Rust encryption library**

Built for:

- privacy nerds  
- terminal romantics  
- developers who prefer encryption tools with personality

---

# Cryptography

AESus uses modern authenticated encryption.

```
Passphrase
↓
Argon2id (salted, memory-hard)
↓
AES-256-GCM
```

Every encrypted output contains:

```
[version][salt][nonce][ciphertext]
```

Security properties:

* **AES-256-GCM** authenticated encryption
* **Argon2id** memory-hard key derivation
* Random **salt per encryption**
* Random **nonce per encryption**
* **Versioned format** for forward compatibility
* Diceware passphrases (~77 bits entropy by default)

---

# Using AESus as a Rust Library

AESus can also be used directly from Rust.

Add to `Cargo.toml`:

```toml
aesus = "0.3"
```

Example:

```rust
use aesus::{encrypt, decrypt, CipherBlob};

let plaintext = b"hello world";
let passphrase = "raven-lamp-oxide-lotus";

let blob = encrypt(plaintext, passphrase)?;

let bytes = blob.to_bytes();

/* store bytes somewhere */

let parsed = CipherBlob::from_bytes(&bytes)?;

let decrypted = decrypt(&parsed, passphrase)?;
```

This allows other tools to use AESus as a cryptographic engine without calling the CLI.

Example ecosystem project:

• **FUR** — encrypted conversation manager *(planned integration)*  
https://crates.io/crates/fur-cli

---

# AESus Web App (Lite Version)

Want to encrypt messages directly in your browser?

👉 [https://aesus.vercel.app](https://aesus.vercel.app)

⚠️ **Note**

The web version uses simplified encryption:

```
AES-256-CBC + SHA-256 key derivation
```

For **strong authenticated encryption** (Argon2id + AES-GCM), use the **Rust CLI**.

Perfect for casual message locking or secret note passing.
Not recommended for storing the nuclear codes.

---

# Features

* 🔑 **Memorable passphrases** (Diceware)
* 🔐 **AES-256-GCM authenticated encryption**
* 🧠 **Argon2id key derivation**
* 📁 File encryption / decryption
* 🧪 Message encryption (hex output)
* 🎲 Diceware passphrase generator
* 🔍 `inspect` command for ciphertext metadata
* 🦀 Usable as both **CLI and Rust library**
* ⚙️ Clean CLI powered by [`clap`](https://docs.rs/clap)

---

# 📦 Installation

### Install locally

```bash
cargo install --path .
```

### Install from crates.io

```bash
cargo install aesus
```

---

# Examples

## Encrypt a message

```bash
aesus encrypt "Confess nothing" --key scythe-raven-lemon-halo
```

Returns a hex blob containing:

```
version + salt + nonce + ciphertext
```

---

## Decrypt a message

```bash
aesus decrypt --hex 02abcd... --key scythe-raven-lemon-halo
```

---

## Encrypt a file

```bash
aesus encrypt --file secret.txt --key pancake-prophet-echo-oxide
```

Creates:

```
secret.txt.aesus
```

Custom output:

```bash
aesus encrypt --file secret.txt --key ... --out recipe.sealed
```

---

## Decrypt a file

```bash
aesus decrypt --file secret.txt.aesus --key pancake-prophet-echo-oxide
```

Or:

```bash
aesus decrypt --file recipe.sealed --key ... --out final-form.txt
```

---

## Inspect encrypted file

```bash
aesus inspect secret.txt.aesus
```

Example output:

```
AESus file info

version: 2
kdf: Argon2id
memory: 128 MB
iterations: 3
cipher: AES-256-GCM
salt length: 16
nonce length: 12
```

---

## Generate passphrase

```bash
aesus generate --words 6
```

Example:

```
quest-ember-black-icicle-neon-crane
Entropy ≈ 77 bits
```

Memorable, weird, and significantly better than `hunter2`.

---

# 🛠 Roadmap

* [x] AES-256-GCM encryption
* [x] Argon2id key derivation
* [x] Diceware passphrase generator
* [x] Versioned ciphertext format
* [x] Inspect command
* [x] Rust library API
* [ ] Vault-like secret storage
* [ ] Cross-platform builds
* [ ] Optional GUI
* [ ] Clipboard passphrase generator
* [ ] Whispered Latin chants on success

---

# 📜 Disclaimer

AESus is **not divine**.

It cannot:

* recover your passphrase
* fix bad backups
* save you from encrypting your taxes as `pancake.jeff`

Backup your data.
Test encryption tools before trusting them.

---

# 🩸 License

MIT.

Free as in freedom — and free to use in your cursed backup rituals.

---

# 🕳️ Contact

Made by **Andrew Garcia**

GitHub
[https://github.com/andrewrgarcia](https://github.com/andrewrgarcia)

PRs, bug reports, and cryptic fanmail welcome.
