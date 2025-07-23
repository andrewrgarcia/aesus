# AESus 🔐✝️👹  
*Because your secrets deserve more than earthly protection.*

---

## 🧿 What is This?

**AESus** is a lean, word-based AES-256 encryption tool written in Rust, with just a hint of divine mischief. It turns memorable passphrases into strong encryption keys, helping you lock up your messages and files without resorting to arcane keyfiles or 32-character gibberish.

It’s built for privacy nerds, terminal romantics, and anyone who prefers encryption with a little style.

---

### 🌐 AESus Web App (Lite Version)

Want to encrypt messages in style, right from your browser?

👉 [aesus.vercel.app](https://aesus.vercel.app)

> ⚠️ **Note**: The web version uses simplified encryption (AES-256-CBC with SHA-256 derived key).
> For **stronger, authenticated encryption** (AES-256-GCM + PBKDF2 + salt + nonce), use the [Rust CLI version](https://crates.io/crates/aesus).

Perfect for casual message locking or secret note passing.
Not recommended for storing the nuclear codes.

---

## ✨ Features

* 🔑 **Memorable passphrases** → PBKDF2-HMAC-SHA256 → AES-256-GCM key
* 🔐 **AES-256-GCM** with random salt + nonce, versioned output
* 📁 File encryption/decryption with optional `--out` override
* 🧪 Message encryption with embedded salt + nonce (prints hex blob)
* 🎲 Diceware-style passphrase generator
* ⚙️ Clean and modern CLI built with [`clap`](https://docs.rs/clap)
* 🦀 Fast, safe, zero-bullshit Rust implementation

---

## 📦 Installation

### Install locally from source:

```bash
cargo install --path .
```

### 📡 Or globally (once published):

```bash
cargo install aesus
```

---

## 🔐 Examples

### Encrypt a message:

```bash
aesus encrypt "Confess nothing" --key scythe-raven-lemon-halo
```

Returns an encrypted hex blob (salt + nonce + ciphertext), ready to share or stash.

---

### Decrypt a hex blob:

```bash
aesus decrypt --hex 01abcd... --key scythe-raven-lemon-halo
```

---

### Encrypt a file:

```bash
aesus encrypt --file secret.txt --key pancake-prophet-echo-oxide
```

Creates: `secret.txt.aesus`
Or use `--out` to choose your own destiny:

```bash
aesus encrypt --file secret.txt --key ... --out recipe.sealed
```

---

### Decrypt a file:

```bash
aesus decrypt --file secret.txt.aesus --key pancake-prophet-echo-oxide
```

Or save the result under any name:

```bash
aesus decrypt --file recipe.sealed --key ... --out final-form.txt
```

---

### Generate a passphrase:

```bash
aesus generate --words 6
```

Output:

```
quest-ember-black-icicle-neon-crane
```

Memorable, weird, and more secure than `hunter2`.

---

## 🛠 Roadmap

* [x] AES-GCM encryption with versioned format
* [x] `--out` flag for flexible output paths
* [x] Per-file random salt and nonce
* [x] Diceware-style passphrase generator
* [ ] Config and vault-like features
* [ ] Cross-platform builds — Windows deserves privacy too, apparently
* [ ] GUI enhancements & WebAuthn/biometrics (maybe)
* [ ] Whispered Latin chants on success — a joke... unless?

---

## 📜 Disclaimer

AESus is **not** divine.
It won’t recover your passphrase or stop you from encrypting your taxes as `pancake.jeff`.

Use responsibly. Backup your data. Don’t test encryption tools with your only copy of anything, unless you like pain.

---

## 🩸 License

MIT. Free as in freedom, and as in “free to use for your cursed backup rituals.”

---

## 🕳️ Contact

Made by [Andrew Garcia](https://github.com/andrewrgarcia)
Open to feedback, PRs, bug reports, or cryptic fanmail.