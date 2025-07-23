# AESus 🔐✝️👹  
*Because your secrets deserve more than earthly protection.*

---

## 🧿 What is This?

**AESus** is a lean, word-based AES-256 encryption tool written in Rust, with just a hint of divine mischief. It turns memorable passphrases into strong encryption keys, helping you lock up your messages and files without resorting to arcane keyfiles or 32-character gibberish.

It’s built for privacy nerds, terminal romantics, and anyone who prefers encryption with a little style.

---

### 🌐 Try the Web Version (GUI)

**Need to lock it down without touching a terminal?**
👉 [Use AESus on the Web (Vercel)](https://aesus.vercel.app)

---

## ✨ Features

- 🔑 Word-based passphrases → SHA-256 → AES-256 key (easy to remember, hard to brute force)
- 🔐 AES-256-CBC encryption/decryption with IV embedding
- 📁 File encryption/decryption support with `.aesus` extension
- 🎲 Diceware-style passphrase generator
- ⚙️ Clean and simple CLI built with [`clap`](https://docs.rs/clap)
- 🦀 Fast, safe, zero-bullshit Rust implementation

---

## 📦 Usage

### ✅ Install (locally)

```bash
cargo install --path .
````

Or install globally from crates.io (after publishing):

```bash
cargo install aesus
```

---

### 🔐 Encrypt a message:

```bash
aesus encrypt "Confess nothing" --key scythe-raven-lemon-halo
```

### 🔓 Decrypt a hex blob:

```bash
aesus decrypt --hex 9bc6f1bed445025faf5521d3240248cf4c95378d695f2a1d100735585f46509d --key scythe-raven-lemon-halo 
```

---

### 📁 Encrypt a file:

```bash
aesus encrypt --file secret.txt --key pancake-prophet-echo-oxide
```

Creates: `secret.txt.aesus`

### 📂 Decrypt a file:

```bash
aesus decrypt --file secret.txt.aesus --key pancake-prophet-echo-oxide 
```

---

### 🎲 Generate a passphrase:

```bash
aesus generate --words 6
```

Example output:

```
quest-ember-black-icicle-neon-crane
```

Strong. Memorable. Weirdly poetic.

---

## 🛠 Roadmap

* [x] CLI using `clap` — built with clean flags and minimal ceremony
* [x] File encryption/decryption — lock up your data with confidence
* [x] Diceware-style passphrase generator — passwords that sound like spells
* [ ] `.aesus` config and secret storage — coming soon for local persistence
* [ ] Cross-platform builds — Windows deserves privacy too, apparently
* [ ] GUI web companion — for those who click before they type
* [ ] Whispered Latin chants on success — a joke... unless?

---

## 📜 Disclaimer

AESus is not divine. It won’t protect you from forgetting your passphrase or encrypting the wrong file.
It does one thing well: turning words into keys, and data into secrets.

Use responsibly. Backup often. Don’t test AES with your only copy of anything.

---

## 🩸 License

MIT. Free as in open source, and as in “open to unusual use cases.”

---

## 🕳️ Contact

Made by [Andrew Garcia](https://github.com/andrewrgarcia)
Bug reports welcome. Feedback encouraged. Incantations optional.

