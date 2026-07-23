# Yugami

**Yugami** (歪み，"distortion") is a x64 binary packer written in Rust. It encrypts PE executables using ChaCha20 stream cipher with page-level key derivation and performs just-in-time page decryption at runtime.

---

## Usage

Build:
```bash
cargo build --release --workspace
```

Pack an executable:
```bash
cargo run --release --bin packer -- --path path/to/target.exe
```

Outputs `packed.exe` in the current directory.

---

## Encryption Process

1. Parse PE headers and map sections to memory.
2. Generate 256-bit random base key.
3. Pad payload to 4KB page boundaries.
4. Derive per-page keys using BLAKE3.
5. Encrypt each page with ChaCha20.
6. Append encrypted payload + metadata as overlay.
