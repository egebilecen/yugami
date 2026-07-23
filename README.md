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

---

## Decryption Process

1. Payload loaded into memory with PAGE_NOACCESS protection.
2. Page fault exception triggered on first access.
3. Page index derived from faulting address.
4. Derive page key using BLAKE3 with page index.
5. Update page protection to PAGE_READWRITE.
6. Decrypt page using ChaCha20 with derived key.
7. Update page protection back to original.
8. Add page to LRU cache (max 256 pages).
9. If LRU full, re-encrypt and protect evicted page as PAGE_NOACCESS.
10. Return from exception handler, execution resumes.
