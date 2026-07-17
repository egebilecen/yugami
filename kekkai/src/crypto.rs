use blake3;
use chacha20::{ChaCha20, KeyIvInit, cipher::StreamCipher};

pub type U8_32 = [u8; 32];

pub const PAGE_SIZE: usize = 4096;
const NONCE: [u8; 12] = [0x69; 12];

pub fn derive_page_key(base_key: &U8_32, page_index: usize, out_key: &mut U8_32) {
    let mut hasher = blake3::Hasher::new_keyed(base_key);

    let mut input_buf = [0u8; std::mem::size_of::<usize>() * 2];
    let offset_bytes = (page_index * PAGE_SIZE).to_be_bytes();
    let index_bytes = page_index.to_be_bytes();

    input_buf[..offset_bytes.len()].copy_from_slice(&offset_bytes);
    input_buf[offset_bytes.len()..].copy_from_slice(&index_bytes);

    hasher.update(&input_buf);
    out_key.copy_from_slice(hasher.finalize().as_bytes());
}

pub fn encrypt_payload(payload: &mut Vec<u8>, base_key: &U8_32) {
    pad_to_page_size(payload);

    let total_pages = payload.len() / PAGE_SIZE;

    for i in 0..total_pages {
        let start_offset = i * PAGE_SIZE;
        let end_offset = start_offset + PAGE_SIZE;

        let mut page_key = [0u8; 32];
        derive_page_key(base_key, i, &mut page_key);

        let page_slice =
            (&mut payload[start_offset..end_offset]).try_into().unwrap();
        perform_xor(page_slice, &page_key);
    }
}

#[inline(always)]
pub fn decrypt_page(page_buf: &mut [u8; PAGE_SIZE], page_key: &U8_32) {
    perform_xor(page_buf, page_key);
}

#[inline(always)]
fn perform_xor(buf: &mut [u8; PAGE_SIZE], key: &U8_32) {
    let mut cipher = ChaCha20::new(key.into(), &NONCE.into());
    cipher.apply_keystream(buf);
}

fn pad_to_page_size(payload: &mut Vec<u8>) {
    let extra_bytes = payload.len() % PAGE_SIZE;

    if extra_bytes != 0 {
        let padding = PAGE_SIZE - extra_bytes;
        payload.resize(payload.len() + padding, 0x0);
    }
}
