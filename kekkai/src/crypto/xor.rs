pub fn xor_in_place(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }

    for (data_byte, key_byte) in data.iter_mut().zip(key.iter().cycle()) {
        *data_byte ^= *key_byte;
    }
}
