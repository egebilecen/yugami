#[allow(dead_code)]
pub(crate) fn print_bytes(buf: &[u8], width: usize) {
    for (i, b) in buf.iter().take(128).enumerate() {
        print!("{:02X} ", b);

        if (i + 1) % width == 0 {
            println!();
        }
    }
}
