pub fn print_bytes(buf: &[u8], len: usize) {
    for (i, b) in buf.iter().take(len).enumerate() {
        print!("{:02X} ", b);

        if (i + 1) % 16 == 0 {
            println!();
        }
    }
}

#[macro_export]
macro_rules! dprintln {
    ($fmt:expr $(, $($arg:tt)*)?) => {
        #[cfg(debug_assertions)]
        println!(concat!("[DEBUG] ", $fmt) $(, $($arg)*)?);
    };
}
