pub fn print_bytes(buf: &[u8], size: usize) {
    for (i, b) in buf.iter().take(size).enumerate() {
        print!("{:02X} ", b);

        if (i + 1) % 16 == 0 {
            println!();
        }
    }
}

#[macro_export]
macro_rules! dprintln {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!($($arg)*);
    };
}
