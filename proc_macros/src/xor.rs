#[proc_macro]
pub fn xor_string(input: TokenStream) -> TokenStream {
    let mut tokens = input.into_iter();
    let token = tokens.next().expect("Expected a string literal");

    let token_str = token.to_string();
    if !token_str.starts_with('"') || !token_str.ends_with('"') {
        panic!("xor_str macro only accepts a literal string enclosed in quotes");
    }

    let original_str = &token_str[1..token_str.len() - 1];
    let xor_key = _simple_random_u64();

    let encrypted_bytes: Vec<u8> = original_str
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ (((xor_key >> ((i % 8) * 8)) & 0xFF) as u8) ^ (i as u8))
        .collect();

    let mut generated_code = String::new();
    generated_code.push_str("{\n");
    generated_code.push_str("    let encrypted: &[u8] = &[");

    for byte in encrypted_bytes {
        generated_code.push_str(&format!("{}, ", byte));
    }

    generated_code.push_str("];\n");
    generated_code.push_str(&format!(
        "    let decrypted: Vec<u8> = encrypted.iter().enumerate().map(|(i, &b)| b ^ ((({}_u64 >> ((i % 8) * 8)) & 0xFF) as u8) ^ (i as u8)).collect();\n", 
        xor_key
    ));
    generated_code.push_str("    unsafe { String::from_utf8_unchecked(decrypted) }\n");
    generated_code.push_str("}\n");

    generated_code.parse().unwrap()
}

#[proc_macro]
pub fn xor_str(input: TokenStream) -> TokenStream {
    let mut tokens = input.into_iter();
    let token = tokens.next().expect("Expected a string literal");

    let token_str = token.to_string();
    if !token_str.starts_with('"') || !token_str.ends_with('"') {
        panic!("xor_str macro only accepts a literal string enclosed in quotes");
    }

    let original_str = &token_str[1..token_str.len() - 1];
    let xor_key = _simple_random_u64();

    let encrypted_bytes: Vec<u8> = original_str
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ (((xor_key >> ((i % 8) * 8)) & 0xFF) as u8) ^ (i as u8))
        .collect();

    let len = encrypted_bytes.len();
    let mut bytes_fmt = String::new();
    for byte in encrypted_bytes {
        bytes_fmt.push_str(&format!("{:#04x}, ", byte));
    }

    let generated_code = format!(
        r#"({{
            static mut BUF: [u8; {len}] = [0u8; {len}];
            static INIT: ::core::sync::atomic::AtomicBool = ::core::sync::atomic::AtomicBool::new(false);

            if !INIT.swap(true, ::core::sync::atomic::Ordering::AcqRel) {{
                let encrypted: [u8; {len}] = [{bytes}];

                unsafe {{
                    let ptr = BUF.as_mut_ptr();
                    let mut i = 0;

                    while i < {len} {{
                        *ptr.add(i) = encrypted[i] ^ ((({key}_u64 >> ((i % 8) * 8)) & 0xFF) as u8) ^ (i as u8);
                        i += 1;
                    }}
                }}
            }}

            unsafe {{ ::core::str::from_utf8_unchecked(&BUF) }}
        }})"#,
        bytes = bytes_fmt,
        key = xor_key,
        len = len
    );

    generated_code.parse().unwrap()
}
