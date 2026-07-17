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
