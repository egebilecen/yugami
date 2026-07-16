use proc_macro::TokenStream;
use rand::rngs::StdRng;
use rand::{Rng, make_rng};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[proc_macro]
/// Generates a compile-time CSPRNG random u64 number.
pub fn random_u64(_input: TokenStream) -> TokenStream {
    make_rng::<StdRng>()
        .next_u64()
        .to_string()
        .parse()
        .expect("u64 literal should parse")
}

#[proc_macro]
/// Generates a compile-time CSPRNG random u32 number.
pub fn random_u32(_input: TokenStream) -> TokenStream {
    make_rng::<StdRng>()
        .next_u32()
        .to_string()
        .parse()
        .expect("u32 literal should parse")
}

#[proc_macro]
/// Generates a compile-time simple random u64 number.
pub fn simple_random_u64(_input: TokenStream) -> TokenStream {
    make_simple_random_u64()
        .to_string()
        .parse()
        .expect("u64 literal should parse")
}

#[proc_macro]
/// Generates a compile-time simple random u32 number.
pub fn simple_random_u32(_input: TokenStream) -> TokenStream {
    make_simple_random_u32()
        .to_string()
        .parse()
        .expect("u32 literal should parse")
}

fn make_simple_random_u64() -> u64 {
    let mut seed = _simple_random_u64();

    for _ in 0..3 {
        seed ^= _simple_random_u64();
    }

    seed
}

fn make_simple_random_u32() -> u32 {
    _simple_random_u64() as u32
}

fn _simple_random_u64() -> u64 {
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    let mut hasher = DefaultHasher::new();

    counter.hash(&mut hasher);
    now.hash(&mut hasher);
    std::process::id().hash(&mut hasher);

    hasher.finish()
}
