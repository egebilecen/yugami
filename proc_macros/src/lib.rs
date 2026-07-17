use proc_macro::{TokenStream, TokenTree};
use rand::rngs::SysRng;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

include!("random.rs");
include!("xor.rs");
