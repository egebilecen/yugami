use rand::rngs::SysRng;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn get_rng() -> impl Rng {
    ChaCha20Rng::try_from_rng(&mut SysRng).unwrap()
}

pub fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut vec = vec![0u8; size];
    let mut rng = get_rng();
    rng.fill_bytes(&mut vec);

    vec
}

pub fn fill_random_bytes(buf: &mut [u8]) {
    let mut rng = get_rng();
    rng.fill_bytes(buf);
}
