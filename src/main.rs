use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
use rand::Rng;

fn main() {
    println!("Hello, world!");
}

fn derive_key(input_str: String) -> [u8; 16] {
    let mut hasher = Shake128::default();
    hasher.update(input_str.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut key: [u8; 16] = [0; 16];
    reader.read(&mut key);

    return key;
}

fn gen_iv() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut iv: [u8; 16] = [0; 16];
    rng.fill(&mut iv);

    return iv;
}