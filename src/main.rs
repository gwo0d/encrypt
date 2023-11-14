use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use rand::Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::io;

fn main() {
    let bold = "\x1B[1m";
    let unbold = "\x1B[22m";

    clear_screen();
    let mut plaintext = String::new();
    println!("{}Enter plaintext: {}", bold, unbold);
    io::stdin()
        .read_line(&mut plaintext)
        .expect("Failed to read plaintext");

    clear_screen();
    let mut password = String::new();
    println!("{}Enter password: {}", bold, unbold);
    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read password");

    let key = derive_key(password);
    let iv = gen_iv();

    let ciphertext = aes_cbc_encrypt(plaintext, key, iv);

    clear_screen();
    println!("{}Ciphertext: {}", bold, unbold);
    for byte in ciphertext.iter() {
        print!("{:02x}", byte);
        print!(" ");
    }

    println!("\n\n{}IV: {}", bold, unbold);
    for byte in iv.iter() {
        print!("{:02x}", byte);
        print!(" ");
    }
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

fn aes_cbc_encrypt(input_str: String, key: [u8; 16], iv: [u8; 16]) -> Vec<u8> {
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let mut buffer = [0u8; 48];
    let plaintext_len = input_str.len();
    buffer[..plaintext_len].copy_from_slice(input_str.as_bytes());

    let ciphertext = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext_len)
        .unwrap();

    return ciphertext.to_vec();
}

fn clear_screen() {
    let black_text = "\x1B[38;2;0;0;0m";
    let yellow_bg = "\x1B[48;2;255;255;0m";
    let reset = "\x1B[0m";

    print!("\x1B[2J\x1B[1;1H");
    println!("{}{}Encryption Tool...{}", black_text, yellow_bg, reset);
}
