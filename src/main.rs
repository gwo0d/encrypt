mod encrypt;

use encrypt::{derive_key, gen_iv, aes_cbc_encrypt};
use std::io;

fn main() {
    let bold = "\x1B[1m";
    let un_bold = "\x1B[22m";

    clear_screen();
    let mut plaintext = String::new();
    println!("{}Enter plaintext: {}", bold, un_bold);
    io::stdin()
        .read_line(&mut plaintext)
        .expect("Failed to read plaintext");

    clear_screen();
    let mut password = String::new();
    println!("{}Enter password: {}", bold, un_bold);
    io::stdin()
        .read_line(&mut password)
        .expect("Failed to read password");

    let key = derive_key(password);
    let iv = gen_iv();

    let ciphertext = aes_cbc_encrypt(plaintext, key, iv);

    clear_screen();
    let mut counter = 0;
    println!("{}Ciphertext • {} Block(s): {}", bold, (ciphertext.len() / 16), un_bold);
    for byte in ciphertext.iter() {
        counter += 1;
        print!("{:02x}", byte);
        if (counter % 16) == 0 {
            print!("\n");
        } else {
            print!(" ");
        }
    }

    println!("\n{}IV: {}", bold, un_bold);
    for byte in iv.iter() {
        print!("{:02x}", byte);
        print!(" ");
    }
}

fn clear_screen() {
    let black_text = "\x1B[38;2;0;0;0m";
    let yellow_bg = "\x1B[48;2;255;255;0m";
    let reset = "\x1B[0m";

    print!("\x1B[2J\x1B[1;1H");
    println!("{}{}Encryption Tool...{}", black_text, yellow_bg, reset);
}
