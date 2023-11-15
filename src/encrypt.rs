use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use rand::Rng;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub(crate) fn derive_key(input_str: String) -> [u8; 16] {
    let mut hasher = Shake128::default();
    hasher.update(input_str.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut key: [u8; 16] = [0; 16];
    reader.read(&mut key);

    return key;
}

pub(crate) fn gen_iv() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut iv: [u8; 16] = [0; 16];
    rng.fill(&mut iv);

    return iv;
}

pub(crate) fn aes_cbc_encrypt(input_str: String, key: [u8; 16], iv: [u8; 16]) -> Vec<u8> {
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let plaintext = input_str.as_bytes();
    let plaintext_len = plaintext.len();

    let mut buffer = vec![0; plaintext_len + 16];
    buffer[..plaintext_len].copy_from_slice(&plaintext);
    
    let ciphertext = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext_len)
        .unwrap();
    
    return ciphertext.to_vec();
}
