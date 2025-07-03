use num_bigint::BigUint;
use rand::Rng;

pub fn encrypt(message: &BigUint, public_key_n: &BigUint, public_key_e: &BigUint) -> BigUint {
    message.modpow(public_key_e, public_key_n)
}

pub fn encrypt_message(message: &str, public_key_n: &BigUint, public_key_e: &BigUint) -> Vec<BigUint> {
    let message_bytes = message.as_bytes();
    let n_bytes = (public_key_n.bits() + 7) / 8;
    println!("nのバイト数: {}", n_bytes);
    let mut block_size = (n_bytes - 1) as usize;
    if n_bytes > 4 {
        let mut rng = rand::thread_rng();
        block_size = rng.gen_range(2..(n_bytes - 1)) as usize;
    }

    let mut ciphertexts = Vec::new();
    
    for chunk in message_bytes.chunks(block_size) {
        let block_value = BigUint::from_bytes_be(chunk);
        let ciphertext = encrypt(&block_value, public_key_n, public_key_e);
        ciphertexts.push(ciphertext);
    }
    
    ciphertexts
}