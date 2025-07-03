use num_bigint::{BigUint, BigInt};
use num_integer::gcd;
use num_traits::{One, Zero};

pub fn try_decrypt_with_public_key_only(
    ciphertexts: &[BigUint],
    public_key_n: &BigUint,
    public_key_e: &BigUint,
) -> Result<String, &'static str> {
    // 攻撃手法1: 素因数分解攻撃
    if let Some((p, q)) = factorize_n(public_key_n) {
        println!("素因数分解成功: p={}, q={}", p, q);
        
        // phi(n) = (p-1)(q-1)を計算
        let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());
        
        // dを計算
        if let Some(d) = mod_inverse(public_key_e, &phi_n) {
            println!("秘密鍵d復元成功: {}", d);
            
            // 復号を実行
            let mut decrypted_bytes = Vec::new();
            for ciphertext in ciphertexts {
                let decrypted_block = ciphertext.modpow(&d, public_key_n);
                let block_bytes = decrypted_block.to_bytes_be();
                decrypted_bytes.extend(block_bytes);
            }
            
            let result = String::from_utf8_lossy(&decrypted_bytes).to_string();
            return Ok(result);
        }
    }
    
    // 攻撃手法2: 小さい平文に対するe乗根攻撃
    for ciphertext in ciphertexts {
        if let Some(plaintext) = nth_root_attack(ciphertext, public_key_e) {
            println!("e乗根攻撃成功: {}", plaintext);
            let bytes = plaintext.to_bytes_be();
            if let Ok(text) = String::from_utf8(bytes) {
                return Ok(text);
            }
        }
    }
    
    Err("公開鍵のみでは復号できませんでした")
}

// 簡単な素因数分解（小さいnのみ対応）
fn factorize_n(n: &BigUint) -> Option<(BigUint, BigUint)> {
    let limit = BigUint::from(1000000u32); // 100万まで試行
    let mut i = BigUint::from(2u32);
    
    while &i * &i <= *n && i <= limit {
        if n % &i == BigUint::zero() {
            let j = n / &i;
            return Some((i, j));
        }
        i += BigUint::one();
    }
    None
}

// e乗根攻撃（平文^e < nの場合）
fn nth_root_attack(ciphertext: &BigUint, e: &BigUint) -> Option<BigUint> {
    if *e == BigUint::from(3u32) {
        // 3乗根を計算
        let cube_root = nth_root(ciphertext, 3);
        // 検証: cube_root^3 == ciphertext
        if cube_root.pow(3) == *ciphertext {
            return Some(cube_root);
        }
    } else if *e == BigUint::from(2u32) {
        // 平方根を計算
        let sqrt = sqrt(ciphertext);
        if &sqrt * &sqrt == *ciphertext {
            return Some(sqrt);
        }
    }
    None
}

// n乗根の近似計算
fn nth_root(n: &BigUint, root: u32) -> BigUint {
    if *n == BigUint::zero() {
        return BigUint::zero();
    }
    
    let mut x = n.clone();
    let mut prev_x = BigUint::zero();
    
    while x != prev_x {
        prev_x = x.clone();
        let x_pow_n_minus_1 = x.pow(root - 1);
        x = ((&x * (root - 1)) + (n / &x_pow_n_minus_1)) / BigUint::from(root);
    }
    
    x
}

// 平方根の計算
fn sqrt(n: &BigUint) -> BigUint {
    nth_root(n, 2)
}

// モジュラ逆数の計算
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_int = BigInt::from(a.clone());
    let m_int = BigInt::from(m.clone());
    
    let mut mn = (m_int.clone(), a_int.clone());
    let mut xy = (BigInt::from(0), BigInt::from(1));

    while mn.1 != BigInt::from(0) {
        let div = &mn.0 / &mn.1;
        mn = (mn.1.clone(), mn.0 - &div * &mn.1);
        xy = (xy.1.clone(), xy.0 - &div * &xy.1);
    }

    if mn.0 > BigInt::from(1) {
        None
    } else {
        let result = (xy.0 % &m_int + &m_int) % &m_int;
        Some(result.try_into().ok()?)
    }
}