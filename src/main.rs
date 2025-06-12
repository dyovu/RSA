use num_bigint:: {BigUint, BigInt};
use num_integer::gcd;
use num_traits::{One, Zero};
use rand::Rng;

// 1. RSAの公開鍵と秘密鍵を作るコード、公開鍵で作られた暗号化文を復号するコード
#[derive(Debug)]
pub struct RsaKeys {
    pub n: BigUint,
    pub e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
}

impl RsaKeys {
    // 秘密鍵と公開鍵を生成する
    pub fn generate_keys(p: BigUint, q: BigUint) -> Result<Self, &'static str> {
        if p == q {
            return Err("pとqは異なる素数である必要があります。");
        }
        if !is_prime(&p) || !is_prime(&q) {
            return Err("pとqは素数である必要があります。");
        }

        let n = &p * &q;
        let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

        let mut rng = rand::thread_rng();
        let mut e;
        loop {
            // eは1 < e < phi_n かつ gcd(e, phi_n) = 1 を満たすように選ぶ
            let random_bytes: Vec<u8> = (0..16).map(|_| rng.gen_range(0..=255)).collect();
            e = BigUint::from_bytes_be(&random_bytes) % &phi_n;
            if e > BigUint::one() && gcd(e.clone(), phi_n.clone()) == BigUint::one() {
                break;
            }
        }

        // d * e % phi_n = 1 となるdを計算 (modInverse)
        let d = mod_inverse(&e, &phi_n).ok_or("dの計算に失敗しました。")?;

        Ok(RsaKeys { n, e: e.clone(), d, p, q })
    }

    // 暗号文を復号する
    pub fn decrypt(&self, ciphertext: &BigUint) -> BigUint {
        // x = f_x^d mod n
        ciphertext.modpow(&self.d, &self.n)
    }

    // 分割された暗号文を復号して結合
    pub fn decrypt_message(&self, ciphertexts: &[BigUint]) -> String {
        let mut decrypted_bytes = Vec::new();
        
        for ciphertext in ciphertexts {
            let decrypted_block = self.decrypt(ciphertext);
            let block_bytes = decrypted_block.to_bytes_be();
            decrypted_bytes.extend(block_bytes);
        }
        
        String::from_utf8_lossy(&decrypted_bytes).to_string()
    }
}

// 2. 1で作った公開鍵を使って文字列を暗号化するコード
pub fn encrypt(message: &BigUint, public_key_n: &BigUint, public_key_e: &BigUint) -> BigUint {
    // f_x = x^e mod n
    message.modpow(public_key_e, public_key_n)
}

// メッセージを適切なサイズに分割して暗号化
pub fn encrypt_message(message: &str, public_key_n: &BigUint, public_key_e: &BigUint) -> Vec<BigUint> {
    let message_bytes = message.as_bytes();
    let n_bytes = (public_key_n.bits() + 7) / 8; // nのバイト数
    println!("nのバイト数: {}", n_bytes);
    let mut block_size = (n_bytes - 1) as usize ;
    if n_bytes > 4{
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

// 3. 公開鍵のみを使って2で作った文字列を復号しようとするコード
// この関数は意図的に失敗します。
pub fn try_decrypt_with_public_key_only(
    _ciphertext: &BigUint,
    _public_key_n: &BigUint,
    _public_key_e: &BigUint,
) -> Result<BigUint, &'static str> {
    Err("公開鍵だけでは復号できません。秘密鍵（d）が必要です。")
}

// 素数判定 (簡単なもの)
fn is_prime(num: &BigUint) -> bool {
    if *num <= BigUint::one() {
        return false;
    }
    if *num == BigUint::from(2u32) || *num == BigUint::from(3u32) {
        return true;
    }
    if num % BigUint::from(2u32) == BigUint::zero() || num % BigUint::from(3u32) == BigUint::zero() {
        return false;
    }

    let mut i = BigUint::from(5u32);
    let two = BigUint::from(2u32);
    let six = BigUint::from(6u32);
    while &i * &i <= *num {
        if num % &i == BigUint::zero() || num % (&i + &two) == BigUint::zero() {
            return false;
        }
        i += &six;
    }
    true
}

// 拡張ユークリッド互除法を用いてモジュラ逆数を計算
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_encryption_decryption() {
        // ハードコードされた素数 (テスト用なので小さい値)
        let p = BigUint::from(61u32); // 実際にははるかに大きな素数を使用
        let q = BigUint::from(53u32); // 実際にははるかに大きな素数を使用

        let keys = RsaKeys::generate_keys(p, q).unwrap();
        println!("Public Key: n = {}, e = {}", keys.n, keys.e);
        println!("Private Key: d = {}", keys.d); // dは公開しない

        let original_message_str = "Rust is great";
        // メッセージを数値に変換 (ここでは簡易的にASCII値を結合)
        let original_message_bytes = original_message_str.as_bytes();
        let original_message = BigUint::from_bytes_be(original_message_bytes);
        println!("Original message (numeric): {}", original_message);

        // 暗号化
        let ciphertext = encrypt(&original_message, &keys.n, &keys.e);
        println!("Ciphertext: {}", ciphertext);

        // 復号
        let decrypted_message = keys.decrypt(&ciphertext);
        println!("Decrypted message (numeric): {}", decrypted_message);

        // 復号された数値を元の文字列に戻す
        let decrypted_message_bytes = decrypted_message.to_bytes_be();
        let decrypted_message_str = String::from_utf8(decrypted_message_bytes).unwrap();
        println!("Decrypted message: {}", decrypted_message_str);

        assert_eq!(original_message_str, decrypted_message_str);
    }

    #[test]
    fn test_public_key_decryption_failure() {
        let p = BigUint::from(17u32);
        let q = BigUint::from(11u32);
        let keys = RsaKeys::generate_keys(p, q).unwrap();

        let original_message = BigUint::from(12345u32);
        let ciphertext = encrypt(&original_message, &keys.n, &keys.e);

        let result = try_decrypt_with_public_key_only(&ciphertext, &keys.n, &keys.e);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "公開鍵だけでは復号できません。秘密鍵（d）が必要です。");
    }

    #[test]
    fn test_is_prime() {
        assert!(!is_prime(&BigUint::from(1u32)));
        assert!(is_prime(&BigUint::from(2u32)));
        assert!(is_prime(&BigUint::from(3u32)));
        assert!(!is_prime(&BigUint::from(4u32)));
        assert!(is_prime(&BigUint::from(5u32)));
        assert!(!is_prime(&BigUint::from(9u32)));
        assert!(is_prime(&BigUint::from(17u32)));
        assert!(is_prime(&BigUint::from(61u32)));
        assert!(is_prime(&BigUint::from(53u32)));
    }

    #[test]
    fn test_mod_inverse() {
        // 7^-1 mod 11 = 8 (7 * 8 = 56 = 5 * 11 + 1)
        assert_eq!(mod_inverse(&BigUint::from(7u32), &BigUint::from(11u32)), Some(BigUint::from(8u32)));
        // 3^-1 mod 10 -> None (3と10は互いに素)
        assert_eq!(mod_inverse(&BigUint::from(3u32), &BigUint::from(10u32)), Some(BigUint::from(7u32)));
        // 2^-1 mod 4 -> None (2と4は互いに素ではない)
        assert_eq!(mod_inverse(&BigUint::from(2u32), &BigUint::from(4u32)), None);
    }
}



fn main() {
    // 実際のRSAでは巨大な素数を使用しますが、ここでは例として小さい素数をいくつかハードコードします。
    // これらの素数は互いに異なり、秘密鍵生成に適したものである必要があります。
    let primes = [
        // BigUint::from(977u32),  // より大きな素数
        // BigUint::from(991u32),
        // BigUint::from(997u32),
        // BigUint::from(1009u32),
        // BigUint::from(1013u32),
        // BigUint::from(1019u32),
        // BigUint::from(1021u32),
        // BigUint::from(1031u32),
        // BigUint::from(1033u32),
        // BigUint::from(1039u32),
        // BigUint::from(1049u32),
        // BigUint::from(1051u32),
        // BigUint::from(1061u32),
        // BigUint::from(1063u32),
        // BigUint::from(1069u32),
        // BigUint::from(1087u32),
        // BigUint::from(1091u32),
        // BigUint::from(1093u32),
        // BigUint::from(1097u32),
        // BigUint::from(1103u32),
        // BigUint::from(1109u32),
        // BigUint::from(1117u32),
        // BigUint::from(1123u32),
        // BigUint::from(1129u32),
        BigUint::from(102871u32),
        BigUint::from(102877u32),
        BigUint::from(102881u32),
        BigUint::from(102911u32),
        BigUint::from(102913u32),
        BigUint::from(102929u32),
    ];

    // pとqの選択 (primes配列から2つ選ぶ)
    let p_val = &primes[Rng::gen_range(&mut rand::thread_rng(), 0..primes.len())];
    let q_val = &primes[Rng::gen_range(&mut rand::thread_rng(), 0..primes.len())];

    println!("使用する素数 p: {}", p_val);
    println!("使用する素数 q: {}", q_val);

    // 1. RSAの公開鍵と秘密鍵を作る
    let keys = match RsaKeys::generate_keys(p_val.clone(), q_val.clone()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("鍵生成エラー: {}", e);
            return;
        }
    };
    println!("\n--- 鍵生成 ---");
    println!("公開鍵 (n, e): ({}, {})", keys.n, keys.e);
    // 秘密鍵dは出力しない (通常は秘密に保つ)
    // println!("秘密鍵 d: {}", keys.d);

    let original_message_str = "Hello, world"; // 暗号化する元のメッセージ
    // メッセージを数値に変換 (ここでは簡易的にASCII値を結合。実際はパディングなどが必要)
    let original_message_bytes = original_message_str.as_bytes();
    let original_message = BigUint::from_bytes_be(original_message_bytes);
    println!("\n--- 暗号化と復号 ---");
    println!("元のメッセージ (文字列): {}", original_message_str);
    println!("元のメッセージ (数値): {}", original_message);

    // // 2. 公開鍵を使って文字列を暗号化する
    // let ciphertext = encrypt(&original_message, &keys.n, &keys.e);
    // println!("暗号文: {}", ciphertext);

    // // 1. 公開鍵で作られた暗号化文を復号するコード
    // let decrypted_message = keys.decrypt(&ciphertext);
    // println!("復号されたメッセージ (数値): {}", decrypted_message);

    // // 復号された数値を元の文字列に戻す
    // let decrypted_message_bytes = decrypted_message.to_bytes_be();
    // let decrypted_message_str = String::from_utf8_lossy(&decrypted_message_bytes);
    // println!("復号されたメッセージ (文字列): {}", decrypted_message_str);


    // 分割して暗号化する
    // 2. 公開鍵を使って文字列を暗号化する
    // メッセージを適切なサイズに分割して暗号化
    let ciphertexts = encrypt_message(&original_message_str, &keys.n, &keys.e);
    println!("暗号文ブロック数: {}", ciphertexts.len());

    // 復号
    let decrypted_message_str = keys.decrypt_message(&ciphertexts);
    for (i, ciphertext) in ciphertexts.iter().enumerate() {
        println!("暗号文ブロック{}: {}", i + 1, ciphertext);
    }
    println!("復号されたメッセージ (文字列): {}", decrypted_message_str);

    if original_message_str == decrypted_message_str {
        println!("復号成功！元のメッセージと一致しました。");
    } else {
        println!("復号失敗！元のメッセージと一致しません。");
    }

    // // 3. 公開鍵のみを使って2で作った文字列を復号しようとするコード
    // println!("\n--- 公開鍵のみでの復号を試行 ---");
    // match try_decrypt_with_public_key_only(&ciphertext, &keys.n, &keys.e) {
    //     Ok(_) => println!("エラー: 公開鍵のみで復号できてしまいました。"),
    //     Err(msg) => println!("結果: {}", msg),
    // }
}