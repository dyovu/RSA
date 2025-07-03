mod keygen;
mod encrypt;
mod attack;

use num_bigint::BigUint;
use rand::Rng;
// extern crate rand;
// extern crate num_bigint;

fn main() {
    let primes = [
        // BigUint::from(102871u32),
        // BigUint::from(102877u32),
        // BigUint::from(102881u32),
        // BigUint::from(102911u32),
        // BigUint::from(67280421310721u64),
        // BigUint::from(14062973813117u64),
        BigUint::from(170141183460469231731687303715884105727u128),
        BigUint::from(679976970267350887175417446781u128),
        BigUint::from(12806424796774796141370392839556386879u128),
        // BigUint::from(102913u32),
        // BigUint::from(102929u32),
    ];

    let tmp = 679976970267350887175417446781u128% 3u128;
    println!("\n3で割った余り: {}", tmp);

    let p_val = &primes[rand::thread_rng().gen_range(0..primes.len())];
    let q_val = &primes[rand::thread_rng().gen_range(0..primes.len())];

    // let p_val = BigUint::from(7u32);
    // let q_val = BigUint::from(13u32);

    println!("使用する素数 p: {}", p_val);
    println!("使用する素数 q: {}", q_val);

    // 1. RSA鍵生成と復号
    let keys = match keygen::RsaKeys::generate_keys(p_val.clone(), q_val.clone()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("鍵生成エラー: {}", e);
            return;
        }
    };
    
    println!("\n--- 鍵生成 ---");
    println!("公開鍵 (n, e): ({}, {})", keys.get_n(), keys.get_e());

    let original_message_str = ".,*";
    println!("\n--- 暗号化と復号 ---");
    println!("元のメッセージ: {}", original_message_str);
    println!("元のメッセージ (数値): {}", BigUint::from_bytes_be(original_message_str.as_bytes()));

    // 2. 暗号化
    let ciphertexts = encrypt::encrypt_message(&original_message_str, keys.get_n(), keys.get_e());
    println!("暗号文ブロック数: {}", ciphertexts.len());

    // 3. 正常な復号
    let decrypted_message_str = keys.decrypt_message(&ciphertexts);
    println!("正常復号結果: {}", decrypted_message_str);

    // 4. 公開鍵のみでの復号攻撃
    println!("\n--- 公開鍵攻撃 ---");
    let attack_result = attack::try_decrypt_with_public_key_only(&ciphertexts, keys.get_n(), keys.get_e());
    match attack_result {
        Ok(message) => println!("攻撃成功: {}", message),
        Err(err) => println!("攻撃失敗: {}", err),
    }
}