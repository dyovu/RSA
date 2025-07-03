use num_bigint::{BigUint, BigInt};
use num_integer::gcd;
use num_traits::{One, Zero};
use rand::Rng;

#[derive(Debug)]
pub struct RsaKeys {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    p: BigUint,
    q: BigUint,
}

impl RsaKeys {
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
        e = BigUint::from(3u32);

        // if (&p - BigUint::one())%&e == BigUint::zero() || (&q - BigUint::one())%&e == BigUint::zero() {
        //     return Err("p-1またはq-1が3の倍数であるため、eの選択に失敗しました。");
        // } else {
        //     // ここではeを3に設定していますが、他の値も検討できます。
        //     e = BigUint::from(3u32);
        // }

        loop {
            let random_bytes: Vec<u8> = (0..16).map(|_| rng.gen_range(0..=255)).collect();
            e = BigUint::from_bytes_be(&random_bytes) % &phi_n;
            e = BigUint::from(3u32);
            if e > BigUint::one() && gcd(e.clone(), phi_n.clone()) == BigUint::one() {
                println!("eの値: {}", e);
                break;
            }
            println!("eの値が条件を満たさないため、再生成します。");
        }

        let d = mod_inverse(&e, &phi_n).ok_or("dの計算に失敗しました。")?;

        Ok(RsaKeys { n, e: e.clone(), d, p, q })
    }

    pub fn get_n(&self) -> &BigUint {
        &self.n
    }

    pub fn get_e(&self) -> &BigUint {
        &self.e
    }

    pub fn decrypt(&self, ciphertext: &BigUint) -> BigUint {
        ciphertext.modpow(&self.d, &self.n)
    }

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