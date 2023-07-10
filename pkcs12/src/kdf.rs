use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use super::Result;

pub fn str_to_unicode(s: &str) -> Vec<u8> {
    let mut unicode: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_be_bytes().to_vec()).collect();
    unicode.push(0);
    unicode.push(0);
    unicode
}

pub enum Pkcs12KeyType {
    EncryptionKey=1,
    Iv=2,
    Mac=3
}

pub fn pkcs12_key_gen<const N: usize>(
    pass: &str,
    salt: &[u8],
    id: Pkcs12KeyType,
    rounds: i32,
) -> Result<[u8; N]> {
    let pass_uni = str_to_unicode(pass);
    let u = 32;
    let v = 64;
    let slen = v*((salt.len()+v-1)/v);
    let plen = v*((pass_uni.len() + v - 1)/v);
    let ilen = slen + plen;
    let mut i_tmp = vec![0u8; ilen];
    for i in 0..slen {
        i_tmp[i] = salt[i%salt.len()];
    }
    for i in slen..ilen {
        i_tmp[i] = pass_uni[(i-slen)%pass_uni.len()];
    }
    let d_tmp = match id {
        Pkcs12KeyType::EncryptionKey => vec![1u8; v],
        Pkcs12KeyType::Iv => vec![2u8; v],
        Pkcs12KeyType::Mac => vec![3u8; v],
    };
    let mut m = N;
    let mut n = 0;
    let mut out = [0u8; N];
    loop {
        let mut hasher = Sha256::new();
        hasher.update(&d_tmp);
        hasher.update(&i_tmp);
        let mut result = hasher.finalize();
        for _ in 1..rounds {
            let mut hasher = Sha256::new();
            hasher.update(&result[0..u]);
            result = hasher.finalize();
        }
        let min_mu = m.min(u);
        out[n..n+min_mu].copy_from_slice(&result[0..min_mu]);
        n += min_mu;
        m -= min_mu;
        if m <= 0 {
            break;
        }
        let mut b_tmp = vec![0u8; v];
        for j in 0..v {
            b_tmp[j] = result[j%u];
        }
        let mut j=0;
        while j<ilen {
            let mut c = 1_u16;
            let mut k: i64 = v as i64 -1;
            while k>=0 {
                c += i_tmp[k as usize +j] as u16 + b_tmp[k as usize] as u16;
                i_tmp[j+k as usize] = (c&0x00ff) as  u8;
                c >>= 8;
                k -= 1;
            }
            j += v;
        }
    }
    Ok(out)
}


