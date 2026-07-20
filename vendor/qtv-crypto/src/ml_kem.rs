//! ML-KEM (FIPS 203) - module lattice key encapsulation. Backs the QUIC transport key exchange in

use crate::sha3::{sha3_256, sha3_512, shake128, shake256};

// Parameters for ML-KEM-768 (FIPS 203, Table 2).
const Q: i32 = 3329; // prime modulus, 13 * 2^8 + 1
const N: usize = 256; // ring degree
const K: usize = 3; // module rank
const ETA1: usize = 2; // secret and error CBD parameter
const ETA2: usize = 2; // encryption error CBD parameter
const DU: usize = 10; // ciphertext compression bits for u
const DV: usize = 4; // ciphertext compression bits for v

// Number of bytes in ByteEncode_12 of a single ring element (12 bits per coefficient).
const POLY_BYTES: usize = 12 * N / 8; // 384

/// Encoded ML-KEM-768 encapsulation key length in bytes.
pub const ENCAPS_KEY_BYTES: usize = K * POLY_BYTES + 32; // 1184
/// Encoded ML-KEM-768 decapsulation key length in bytes.
pub const DECAPS_KEY_BYTES: usize = 2 * K * POLY_BYTES + 96; // 2400
/// Encoded ML-KEM-768 ciphertext length in bytes.
pub const CIPHERTEXT_BYTES: usize = 32 * (DU * K + DV); // 1088
/// Length of the shared secret in bytes.
pub const SHARED_SECRET_BYTES: usize = 32;
/// Length of each key generation and encapsulation seed in bytes.
pub const SEED_BYTES: usize = 32;

/// Encoded ML-KEM-768 encapsulation key.
pub type EncapsKey = [u8; ENCAPS_KEY_BYTES];
/// Encoded ML-KEM-768 decapsulation key.
pub type DecapsKey = [u8; DECAPS_KEY_BYTES];
/// Encoded ML-KEM-768 ciphertext.
pub type Ciphertext = [u8; CIPHERTEXT_BYTES];
/// The shared secret produced by encapsulation and decapsulation.
pub type SharedSecret = [u8; SHARED_SECRET_BYTES];

// A ring element, represented by its 256 coefficients in [0, Q).
type Poly = [i32; N];

const ZERO_POLY: Poly = [0i32; N];

// Modular arithmetic over Z_q for inputs already reduced into [0, Q).

fn add_q(a: i32, b: i32) -> i32 {
    let r = a + b;
    if r >= Q {
        r - Q
    } else {
        r
    }
}

fn sub_q(a: i32, b: i32) -> i32 {
    let r = a - b;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

fn mul_q(a: i32, b: i32) -> i32 {
    (a * b) % Q
}

// Number theoretic transform tables.

// Bit reversal of the low seven bits of i.
const fn brv7(mut i: usize) -> u32 {
    let mut r = 0u32;
    let mut b = 0;
    while b < 7 {
        r = (r << 1) | (i & 1) as u32;
        i >>= 1;
        b += 1;
    }
    r
}

// base^exp mod Q for base in [0, Q).
const fn pow_mod(base: i64, mut exp: u32) -> i64 {
    let mut result = 1i64;
    let mut b = base % Q as i64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * b) % Q as i64;
        }
        b = (b * b) % Q as i64;
        exp >>= 1;
    }
    result
}

// ZETAS[i] = 17^{brv7(i)} mod Q, the twiddle factors of the length-128 transform (FIPS 203, 4.3).
const ZETAS: [i32; 128] = {
    let mut z = [0i32; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow_mod(17, brv7(i)) as i32;
        i += 1;
    }
    z
};

// GAMMAS[i] = 17^{2*brv7(i)+1} mod Q, the moduli of the degree-two base rings (FIPS 203, 4.3).
const GAMMAS: [i32; 128] = {
    let mut g = [0i32; 128];
    let mut i = 0;
    while i < 128 {
        g[i] = pow_mod(17, 2 * brv7(i) + 1) as i32;
        i += 1;
    }
    g
};

// In-place forward NTT (FIPS 203, Algorithm 9). Coefficients stay in [0, Q).
fn ntt(a: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            let mut j = start;
            while j < start + len {
                let t = mul_q(zeta, a[j + len]);
                a[j + len] = sub_q(a[j], t);
                a[j] = add_q(a[j], t);
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

// In-place inverse NTT (FIPS 203, Algorithm 10). Coefficients stay in [0, Q).
fn inv_ntt(a: &mut Poly) {
    // 128^{-1} mod Q.
    const F: i32 = 3303;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            let mut j = start;
            while j < start + len {
                let t = a[j];
                let u = a[j + len];
                a[j] = add_q(t, u);
                a[j + len] = mul_q(zeta, sub_q(u, t));
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for x in a.iter_mut() {
        *x = mul_q(F, *x);
    }
}

// MultiplyNTTs (FIPS 203, Algorithm 11) built from BaseCaseMultiply (Algorithm 12). The product of
// two NTT-domain elements is taken in the 128 degree-two rings Z_q[x]/(x^2 - GAMMAS[i]).
fn multiply_ntts(f: &Poly, g: &Poly) -> Poly {
    let mut h = ZERO_POLY;
    let mut i = 0usize;
    while i < 128 {
        let gamma = GAMMAS[i];
        let a0 = f[2 * i];
        let a1 = f[2 * i + 1];
        let b0 = g[2 * i];
        let b1 = g[2 * i + 1];
        h[2 * i] = add_q(mul_q(a0, b0), mul_q(mul_q(a1, b1), gamma));
        h[2 * i + 1] = add_q(mul_q(a0, b1), mul_q(a1, b0));
        i += 1;
    }
    h
}

// Pointwise product in the NTT domain, accumulated into acc.
fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    let h = multiply_ntts(a, b);
    for i in 0..N {
        acc[i] = add_q(acc[i], h[i]);
    }
}

// Compression and decompression (FIPS 203, 4.2.1). Coefficients round to and from d-bit values.

fn compress(x: i32, d: usize) -> i32 {
    let t = ((x as u32) << d) + (Q as u32) / 2;
    ((t / Q as u32) & ((1u32 << d) - 1)) as i32
}

fn decompress(y: i32, d: usize) -> i32 {
    let t = (y as u32 * Q as u32 + (1u32 << (d - 1))) >> d;
    t as i32
}

// Bit packing (FIPS 203, ByteEncode and ByteDecode, Algorithms 5 and 6). Coefficients are packed
// least significant bit first.

fn pack_bits(coeffs: &Poly, bits: usize, out: &mut Vec<u8>) {
    let mask: u64 = (1u64 << bits) - 1;
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    for &c in coeffs.iter() {
        acc |= (c as u64 & mask) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out.push((acc & 0xff) as u8);
            acc >>= 8;
            acc_bits -= 8;
        }
    }
}

fn unpack_bits(data: &[u8], bits: usize) -> Poly {
    let mask: u64 = (1u64 << bits) - 1;
    let mut coeffs = ZERO_POLY;
    let mut acc: u64 = 0;
    let mut acc_bits = 0usize;
    let mut byte = 0usize;
    for c in coeffs.iter_mut() {
        while acc_bits < bits {
            acc |= (data[byte] as u64) << acc_bits;
            byte += 1;
            acc_bits += 8;
        }
        *c = (acc & mask) as i32;
        acc >>= bits;
        acc_bits -= bits;
    }
    coeffs
}

// ByteDecode_12 of one ring element, reducing each coefficient modulo Q (FIPS 203, Algorithm 6).
fn byte_decode_12(data: &[u8]) -> Poly {
    let mut p = unpack_bits(data, 12);
    for c in p.iter_mut() {
        *c %= Q;
    }
    p
}

// Sampling routines (FIPS 203, 4.2.2).

// SHAKE128 rate in bytes, used to size the squeeze buffer for the uniform sampler.
const SHAKE128_RATE: usize = 168;

// SampleNTT (Algorithm 7): rejection sample a uniform NTT-domain element from a 34-byte seed.
fn sample_ntt(seed: &[u8]) -> Poly {
    let mut a = ZERO_POLY;
    let mut buflen = SHAKE128_RATE * 6;
    loop {
        let mut buf = vec![0u8; buflen];
        shake128(seed, &mut buf);
        let mut ctr = 0usize;
        let mut pos = 0usize;
        while ctr < N && pos + 3 <= buf.len() {
            let d1 = buf[pos] as i32 + 256 * ((buf[pos + 1] & 0x0f) as i32);
            let d2 = (buf[pos + 1] >> 4) as i32 + 16 * (buf[pos + 2] as i32);
            pos += 3;
            if d1 < Q {
                a[ctr] = d1;
                ctr += 1;
            }
            if d2 < Q && ctr < N {
                a[ctr] = d2;
                ctr += 1;
            }
        }
        if ctr == N {
            return a;
        }
        buflen *= 2;
    }
}

// SamplePolyCBD_eta (Algorithm 8): sample an element with coefficients from a centered binomial
// distribution over the byte array (length 64*eta).
fn sample_poly_cbd(bytes: &[u8], eta: usize) -> Poly {
    let bit = |l: usize| -> i32 { ((bytes[l >> 3] >> (l & 7)) & 1) as i32 };
    let mut f = ZERO_POLY;
    for i in 0..N {
        let mut x = 0i32;
        let mut y = 0i32;
        for j in 0..eta {
            x += bit(2 * i * eta + j);
            y += bit(2 * i * eta + eta + j);
        }
        f[i] = (x - y).rem_euclid(Q);
    }
    f
}

// PRF_eta (FIPS 203, 4.1): SHAKE256 keyed by a 32-byte seed and a one-byte nonce, 64*eta bytes out.
fn prf(eta: usize, seed: &[u8], nonce: u8) -> Vec<u8> {
    let mut input = Vec::with_capacity(33);
    input.extend_from_slice(seed);
    input.push(nonce);
    let mut out = vec![0u8; 64 * eta];
    shake256(&input, &mut out);
    out
}

// ExpandA: derive the k-by-k matrix of NTT-domain elements from rho. When transpose is false, entry
// [i][j] is sampled from rho || j || i (the layout used by key generation); when true, from
// rho || i || j (the transposed layout used by encryption).
fn expand_a(rho: &[u8], transpose: bool) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![ZERO_POLY; K]; K];
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    for i in 0..K {
        for j in 0..K {
            if transpose {
                seed[32] = i as u8;
                seed[33] = j as u8;
            } else {
                seed[32] = j as u8;
                seed[33] = i as u8;
            }
            a[i][j] = sample_ntt(&seed);
        }
    }
    a
}

// K-PKE.KeyGen (FIPS 203, Algorithm 13): expand the seed into an encryption key pair.
fn kpke_keygen(d: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut g_in = Vec::with_capacity(33);
    g_in.extend_from_slice(d);
    g_in.push(K as u8);
    let g = sha3_512(&g_in);
    let rho = &g[..32];
    let sigma = &g[32..];

    let a = expand_a(rho, false);

    let mut nonce = 0u8;
    let mut s = vec![ZERO_POLY; K];
    for poly in s.iter_mut() {
        *poly = sample_poly_cbd(&prf(ETA1, sigma, nonce), ETA1);
        nonce += 1;
    }
    let mut e = vec![ZERO_POLY; K];
    for poly in e.iter_mut() {
        *poly = sample_poly_cbd(&prf(ETA1, sigma, nonce), ETA1);
        nonce += 1;
    }
    for poly in s.iter_mut() {
        ntt(poly);
    }
    for poly in e.iter_mut() {
        ntt(poly);
    }

    // t_hat = A_hat * s_hat + e_hat.
    let mut t = vec![ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..K {
            pointwise_acc(&mut acc, &a[i][j], &s[j]);
        }
        for n in 0..N {
            t[i][n] = add_q(acc[n], e[i][n]);
        }
    }

    let mut ek = Vec::with_capacity(ENCAPS_KEY_BYTES);
    for poly in t.iter() {
        pack_bits(poly, 12, &mut ek);
    }
    ek.extend_from_slice(rho);

    let mut dk = Vec::with_capacity(K * POLY_BYTES);
    for poly in s.iter() {
        pack_bits(poly, 12, &mut dk);
    }
    (ek, dk)
}

// K-PKE.Encrypt (FIPS 203, Algorithm 14): encrypt the 32-byte message m under ek with randomness r.
fn kpke_encrypt(ek: &[u8], m: &[u8], r: &[u8]) -> Vec<u8> {
    let mut t = vec![ZERO_POLY; K];
    for i in 0..K {
        t[i] = byte_decode_12(&ek[i * POLY_BYTES..(i + 1) * POLY_BYTES]);
    }
    let rho = &ek[K * POLY_BYTES..K * POLY_BYTES + 32];
    let a = expand_a(rho, true);

    let mut nonce = 0u8;
    let mut y = vec![ZERO_POLY; K];
    for poly in y.iter_mut() {
        *poly = sample_poly_cbd(&prf(ETA1, r, nonce), ETA1);
        nonce += 1;
    }
    let mut e1 = vec![ZERO_POLY; K];
    for poly in e1.iter_mut() {
        *poly = sample_poly_cbd(&prf(ETA2, r, nonce), ETA2);
        nonce += 1;
    }
    let e2 = sample_poly_cbd(&prf(ETA2, r, nonce), ETA2);

    for poly in y.iter_mut() {
        ntt(poly);
    }

    // u = NTT^{-1}(A_hat^T * y_hat) + e1.
    let mut u = vec![ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..K {
            pointwise_acc(&mut acc, &a[i][j], &y[j]);
        }
        inv_ntt(&mut acc);
        for n in 0..N {
            u[i][n] = add_q(acc[n], e1[i][n]);
        }
    }

    // v = NTT^{-1}(t_hat^T * y_hat) + e2 + Decompress_1(m).
    let mut acc = ZERO_POLY;
    for i in 0..K {
        pointwise_acc(&mut acc, &t[i], &y[i]);
    }
    inv_ntt(&mut acc);
    let mu = unpack_bits(m, 1);
    let mut v = ZERO_POLY;
    for n in 0..N {
        v[n] = add_q(add_q(acc[n], e2[n]), decompress(mu[n], 1));
    }

    let mut c = Vec::with_capacity(CIPHERTEXT_BYTES);
    for poly in u.iter() {
        let mut comp = ZERO_POLY;
        for n in 0..N {
            comp[n] = compress(poly[n], DU);
        }
        pack_bits(&comp, DU, &mut c);
    }
    let mut comp = ZERO_POLY;
    for n in 0..N {
        comp[n] = compress(v[n], DV);
    }
    pack_bits(&comp, DV, &mut c);
    c
}

// K-PKE.Decrypt (FIPS 203, Algorithm 15): recover the 32-byte message from the ciphertext.
fn kpke_decrypt(dk: &[u8], c: &[u8]) -> Vec<u8> {
    let split = 32 * DU * K;
    let mut u = vec![ZERO_POLY; K];
    for i in 0..K {
        let raw = unpack_bits(&c[i * 32 * DU..(i + 1) * 32 * DU], DU);
        for n in 0..N {
            u[i][n] = decompress(raw[n], DU);
        }
    }
    let raw = unpack_bits(&c[split..split + 32 * DV], DV);
    let mut v = ZERO_POLY;
    for n in 0..N {
        v[n] = decompress(raw[n], DV);
    }

    let mut s = vec![ZERO_POLY; K];
    for i in 0..K {
        s[i] = byte_decode_12(&dk[i * POLY_BYTES..(i + 1) * POLY_BYTES]);
    }

    for poly in u.iter_mut() {
        ntt(poly);
    }
    let mut acc = ZERO_POLY;
    for i in 0..K {
        pointwise_acc(&mut acc, &s[i], &u[i]);
    }
    inv_ntt(&mut acc);

    let mut w = ZERO_POLY;
    for n in 0..N {
        w[n] = compress(sub_q(v[n], acc[n]), 1);
    }
    let mut out = Vec::with_capacity(32);
    pack_bits(&w, 1, &mut out);
    out
}

// Constant-time equality mask: 0xff when the slices are equal, 0x00 otherwise.
fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    (((diff as u16).wrapping_sub(1)) >> 8) as u8
}

/// Generate an ML-KEM-768 key pair deterministically from the 32-byte seeds d and z
pub fn keygen(d: &[u8; SEED_BYTES], z: &[u8; SEED_BYTES]) -> (EncapsKey, DecapsKey) {
    let (ek_pke, dk_pke) = kpke_keygen(d);

    let mut ek = [0u8; ENCAPS_KEY_BYTES];
    ek.copy_from_slice(&ek_pke);

    let mut dk = Vec::with_capacity(DECAPS_KEY_BYTES);
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek_pke);
    dk.extend_from_slice(&sha3_256(&ek_pke));
    dk.extend_from_slice(z);

    let mut dk_arr = [0u8; DECAPS_KEY_BYTES];
    dk_arr.copy_from_slice(&dk);
    (ek, dk_arr)
}

/// Encapsulate to an encapsulation key using the 32-byte message m, returning the shared secret and
pub fn encaps(ek: &EncapsKey, m: &[u8; SEED_BYTES]) -> (SharedSecret, Ciphertext) {
    let mut g_in = Vec::with_capacity(64);
    g_in.extend_from_slice(m);
    g_in.extend_from_slice(&sha3_256(ek));
    let g = sha3_512(&g_in);

    let mut shared = [0u8; SHARED_SECRET_BYTES];
    shared.copy_from_slice(&g[..32]);

    let c = kpke_encrypt(ek, m, &g[32..]);
    let mut ct = [0u8; CIPHERTEXT_BYTES];
    ct.copy_from_slice(&c);
    (shared, ct)
}

/// Decapsulate a ciphertext with a decapsulation key, returning the shared secret. On a ciphertext
pub fn decaps(dk: &DecapsKey, c: &Ciphertext) -> SharedSecret {
    let dk_pke = &dk[..K * POLY_BYTES];
    let ek_pke = &dk[K * POLY_BYTES..2 * K * POLY_BYTES + 32];
    let h = &dk[2 * K * POLY_BYTES + 32..2 * K * POLY_BYTES + 64];
    let z = &dk[2 * K * POLY_BYTES + 64..2 * K * POLY_BYTES + 96];

    let m_prime = kpke_decrypt(dk_pke, c);

    let mut g_in = Vec::with_capacity(64);
    g_in.extend_from_slice(&m_prime);
    g_in.extend_from_slice(h);
    let g = sha3_512(&g_in);
    let mut k_prime = [0u8; SHARED_SECRET_BYTES];
    k_prime.copy_from_slice(&g[..32]);
    let r_prime = &g[32..];

    let mut j_in = Vec::with_capacity(32 + CIPHERTEXT_BYTES);
    j_in.extend_from_slice(z);
    j_in.extend_from_slice(c);
    let mut k_bar = [0u8; SHARED_SECRET_BYTES];
    shake256(&j_in, &mut k_bar);

    let c_prime = kpke_encrypt(ek_pke, &m_prime, r_prime);
    let keep = ct_eq(&c_prime, c);

    let mut shared = [0u8; SHARED_SECRET_BYTES];
    for i in 0..SHARED_SECRET_BYTES {
        shared[i] = (keep & k_prime[i]) | (!keep & k_bar[i]);
    }
    shared
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn as_array<const M: usize>(v: &[u8]) -> [u8; M] {
        let mut a = [0u8; M];
        a.copy_from_slice(v);
        a
    }

    fn seed32(v: &[u8]) -> [u8; 32] {
        as_array::<32>(v)
    }

    fn load(name: &str) -> String {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("vectors/ml-kem");
        path.push(name);
        fs::read_to_string(path).unwrap()
    }

    fn records(name: &str) -> Vec<Vec<String>> {
        load(name)
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.split_whitespace().map(|s| s.to_string()).collect())
            .collect()
    }

    #[test]
    fn keygen_matches_official_vectors() {
        let recs = records("keygen_768.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let d = seed32(&hex(&r[0]));
            let z = seed32(&hex(&r[1]));
            let want_ek = hex(&r[2]);
            let want_dk = hex(&r[3]);
            let (ek, dk) = keygen(&d, &z);
            assert_eq!(&ek[..], &want_ek[..], "encapsulation key mismatch");
            assert_eq!(&dk[..], &want_dk[..], "decapsulation key mismatch");
        }
    }

    #[test]
    fn encaps_matches_official_vectors() {
        let recs = records("encaps_768.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let ek = as_array::<ENCAPS_KEY_BYTES>(&hex(&r[0]));
            let m = seed32(&hex(&r[1]));
            let want_c = hex(&r[2]);
            let want_k = hex(&r[3]);
            let (k, c) = encaps(&ek, &m);
            assert_eq!(&c[..], &want_c[..], "ciphertext mismatch");
            assert_eq!(&k[..], &want_k[..], "shared secret mismatch");
        }
    }

    #[test]
    fn decaps_matches_official_vectors() {
        let recs = records("decaps_768.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let dk = as_array::<DECAPS_KEY_BYTES>(&hex(&r[0]));
            let c = as_array::<CIPHERTEXT_BYTES>(&hex(&r[1]));
            let want_k = hex(&r[2]);
            let k = decaps(&dk, &c);
            assert_eq!(&k[..], &want_k[..], "shared secret mismatch");
        }
    }

    #[test]
    fn encaps_then_decaps_round_trip() {
        let d = [3u8; 32];
        let z = [5u8; 32];
        let (ek, dk) = keygen(&d, &z);
        let m = [9u8; 32];
        let (k, c) = encaps(&ek, &m);
        assert_eq!(decaps(&dk, &c), k);

        // A tampered ciphertext must decapsulate to the implicit rejection secret, not to k.
        let mut bad = c;
        bad[0] ^= 1;
        assert_ne!(decaps(&dk, &bad), k);
    }
}
