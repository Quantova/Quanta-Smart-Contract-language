//! ML-DSA (FIPS 204) - module lattice digital signatures. The stack's primary signature scheme:

use crate::sha3::{shake128, shake256};

// Parameters for ML-DSA-65 (FIPS 204, Table 1).
const Q: i32 = 8380417; // prime modulus, 2^23 - 2^13 + 1
const N: usize = 256; // ring degree
const D: usize = 13; // number of dropped bits from t
const K: usize = 6; // rows of A
const L: usize = 5; // columns of A
const ETA: i32 = 4; // secret coefficient range
const TAU: usize = 49; // number of nonzero coefficients in the challenge
const BETA: i32 = 196; // TAU * ETA
const GAMMA1: i32 = 1 << 19; // coefficient range of the mask y
const GAMMA2: i32 = (Q - 1) / 32; // low-order rounding range
const OMEGA: usize = 55; // maximum number of ones in the hint
const LAMBDA: usize = 192; // collision strength in bits

// Derived encoding sizes.
const CTILDE_BYTES: usize = LAMBDA / 4; // 48
const POLYT1_PACKED: usize = 320; // 10 bits per coefficient
const POLYT0_PACKED: usize = 416; // 13 bits per coefficient
const POLYETA_PACKED: usize = 128; // 4 bits per coefficient
const POLYZ_PACKED: usize = 640; // 20 bits per coefficient
const POLYW1_PACKED: usize = 128; // 4 bits per coefficient

/// Encoded ML-DSA-65 public key length in bytes.
pub const PUBLIC_KEY_BYTES: usize = 32 + K * POLYT1_PACKED; // 1952
/// Encoded ML-DSA-65 secret key length in bytes.
pub const SECRET_KEY_BYTES: usize = 128 + (L + K) * POLYETA_PACKED + K * POLYT0_PACKED; // 4032
/// Encoded ML-DSA-65 signature length in bytes.
pub const SIGNATURE_BYTES: usize = CTILDE_BYTES + L * POLYZ_PACKED + OMEGA + K; // 3309
/// Length of the key generation seed in bytes.
pub const SEED_BYTES: usize = 32;

/// Encoded ML-DSA-65 public key.
pub type PublicKey = [u8; PUBLIC_KEY_BYTES];
/// Encoded ML-DSA-65 secret key.
pub type SecretKey = [u8; SECRET_KEY_BYTES];
/// Encoded ML-DSA-65 signature.
pub type Signature = [u8; SIGNATURE_BYTES];

// A ring element, represented by its 256 coefficients.
type Poly = [i32; N];

const ZERO_POLY: Poly = [0i32; N];

// SHAKE rates in bytes, used to size squeeze buffers for the rejection samplers.
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

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
    ((a as i64 * b as i64).rem_euclid(Q as i64)) as i32
}

// Map a small signed value in (-Q, Q) to its representative in [0, Q).
fn to_pos(a: i32) -> i32 {
    if a < 0 {
        a + Q
    } else {
        a
    }
}

// The centered representative of a in [0, Q), i.e. a mod +/- Q, in the range (-Q/2, Q/2].
fn center(a: i32) -> i32 {
    if a > (Q - 1) / 2 {
        a - Q
    } else {
        a
    }
}

// The infinity norm of a polynomial whose coefficients lie in [0, Q).
fn inf_norm(p: &Poly) -> i32 {
    let mut max = 0;
    for &c in p.iter() {
        let v = center(c).abs();
        if v > max {
            max = v;
        }
    }
    max
}

// Number theoretic transform tables.

// Bit reversal of the low eight bits of i.
const fn brv8(mut i: usize) -> u32 {
    let mut r = 0u32;
    let mut b = 0;
    while b < 8 {
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

// ZETAS[i] = 1753^{brv8(i)} mod Q, the twiddle factors used by the transform (FIPS 204, section 7.5).
const ZETAS: [i32; N] = {
    let mut z = [0i32; N];
    let mut i = 0;
    while i < N {
        z[i] = pow_mod(1753, brv8(i)) as i32;
        i += 1;
    }
    z
};

// In-place forward NTT (FIPS 204, Algorithm 41). Coefficients stay in [0, Q).
fn ntt(a: &mut Poly) {
    let mut k = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            k += 1;
            let zeta = ZETAS[k];
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

// In-place inverse NTT (FIPS 204, Algorithm 42). Coefficients stay in [0, Q).
fn inv_ntt(a: &mut Poly) {
    // 256^{-1} mod Q.
    const F: i32 = 8347681;
    let mut k = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            k -= 1;
            let zeta = Q - ZETAS[k];
            let mut j = start;
            while j < start + len {
                let t = a[j];
                a[j] = add_q(t, a[j + len]);
                a[j + len] = sub_q(t, a[j + len]);
                a[j + len] = mul_q(zeta, a[j + len]);
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

// Pointwise product in the NTT domain, accumulated into acc.
fn pointwise_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] = add_q(acc[i], mul_q(a[i], b[i]));
    }
}

// SHAKE helpers.

fn shake256_bytes(input: &[u8], outlen: usize) -> Vec<u8> {
    let mut out = vec![0u8; outlen];
    shake256(input, &mut out);
    out
}

// Rounding helpers (FIPS 204, section 7.4).

// Power2Round: split r in [0, Q) into (r1, r0) with r = r1 * 2^D + r0 and r0 in (-2^{D-1}, 2^{D-1}].
fn power2round(r: i32) -> (i32, i32) {
    let mut r0 = r & ((1 << D) - 1);
    if r0 > (1 << (D - 1)) {
        r0 -= 1 << D;
    }
    let r1 = (r - r0) >> D;
    (r1, r0)
}

// Decompose r in [0, Q) into (r1, r0) using 2*GAMMA2 as the modulus (FIPS 204, Algorithm 36).
fn decompose(r: i32) -> (i32, i32) {
    let mut r0 = r % (2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    if r - r0 == Q - 1 {
        return (0, r0 - 1);
    }
    let r1 = (r - r0) / (2 * GAMMA2);
    (r1, r0)
}

fn high_bits(r: i32) -> i32 {
    decompose(r).0
}

fn low_bits(r: i32) -> i32 {
    decompose(r).1
}

// MakeHint (FIPS 204, Algorithm 39): does adding z to r change the high bits.
fn make_hint(z: i32, r: i32) -> u8 {
    if high_bits(r) != high_bits(add_q(r, z)) {
        1
    } else {
        0
    }
}

// UseHint (FIPS 204, Algorithm 40): recover the high bits given the hint bit.
fn use_hint(h: u8, r: i32) -> i32 {
    let m = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose(r);
    if h == 0 {
        r1
    } else if r0 > 0 {
        (r1 + 1).rem_euclid(m)
    } else {
        (r1 - 1).rem_euclid(m)
    }
}

// Bit packing (FIPS 204, section 7.1). Coefficients are packed least significant bit first.

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

// Sampling routines (FIPS 204, section 7.3).

// RejNTTPoly (Algorithm 30): rejection sample a uniform NTT-domain polynomial from a 34-byte seed.
fn rej_ntt_poly(seed: &[u8]) -> Poly {
    let mut a = ZERO_POLY;
    let mut buflen = SHAKE128_RATE * 6;
    loop {
        let mut buf = vec![0u8; buflen];
        shake128(seed, &mut buf);
        let mut ctr = 0usize;
        let mut pos = 0usize;
        while ctr < N && pos + 3 <= buf.len() {
            let b0 = buf[pos] as i32;
            let b1 = buf[pos + 1] as i32;
            let b2 = (buf[pos + 2] & 0x7f) as i32;
            pos += 3;
            let z = b0 | (b1 << 8) | (b2 << 16);
            if z < Q {
                a[ctr] = z;
                ctr += 1;
            }
        }
        if ctr == N {
            return a;
        }
        buflen *= 2;
    }
}

// CoeffFromHalfByte for ETA = 4 (FIPS 204, Algorithm 15).
fn coeff_from_half_byte(b: u8) -> Option<i32> {
    if (b as i32) < 9 {
        Some(ETA - b as i32)
    } else {
        None
    }
}

// RejBoundedPoly (Algorithm 31): rejection sample a polynomial with coefficients in [-ETA, ETA].
fn rej_bounded_poly(seed: &[u8]) -> Poly {
    let mut a = ZERO_POLY;
    let mut buflen = SHAKE256_RATE * 5;
    loop {
        let buf = shake256_bytes(seed, buflen);
        let mut ctr = 0usize;
        let mut pos = 0usize;
        while ctr < N && pos < buf.len() {
            let b = buf[pos];
            pos += 1;
            if let Some(v) = coeff_from_half_byte(b & 0x0f) {
                a[ctr] = v;
                ctr += 1;
            }
            if ctr < N {
                if let Some(v) = coeff_from_half_byte(b >> 4) {
                    a[ctr] = v;
                    ctr += 1;
                }
            }
        }
        if ctr == N {
            return a;
        }
        buflen *= 2;
    }
}

// ExpandA (Algorithm 32): derive the k-by-l matrix A of NTT-domain polynomials from rho.
fn expand_a(rho: &[u8]) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![ZERO_POLY; L]; K];
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    for r in 0..K {
        for s in 0..L {
            seed[32] = s as u8;
            seed[33] = r as u8;
            a[r][s] = rej_ntt_poly(&seed);
        }
    }
    a
}

// ExpandS (Algorithm 33): derive the secret vectors s1 and s2 from rho_prime.
fn expand_s(rho_prime: &[u8]) -> (Vec<Poly>, Vec<Poly>) {
    let mut s1 = vec![ZERO_POLY; L];
    let mut s2 = vec![ZERO_POLY; K];
    let mut seed = [0u8; 66];
    seed[..64].copy_from_slice(rho_prime);
    for i in 0..L {
        let idx = i as u16;
        seed[64] = (idx & 0xff) as u8;
        seed[65] = (idx >> 8) as u8;
        s1[i] = rej_bounded_poly(&seed);
    }
    for i in 0..K {
        let idx = (i + L) as u16;
        seed[64] = (idx & 0xff) as u8;
        seed[65] = (idx >> 8) as u8;
        s2[i] = rej_bounded_poly(&seed);
    }
    (s1, s2)
}

// ExpandMask (Algorithm 34): derive the mask vector y from rho_prime_prime and the counter kappa.
fn expand_mask(rho_pp: &[u8], kappa: usize) -> Vec<Poly> {
    let mut y = vec![ZERO_POLY; L];
    let mut seed = [0u8; 66];
    seed[..64].copy_from_slice(rho_pp);
    for r in 0..L {
        let idx = (kappa + r) as u16;
        seed[64] = (idx & 0xff) as u8;
        seed[65] = (idx >> 8) as u8;
        let v = shake256_bytes(&seed, 32 * 20);
        let raw = unpack_bits(&v, 20);
        for i in 0..N {
            y[r][i] = to_pos(GAMMA1 - raw[i]);
        }
    }
    y
}

// SampleInBall (Algorithm 29): derive the challenge polynomial from c_tilde.
fn sample_in_ball(c_tilde: &[u8]) -> Poly {
    let mut buflen = SHAKE256_RATE * 2;
    loop {
        let buf = shake256_bytes(c_tilde, buflen);
        let mut c = ZERO_POLY;
        let mut signs: u64 = 0;
        for i in 0..8 {
            signs |= (buf[i] as u64) << (8 * i);
        }
        let mut pos = 8usize;
        let mut bit = 0usize;
        let mut failed = false;
        let mut i = N - TAU;
        while i < N {
            let mut j = 0usize;
            loop {
                if pos >= buf.len() {
                    failed = true;
                    break;
                }
                j = buf[pos] as usize;
                pos += 1;
                if j <= i {
                    break;
                }
            }
            if failed {
                break;
            }
            c[i] = c[j];
            c[j] = if (signs >> bit) & 1 == 1 { -1 } else { 1 };
            bit += 1;
            i += 1;
        }
        if !failed {
            return c;
        }
        buflen *= 2;
    }
}

// Key, signature, and message encodings (FIPS 204, section 7.2).

fn pk_encode(rho: &[u8], t1: &[Poly]) -> PublicKey {
    let mut out = Vec::with_capacity(PUBLIC_KEY_BYTES);
    out.extend_from_slice(rho);
    for poly in t1.iter() {
        pack_bits(poly, 10, &mut out);
    }
    let mut pk = [0u8; PUBLIC_KEY_BYTES];
    pk.copy_from_slice(&out);
    pk
}

fn pk_decode(pk: &PublicKey) -> ([u8; 32], Vec<Poly>) {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let mut t1 = vec![ZERO_POLY; K];
    for i in 0..K {
        let start = 32 + i * POLYT1_PACKED;
        t1[i] = unpack_bits(&pk[start..start + POLYT1_PACKED], 10);
    }
    (rho, t1)
}

fn sk_encode(
    rho: &[u8],
    key: &[u8],
    tr: &[u8],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
) -> SecretKey {
    let mut out = Vec::with_capacity(SECRET_KEY_BYTES);
    out.extend_from_slice(rho);
    out.extend_from_slice(key);
    out.extend_from_slice(tr);
    for poly in s1.iter().chain(s2.iter()) {
        let mut packed = ZERO_POLY;
        for i in 0..N {
            packed[i] = ETA - poly[i];
        }
        pack_bits(&packed, 4, &mut out);
    }
    for poly in t0.iter() {
        let mut packed = ZERO_POLY;
        for i in 0..N {
            packed[i] = (1 << (D - 1)) - poly[i];
        }
        pack_bits(&packed, 13, &mut out);
    }
    let mut sk = [0u8; SECRET_KEY_BYTES];
    sk.copy_from_slice(&out);
    sk
}

struct SecretComponents {
    rho: [u8; 32],
    key: [u8; 32],
    tr: [u8; 64],
    s1: Vec<Poly>,
    s2: Vec<Poly>,
    t0: Vec<Poly>,
}

fn sk_decode(sk: &SecretKey) -> SecretComponents {
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&sk[32..64]);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&sk[64..128]);

    let mut off = 128usize;
    let mut s1 = vec![ZERO_POLY; L];
    for poly in s1.iter_mut() {
        let raw = unpack_bits(&sk[off..off + POLYETA_PACKED], 4);
        for i in 0..N {
            poly[i] = ETA - raw[i];
        }
        off += POLYETA_PACKED;
    }
    let mut s2 = vec![ZERO_POLY; K];
    for poly in s2.iter_mut() {
        let raw = unpack_bits(&sk[off..off + POLYETA_PACKED], 4);
        for i in 0..N {
            poly[i] = ETA - raw[i];
        }
        off += POLYETA_PACKED;
    }
    let mut t0 = vec![ZERO_POLY; K];
    for poly in t0.iter_mut() {
        let raw = unpack_bits(&sk[off..off + POLYT0_PACKED], 13);
        for i in 0..N {
            poly[i] = (1 << (D - 1)) - raw[i];
        }
        off += POLYT0_PACKED;
    }
    SecretComponents {
        rho,
        key,
        tr,
        s1,
        s2,
        t0,
    }
}

// w1Encode (Algorithm 28): pack the high bits of w for the challenge hash.
fn w1_encode(w1: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(K * POLYW1_PACKED);
    for poly in w1.iter() {
        pack_bits(poly, 4, &mut out);
    }
    out
}

// HintBitPack (Algorithm 20): encode the hint as positions plus running counts.
fn hint_bit_pack(h: &[Poly]) -> Vec<u8> {
    let mut y = vec![0u8; OMEGA + K];
    let mut index = 0usize;
    for i in 0..K {
        for j in 0..N {
            if h[i][j] != 0 {
                y[index] = j as u8;
                index += 1;
            }
        }
        y[OMEGA + i] = index as u8;
    }
    y
}

// HintBitUnpack (Algorithm 21): decode the hint, returning None on any malformed encoding.
fn hint_bit_unpack(y: &[u8]) -> Option<Vec<Poly>> {
    let mut h = vec![ZERO_POLY; K];
    let mut index = 0usize;
    for i in 0..K {
        let limit = y[OMEGA + i] as usize;
        if limit < index || limit > OMEGA {
            return None;
        }
        let first = index;
        while index < limit {
            if index > first && y[index - 1] >= y[index] {
                return None;
            }
            h[i][y[index] as usize] = 1;
            index += 1;
        }
    }
    for &b in y.iter().take(OMEGA).skip(index) {
        if b != 0 {
            return None;
        }
    }
    Some(h)
}

fn sig_encode(c_tilde: &[u8], z: &[Poly], h: &[Poly]) -> Signature {
    let mut out = Vec::with_capacity(SIGNATURE_BYTES);
    out.extend_from_slice(c_tilde);
    for poly in z.iter() {
        let mut packed = ZERO_POLY;
        for i in 0..N {
            packed[i] = GAMMA1 - center(poly[i]);
        }
        pack_bits(&packed, 20, &mut out);
    }
    out.extend_from_slice(&hint_bit_pack(h));
    let mut sig = [0u8; SIGNATURE_BYTES];
    sig.copy_from_slice(&out);
    sig
}

struct DecodedSig {
    c_tilde: Vec<u8>,
    z: Vec<Poly>,
    h: Vec<Poly>,
}

fn sig_decode(sig: &Signature) -> Option<DecodedSig> {
    let c_tilde = sig[..CTILDE_BYTES].to_vec();
    let mut z = vec![ZERO_POLY; L];
    let mut off = CTILDE_BYTES;
    for poly in z.iter_mut() {
        let raw = unpack_bits(&sig[off..off + POLYZ_PACKED], 20);
        for i in 0..N {
            poly[i] = GAMMA1 - raw[i];
        }
        off += POLYZ_PACKED;
    }
    let h = hint_bit_unpack(&sig[off..off + OMEGA + K])?;
    Some(DecodedSig { c_tilde, z, h })
}

// The number of ones in a hint.
fn hint_weight(h: &[Poly]) -> usize {
    h.iter()
        .map(|poly| poly.iter().filter(|&&x| x != 0).count())
        .sum()
}

/// Generate an ML-DSA-65 key pair deterministically from a 32-byte seed
pub fn keygen(seed: &[u8; SEED_BYTES]) -> (PublicKey, SecretKey) {
    let mut h_in = Vec::with_capacity(34);
    h_in.extend_from_slice(seed);
    h_in.push(K as u8);
    h_in.push(L as u8);
    let expanded = shake256_bytes(&h_in, 128);
    let rho = &expanded[..32];
    let rho_prime = &expanded[32..96];
    let key = &expanded[96..128];

    let a = expand_a(rho);
    let (s1, s2) = expand_s(rho_prime);

    // s1_hat = NTT(s1).
    let mut s1_hat = s1.clone();
    for poly in s1_hat.iter_mut() {
        for c in poly.iter_mut() {
            *c = to_pos(*c);
        }
        ntt(poly);
    }

    // t = A * s1 + s2, then split into (t1, t0) by Power2Round.
    let mut t1 = vec![ZERO_POLY; K];
    let mut t0 = vec![ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..L {
            pointwise_acc(&mut acc, &a[i][j], &s1_hat[j]);
        }
        inv_ntt(&mut acc);
        for n in 0..N {
            let t = add_q(acc[n], to_pos(s2[i][n]));
            let (r1, r0) = power2round(t);
            t1[i][n] = r1;
            t0[i][n] = r0;
        }
    }

    let pk = pk_encode(rho, &t1);
    let tr = shake256_bytes(&pk, 64);
    let sk = sk_encode(rho, key, &tr, &s1, &s2, &t0);
    (pk, sk)
}

// The core signing loop shared by the internal and external interfaces (FIPS 204, Algorithm 7).
// mu is the 64-byte message representative; rnd is the 32-byte per-signature randomizer.
fn sign_with_mu(sk: &SecretKey, mu: &[u8], rnd: &[u8; 32]) -> Signature {
    let sc = sk_decode(sk);
    let a = expand_a(&sc.rho);

    let mut s1_hat = sc.s1.clone();
    for poly in s1_hat.iter_mut() {
        for c in poly.iter_mut() {
            *c = to_pos(*c);
        }
        ntt(poly);
    }
    let mut s2_hat = sc.s2.clone();
    for poly in s2_hat.iter_mut() {
        for c in poly.iter_mut() {
            *c = to_pos(*c);
        }
        ntt(poly);
    }
    let mut t0_hat = sc.t0.clone();
    for poly in t0_hat.iter_mut() {
        for c in poly.iter_mut() {
            *c = to_pos(*c);
        }
        ntt(poly);
    }

    // rho_prime_prime = H(K || rnd || mu, 64).
    let mut seed = Vec::with_capacity(32 + 32 + mu.len());
    seed.extend_from_slice(&sc.key);
    seed.extend_from_slice(rnd);
    seed.extend_from_slice(mu);
    let rho_pp = shake256_bytes(&seed, 64);

    let mut kappa = 0usize;
    loop {
        let y = expand_mask(&rho_pp, kappa);
        kappa += L;

        // w = A * y.
        let mut y_hat = y.clone();
        for poly in y_hat.iter_mut() {
            ntt(poly);
        }
        let mut w = vec![ZERO_POLY; K];
        let mut w1 = vec![ZERO_POLY; K];
        for i in 0..K {
            let mut acc = ZERO_POLY;
            for j in 0..L {
                pointwise_acc(&mut acc, &a[i][j], &y_hat[j]);
            }
            inv_ntt(&mut acc);
            w[i] = acc;
            for n in 0..N {
                w1[i][n] = high_bits(w[i][n]);
            }
        }

        // c_tilde = H(mu || w1Encode(w1), CTILDE_BYTES), then c = SampleInBall(c_tilde).
        let mut ch_in = Vec::with_capacity(mu.len() + K * POLYW1_PACKED);
        ch_in.extend_from_slice(mu);
        ch_in.extend_from_slice(&w1_encode(&w1));
        let c_tilde = shake256_bytes(&ch_in, CTILDE_BYTES);
        let c = sample_in_ball(&c_tilde);
        let mut c_hat = c;
        ntt(&mut c_hat);

        // z = y + c*s1.
        let mut z = vec![ZERO_POLY; L];
        for j in 0..L {
            let mut cs1 = ZERO_POLY;
            pointwise_acc(&mut cs1, &c_hat, &s1_hat[j]);
            inv_ntt(&mut cs1);
            for n in 0..N {
                z[j][n] = add_q(y[j][n], cs1[n]);
            }
        }
        let mut z_norm = 0i32;
        for poly in z.iter() {
            z_norm = z_norm.max(inf_norm(poly));
        }

        // r0 = LowBits(w - c*s2).
        let mut cs2 = vec![ZERO_POLY; K];
        let mut r0_norm = 0i32;
        for i in 0..K {
            let mut acc = ZERO_POLY;
            pointwise_acc(&mut acc, &c_hat, &s2_hat[i]);
            inv_ntt(&mut acc);
            cs2[i] = acc;
            for n in 0..N {
                let r0 = low_bits(sub_q(w[i][n], cs2[i][n]));
                r0_norm = r0_norm.max(r0.abs());
            }
        }

        if z_norm >= GAMMA1 - BETA || r0_norm >= GAMMA2 - BETA {
            continue;
        }

        // Build the hint from c*t0.
        let mut h = vec![ZERO_POLY; K];
        let mut ct0_norm = 0i32;
        for i in 0..K {
            let mut ct0 = ZERO_POLY;
            pointwise_acc(&mut ct0, &c_hat, &t0_hat[i]);
            inv_ntt(&mut ct0);
            for n in 0..N {
                ct0_norm = ct0_norm.max(center(ct0[n]).abs());
                let neg_ct0 = sub_q(0, ct0[n]);
                let r = add_q(sub_q(w[i][n], cs2[i][n]), ct0[n]);
                h[i][n] = make_hint(neg_ct0, r) as i32;
            }
        }

        if ct0_norm >= GAMMA2 || hint_weight(&h) > OMEGA {
            continue;
        }

        return sig_encode(&c_tilde, &z, &h);
    }
}

// Compute mu = H(tr || m_prime, 64).
fn compute_mu(tr: &[u8], m_prime: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(tr.len() + m_prime.len());
    buf.extend_from_slice(tr);
    buf.extend_from_slice(m_prime);
    shake256_bytes(&buf, 64)
}

/// Sign a pre-formatted message representative (FIPS 204, Algorithm 7, ML-DSA.Sign_internal).
pub fn sign_internal(sk: &SecretKey, m_prime: &[u8], rnd: &[u8; 32]) -> Signature {
    let sc = sk_decode(sk);
    let mu = compute_mu(&sc.tr, m_prime);
    sign_with_mu(sk, &mu, rnd)
}

/// Verify a pre-formatted message representative (FIPS 204, Algorithm 8, ML-DSA.Verify_internal).
pub fn verify_internal(pk: &PublicKey, m_prime: &[u8], sig: &Signature) -> bool {
    let tr = shake256_bytes(pk, 64);
    let mu = compute_mu(&tr, m_prime);
    verify_with_mu(pk, &mu, sig)
}

// The core verification routine shared by the internal and external interfaces.
fn verify_with_mu(pk: &PublicKey, mu: &[u8], sig: &Signature) -> bool {
    let decoded = match sig_decode(sig) {
        Some(d) => d,
        None => return false,
    };
    let (rho, t1) = pk_decode(pk);

    let mut z_norm = 0i32;
    for poly in decoded.z.iter() {
        for &c in poly.iter() {
            z_norm = z_norm.max(c.abs());
        }
    }
    if z_norm >= GAMMA1 - BETA {
        return false;
    }

    let a = expand_a(&rho);
    let c = sample_in_ball(&decoded.c_tilde);
    let mut c_hat = c;
    ntt(&mut c_hat);

    // z_hat = NTT(z) with z coefficients mapped into [0, Q).
    let mut z_hat = decoded.z.clone();
    for poly in z_hat.iter_mut() {
        for c in poly.iter_mut() {
            *c = to_pos(*c);
        }
        ntt(poly);
    }

    // t1_hat = NTT(t1 * 2^D).
    let mut t1_hat = t1.clone();
    for poly in t1_hat.iter_mut() {
        for c in poly.iter_mut() {
            *c = *c << D;
        }
        ntt(poly);
    }

    // w_approx = A*z - c*t1*2^D, then w1 = UseHint(h, w_approx).
    let mut w1 = vec![ZERO_POLY; K];
    for i in 0..K {
        let mut acc = ZERO_POLY;
        for j in 0..L {
            pointwise_acc(&mut acc, &a[i][j], &z_hat[j]);
        }
        let mut ct1 = ZERO_POLY;
        pointwise_acc(&mut ct1, &c_hat, &t1_hat[i]);
        for n in 0..N {
            acc[n] = sub_q(acc[n], ct1[n]);
        }
        inv_ntt(&mut acc);
        for n in 0..N {
            w1[i][n] = use_hint(decoded.h[i][n] as u8, acc[n]);
        }
    }

    let mut ch_in = Vec::with_capacity(mu.len() + K * POLYW1_PACKED);
    ch_in.extend_from_slice(mu);
    ch_in.extend_from_slice(&w1_encode(&w1));
    let c_tilde = shake256_bytes(&ch_in, CTILDE_BYTES);

    c_tilde == decoded.c_tilde
}

// Format the external message representative M' = 0x00 || len(ctx) || ctx || message (pure variant).
fn format_message(context: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    if context.len() > 255 {
        return None;
    }
    let mut m = Vec::with_capacity(2 + context.len() + message.len());
    m.push(0x00);
    m.push(context.len() as u8);
    m.extend_from_slice(context);
    m.extend_from_slice(message);
    Some(m)
}

/// Sign a message with an application context string (FIPS 204, Algorithm 2, ML-DSA.Sign, pure).
pub fn sign(sk: &SecretKey, message: &[u8], context: &[u8], rnd: &[u8; 32]) -> Option<Signature> {
    let m_prime = format_message(context, message)?;
    Some(sign_internal(sk, &m_prime, rnd))
}

/// Verify a message and its context string (FIPS 204, Algorithm 3, ML-DSA.Verify, pure).
pub fn verify(pk: &PublicKey, message: &[u8], signature: &Signature, context: &[u8]) -> bool {
    let m_prime = match format_message(context, message) {
        Some(m) => m,
        None => return false,
    };
    verify_internal(pk, &m_prime, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn hex(s: &str) -> Vec<u8> {
        if s == "-" {
            return Vec::new();
        }
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
        path.push("vectors/ml-dsa");
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
        let recs = records("keygen_65.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let seed = seed32(&hex(&r[0]));
            let want_pk = hex(&r[1]);
            let want_sk = hex(&r[2]);
            let (pk, sk) = keygen(&seed);
            assert_eq!(&pk[..], &want_pk[..], "public key mismatch");
            assert_eq!(&sk[..], &want_sk[..], "secret key mismatch");
        }
    }

    #[test]
    fn sign_internal_matches_official_vectors() {
        let recs = records("siggen_internal_65.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let message = hex(&r[0]);
            let rnd = seed32(&hex(&r[1]));
            let sk = as_array::<SECRET_KEY_BYTES>(&hex(&r[2]));
            let want_sig = hex(&r[3]);
            let sig = sign_internal(&sk, &message, &rnd);
            assert_eq!(&sig[..], &want_sig[..], "signature mismatch");
        }
    }

    #[test]
    fn sign_external_matches_official_vectors() {
        let recs = records("siggen_external_65.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let message = hex(&r[0]);
            let context = hex(&r[1]);
            let rnd = seed32(&hex(&r[2]));
            let sk = as_array::<SECRET_KEY_BYTES>(&hex(&r[3]));
            let want_sig = hex(&r[4]);
            let sig = sign(&sk, &message, &context, &rnd).unwrap();
            assert_eq!(&sig[..], &want_sig[..], "signature mismatch");
        }
    }

    #[test]
    fn verify_external_matches_official_vectors() {
        let recs = records("sigver_external_65.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let expected = r[0] == "1";
            let pk = as_array::<PUBLIC_KEY_BYTES>(&hex(&r[1]));
            let message = hex(&r[2]);
            let context = hex(&r[3]);
            let sig = as_array::<SIGNATURE_BYTES>(&hex(&r[4]));
            assert_eq!(verify(&pk, &message, &sig, &context), expected);
        }
    }

    #[test]
    fn verify_internal_matches_official_vectors() {
        let recs = records("sigver_internal_65.txt");
        assert!(!recs.is_empty());
        for r in &recs {
            let expected = r[0] == "1";
            let pk = as_array::<PUBLIC_KEY_BYTES>(&hex(&r[1]));
            let message = hex(&r[2]);
            let sig = as_array::<SIGNATURE_BYTES>(&hex(&r[3]));
            assert_eq!(verify_internal(&pk, &message, &sig), expected);
        }
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let seed = [7u8; 32];
        let (pk, sk) = keygen(&seed);
        let message = b"quantova ml-dsa round trip";
        let context = b"ctx";
        let rnd = [0u8; 32];
        let sig = sign(&sk, message, context, &rnd).unwrap();
        assert!(verify(&pk, message, &sig, context));
        assert!(!verify(&pk, b"other message", &sig, context));
        assert!(!verify(&pk, message, &sig, b"other ctx"));
    }
}
