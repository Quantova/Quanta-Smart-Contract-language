//! Hash based post quantum VRF (SHA-3/SHAKE). Backs validator committee sampling in QORUS and the

use crate::sha3::shake256;
use crate::slh_dsa;

/// Secret key length in bytes (the SLH-DSA secret key).
pub const SECRET_KEY_BYTES: usize = slh_dsa::SECRET_KEY_BYTES;
/// Public key length in bytes (the SLH-DSA public key).
pub const PUBLIC_KEY_BYTES: usize = slh_dsa::PUBLIC_KEY_BYTES;
/// Proof length in bytes (one SLH-DSA signature).
pub const PROOF_BYTES: usize = slh_dsa::SIGNATURE_BYTES;
/// Output length in bytes (fixed SHAKE256 output).
pub const OUTPUT_BYTES: usize = 32;

// Length of a single SLH-DSA seed. The secret key holds four seed-sized fields
// (SK.seed, SK.prf, PK.seed, PK.root), so one seed is a quarter of the secret key.
const SEED_BYTES: usize = slh_dsa::SECRET_KEY_BYTES / 4;

// The VRF output is a fixed-length SHAKE256 digest of the proof.
fn output_from_proof(proof: &[u8; PROOF_BYTES]) -> [u8; OUTPUT_BYTES] {
    let mut output = [0u8; OUTPUT_BYTES];
    shake256(proof, &mut output);
    output
}

/// Generate a VRF key pair from a caller-supplied seed.
pub fn keygen(seed: &[u8]) -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
    let mut expanded = [0u8; 3 * SEED_BYTES];
    shake256(seed, &mut expanded);

    let mut sk_seed = [0u8; SEED_BYTES];
    let mut sk_prf = [0u8; SEED_BYTES];
    let mut pk_seed = [0u8; SEED_BYTES];
    sk_seed.copy_from_slice(&expanded[..SEED_BYTES]);
    sk_prf.copy_from_slice(&expanded[SEED_BYTES..2 * SEED_BYTES]);
    pk_seed.copy_from_slice(&expanded[2 * SEED_BYTES..]);

    slh_dsa::keygen(&sk_seed, &sk_prf, &pk_seed)
}

/// Evaluate the VRF on `input` with the secret key.
pub fn prove(sk: &[u8; SECRET_KEY_BYTES], input: &[u8]) -> ([u8; OUTPUT_BYTES], [u8; PROOF_BYTES]) {
    let mut addrnd = [0u8; SEED_BYTES];
    addrnd.copy_from_slice(&sk[2 * SEED_BYTES..3 * SEED_BYTES]);

    let proof = slh_dsa::sign_internal(sk, input, &addrnd);
    let output = output_from_proof(&proof);
    (output, proof)
}

/// Verify a VRF output and proof for `input` under the public key.
pub fn verify(
    pk: &[u8; PUBLIC_KEY_BYTES],
    input: &[u8],
    output: &[u8; OUTPUT_BYTES],
    proof: &[u8; PROOF_BYTES],
) -> bool {
    if !slh_dsa::verify_internal(pk, input, proof) {
        return false;
    }
    output_from_proof(proof) == *output
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed key pair for the tests.
    fn key_pair() -> ([u8; SECRET_KEY_BYTES], [u8; PUBLIC_KEY_BYTES]) {
        keygen(b"quantova vrf test seed")
    }

    #[test]
    fn verify_accepts_valid_output_and_proof() {
        let (sk, pk) = key_pair();
        let input = b"committee sampling input";
        let (output, proof) = prove(&sk, input);
        assert!(verify(&pk, input, &output, &proof));
    }

    #[test]
    fn output_is_deterministic() {
        let (sk, _pk) = key_pair();
        let input = b"the same input every time";
        let (output_a, proof_a) = prove(&sk, input);
        let (output_b, proof_b) = prove(&sk, input);
        assert_eq!(output_a, output_b);
        assert_eq!(&proof_a[..], &proof_b[..]);
    }

    #[test]
    fn verify_rejects_wrong_output() {
        let (sk, pk) = key_pair();
        let input = b"an input";
        let (mut output, proof) = prove(&sk, input);
        output[0] ^= 1;
        assert!(!verify(&pk, input, &output, &proof));
    }

    #[test]
    fn verify_rejects_wrong_proof() {
        let (sk, pk) = key_pair();
        let input = b"an input";
        let (output, mut proof) = prove(&sk, input);
        proof[0] ^= 1;
        assert!(!verify(&pk, input, &output, &proof));
    }

    #[test]
    fn verify_rejects_wrong_input() {
        let (sk, pk) = key_pair();
        let (output, proof) = prove(&sk, b"the real input");
        assert!(!verify(&pk, b"a different input", &output, &proof));
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let (sk, _pk) = key_pair();
        let (output_a, _) = prove(&sk, b"input one");
        let (output_b, _) = prove(&sk, b"input two");
        assert_ne!(output_a, output_b);
    }
}
