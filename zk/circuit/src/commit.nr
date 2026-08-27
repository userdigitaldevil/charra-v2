//! Poseidon commitment to a file path -- the "cleaned" value that replaces
//! the real path in log_r.
//!
//! The RP computes these itself, in C, and puts them in log_r; the circuit
//! checks them. That requires a C Poseidon that agrees with this one
//! exactly, which is why the hash here is **Poseidon1 over BN254**, not
//! Poseidon2.
//!
//! The difference matters. Poseidon2::hash delegates its permutation to
//! std::hash::poseidon2_permutation, a *blackbox* -- the round constants
//! live in barretenberg's C++, not in any Noir source we can read. Poseidon1
//! for BN254 is ordinary Noir: constants and MDS matrix sit in
//! poseidon/bn254/consts.nr, and its header states it is consistent with
//! iden3/circomlib, which is the most widely reimplemented and
//! cross-checked Poseidon there is.
//!
//! x5_8 config: t = 8, 8 full rounds, 64 partial rounds, alpha = 5.
//! hash_7 is exactly our arity: 5 path limbs, path_len, salt.

use poseidon::poseidon::bn254::hash_7;

/// A BN254 field element holds 254 bits, so 31 bytes always fit with room
/// to spare. 5 limbs cover MAX_PATH's 136 bytes (155 capacity).
global LIMBS: u32 = 5;
global BYTES_PER_LIMB: u32 = 31;
/// Must match template::MAX_PATH.
global PATH_BYTES: u32 = 136;

/// Commit to `path` under `salt`.
///
/// `path_len` is folded in as well. Without it a path and the same path
/// with its trailing NUL dropped would pack to identical bytes (the buffer
/// is zero-padded either way) and collide. The PCR chain already pins the
/// true length, so this is not closing an attack so much as making the
/// commitment mean exactly one thing on its own.
pub fn commit(path: [u8; PATH_BYTES], path_len: u32, salt: Field) -> Field {
    let mut input: [Field; 7] = [0; 7];  // LIMBS + 2, spelled out for hash_7

    for l in 0..LIMBS {
        let mut acc: Field = 0;
        for j in 0..BYTES_PER_LIMB {
            let idx = l * BYTES_PER_LIMB + j;
            // Comptime bound: the last limb is only partly used.
            if idx < PATH_BYTES {
                acc = acc * 256 + path[idx] as Field;
            }
        }
        input[l] = acc;
    }

    input[LIMBS] = path_len as Field;
    input[LIMBS + 1] = salt;

    hash_7(input)
}
