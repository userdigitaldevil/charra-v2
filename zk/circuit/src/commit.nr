//! Poseidon commitment to a file path -- the "cleaned" value that replaces
//! the real path in log_r.
//!
//! The circuit *returns* these rather than checking them against an input.
//! That is deliberate: the RP is what produces log_r, so the proof should
//! be the thing that decides what the cleaned paths are. It also keeps any
//! second Poseidon implementation out of the surrounding C and Python --
//! matching Noir's exact parameters (rate, rounds, MDS matrix, round
//! constants) from another language is a genuine multi-day trap, and
//! nothing here needs to.
//!
//! The Verifier's check is therefore: the commitments in log_r are exactly
//! the proof's public outputs, in order.

use poseidon::poseidon2::Poseidon2;

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
    let mut input: [Field; LIMBS + 2] = [0; LIMBS + 2];

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

    Poseidon2::hash(input, LIMBS + 2)
}
