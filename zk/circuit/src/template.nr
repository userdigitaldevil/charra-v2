//! Reconstruct an `ima-ng` template_data record in-circuit.
//!
//! Until now the circuit was handed finished `template_data` bytes, which
//! proved our SHA-256 but not that we can *build* the record. That matters:
//! in the real proof the path is a private witness, and the whole argument
//! rests on the RP being unable to feed in a path that is not the one the
//! Attester measured. So the layout has to be reproduced exactly, from the
//! path and the file hash alone.
//!
//! Layout, from attester_ima_log.c's build_ima_ng_template_data() and
//! frozen in ZK_REDACTION.md:
//!
//!     off  0..3    u32le d_len = 40        (8-byte alg prefix + 32-byte digest)
//!     off  4..11   "sha256:\0"             (alg name, its COLON, and the NUL)
//!     off 12..43   file_hash               (32 bytes)
//!     off 44..47   u32le n_len             (path length INCLUDING its NUL)
//!     off 48..     path ‖ "\0"             (n_len bytes)
//!
//! so template_data_len = 48 + n_len. Note all three of the colon and the
//! two NULs: the algorithm prefix, its terminator and the path's are inside
//! the hashed bytes, and omitting any of them shifts every following byte
//! and changes the digest.
//!
//! The prefix is EIGHT bytes, not seven -- the kernel writes "sha256:" NUL,
//! and CHARRA_IMA_ALGO_PREFIX_LEN in charra_event_log.h agrees. Building it
//! seven bytes wide costs nothing here and fails much later, as an
//! unexplained pcrdigest_a mismatch, because every byte after the alg name
//! lands one position early.

/// Width of the rejoined n-ng field this module hashes: dir + '/' + base +
/// NUL. Not the same thing as charra_poseidon.h's CHARRA_POSEIDON_MAX_PATH
/// (136), which sizes the DIRECTORY the commitment pads -- the rejoined path
/// is necessarily longer. The reference log's longest is 137 (a 136-byte
/// path plus its NUL); 144 leaves a little room without a fifth block.
global MAX_PATH: u32 = 144;

/// The largest n-ng field that still fits sha256_var's four blocks:
/// MAX_MSG (247) - HEADER_LEN (48).
global MAX_PATH_HASHABLE: u32 = 199;

/// 4 (d_len) + 40 (d-ng field) + 4 (n_len).
global HEADER_LEN: u32 = 48;

/// Must match sha256_var::MAX_BYTES. Kept as a literal rather than imported
/// so the two modules do not have to agree on global visibility; if you
/// change one, change the other.
global BUF_LEN: u32 = 256;

/// Build the record, returning the buffer and the true length of the bytes
/// within it. Everything past that length is zero and is ignored by
/// sha256_var.
pub fn build(
    file_hash: [u8; 32],
    path: [u8; MAX_PATH],
    path_len: u32,
) -> ([u8; BUF_LEN], u32) {
    assert(path_len <= MAX_PATH_HASHABLE, "path too long");

    let mut td: [u8; BUF_LEN] = [0; BUF_LEN];

    // d_len = 40, little-endian. Constant, so only the low byte is non-zero.
    td[0] = 40;

    // "sha256:\0" -- the algorithm name, its colon, and the terminator.
    td[4] = 0x73; // s
    td[5] = 0x68; // h
    td[6] = 0x61; // a
    td[7] = 0x32; // 2
    td[8] = 0x35; // 5
    td[9] = 0x36; // 6
    td[10] = 0x3a; // :
    td[11] = 0x00;

    for i in 0..32 {
        td[12 + i] = file_hash[i];
    }

    // n_len, little-endian. MAX_PATH is 136, so two bytes always suffice.
    td[44] = (path_len & 0xff) as u8;
    td[45] = ((path_len >> 8) & 0xff) as u8;

    // The path is copied in full, not just its first path_len bytes: the
    // caller zero-pads it, and sha256_var ignores everything past the
    // length anyway. Copying unconditionally avoids a comparison per byte.
    for i in 0..MAX_PATH {
        td[HEADER_LEN + i] = path[i];
    }

    (td, HEADER_LEN + path_len)
}
