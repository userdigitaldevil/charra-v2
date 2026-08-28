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
//!     off  0..3    u32le d_len = 39        (7-byte alg name + 32-byte digest)
//!     off  4..10   "sha256\0"              (alg name INCLUDING its NUL)
//!     off 11..42   file_hash               (32 bytes)
//!     off 43..46   u32le n_len             (path length INCLUDING its NUL)
//!     off 47..     path ‖ "\0"             (n_len bytes)
//!
//! so template_data_len = 47 + n_len. Note both NULs: the algorithm name's
//! and the path's are inside the hashed bytes, and omitting either shifts
//! every following byte and changes the digest.

/// Longest path (including its NUL) the circuit accepts. Chosen so that
/// 47 + MAX_PATH lands exactly on sha256_var's MAX_MSG of 183 -- i.e. this
/// is as large as it can be without a fourth SHA-256 block. The log's real
/// worst case is 77, so there is ample headroom.
global MAX_PATH: u32 = 136;

/// 4 (d_len) + 39 (d-ng field) + 4 (n_len).
global HEADER_LEN: u32 = 47;

/// Must match sha256_var::MAX_BYTES. Kept as a literal rather than imported
/// so the two modules do not have to agree on global visibility; if you
/// change one, change the other.
global BUF_LEN: u32 = 192;

/// Build the record, returning the buffer and the true length of the bytes
/// within it. Everything past that length is zero and is ignored by
/// sha256_var.
pub fn build(
    file_hash: [u8; 32],
    path: [u8; MAX_PATH],
    path_len: u32,
) -> ([u8; BUF_LEN], u32) {
    assert(path_len <= MAX_PATH, "path too long");

    let mut td: [u8; BUF_LEN] = [0; BUF_LEN];

    // d_len = 39, little-endian. Constant, so only the low byte is non-zero.
    td[0] = 39;

    // "sha256\0" -- the algorithm name and its terminator.
    td[4] = 0x73; // s
    td[5] = 0x68; // h
    td[6] = 0x61; // a
    td[7] = 0x32; // 2
    td[8] = 0x35; // 5
    td[9] = 0x36; // 6
    td[10] = 0x00;

    for i in 0..32 {
        td[11 + i] = file_hash[i];
    }

    // n_len, little-endian. MAX_PATH is 136, so two bytes always suffice.
    td[43] = (path_len & 0xff) as u8;
    td[44] = ((path_len >> 8) & 0xff) as u8;

    // The path is copied in full, not just its first path_len bytes: the
    // caller zero-pads it, and sha256_var ignores everything past the
    // length anyway. Copying unconditionally avoids a comparison per byte.
    for i in 0..MAX_PATH {
        td[HEADER_LEN + i] = path[i];
    }

    (td, HEADER_LEN + path_len)
}
