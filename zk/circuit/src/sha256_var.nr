//! Variable-length SHA-256, built on the `sha256_compression` blackbox.
//!
//! Why this exists: noir-lang/sha256 v0.3.0 exposes only `digest()`, which
//! hashes exactly N bytes for a *compile-time* N. Our `template_data` runs
//! from 62 to 124 bytes and straddles a block boundary -- 2 blocks below
//! 120, 3 at or above -- so no single N serves every entry, and a circuit
//! cannot branch on a runtime length to choose one.
//!
//! So we do what a `sha256_var` would: pad into a MAX_BLOCKS-sized buffer,
//! run the compression function over every block, and select the
//! intermediate state at the block count the real length implies. The cost
//! is MAX_BLOCKS compressions for every message regardless of its actual
//! length -- which is why MAX_BLOCKS is what drives circuit size, and the
//! true length costs nothing and therefore need not be revealed.
//!
//! MAX_BLOCKS = 4 covers messages up to 247 bytes. Three (183) was not
//! enough once the circuit began rebuilding the FULL path: the longest entry
//! in the reference log is a 136-byte path, so its n-ng field is 137 and its
//! template_data 185. The fourth block costs about a third more SHA gates
//! per entry and is what that one entry buys.

global MAX_BLOCKS: u32 = 4;
/// MAX_BLOCKS * 64.
global MAX_BYTES: u32 = 256;
/// Longest message that still fits: the 1-byte 0x80 and the 8-byte length
/// field must land inside the same MAX_BLOCKS blocks.
global MAX_MSG: u32 = 247;

/// SHA-256 initial state (FIPS 180-4 §5.3.3).
global IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 of the first `msg_len` bytes of `msg`.
///
/// Bytes at or past `msg_len` are ignored -- the caller may leave anything
/// there. `msg_len` may be private; nothing about the cost depends on it.
pub fn hash(msg: [u8; MAX_BYTES], msg_len: u32) -> [u8; 32] {
    assert(msg_len <= MAX_MSG, "message too long for MAX_BLOCKS");

    // --- pad ---------------------------------------------------------
    // Message, then the mandatory 0x80, then zeros. The trailing 8-byte
    // length field is placed further down, once we know the block count.
    // Written as one pass with a comparison per byte rather than a
    // dynamic-index write, which keeps every array index compile-time.
    let mut buf: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..MAX_BYTES {
        if i < msg_len {
            buf[i] = msg[i];
        } else if i == msg_len {
            buf[i] = 0x80;
        }
    }

    // ceil((msg_len + 9) / 64): the 0x80 byte plus the 64-bit length must
    // fit alongside the message.
    let nblocks: u32 = (msg_len + 9 + 63) / 64;

    // Big-endian 64-bit bit length. Only the low two bytes can ever be
    // non-zero: the assert above bounds msg_len at MAX_MSG (247), so
    // bitlen <= 1976. Writing just those two, rather than shifting a u64
    // eight times, keeps everything in u32 -- and stays correct for any
    // MAX_MSG below 8192.
    let bitlen: u32 = msg_len * 8;
    let mut lenb: [u8; 8] = [0; 8];
    lenb[6] = ((bitlen >> 8) & 0xff) as u8;
    lenb[7] = (bitlen & 0xff) as u8;

    // The length field's position depends on the block count, so write it
    // at whichever of the four candidate offsets applies. The other three
    // writes are predicated off. Offsets are the last 8 bytes of block
    // 1, 2, 3 and 4 respectively.
    //
    // Every case MAX_BLOCKS allows must appear here. Raising MAX_BLOCKS
    // without adding its case leaves a message of that size with no length
    // field at all -- it still hashes, just not to SHA-256, and the only
    // symptom is an unexplained pcrdigest_a mismatch much later.
    for k in 0..8 {
        let b = lenb[k];
        if nblocks == 1 {
            buf[56 + k] = b;
        }
        if nblocks == 2 {
            buf[120 + k] = b;
        }
        if nblocks == 3 {
            buf[184 + k] = b;
        }
        if nblocks == 4 {
            buf[248 + k] = b;
        }
    }

    // --- compress ----------------------------------------------------
    // Every block is compressed unconditionally; we keep the state after
    // each so the right one can be selected below. Compressing only
    // `nblocks` blocks is not an option -- a circuit has no runtime loop
    // bound.
    let mut state: [u32; 8] = IV;
    let mut after_1: [u32; 8] = IV;
    let mut after_2: [u32; 8] = IV;
    let mut after_3: [u32; 8] = IV;
    let mut after_4: [u32; 8] = IV;

    for b in 0..MAX_BLOCKS {
        let mut w: [u32; 16] = [0; 16];
        for j in 0..16 {
            let o: u32 = b * 64 + j * 4;
            w[j] = ((buf[o] as u32) << 24)
                 | ((buf[o + 1] as u32) << 16)
                 | ((buf[o + 2] as u32) << 8)
                 | (buf[o + 3] as u32);
        }
        state = std::hash::sha256_compression(w, state);
        if b == 0 {
            after_1 = state;
        }
        if b == 1 {
            after_2 = state;
        }
        if b == 2 {
            after_3 = state;
        }
        if b == 3 {
            after_4 = state;
        }
    }

    let mut out_state: [u32; 8] = after_4;
    if nblocks == 1 {
        out_state = after_1;
    }
    if nblocks == 2 {
        out_state = after_2;
    }
    if nblocks == 3 {
        out_state = after_3;
    }

    // --- serialise ---------------------------------------------------
    let mut out: [u8; 32] = [0; 32];
    for i in 0..8 {
        let v = out_state[i];
        out[i * 4] = ((v >> 24) & 0xff) as u8;
        out[i * 4 + 1] = ((v >> 16) & 0xff) as u8;
        out[i * 4 + 2] = ((v >> 8) & 0xff) as u8;
        out[i * 4 + 3] = (v & 0xff) as u8;
    }
    out
}

// --- tests ---------------------------------------------------------------
// Known-good vectors from Python's hashlib, one per block count including
// both boundary lengths. Run with `nargo test`; these need no Prover.toml
// and no proving backend, so a failure here is unambiguously our padding
// logic rather than anything downstream.

#[test]
fn test_one_block_abc() {
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    m[0] = 0x61; // 'a'
    m[1] = 0x62; // 'b'
    m[2] = 0x63; // 'c'
    let expect: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    assert(hash(m, 3) == expect);
}

#[test]
fn test_two_blocks_62() {
    // 62 bytes of 0x41 -- our shortest real template_data length.
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..62 {
        m[i] = 0x41;
    }
    let expect: [u8; 32] = [
        0x5a, 0x2a, 0xaf, 0xca, 0xcb, 0x98, 0x28, 0xe4,
        0x1f, 0xb7, 0xc8, 0xf8, 0x09, 0x89, 0x52, 0x63,
        0x86, 0x45, 0x87, 0x4b, 0x3a, 0x8c, 0xa4, 0x5d,
        0x25, 0x23, 0xfb, 0x2d, 0x5f, 0xc7, 0x16, 0x6d,
    ];
    assert(hash(m, 62) == expect);
}

#[test]
fn test_two_blocks_boundary_119() {
    // 119 is the largest message that still fits in two blocks.
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..119 {
        m[i] = 0x43;
    }
    let expect: [u8; 32] = [
        0x32, 0x34, 0xd2, 0x9b, 0x64, 0x6e, 0xd7, 0xa2,
        0x07, 0x39, 0xd0, 0x85, 0xe7, 0x57, 0xdd, 0x42,
        0x3f, 0x9d, 0x59, 0x8a, 0xb7, 0x86, 0x21, 0x92,
        0x39, 0xb3, 0xa0, 0x97, 0x16, 0x5a, 0x4d, 0x48,
    ];
    assert(hash(m, 119) == expect);
}

#[test]
fn test_three_blocks_124() {
    // 124 bytes -- our longest real template_data, and the first length
    // that spills into a third block.
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..124 {
        m[i] = 0x42;
    }
    let expect: [u8; 32] = [
        0x1d, 0xaa, 0x4b, 0x86, 0x6a, 0xa3, 0x4f, 0xb1,
        0x56, 0x9c, 0x30, 0x11, 0x62, 0x61, 0x12, 0x0a,
        0xa8, 0xd6, 0x11, 0x1b, 0x2e, 0x98, 0x5f, 0x60,
        0xa4, 0x1e, 0xb2, 0x61, 0x53, 0x49, 0xb2, 0xc8,
    ];
    assert(hash(m, 124) == expect);
}

#[test]
fn test_three_blocks_boundary_183() {
    // MAX_MSG: the largest message MAX_BLOCKS can hold.
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..183 {
        m[i] = 0x44;
    }
    let expect: [u8; 32] = [
        0xce, 0x23, 0x05, 0xce, 0xc1, 0x07, 0x5b, 0x3d,
        0xa1, 0x4f, 0x6a, 0xfb, 0x4c, 0x2e, 0xa7, 0x40,
        0x93, 0xb4, 0x9b, 0xf4, 0x58, 0x9c, 0x6e, 0x99,
        0xa6, 0x28, 0x07, 0xad, 0x0a, 0x0e, 0x76, 0xd8,
    ];
    assert(hash(m, 183) == expect);
}

#[test]
fn test_ignores_bytes_past_the_length() {
    // Garbage past msg_len must not affect the result -- the caller is
    // allowed to leave anything there, and the real prover will.
    let mut clean: [u8; MAX_BYTES] = [0; MAX_BYTES];
    let mut dirty: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..62 {
        clean[i] = 0x41;
        dirty[i] = 0x41;
    }
    for i in 62..MAX_BYTES {
        dirty[i] = 0xff;
    }
    assert(hash(clean, 62) == hash(dirty, 62));
}

#[test]
fn test_four_blocks_185() {
    // 185 bytes -- the longest real template_data once the circuit rebuilds
    // the FULL path: a 136-byte path gives a 137-byte n-ng field and
    // 48 + 137 = 185. This is the length that forced MAX_BLOCKS to 4, and
    // the case whose missing length-field offset made every 4-block hash
    // silently wrong.
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..185 {
        m[i] = 0x42;
    }
    let expect: [u8; 32] = [
        0x0c, 0x7a, 0xc4, 0x3e, 0x14, 0x54, 0x62, 0x5e,
        0xed, 0x3e, 0x4a, 0xda, 0xca, 0x1b, 0x20, 0xd3,
        0x75, 0xa2, 0x0c, 0xe5, 0x9b, 0xdb, 0x7b, 0x7c,
        0xe4, 0x5e, 0xea, 0xfb, 0x5d, 0xaa, 0x4a, 0xf5,
    ];
    assert(hash(m, 185) == expect);
}

#[test]
fn test_four_blocks_boundary_247() {
    // MAX_MSG: the largest message MAX_BLOCKS = 4 can hold.
    let mut m: [u8; MAX_BYTES] = [0; MAX_BYTES];
    for i in 0..247 {
        m[i] = 0x44;
    }
    let expect: [u8; 32] = [
        0xd5, 0xe4, 0x3f, 0x2b, 0xcc, 0xa8, 0x67, 0xf1,
        0x5d, 0xbf, 0x1d, 0xaf, 0x51, 0x93, 0x92, 0xae,
        0xa2, 0xe8, 0x8f, 0x00, 0x3d, 0x24, 0x5e, 0x0f,
        0xa5, 0x07, 0x19, 0xf1, 0x32, 0x42, 0x9d, 0x66,
    ];
    assert(hash(m, 247) == expect);
}
