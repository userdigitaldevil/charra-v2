//! CHARRA ZK redaction circuit -- see ZK_REDACTION.md.
//!
//! The statement, in one sentence: *I know a set of file paths whose IMA
//! measurements produce the PCR digest the Attester's TPM signed, and the
//! values I am publishing are Poseidon commitments to exactly those paths.*
//!
//! For every entry the circuit rebuilds the ima-ng template_data record
//! from a private path and a public file hash, hashes it, and folds the
//! result into a PCR chain exactly as the TPM did -- then checks the
//! composite against pcrdigest_a, straight out of the signed quote.
//!
//! That assertion is what makes the redaction trustworthy. A prover that
//! substitutes a path, reorders entries, drops or adds one, or lies about
//! a file hash cannot satisfy it, because every one of those changes the
//! chain. And because the commitments are computed from the same private
//! `paths` array the chain consumes, the published values cannot describe
//! a different set of files than the ones that were actually measured.
//!
//! Verified against real TPM output: 33 entries from a live Attester
//! reproduce pcrdigest_a = 2b24614b17f7ac48f5081665fbc1bdc6091887c4f327
//! 2492b18f22d592f2509b in-circuit.
//!
//! `nargo execute` solves the witness only if every assertion holds, so it
//! serves as a full functional test with no proving backend involved.

mod sha256_var;
mod template;
mod commit;

/// Entries in the log. Fixed at compile time -- a circuit has no runtime
/// loop bound -- so this circuit is specific to a 33-entry log. Handling a
/// variable count needs padding with dummy entries plus a real/dummy
/// selector; see the PoC boundary note in ZK_REDACTION.md.
global N: u32 = 33;

fn main(
    // Private: the file paths the redaction exists to hide. Each is the
    // n-ng field -- path plus its trailing NUL -- zero-padded.
    paths: [[u8; 136]; N],
    path_lens: [u32; N],
    // Private: blinding factors. Without them the commitments would be
    // brute-forceable -- the space of plausible system paths is small
    // enough to enumerate. The RP must draw these from a CSPRNG and must
    // not reuse one across entries or across runs.
    salts: [Field; N],
    // Public: the Verifier needs these to run its own blacklist check, and
    // the pcrdigest_a assertion below forces them to be honest -- a lie
    // here changes template_data and breaks the chain.
    file_hashes: pub [[u8; 32]; N],
    // Public: the eight non-IMA PCRs the quote covers. Never extended by an
    // IMA log, so all-zero in this setup -- but taken as input rather than
    // assumed, so the circuit is not silently specific to that.
    other_pcrs: pub [[u8; 32]; 8],
    // Public: straight out of the Attester's TPM-signed quote.
    pcrdigest_a: pub [u8; 32],
) -> pub [Field; N] {
    let mut pcr: [u8; 32] = [0; 32];
    let mut cleaned: [Field; N] = [0; N];

    for i in 0..N {
        // --- rebuild and replay -------------------------------------------
        // charra_pcr_extend(): PCR = SHA256(PCR || template_digest), from an
        // all-zero start. The 64-byte extend input is a fixed length, so the
        // library digest() serves; only template_data needs sha256_var.
        let (td, td_len) = template::build(file_hashes[i], paths[i], path_lens[i]);
        let td_digest = sha256_var::hash(td, td_len);

        let mut ext: [u8; 64] = [0; 64];
        for j in 0..32 {
            ext[j] = pcr[j];
            ext[32 + j] = td_digest[j];
        }
        pcr = sha256::digest(ext);

        // --- commit -------------------------------------------------------
        // Same `paths[i]` the chain just consumed, which is the whole point:
        // the published commitment and the replayed measurement cannot
        // disagree about what the path was.
        cleaned[i] = commit::commit(paths[i], path_lens[i], salts[i]);
    }

    // --- composite over the quoted selection ------------------------------
    // hash_sha256_array(): SHA-256 over every selected PCR's value,
    // concatenated in ascending index order. PCR 10 is last because it is
    // the highest index in {0..7, 10}.
    let mut composite: [u8; 288] = [0; 288];
    for k in 0..8 {
        for j in 0..32 {
            composite[k * 32 + j] = other_pcrs[k][j];
        }
    }
    for j in 0..32 {
        composite[256 + j] = pcr[j];
    }

    assert(sha256::digest(composite) == pcrdigest_a, "pcrdigest_a mismatch");

    cleaned
}
