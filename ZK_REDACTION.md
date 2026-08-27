# Zero-knowledge log redaction

Replacing the simulated TEE with an actual proof.

Status: **Phase 0.** The TEE mechanism has been deleted (see "What this
commit removed"); nothing has replaced it yet, so `/appraise` currently has
no check at all that `log_r`'s cleaned paths relate to what the Attester
measured. That gap is deliberate and temporary.

---

## 1. What this replaces, and why

The redaction pipeline hashes every measured file path out of the log
before a Verifier sees it. Two questions follow, and only one of them has
ever been answered:

- *Did the RP redact honestly?* — i.e. are the cleaned paths in `log_r`
  commitments to the paths the Attester actually measured, or did the RP
  invent them?
- *Did the RP run the appraisal at all?*

The simulated TEE answered these by assertion: the RP hashed its own source
files, signed `(file_hash, report_data)` with a key it generated itself, and
the Verifier checked that signature. Since nothing isolated that key from
the RP, an RP willing to lie could sign anything it liked. The mechanism
documented the intent but proved nothing.

A ZK proof answers the first question outright, with no trust in the RP's
code or hardware — and answering it makes the second question moot, because
a faithful redaction is exactly what the appraisal was supposed to
guarantee.

### The statement being proved

For a log of `N` entries, with `P[i]` the real file path and `S[i]` a fresh
per-entry salt (both private):

```
for each i:   C[i]  == Poseidon(P[i], S[i])                    // C[i] public
              TD[i] == SHA256(template_data(file_hash[i], P[i]))
              PCR   := SHA256(PCR ‖ TD[i])                     // PCR starts 0^32
              pcrDigest == SHA256(PCR0 ‖ … ‖ PCR7 ‖ PCR)       // == pcrdigest_a, public
```

`C[i]` are the cleaned paths that appear in `log_r`; `pcrdigest_a` is the
value inside the Attester's TPM-signed quote, which the Verifier already
holds. The two halves together say: *the paths committed to in `log_r` are
the paths whose measurements the Attester's TPM signed.* Neither `P[i]` nor
`TD[i]` is revealed.

### A property worth noticing

`file_hash[i]` is a **public** input, and the circuit reconstructs
`template_data` from it. An RP that lies about a file hash therefore
produces a `TD[i]` that does not replay to `pcrdigest_a`, and the proof
fails. The hashes are *forced* honest by the same constraint that forces
the paths — so the Verifier can run the blacklist check itself, on values
it knows are genuine, instead of trusting that the RP ran it.

---

## 2. Frozen specification

Everything below was read out of the code, not assumed. The circuit has to
reproduce it byte for byte; a one-byte disagreement means `pcrdigest_a`
never matches and the failure gives no clue why.

### Binary log entry — `charra_event_log_parse_entry()`

```
u32le  pcr_index                      (read_u32, little-endian, line 30)
32B    template_digest                (fixed size, NOT length-prefixed)
u32le  name_len                       (= 6)
6B     template_name                  ("ima-ng", no NUL)
u32le  data_len
data_len B  template_data
```

### `template_data` — `build_ima_ng_template_data()`, attester_ima_log.c:39

```
u32le  d_len       (= alg_len + 32 = 7 + 32 = 39)
7B     "sha256\0"  (alg name INCLUDING its NUL)
32B    file_digest
u32le  n_len       (= strlen(path) + 1)
n_len B  path ‖ "\0"
```

So `data_len = 48 + L`, where `L = strlen(path)`.

### Digests

```
template_digest = SHA256(template_data)
PCR10           = SHA256(PCR10_prev ‖ template_digest)   64B input, starts 0^32
pcrdigest_a     = SHA256(PCR0 ‖ … ‖ PCR7 ‖ PCR10)        9 × 32 = 288B, ascending
```

`charra_pcr_extend()` zero-pads a short digest to 32 bytes on the right;
with SHA-256 template digests that padding is never exercised.

### Two things that would otherwise mislead

**The ASCII test log's digests are discarded.** `ima_test_logs.txt` carries
40-hex-char SHA-**1** template digests, but `attester_ima_log.c:145` reads
them into `unused_digest` and recomputes `template_digest =
SHA256(template_data)`. The binary log the RP appraises is all SHA-256.
There is no SHA-1 anywhere in the circuit.

**Only PCR-10 entries are replayed.** `charra_replay_ima_log()` skips any
entry whose `pcr_index` differs. Every entry in the test log is PCR 10; the
circuit assumes that, and the Verifier should reject a `log_r` that
contains anything else rather than silently diverging.

### Measured shape of the test log

Confirmed by `bin/dump_witness` (see §5, Phase 0), not derived:

| Property | Value |
|---|---|
| Entries | 33 |
| n-ng field: max (path + NUL) | 77 B → 76-character path |
| `template_data`: max | 124 B → **3 SHA-256 blocks** |
| Raw log size | 4728 B |
| `pcr10_final` | `bce31f0f128ef7244955dc185a0206aaeed66e8eca95f55970e3ea7d76e5deab` |
| `pcrdigest_a` | `2b24614b17f7ac48f5081665fbc1bdc6091887c4f3272492b18f22d592f2509b` |

**Both digests are known-good, not computed on paper.** They reproduce
exactly what the RP logs during a live attestation, and `pcrdigest_a` is the
value that `charra_verify_log_matches_quote_pcr_digest()` matched against
the Attester's TPM-signed quote in that run. The circuit's final assertion
therefore has a target the TPM itself vouched for.

With `MAX_PATH = 80` (covering the 76-character worst case with headroom):
`template_data ≤ 128 B` → 3 SHA-256 blocks; each PCR extend is 2; the final
composite is 5. Total ≈ **170 SHA-256 compressions and 33 Poseidon hashes**.

### Library dependencies

Noir 1.0.0-beta.26 carries **neither** SHA-256 nor Poseidon in its standard
library — both were moved out into `noir-lang/sha256` and
`noir-lang/poseidon`, and must be declared in `Nargo.toml`. `zk/probe2.sh`
discovers the current release tags and reports which API names each library
actually exports.

---

## 3. Decisions

**Paths stay private, and so do their lengths.** A circuit is fixed-size: it
pays for `MAX_PATH` blocks on every entry regardless, and it cannot branch
on a public input any more than a private one. Publishing lengths therefore
buys *no* reduction in gate count — it is purely a privacy giveaway, so we
don't make it. The only real lever on cost is `MAX_PATH` itself, pinned at
≥ 76 by two kernel-module paths in the test log.

(For files present in a public hash database the length would leak nothing
the already-public `file_hash` doesn't. For proprietary binaries, where the
hash is opaque, the length would narrow the candidate set. Small, but free
to avoid.)

**`file_hash` is public.** Without it the Verifier could store nothing
useful about the log, which would make forwarding `log_r` pointless. It is
also what lets the Verifier run the blacklist check itself — see §1.

**The nonce is not bound into the circuit.** `Quote_r` already binds
`log_r` → nonce (Step 3a items 3 and 4); the proof binds `log_r` →
`pcrdigest_a`. The chain is complete without paying for a nonce constraint,
and `Quote_r` stays exactly as it is.

**The prover owns the redaction.** `bin/zk_redact_and_prove` will take
`log_a` and emit `log_r` *and* the proof together. This keeps Poseidon out
of the C code entirely — matching a C implementation's round constants and
MDS matrix to the circuit library's, bit for bit, is a well-known way to
lose several days.

**Toolchain: Noir + barretenberg.** Barretenberg's lookup-based SHA-256
costs roughly an order of magnitude less per block than R1CS, and Noir has
both SHA-256 and Poseidon in its standard library. The circom/Groth16 route
would be ~4.6M constraints and a 2^23 trusted setup.

---

## 4. Cost, and what would make it unaffordable

Order-of-magnitude only, to be replaced with measurements at the Phase 1
gate:

| | Gates / constraints | Setup | Prove |
|---|---|---|---|
| Noir + barretenberg | ~300–500k | none (universal SRS) | seconds to tens of seconds |
| circom + Groth16 | ~4.6M | 30–90 min, 16 GB+, 1.2 GB ptau | 3–10 min |

Add roughly 2–4× on top for x86-under-Rosetta emulation in the dev
container.

**This does not scale to a production IMA log.** 33 entries is a toy; a
real one has thousands, and at 5,000 entries the cost is ~150× the above —
infeasible for Groth16 and painful even in a zkVM. That is a PoC boundary,
not a detail.

---

## 5. Plan

Each phase is checkable on its own. Phase 1 is a hard go/no-go, and Phase 3
is where byte-exactness either works or doesn't.

| Phase | Goal | Done when |
|---|---|---|
| 0 | Delete the TEE; freeze this spec; add a witness dump to the C replay | Dump prints per-entry `template_data`, `TD`, running PCR, composite |
| 1 | **Gate:** toolchain installed; measure one 128-B SHA-256 block | Real gate count and prove time known |
| 2 | Poseidon-only circuit, N=33 | Full prove → verify round trip |
| 3 | One entry's `SHA256(template_data)` in-circuit | Matches the Phase-0 dump byte for byte — **done, 33/33** |
| 4a | Rebuild `template_data` in-circuit from the path | Digest matches for every entry — **done, 33/33** |
| 4b | Full replay, N=33 | Circuit asserts `== pcrdigest_a` — **done** |
| 4c | Poseidon commitments as public outputs | Witness solves and returns 33 fields — **done** |
| 4d | Soundness smoke test | Tampered witnesses rejected — **done, 4/4** |
| 5 | C integration | New DTO field, marshaling, RP + Verifier subprocess calls |
| 6 | Docs, tests, live run | `run_live_test.sh` passes end to end |

If Phase 1 shows SHA-256 costing far more than expected, stop and
reconsider the backend before writing the real circuit. If proving is too
slow to be usable, prove over the first *N* entries only and document the
reduced coverage — the property is unchanged, the scope isn't.

### What Phase 4 established

Against the 33-entry log from a live Attester, the circuit reconstructs
every `template_data` record from a *private* path and a public file hash,
replays the PCR-10 chain, composes it with the other eight quoted PCRs, and
lands on

    pcrdigest_a = 2b24614b17f7ac48f5081665fbc1bdc6091887c4f3272492b18f22d592f2509b

which is the value the Attester's TPM signed. Nothing about the spec in
§2 is assumed any more; all of it is confirmed against hardware output.

A solved witness only shows the circuit accepts the truth, so
`zk/negative_test.sh` checks the other direction — that it *rejects* what a
dishonest RP would want to get away with:

| Tampering | Result |
|---|---|
| One path byte substituted | rejected |
| One file hash falsified | rejected |
| Two entries swapped | rejected |
| An entry blanked | rejected |
| *(control)* honest witness | accepted |

Without the control, a circuit that rejected everything would also score
4/4. Without the negative cases, a trivially-satisfiable assertion would
score a clean pass on the honest witness. Both halves are needed.

### Two things Phase 5 must not inherit

**Salts are deterministic test values.** `test_salt()` derives them from a
fixed string so failures reproduce. The real RP must draw each from a
CSPRNG and never reuse one — the space of plausible system paths is small
enough to enumerate, so a missing or reused salt makes the commitments
brute-forceable and linkable across attestation runs. This is the one place
where the harness does something the product must not.

**Field elements serialize as fixed 32 bytes.** `nargo` prints them as
minimal hex, so a commitment that happens to fall below 2^248 shows 62 hex
digits rather than 64 — index 8 of the current log does. Any marshaling
that treats these as variable-length hex will silently produce a 31-byte
value and mismatch on roughly one entry in 256. Always big-endian, always
padded to 32.

### The proving backend cannot run in the dev container

Settled, after chasing it through three layers. Recorded so none of these
are retried.

1. `bbup` cannot resolve a bb version for Noir 1.0.0-beta.26: its
   `bb-versions.json` map stops at beta.22. Not environmental.
2. Every bb release needs a newer glibc than Focal's 2.31 -- the newest
   (5.0.0-nightly.20260522) wants 2.34, and every *older* release wants
   2.38+, so there is no version to fall back to. zk/setup_bb.sh solves
   this with a private jammy sysroot and an explicit loader; it works, and
   it is not enough.
3. **The real blocker.** The container is x86_64 under Rosetta on Apple
   Silicon, and Rosetta does not emulate ADX. `/proc/cpuinfo` shows avx,
   avx2, bmi1, bmi2 -- and no adx. Barretenberg's BN254 field arithmetic
   uses ADCX/ADOX carry chains, so bb dies with SIGILL on startup.

No bb version, and no amount of library work, fixes (3). The x86_64
barretenberg binaries cannot run here at all.

Ways out, none free:

| Option | Cost |
|---|---|
| Run bb natively on the arm64 macOS host | works today; RP-in-container cannot invoke it |
| Build bb from source without the ASM backend | long C++ build, and much slower proving |
| arm64 Linux sidecar container | native bb, but needs a job protocol over the shared volume |
| Move charra itself to arm64 | cleanest; depends on the TPM simulator building there |

For circuit development the host is the answer: nargo and bb both run
native arm64, and the repo is bind-mounted, so the circuit can be compiled
and proved from macOS while the C and TPM work stays in the container.

Phase 5 is what actually has to choose, since it assumed the RP could shell
out to `bb prove`. That assumption is now known to be false in this
environment.

### Measured, on the arm64 host

bb 5.0.0-nightly.20260522 runs natively on arm64 macOS, and accepts Noir
1.0.0-beta.26's ACIR despite the version map not pairing them. Full
prove/verify round trip, UltraHonk, 8 threads:

| | |
|---|---|
| Circuit size | 790,495 gates (82,243 ACIR opcodes) |
| Proving key | ~1.6 s |
| Prove | **9.9 s** wall, 55 s CPU |
| Peak memory | ~1.26 GB |
| Proof | 14.6 KB |
| Public inputs | 44 KB |
| Verification key | 3.7 KB |
| Verify | under a second |

Proving is cheap enough that the RP can do it live, per attestation. The
earlier worry that proving time might force a reduced-coverage circuit was
unfounded -- and the only remaining obstacle is *where* bb can execute, not
how long it takes.

### Public-input layout, for the C integration

44064 bytes / 32 = 1377 field elements, one field per **byte** of each
byte-array input. In ABI order:

| Fields | Bytes | Contents |
|---|---|---|
| 0..1055 | 0..33791 | `file_hashes`, 33 x 32 |
| 1056..1311 | 33792..41983 | `other_pcrs`, 8 x 32 |
| 1312..1344 | 41984..43039 | `cleaned` -- the commitments, 33 |
| 1345..1376 | 43040..44063 | `pcrdigest_a`, 32 |

Order follows `main()`'s parameter list. The commitments were *last* while
the circuit returned them; making them a public input moved them ahead of
`pcrdigest_a`. Nothing warns about getting this wrong -- verification simply
fails -- so it was confirmed against a real `bb prove` rather than reasoned
about. Each is a full 32-byte big-endian
field element -- `nargo` *prints* them as minimal hex, so one that happens
to fall below 2^248 shows 62 hex digits rather than 64 (index 8 does), but
in this file every one occupies exactly 32 bytes.

**The Verifier derives all of this itself**, in charra_zk_job.c. File hashes
and commitments come from `log_r`, `pcrdigest_a` from the quote it already
validates, and `other_pcrs` are zeros. So only the 14.6 KB proof crosses the
wire (`msg_rp_evidence_dto.zk_proof`), not the 44 KB of public inputs -- and having the Verifier rebuild them
rather than accept them is also what forces the proof to be about the log
it was actually sent.

`bb verify` takes public inputs via `-i/--public_inputs_path`. It defaults
to the proof's directory, which works interactively; pass it explicitly
from C.

### The one thing phase 5 must get right

The witness JSON the RP hands the prover contains `pcrdigest_a`, and the RP
writes that file. So an RP that substitutes a path *and* recomputes
`pcrdigest_a` to match gets a perfectly valid proof -- of a log it invented.
The proof is not lying: those paths really do replay to that digest.

The security therefore rests entirely on **where the Verifier gets
`pcrdigest_a`**. The right source already exists in the code and costs
nothing to use:

    verifier_appraise.c step 3b
      :419  charra_trusted_keys_check()  -- is AK_a trusted?
      :444  verify_quote_signature()     -- is Quote_a genuine?
      :456  charra_unmarshal_tpm2_quote() -> attest_struct
            attest_struct.attested.quote.pcrDigest   <-- USE THIS

Never `public_inputs` from the proof job, and never a field the RP could
set independently of the signed quote. Likewise the commitments must come
from `log_r`, and the file hashes with them.

(What makes this a PoC rather than a deployment is the trust anchor itself
-- keys written offline into `trusted_keys.txt`, no PKI, no revocation --
not this step. The signature check and the anchor lookup are real.)

This is why the Verifier assembles its own public-inputs file rather than
accepting the RP's. That is not a bandwidth optimisation -- it is the step
that makes verification mean anything. zk/test_watcher.sh case 3 shows the
mechanism works: alter one byte of the public inputs and the verdict flips
to rejected. What phase 5 has to get right is populating them from the
quote rather than from the prover's output.

### The verification is bound

`zk/verify_binding_test.sh` checks the thing that would otherwise be
assumed: that verification actually depends on the public inputs, rather
than merely confirming some valid proof exists. Flipping one bit of
`pcrdigest_a`, and one bit of a commitment, each break verification, with
an untouched control that still verifies.

Without this, a Verifier could be handed a genuine proof of a *different*
log and accept it.

Everything above is `nargo execute`, which solves the witness and checks
every assertion but produces no proof. `bbup` cannot resolve a `bb` version
for Noir 1.0.0-beta.26, and fails identically in-container and natively, so
it is not environmental. This was not blocking through Phase 4 — it is
blocking for Phase 5, which needs `bb prove` on the RP and `bb verify` on
the Verifier. Resolve before the C integration is worth wiring up.

---

## 6. What this commit removed

Deleted outright:

- `src/core/TEE.{c,h}` — `tee_hash_files()`, `tee_attestation()`,
  `tee_sign()`, `tee_public_key_der()`, and the process-lifetime RSA keypair
  they shared.
- `msg_rp_evidence_dto`'s four `tee_*` fields, and their marshal/unmarshal
  legs. **The `/appraise` wire format changed** — 12 positional CBOR fields
  down to 8. RP and Verifier must be rebuilt together.
- `rp_evidence.c`: `rp_appraisal_code_files[]`, the `rp_pcrdigest_a`
  capture, and the REPORT_DATA/attestation/sign block in
  `charra_rp_build_evidence_message()`.
- `verifier_appraise.c`: `expected_appraisal_code_files[]`,
  `verifier_hash_expected_appraisal_code()`, the Step 3a item 5 block, the
  two length pre-checks, and `attestation_result_tee` from the AND-chain.
  The verdict is now **seven** booleans, not eight.
- The corresponding cases in `tests/test_rp_evidence_marshaling.c`. Both
  exact-length fields were TEE fields, so `test_wrong_size_exact_fields_
  rejected()` went with them; `RAW_FIELD_COUNT` is 12 → 8.
- `TEE` from the Makefile's `OBJECTS`.

- `crypto_util`'s software RSA keypair helpers
  (`charra_crypto_rsa_generate_keypair()`, `_public_key_to_der()`,
  `_sign()`, the static `seed_drbg()`, and `CHARRA_RSA_PUB_KEY_DER_MAX`).
  The TEE was their only caller. These were initially kept as
  general-purpose `util/` code, then removed once the build proved they
  were dead: `crypto_util_rng_personalization` — orphaned earlier, when
  `charra_crypto_seeded_rng_init()` went with the certificate PKI — was
  emitting a `-Wunused-const-variable` warning.

Left in place deliberately:

- `CHARRA_RSA_KEY_BITS` and `CHARRA_RSA_SIGNATURE_LEN`, which are **not**
  dead — they size the wire DTOs' signature fields for the TPM-resident AKs.
- `CHARRA_V2_NOTES.md`'s TEE entry, which is a historical record of what was
  built and why it was replaced, not a description of current state.

### Two regressions from the previous commit, fixed here

Both were latent in `681c938` (the certificate-PKI removal) and only
surfaced on the first build after it:

- **`cli_util.c` lost `#include <limits.h>`.** It was removed along with the
  `LONG_MAX` bound on the deleted `--ak-validity`, but `UCHAR_MAX` — used by
  the `cli_flag_given[]` table — comes from the same header. Restored.
- **`rp_send_attestation_result()` was deleted with the file it happened to
  live in.** It sat at `rp_attester_identity.c:892`, and that whole module
  was removed for its certificate content; this one function is the Step 2a
  verdict sender and is unrelated to identity provisioning. `get_evidence()`
  still called it, so `bin/relying_party` would have failed to link.
  Reimplemented in `rp_attestation.c`, where its only caller lives, with a
  file-local completion flag instead of the shared global it used to borrow
  from the identity module.

The lesson worth keeping: deleting a *file* because most of it is obsolete
is not the same as deleting the symbols that are obsolete. Grepping each
exported symbol for callers before removing the file would have caught the
second one immediately.

---

## 7. Generalising beyond this configuration

Deferred, not dismissed. The circuit as written is specific to *this* log
and *this* quote, and the reasons are worth stating so the cost of changing
that is known in advance rather than discovered.

The constraint underneath all of it: **a circuit has no runtime loop
bound.** Every array size and iteration count is fixed at compile time.
That is not an artefact of this implementation, it is what a circuit is. So
"general" can only ever mean "compiled for a worst case and paying for it
on every proof."

### What breaks if the deployment changes

| Change | Breaks | Severity |
|---|---|---|
| Different entry count | `N = 33` | recompile |
| Paths longer than 136 B | `MAX_PATH`, `MAX_BLOCKS = 3` | recompile, and see cost below |
| Different number of quoted PCRs | composite hardcoded 288 B = 9x32 | recompile |
| A quoted PCR above index 10 | PCR 10 is no longer last in the composite | wrong shape |
| Log extends more than one PCR | single `pcr` accumulator | redesign |
| `ima-sig` / `ima-buf` instead of `ima-ng` | `template.nr` layout | rewrite that module |
| SHA-1 or SHA-512 template hash | `d_len = 39`, digest primitive | rewrite |

### How each would be done, cheapest first

**Variable entry count** (~1 h). Compile for `MAX_N`, take `n_real`, derive
`is_real[i] = i < n_real`, and make the extend conditional.

> `n_real` **must be a public input.** If the prover controls how many
> entries count, it can drop any entry it likes -- which is exactly the
> `drop` case in zk/negative_test.sh, reintroduced through the front door.
> Public, and tied by the Verifier to `log_r`'s length, keeps it sound.

Cost: the full `MAX_N` is paid on every proof.

**Variable PCR selection** (~half a day). Take `pcr_values`, `num_pcrs` and
`ima_slot` (the replayed PCR's position in the ascending selection); build
the composite over the first `num_pcrs` values with the computed PCR
substituted at `ima_slot`; hash with `sha256_var`, which already handles
variable lengths and needs only `MAX_BLOCKS` raised to 13 to span 24 PCRs.

**Multi-PCR logs** (expensive). A 24-entry PCR bank with a conditional
extend per entry -- a 24-way select on every entry, so roughly 24x the
chain cost. Avoid unless actually needed.

### The cost warning on path length

`MAX_PATH = 136` covers this log's 77-byte worst case. Linux `PATH_MAX` is
4096, which needs `MAX_BLOCKS` around 65 rather than 3: a **~20x increase
per entry**, paid on every entry regardless of its real length. With
`MAX_N = 128` on top, ~80x the current circuit. That is where proving time
stops being incidental, and it is the reason to size these bounds to the
deployment rather than to the theoretical maximum.

Shipping a small set of fixed circuit sizes, rather than one dynamic
circuit, is also what production ZK systems generally do.

### Consequence for deployment

**Every circuit change produces a different verification key.** The
Verifier must hold the vk matching the RP's circuit, so a configuration
change is a coordinated redeployment, not a config-file edit. If the PCR
selection is expected to vary, that argues for generalising before
deploying rather than after.

### Known issue: the PCR selection is declared twice

`tpm_pcr_selection` in relying_party.c is the selection actually quoted.
`QUOTED_PCRS` in dump_witness.c restates it. They agree today.

If the real selection changes, dump_witness keeps using the stale one and
emits a `pcrdigest_a` consistent with *itself*; the generator feeds that to
the circuit, and the harness passes green while the real system is broken
-- because the circuit is checked against this duplicate assumption, never
against the actual quote. Every other failure mode here is loud; this one
is silent, which is what makes it worth fixing.

Fix: have dump_witness read the selection from the same declaration instead
of restating it.
