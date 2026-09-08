# Zero-knowledge log redaction

Proving the redaction rather than asserting it.

Status: **implemented and working**, selected with `--trust-mode=zk` on both
the Relying Party and every Verifier. It is one of three exclusive mechanisms
-- the others being the `/qualify` handshake and the simulated TEE -- and this
document is the design record for the proof. Measured costs live in
`charra-ressources/charra_measurements_v2.md`; operational instructions live
in `charra-ressources/charra2-manual-v2.md`.

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
u32le  d_len       (= alg_len + 32 = 8 + 32 = 40)
8B     "sha256:\0" (alg name, its COLON, and the NUL)
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

Confirmed against the C replay's own output, not derived:

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

**Measured, not estimated.** Noir + barretenberg, UltraHonk, in a native
linux/arm64 container:

| | 33 entries | 192 entries |
|---|---|---|
| Gates | 839,117 | 4,765,304 |
| Prove | 3.10 s ± 0.06 | 16.47 s ± 0.62 |
| Peak RAM | 1,249 MiB | 6,839 MiB |
| Proof | 14,656 B | 14,656 B |
| Verify | ~0.01 s | ~0.02 s |

Cost is linear in the entry count: 24,693 gates, 81.5 ms and 34.9 MiB per
entry, with a small fixed intercept. Proof size, verification key and
verification time do not grow at all.

The circom + Groth16 route was not taken. It would have been roughly 4.6M
constraints with a 30-90 minute trusted setup needing 16 GB and a 1.2 GB ptau
file; Noir's PLONKish arithmetisation with a universal SRS avoids all of that.

The full scaling study, including the measured OOM ceiling, is in
`charra-ressources/charra_measurements_v2.md`.

**This does not scale to a production IMA log.** 33 entries is a toy; a
real one has thousands, and at 5,000 entries the cost is ~150× the above —
infeasible for Groth16 and painful even in a zkVM. That is a PoC boundary,
not a detail.

---

## 5. How it is built

Each stage below was checkable on its own, and all of them are done. The two
that could have stopped the work were byte-exactness -- whether the circuit's
SHA-256 reproduces the C replay exactly -- and soundness, whether the circuit
rejects a tampered witness rather than merely accepting an honest one.

| Stage | Goal | Outcome |
|---|---|---|
| 1 | Toolchain, and a real gate count | 839,117 gates at 33 entries |
| 2 | Poseidon-only circuit | full prove -> verify round trip |
| 3 | One entry's `SHA256(template_data)` in-circuit | matches the C dump byte for byte, 33/33 |
| 4a | Rebuild `template_data` in-circuit from the path | digest matches for every entry, 33/33 |
| 4b | Full replay | circuit asserts `== pcrdigest_a` |
| 4c | Poseidon commitments as public outputs | witness solves, returns 33 fields |
| 4d | Soundness | every tampered witness rejected, 6/6 |
| 5 | C integration | RP proves, Verifier verifies, live |
| 6 | Variable entry count | `n_real` public; the `nreal` tampering case rejected |

The C Poseidon and the circuit's must agree bit for bit or every proof fails
with no diagnostic beyond an unsatisfiable constraint system.
`tests/test_poseidon.c` pins that against 33 commitments the circuit itself
produced, and runs in `make test`.

### How the pieces fit, after phase 5

    RP   charra_sdk_redact_ima_log_with_witness()   paths+salts captured
         charra_poseidon_commit()                   log_r's cleaned paths
         charra_zk_prove()          -> watcher -> bb prove
         ev.zk_proof                                14.6 KB on the wire

    V    step 3b item 4
         charra_zk_public_inputs_from_log_r()       from log_r + Quote_a
         charra_zk_verify()         -> watcher -> bb verify

The witness never leaves the RP and is zeroized on every exit path from
charra_rp_prepare_evidence(), including the failures — it holds precisely
the paths the redaction exists to withhold.

The proof is produced once per cycle, not once per Verifier: every Verifier
receives the same log_r and the same Quote_a, so the proof is identical, and
at ten seconds it is the most expensive step in the cycle by two orders of
magnitude.

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

### The proving backend cannot run in the charra container

`bb` needs x86 ADX instructions that Rosetta does not emulate, so in the
`linux/amd64` charra image on an Apple-silicon host it dies with SIGILL --
reproducibly, exit 132, whatever the version or libraries.

It runs normally in a **native `linux/arm64` container**, where nothing is
emulated. So the prover is a sibling container, built by `docker/build-zk.sh`
and started and stopped by `run_daemon.sh` alongside the TPM simulators. The
two containers share the checkout, and that shared mount is the channel: the
RP writes a job directory under `zk/jobs/` and the prover writes the answer
back. `src/core/charra_zk_job.{h,c}` is the client side, `zk/proof_watcher.sh`
the server side.

That handoff is scaffolding, not design: a real deployment would have the RP
and Verifier each invoke a local `bb`. Nothing about it is load-bearing for
security. The Verifier supplies its own verification key and rebuilds its own
public inputs, so a compromised prover can cause a failure but cannot cause a
false accept.

---

## 6. What this does not establish

Worth stating plainly, because a proof invites more confidence than it earns.

**It does not prove the RP ran any particular code.** It proves a relationship
between values: that `log_r`'s commitments and the Attester's signed
`pcrdigest_a` are consistent with one set of paths. An RP that redacted
honestly and one that reimplemented the SDK differently but correctly produce
equally valid proofs. Naming the code is what `--trust-mode=tee` does instead.

**It does not protect `log_a`'s contents from the RP.** The RP sees every real
path; that is inherent to its role. The proof protects them from the
*Verifier*.

**It does not cover entries for PCRs other than 10.** The circuit replays a
single accumulator, and `gen_prover_toml.py` refuses a witness whose entries
target anything else rather than silently corrupting the chain.

**The trusted setup is universal, not per-circuit** -- an SRS from a public
ceremony, not something generated here. Verification still depends on
`zk/vk` being the key for the circuit the RP actually proved with; a stale key
rejects every proof.

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
| More entries than `N` | `global N` in `main.nr` | recompile + new `zk/vk` |
| Paths longer than 136 B | `MAX_PATH`, `MAX_BLOCKS = 3` | recompile, and see cost below |
| Different number of quoted PCRs | composite hardcoded 288 B = 9x32 | recompile |
| A quoted PCR above index 10 | PCR 10 is no longer last in the composite | wrong shape |
| Log extends more than one PCR | single `pcr` accumulator | redesign |
| `ima-sig` / `ima-buf` instead of `ima-ng` | `template.nr` layout | rewrite that module |
| SHA-1 or SHA-512 template hash | `d_len = 40`, digest primitive | rewrite |

### How each would be done, cheapest first

**Variable entry count — done.** The circuit compiles for `N` as a ceiling and
takes `n_real`, deriving `is_real[i] = i < n_real` and making the extend
conditional.

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
