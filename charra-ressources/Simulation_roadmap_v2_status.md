# Simulation Roadmap — Status Report

**What has been built since the starting point**

---

**1) Introduction:**

The original `Simulation_roadmap` document — **roadmap v1** — described the
plan for building a remote attestation simulation system on top of the IETF proof-of-concept
implementation. This document reports what has actually been built since.

Throughout, **"the starting point"** means the codebase as it stood when
roadmap v1 was written, and **"now"** means the system as it stands today. The two
are compared directly, file by file and symbol by symbol.

Measured across the two:

| | starting point | now |
|---|:--:|:--:|
| Source files in `src/` (`.c` + `.h`) | 35 | 94 |
| Lines of C in `src/` | 8 057 | 21 918 |
| Binaries built | 5 | 6 |
| CoAP resources served | 4 | 7 |
| Marshalled message types (`msg_*_dto`) | 2 | 10 |
| Test suites | 0 | 18 (418 assertions) |

---

**2) Protocols and encoding:**

Unchanged from roadmap v1. The system still uses:

- **CoAP** for all communication between roles, over UDP.
- **CBOR** (QCBOR) to marshal every payload.
- **DTLS** now works on every leg, and is off by default. Previously it did
  not work at all — see 4.9. `verifier.der` also has a second, unrelated
  job: it is the key every Verifier signs its `/appraise` verdict with (see
  4.5), and that use is independent of whether DTLS is on.

What changed is not the protocols but how much travels over them: 2 marshalled
message types have become 10, and 4 CoAP resources have become 7.

---

**3) What was already implemented at the starting point:**

This is the part of roadmap v1 that was already complete before any of the work
below, and it is more than roadmap v1 anticipated. The starting point was
**not** the bare IETF two-party proof of concept. It already contained:

- `relying_party` and `trust_manager` binaries, alongside `attester`,
  `verifier` and `verifier_old`.
- The inverted verifier role roadmap v1 called for: the Verifier receives
  evidence rather than requesting it, appraises it, and returns a result.
- Three of the four CoAP resources it served: `/nonce`, `/appraise` and
  `/get_verifiers`. The fourth, `/attest`, came from the IETF PoC itself.
- Multi-verifier fan-out with one thread per Verifier, and **majority voting**
  over the returned results.
- The benchmark sweep and statistics code (`calculate_stats`).

In roadmap v1 terms, both staged milestones — "Figure 3" (RP plus multiple
Verifiers) and the trust manager integration — were already reached. The work
since has been of a different kind.

---

**4) What has been implemented since:**

Everything in this section is absent from the starting point and present now;
each item was checked by symbol lookup in both versions.

**4.1 Privacy: log redaction and a second quote.** Previously the Relying Party
forwarded the Attester's evidence as received. It now has
`charra_sdk_redact_ima_log()`, which rewrites each log entry's **directory** —
committing it and leaving the filename in the clear — and `charra_event_log` /
IMA log replay (`charra_replay_ima_log`). Because the redacted log is no longer
the log the Attester measured, the RP cannot forward the Attester's PCR value;
it replays the redacted log into **its own TPM** to rebuild `PCR_r` and signs a
second quote, `Quote_r`, over it (`rp_quote_pcr_with_ak`). **That replay is the
single most expensive operation in the system** — not the quote that follows
it, and not the redaction that necessitates it. The redacted log the Verifiers
receive can now be read directly: `--redacted-log-out` writes it as ASCII every
cycle (default `redacted_ima_logs.txt`), in the same format the Attester's own
log arrives in, so the two diff column for column. See `charra_measurements_v2`
for the figures and **Appendix A** for how the mechanism works.

**4.2 An identity mechanism.** There was none before. There is now a flat trust
anchor, `keys/trusted_keys.txt`, holding the public halves of the two
TPM-resident signing keys, plus `charra_trusted_keys_check()` and a new binary,
`provision_trusted_keys`, to populate it. **Appendix B** explains what this
does and does not establish.

Each key is read from **its own** TPM — the Attester's from `:2321`, the RP's
from `:2325` — which is why `provision_trusted_keys` takes `--role`. That flag
is a security boundary rather than a convenience: a run without it emits *both*
identities from whichever TPM it is pointed at, which would place a key the RP
can itself derive into the entry labelled `attester`. Since `TPM2_Quote` accepts
restricted and unrestricted keys alike, the RP could then produce genuine quotes
that pass the Verifier's check.

The name of that identity also travels on the wire. `/attest` carries a
`sig_key_id` naming which signing key the Attester should quote with; upstream
sent `"PK.RSA.default"`. It now sends `"attester"` — the same string `--role`
provisions under, the same label the anchor uses, and the same name a successful
lookup reports back. No TPM object carries that name: matching it selects the
restricted primary the Attester would have derived anyway, so the field's only
real effect is to let it refuse a request naming anything else.

**4.3 A TPM identity for the Relying Party.** Previously the RP used **no TPM at
all**: `src/relying_party.c` contained no `CHARRA_TCTI` reference and no quote
or signing call, because it had no key of its own to prove. Only the Attester
and the old Verifier opened a TPM. The RP now has its own attestation key, so
the two roles are separated: the run scripts start one simulator per role —
Attester on `:2321`, RP on `:2325` — and launch each process with its own
`CHARRA_TCTI` value.

The reason is **impersonation, not key collision.** The two identities use
different templates — the Attester's is the *restricted* quoting key, the RP's
the *unrestricted* `Quote_r` signing key — and `TPM2_CreatePrimary` derives from
the hierarchy seed **and the template**, so even one shared TPM would yield two
distinct keys. The danger is subtler: on a shared TPM the RP's own device can
derive the restricted primary too, which is exactly the key the anchor labels
`attester`. Since `TPM2_Quote` accepts a restricted key, the RP could then
produce a genuine hardware quote that satisfies the Verifier's Step 3b. Nothing
would be forged and nothing would look wrong. That is why
`provision_trusted_keys --role` emits exactly one identity per TPM: one TPM, one
role, one key.

The separation is operational rather than a code change: `RP_TCTI` is a variable
in the run scripts, not in `src/`, where both roles still read the same
`CHARRA_TCTI` environment variable.

**4.4 The RP qualification handshake.** New: `/qualify` and
`/qualify_submit`, implemented by `charra_rp_qualification` and
`charra_synthetic_log`. A Verifier generates a synthetic IMA log — 40 entries in
the measured configuration — redacts it itself to produce a golden answer, and grants the RP a time-limited
qualification only if the RP's redaction of the same log comes out
byte-identical. Grants are recorded per RP fingerprint in a registry every
Verifier reads (`verifier_qualified_rps_is_qualified`). **Appendix B** walks
through the exchange.

This is the default, and until 4.10 it was the only option. **In TEE mode the
handshake does not run at all** — the RP is never asked to qualify and no
grant is looked up, because it proves itself per message instead.

**4.5 Signed verdicts.** Verifiers used to return an unauthenticated result.
They now return `charra_verdict`, a signed record binding the verdict to the
challenge nonce, an `evidence_digest` over the exact submission appraised, and a
timestamp. The RP verifies each one; an unverifiable YES counts as a NO. What
each binding stops is set out in **Appendix B**.

**4.6 Policy enforcement.** New: `charra_verify_log_file_hashes_against_policy`,
checking measured file hashes against whitelist and blacklist files. This runs
on the RP only — the Verifiers do not repeat it.

**4.7 A Step 2a result path back to the Attester.** New CoAP resource
`/attest_result`. It carries **one specific thing: the RP's own local Step 2a
appraisal of the evidence it just received** — not the Verifiers' verdict, and
not the majority vote.

The distinction matters because the two decisions are made in different places.
`rp_send_attestation_result()` is called from exactly two lines
(`rp_attestation.c:504` and `:507`), both immediately after the `/attest`
exchange, and both reporting the boolean returned by
`charra_rp_appraise_evidence()` — the RP's six local checks: the Attester's AK
is in the trust anchor, the quote signature verifies, the nonce answers the
challenge just sent, each log entry's `template_digest` matches
`hash(template_data)`, replaying the log rebuilds the PCR composite digest, and
no measured file is blacklisted.

The majority vote is tallied much later and elsewhere
(`get_attestation_results()`, `rp_attestation.c:774`). It logs its outcome and
**the cycle ends there** — nothing is sent to the Attester. The Attester is
never told how the Verifiers voted, or even that a vote took place.

Nor does the message itemise *which* check failed: the payload is
`{accepted, reason}`, and the reason is one of two fixed strings, `"Step 2a
local verification failed"` or `"...passed"`. The failing check is named in the
RP's log, not on the wire.

Step 2a is a hard stop, so the two cases never overlap: if the local appraisal
fails, the cycle aborts before any Verifier is contacted, and there is no vote
to report. Delivery is advisory — a failure to reach the Attester is logged and
ignored.

**4.8 Restructuring and tests.** `src/` gained `attester/`, `rp/` and
`verifier/` subdirectories; `verifier.c` shrank from 678 lines to 245 plus 11
files under `src/verifier/`. Nine new modules appeared under `src/core/`:
`charra_event_log`, `charra_rp_qualification`, `charra_sdk`,
`charra_synthetic_log`, `charra_trusted_keys`, `charra_verdict`, `TEE`, plus
`charra_poseidon` and `charra_zk` for the proof of 4.11. There were
**no tests at all** before; there are now 18 suites and 418 assertions. That they need
neither a TPM nor the network is not an assumption — the suite was re-run inside
a container started with `--network none` and with `tpm_server` killed, and all
18 suites still reported 418 assertions and 0 failures.

**4.9 DTLS, which previously could not be switched on at all.** Roadmap v1
recorded DTLS as "present in the code but not enabled". That was accurate but
understated: it was not *disabled*, it was **unreachable**. The transport was
complete from the very first commit — the Relying Party had the full PSK and
raw-public-key session code — but `relying_party.c`'s entry point was declared

```c
int main(int argc CHARRA_UNUSED, char** argv CHARRA_UNUSED)
```

with both parameters marked unused. It included `<getopt.h>` and never called
it, so `use_psk` / `use_rpk` could only be changed by editing the source and
recompiling. The Attester and Verifier parsed their command lines from the
start, which is what produced the asymmetry. No commit in the project's history
ever set either flag true.

Two things were needed to make it work.

*First, the missing command line.* All four roles now accept `--psk` / `--rpk`.
The Relying Party needed ten flags rather than the shared set, because it is a
client to three different servers and therefore needs one peer-key path per kind
of peer, where the Attester and Verifier each face one. The Trust Manager had
neither a DTLS configuration nor a real command line — its `main()` rejected
every argument except `--help` — so both were added, along with a new
`keys/trust_manager` keypair; `/get_verifiers` is no longer the one leg that
stays in plaintext. `run_daemon.sh` gained a single `DTLS_MODE` setting
(`off` | `psk` | `rpk`) that configures all four roles at once, because they
must agree: a mismatch does not raise an error, the request simply times out,
and a timeout counts as a NO vote — so it presents as a failed attestation
rather than as a misconfiguration.

*Second, a library defect.* With the flags in place, PSK worked immediately but
RPK hung. It hung at the same point every time — `/qualify` and
`/qualify_submit` completed, then `/nonce` never returned — and it hung with a
single Verifier just as with five, which ruled out contention. The dividing line
was which thread the request came from: `/qualify` runs on the main thread,
`/nonce` inside one of the per-Verifier worker threads. **libcoap 4.3.4, the
version the container image pinned, offers no `--enable-thread-safe` option at
all**; it first appears in 4.3.5. Without it, a DTLS session opened from a
worker thread never completes its handshake, while the same session from the
main thread does. PSK was unaffected, because only the raw-public-key path
carries the state that requires the locking.

The image now builds libcoap `v4.3.5b` with `--enable-thread-safe`. Two
side-effects came with it: the bundled example programs fail to link without
`-lpthread`, so they are disabled and the flag added. `run_daemon.sh` also
refuses `DTLS_MODE=rpk` outright when the image lacks the option, rather than
hanging — the original failure looked like a stuck attestation rather than a
missing library feature.

Measured on one image, so the figures are comparable, over two cycles at five
Verifiers:

| mode | result | fan-out |
|---|:--:|:--:|
| `off` (plain UDP) | 5/5, both cycles | 3.916s |
| `psk` | 5/5, both cycles | 3.935s |
| `rpk` (mutual auth) | 5/5, both cycles | 4.067s |

Encryption costs about 0.02s per cycle; mutual authentication about 0.15s.
Under `rpk` each role proves possession of its own keypair and checks its peer
against the reference copy — 28 authenticated handshakes per two-cycle run.

This is hop-by-hop, so it does not replace the signed verdict of 4.5, which is
end-to-end and survives a compromised endpoint. The two are complementary.

**4.10 A second way for the RP to prove itself: a simulated TEE.** Until now
the RP had exactly one way to show it was not fabricating the redaction — the
`/qualify` handshake of 4.4, which proves the redaction *output* matches a
synthetic challenge the Verifier already knows the answer to. It says nothing
about *which code* produced that output. A second mechanism answers the other
question.

`src/core/TEE.{h,c}` simulates the primitive a real TEE provides: an
Attestation Document binding a measurement of the code that ran to a
caller-supplied value, signed by a key that never leaves the enclave. Here the
"enclave image" is a SHA-256 over the RP's own appraisal sources
(`rp_evidence.c`, `charra_sdk.c`, `charra_event_log.c`, in that order — order
is part of the measurement), and the bound value is
`hash(verifier_nonce || pcrdigest_a || log_r)`: this Verifier's own challenge,
the exact TPM-signed digest that gated appraisal, and the exact redacted log
being submitted. One document per Verifier, since each contributes its own
nonce.

*Why the TEE's key is certified by AK_r.* The keypair is generated per process
and has to travel with every document, since no Verifier can know it in
advance. On its own that would prove nothing: a dishonest RP could generate
its own keypair, sign any document it liked, attach the matching public key,
and pass every check — the measurement is over public source files, so
claiming the expected hash costs nothing. What makes a real enclave's document
unforgeable is the chain from its signing key to a vendor root, and that chain
is the part software cannot simulate. It is replaced here with a root the
system already has: the RP certifies the TEE's public key with **AK_r**, which
is in `keys/trusted_keys.txt`. The Verifier therefore reaches the TEE key by a
chain it already checks — anchor → AK_r → TEE key → document — instead of
believing what arrived beside the signature. This also gives AK_r's
unrestricted template a second justification: in TEE mode the qualification
handshake, previously its only caller, does not run.

The Verifier's five checks are its own work throughout. It holds an
independent copy of the file list and hashes its own sources; it never calls
into the RP's TEE code, and there is no shared symbol between the two.

Which mechanism is in force is a CLI flag on both roles, `--trust-mode=qualify`
(the default, so nothing that ran before changes) or `--trust-mode=tee`, set
for both at once by `run_daemon.sh`'s `TRUST_MODE`. **Unlike `DTLS_MODE`, a
mismatch is reported rather than guessed at**: the RP states its mode in every
`/appraise` request, so a Verifier configured the other way votes NO and logs
`MODE MISMATCH` — the DTLS behaviour above, where disagreement presents as a
timeout, is precisely what this avoids.

Measured over the full 1..5-Verifier sweep, TEE mode costs between 1.8 % and
3.4 % more per cycle. The fixed cost is unchanged and the whole difference is
marginal, about 24 ms per Verifier — the shape the design predicts rather than
a surprise, since the handshake is once per cycle and usually a no-op whereas
a TEE document is built and signed per Verifier. The figures are in
`charra_measurements_v2`, which is where they are maintained.

**4.11 A third way: proving the redaction rather than asserting it.** 4.10
names the code that ran; it cannot show the code was not lied to. A third
mode, `--trust-mode=zk`, closes that with a zero-knowledge proof.

The circuit (`zk/circuit/`, Noir) proves one statement: every cleaned path in
`log_r` is a Poseidon commitment to a path that really was measured — the same
paths whose replay reproduces the Attester's TPM-signed `pcrdigest_a`. One
variable feeds both the replay and the commitment, so a lie about a path
breaks one or the other. No path is revealed.

Unlike the TEE document the proof is **once per cycle**, not once per
Verifier: every Verifier receives the same `log_r` and the same `Quote_a`, so
one proof serves all of them. Over the full 1..5 sweep it adds **4499 ms to
the fixed cost and 7.8 ms to the marginal** — `tee` is the mirror image,
nothing fixed and ~24 ms per Verifier. Producing a proof costs 4.13 s ± 0.11
once warm, checking one 0.224 s, against a 839,117-gate circuit and a 14.6 KB
proof.

Three things make it sound rather than decorative. The Verifier rebuilds every
public input itself — commitments and file hashes from the `log_r` it is
appraising, `pcrdigest_a` from the `Quote_a` it has already verified, and the
entry count from `log_r`'s own length. A proof is only ever a proof *about its
public inputs*, so accepting the RP's copy would let a genuine proof of a
fabricated log verify. The entry count is public for the same reason: if the
prover chose it, it could mark entries as padding and drop them from the
replay. And `zk/negative_test.sh` checks all of that empirically — six
tampering cases, each rejected, against an honest witness that is accepted.

Two boundaries are worth stating plainly. The circuit is compiled for a fixed
entry count — `global N`, currently **167**, sized to the vendor evidence log
now used throughout. Proving that costs about 39 s and 6.8 GiB of peak RAM,
which is close to the ceiling a 7.75 GiB Docker allocation allows; a real IMA
log has thousands of entries, and since every proof pays for all `N` slots
whatever the log's actual length, this does not scale to one. Raising `N`
means editing three constants that must agree (`main.nr`, `gen_prover_toml.py`,
`charra_zk.h`), recompiling the circuit and redistributing `zk/vk`. And
Barretenberg needs x86 instructions Rosetta does not emulate, so the prover
runs in its own `linux/arm64` container alongside the charra one, sharing the
checkout — which is also the job queue between them.

The circuit takes the directory as a **private** input and the filename as a
**public** one, and rejoins them with the label to rebuild the record the
Attester measured. It has to: the commitment in `log_r` covers the directory
alone, while the PCR chain covers the whole path, so one array cannot serve
both. Making the filename public is also what lets a Verifier tie the name it
reads in `log_r` to the one that was proved — a private filename would let an
RP prove one and publish another.

Neither mechanism subsumes the other. Qualification proves the redaction OUTPUT, the
TEE names the CODE that produced it, and the ZK proof shows the redaction was
done correctly without revealing a path. All three are exclusive, selected by
one CLI flag on both roles, and all three fail closed.

---

**5) Status against roadmap v1's questions:**

Roadmap v1 closed by asking for validation on two points. Both are now settled
by what was built:

- *"Our PoC will use the protocols of Section 2"* — held: CoAP and CBOR
  throughout, and the code reuse roadmap v1 counted on did happen, though not
  untouched. Figures below.
- *"The implementation will proceed in two steps, first the subsystem with a
  relying party and multiple verifiers, then the trust manager"* — both steps
  were already complete at the starting point. The work since has gone into the
  privacy properties and the trust model, which roadmap v1 did not scope.

**How much of the original code survived.** Comparing the two versions file by
file:

| | count |
|---|:--:|
| Original source files still present | 35 of 35 |
| — byte-identical | 5 |
| — modified | 30 |
| Original files deleted | 0 |
| Files added | 50 |

Nothing from the original was thrown away, but little survived untouched either:
the growth is 50 new files on top of a substantially reworked 35.
`charra_marshaling.c` in particular grew from 478 lines to 1 618 — more than
triple — to carry ten message types instead of two, while lower-level pieces
such as `charra_rim_mgr.c` (28 changed lines of 241) and `charra_log.c` (34 of
171) are close to their originals. `verifier_old.c` is still in the tree as the v1
baseline.

Roadmap v1's Figure 2 target has been reached and exceeded. What it did not
anticipate is the cost: rebuilding `PCR_r` in the RP's TPM accounts for roughly
87 % of an attestation cycle.

---

**Appendix A (Optional reading): redaction, `PCR_r`, and why there are two
quotes**

The original Appendix A explained CoAP, because CoAP was the machinery a reader
had to understand to follow the code. The equivalent today is **log redaction**:
it is the reason the system exists, and it is the reason one operation accounts
for 87 % of an attestation. Here are the key concepts.

1\. **A measurement log.** Linux IMA records every file it measures as an entry
containing the file's content digest and its path, and extends a digest of that
entry into a TPM PCR. By default that is **PCR 10**
(`CHARRA_IMA_PCR_INDEX`). The log is the human-readable story; the PCR is the
TPM-protected summary of it.

2\. **A PCR is a running hash, not a register you can write.** Each extend
folds the new digest into the old value. A PCR value therefore has no meaning on
its own — it can only be *derived*, by starting from an all-zero PCR and
replaying every extend the TPM did, in order. That derivation is
`charra_replay_ima_log()`.

3\. **A quote binds the PCR, not the log.** `TPM2_Quote` signs the current PCR
values plus a caller-supplied nonce. So a quote proves "my PCR 10 holds value
X"; it says nothing about *why*. Whoever appraises it must replay the log and
check that the replay reproduces X. If it does, the log is exactly the log the
TPM saw.

4\. **The privacy problem.** An IMA entry's `template_data` holds two
length-prefixed fields: the content digest (`d-ng`) and the **path** (`n-ng`).
The path is the sensitive half — it reveals what software and configuration
exist on the Attester. The content digest is not: on its own it says only that
some file hashed to some value, not where that file lives.

5\. **Redaction.** Only the **directory** is sensitive, so only the directory is
hidden. A path splits at its last `/`, and the two halves leak very different
things: the directory carries deployment detail — mount points, job instance
identifiers, version-stamped image names such as
`/var/secbox/job/lte/secbox_lte_ai_3_24_0/…` — while the filename is a generic
library name the vendor's own published baseline already lists. So
`charra_sdk_redact_ima_log()` rewrites each entry's n-ng field as

```
hex(SHA256(dir || salt)) | label | filename | NUL
```

copying the content digest through byte for byte. In practice an entry reads
`2305abb3…5d1e/libxt_tcp.so`. The salt is a fresh 32 bytes **per entry**, and
for real evidence it is never transmitted (the qualification handshake is the
one deliberate exception — see Appendix B). That granularity buys two distinct
properties: the mapping is irreversible even against a dictionary of guessed
directories, which an unsalted `SHA256(dir)` would not be; and two entries in
the *same* directory redact to *different* values, so a Verifier cannot count
or correlate them.

Keeping the filename in the clear is what makes appraisal still work at full
strength: the whitelist is matched on **name and content hash together**, so a
known-good binary sitting under a name it has no business having is still a
finding. The commitment is rendered as 64 hex characters rather than 32 raw
bytes so that `log_r` remains a printable IMA log, writable in the same ASCII
format `log_a` arrived in and diffable against it column for column — which is
what `--redacted-log-out` now writes to disk every cycle.

`charra_sdk_redact_ima_log_with_witness()` is the same function with Poseidon
in place of SHA-256, used only in ZK mode because a commitment the circuit has
to re-check is far cheaper there. Both are 32 bytes before hex, so `log_r`'s
format is identical either way.

6\. **Why redaction forces a second quote.** Change any entry and the replay no
longer reproduces the Attester's PCR 10. The RP therefore *cannot* forward
`Quote_a`'s PCR value alongside a redacted log: the two would not agree. It must
rebuild the PCR that the redacted log actually implies, in its own TPM, and sign
*that*.

**Example: how the Relying Party does it.**

1\. **Appraise first, redact second.** `charra_rp_appraise_evidence()` verifies
`Quote_a` against the *unredacted* log while it still can — the Attester's key
against the trust anchor, the quote signature, the nonce, each entry's
self-consistency, and the replay against the quoted digest. Redaction destroys
the ability to do this, so it happens only after the check passes.

2\. **Redact.** `charra_sdk_redact_ima_log()` produces `log_r` from the raw log.
In the measured configuration this turns 4728 bytes into 4257.

3\. **Replay into a different PCR.** `rp_replay_log_into_pcr()` extends every
`log_r` entry into **PCR 23** (`RP_REPLAY_PCR_INDEX`), not PCR 10.

The operative reason is **resettability**. Each cycle replays a fresh `log_r`
from an all-zero PCR, so the RP must *rewind* the PCR first — and PCR 10, being
in the 0–15 range, correctly refuses `TPM2_PCR_Reset`. Only PCRs 16 and 23 are
resettable from locality 0 on this platform, so 23 is one of two available
choices.

A second reason is sometimes cited — that 23 lies outside the Attester's quoted
selection (`{0..7, 10}`), so RP activity cannot perturb `Quote_a`. **In the
normal configuration that is irrelevant**: the Attester and the RP hold separate
TPMs, so nothing the RP extends on its own device can affect the Attester's PCRs
at all. It becomes load-bearing only in the fallback where both roles share one
simulator (`TWO_TPMS=0` in `run_daemon.sh`, which points the RP at the
Attester's TCTI). There, an RP replaying into PCR 10 would corrupt the very PCR
`Quote_a` attests to.

That fallback is a testing convenience, not a supported deployment: as §4.3
explains, sharing a TPM also lets the RP derive the Attester's restricted key
and quote as it.

4\. **Quote it.** `rp_quote_pcr_with_ak()` signs PCR 23 under a nonce supplied
by the Verifier, producing `Quote_r`. This happens once **per Verifier**,
because each Verifier issues its own nonce.

5\. **What the Verifier receives.** `log_r`, `Quote_r`, and the original
`Quote_a` with the Attester's public key. It replays `log_r` against `Quote_r`'s
PCR to confirm the redacted log is what the RP actually committed to, and
independently re-checks `Quote_a` to confirm the evidence originated from a
trusted Attester answering a fresh challenge.

In summary: the Attester proves what it measured, the RP proves what it forwards
is a faithful redaction of that, and the Verifier checks both without ever
seeing a path. The cost of that guarantee is step 3 — 33 TPM extends, about
86 ms each on the measured platform, and 87 % of the attestation cycle.

---

**Appendix B (Optional reading): the trust model — anchor, qualification,
verdicts**

Roadmap v1 did not scope a trust model, so this is the part of the system with
no counterpart in the original document. Three mechanisms, each answering a
different question.

**1. Who are you? — the trust anchor**

There is no CA and there are no certificates. `keys/trusted_keys.txt` holds the
public halves of the two TPM-resident signing keys in PEM, one labelled
`attester` and one `relying-party`. **The file *is* the trust decision**:
`charra_trusted_keys_check()` accepts a key if and only if it appears there.

Two consequences worth understanding:

- **Keys are derived, not stored.** `TPM2_CreatePrimary` reproduces the same key
  on every call from two inputs: the TPM's **hierarchy seed** and the **key
  template**. Nothing is persisted inside the TPM. The template is what
  distinguishes the two identities on one device — the Attester's key is the
  restricted primary, the RP's the unrestricted one. Wipe the TPM's state and
  the seed changes, so every derived key changes, and the anchor must be
  regenerated — otherwise every signature check fails, reported as "this key is
  not a trusted identity", which reads like a rejected peer rather than a stale
  file.
- **It establishes identity, not behaviour.** Anything listed in the file is
  accepted as that identity. It cannot express "this RP redacts correctly",
  which is precisely the gap the next mechanism fills.

**2. Do you behave? — the qualification handshake**

An identity does not go stale, but behaviour can. Before any Verifier accepts a
submission, the RP must hold a qualification grant, obtained by passing a
redaction competence test:

1\. The RP asks a Verifier for a challenge over `/qualify`.

2\. The Verifier generates a **synthetic** IMA log (40 entries in the measured
configuration, about 5.2 kB) from a random seed, and redacts it *itself* with a
random salt to produce a golden answer. It returns the log **and the salt**.

3\. The RP redacts the same log through the exact pipeline it uses for real
evidence, signs `(redacted log ‖ salt)` with its attestation key, and submits
over `/qualify_submit`.

4\. The Verifier checks the signature, then compares the RP's redaction with its
golden answer **byte for byte**. A grant is issued only on an exact match.

Three design details explain the shape:

- **The salt is deliberately transmitted here** — the one exception to "the salt
  is never sent". A fresh per-entry salt could never produce a byte-identical
  answer, so the shared salt is what turns the test into an equality check
  rather than a re-derivation. This is safe specifically because the challenge
  log is synthetic: its paths are fabricated, so irreversibility and
  non-correlation — which matter only for a real device's data — give up
  nothing. Real evidence is always redacted with no caller-supplied salt.
- **The signature says *who*, not *what state*.** The grant is recorded against
  the signing key's fingerprint. The salt is folded into the signed data so a
  captured submission cannot be replayed into a later round.
- **No replay, no PCR.** Unlike the evidence path, the handshake never touches
  `TPM2_PCR_Extend`: two identical logs replay identically, so comparing bytes
  is sufficient.

The grant is time-limited (180 seconds by default), single-use per challenge,
and shared between Verifiers through `qualified_rps.txt` — so an RP that
qualified once, with any Verifier, is qualified everywhere until the deadline
that Verifier stamped.

**3. Did you really say that? — signed verdicts**

A Verifier's answer is a signed `charra_verdict` record carrying four fields:
`accepted`, `challenge_nonce`, `evidence_digest`, and `signed_at`. The RP
verifies every one; **an unverifiable YES is counted as a NO.**

| Field | What it stops |
|---|---|
| `challenge_nonce` | Replay across rounds — and, since every Verifier draws its own, a vote being counted in another Verifier's slot |
| `evidence_digest` | A verdict cast over evidence the RP did not send. The RP hashes the submission before sending and the Verifier hashes it on arrival, so an on-path swap is caught — which the nonce alone does not do, since it travelled in the clear |
| `signed_at` | Nothing cryptographically: no role has a trusted clock. It is an assertion useful for the log and a staleness bound. Freshness comes from the nonce |

In summary: the anchor establishes *who*, qualification establishes *behaves
correctly*, and the signed verdict establishes *this answer, about this
evidence, from that Verifier*. All three are needed, because each is silent
about what the other two assert.
