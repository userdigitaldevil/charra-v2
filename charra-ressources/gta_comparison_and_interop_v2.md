# Global Trust Authority: Architecture, Comparison with CHARRA-v2, and an Interoperability Experiment

Every claim in this document was checked against the code or produced by a run
that was actually performed. Where a result depends on a condition that would
not hold on real hardware, that condition is stated rather than omitted.

---

## 1. What Global Trust Authority is

**Global Trust Authority (GTA)** is an openEuler remote-attestation project,
written in Rust and licensed under the Mulan PSL v2. It was obtained by cloning
`https://gitcode.com/openeuler/global-trust-authority.git`, and it is kept in
this repository only as a reference point for comparison; it is not part of
CHARRA and is excluded from version control.

Its stated purpose is to let a central service verify the integrity of remote
nodes using hardware-rooted evidence. It supports a considerably wider range of
attestation technologies than CHARRA does:

| Backend | What it attests |
|---|---|
| `tpm`, `tpm_boot`, `tpm_ima` | Standard TPM 2.0 — quotes, boot log, IMA runtime measurements |
| `cca` | Arm Confidential Compute Architecture |
| `virtcca` | Virtualised CCA, for confidential VMs |
| `itrustee` | Huawei's TrustZone-based TEE OS |
| `ascend_npu` | Huawei Ascend AI accelerator |
| `dice` | DICE — layered hardware root of trust |

Each backend exists twice: once as an *attester* plugin on the node, and once
as a *verifier* plugin inside the server. Both are compiled into their
respective binaries and loaded through a plugin manager.

### 1.1 Components

- **`attestation_agent`** — runs on the node being attested. Collects evidence
  (TPM quote, PCR values, measurement logs) and sends it to the server.
- **`attestation_server`** — the service. Issues nonces, verifies evidence,
  evaluates policy, and issues signed tokens. Its `verifier/` subdirectory is
  a set of modules *inside this one binary*, not separately deployable
  processes.
- **`attestation_cli`** — a command-line client that can perform the agent's
  work manually.
- **`key_manager`** — optional integration with an external KMS.

### 1.2 The REST interface

| Method and path | Purpose |
|---|---|
| `GET /global-trust-authority/service/v1/challenge` | Obtain a signed nonce |
| `POST …/v1/attest` | Submit evidence; receive an EAT/JWT token |
| `POST …/v1/cert` | Register a CA certificate as a trust root for AK certificates |
| `POST …/v1/ref_value` | Register a baseline of known-good file hashes |
| `POST …/v1/token/verify` | Verify a previously issued token |

### 1.3 Persistent state

GTA keeps state in a **relational database** — SQLite by default, with MySQL
and PostgreSQL supported through configuration. Two tables matter for IMA
appraisal:

- **`t_ref_value`** — one row per registered baseline: `id`, `name`,
  `attester_type`, `content`, `content_type`, `version`, `signature`.
- **`t_ref_value_detail`** — one row per entry within a baseline:
  `file_name`, `sha256`, `ref_value_id`.

Policies are written in **Rego** (Open Policy Agent) and evaluated after
verification, converting the verifier's findings into a trustworthiness score
that is embedded in the issued token.

---

## 2. What the server does with an attestation request

The request passes through a chain of six handlers. The steps below were read
from the source, not inferred from behaviour.

**Step 0 — Schema validation.** Field lengths, at least one measurement and one
piece of evidence, a recognised `nonce_type`, and a `User-Id` header.

**Step 1 — `NonceValidationHandler`.** Behaviour depends on `nonce_type`:
`verifier` validates a server-issued signed nonce; `user` accepts a
caller-supplied one; **`ignore` performs no check at all** and returns
immediately.

**Step 2 — `NonceProcessingHandler`.** Prepares the nonce for comparison
against the value inside the quote.

**Step 3 — `EvidenceVerificationHandler`.** Dispatches to the plugin named by
`attester_type`. For `tpm_ima` this divides into two parts.

*Step 3a — cryptographic verification.* This is the hard gate; every check
fails closed.

1. Each AK certificate is validated against the CA certificates registered
   through `POST /cert`.
2. An AK certificate is selected (`lak` when several are present).
3. The certificate is parsed and its public key extracted.
4. The quote signature is verified with that key, and the nonce inside the
   quote is checked.
5. The PCR composite digest is recomputed over the quoted selection and
   compared with the digest inside the quote. A mismatch rejects the request.

*Step 3b — IMA log processing.*

6. The log must be non-empty and of type `ima_log`.
7. The log is Base64-decoded and parsed line by line. Each line must have at
   least five whitespace-separated fields, a numeric PCR index, and a
   `<algorithm>:<hash>` field that splits in two. At most 100,000 lines.
8. Each entry's `template_hash` is **recomputed** from that line's `file_hash`
   and `file_path`; the value written in the log is discarded.
9. The recomputed hashes are folded into a PCR chain and compared against the
   quoted PCR value, producing `ima_replayed`.
10. The `file_hash` values are looked up in `t_ref_value_detail`, producing
    `ima_rv_matched`.

**Step 4 — `ExportPolicyHandler`.** The built-in Rego policy maps the two
booleans to a trustworthiness score.

**Step 5 — `CustomPolicyHandler`.** Applies user policies named by
`policy_ids`. **If none are attached, nothing gates on steps 9 and 10.**

**Step 6 — `EvidenceResponseHandler`.** Builds an EAT, sets `status`, and signs
it as a JWT.

---

## 3. How GTA compares with CHARRA-v2

### 3.1 The decisive difference: two parties versus three

CHARRA-v2 separates three roles. GTA has two.

```
CHARRA-v2:   Attester  ->  Relying Party  ->  Verifier 1..N  (majority vote)
                              |
                              +-- appraises evidence independently
                              +-- redacts the log
                              +-- fans out to independent Verifiers

GTA:         Agent     ->  Server
                              |
                              +-- nonce issuer, sole verifier,
                                  policy engine and token issuer
```

In GTA the agent is its own HTTP client: it fetches a nonce, collects evidence,
and posts it to `/attest` from the same process. The server that receives the
evidence is also the only party that judges it. There is no second opinion and
no vote.

The agent does expose REST endpoints of its own (`/agent/v1/evidences`,
`/agent/v1/tokens`) that would allow something to pull evidence from it — the
shape a relying party would need. Nothing in the repository calls them.

### 3.2 Consequences of that difference

**Privacy.** CHARRA's Relying Party redacts the log before any Verifier sees
it. GTA has no component positioned between the agent and the server, so raw
evidence — including full filesystem paths — reaches the verifier unmodified.
There is no redaction code anywhere in the project.

**Independent appraisal.** CHARRA's RP performs a complete appraisal of the
Attester's evidence *before* forwarding anything, and each Verifier then
repeats the appraisal independently. The redundancy is deliberate. GTA
verifies once.

**Enforcement.** In CHARRA, appraisal *is* the verdict: a failed log replay or
a whitelist miss fails the attestation. In GTA the two IMA findings are
recorded in the token but do not by themselves determine `status`, which is
`pass` unless an attached policy explicitly fails.

### 3.3 Reference-value matching

Both systems check measured file hashes against a baseline, but they ask
different questions.

| | CHARRA-v2 | GTA |
|---|---|---|
| Baseline lives in | a JSON or flat-hash file on disk | rows in a database table |
| Read | on **every appraisal** | queried from the database |
| Matching key | **filename and hash together** | **hash only** |
| Can detect a known-good binary at an unexpected path | yes, reported as its own finding | no |
| Effect of a miss | fails the appraisal | sets a boolean in the token |

GTA's `t_ref_value_detail` table *does* store a `file_name` column, but the
lookup filters on `Column::Sha256` alone; the path is discarded before the
query is built. The information is present in the schema and unused at
matching time.

### 3.4 Summary table

| | CHARRA-v2 | GTA |
|---|---|---|
| Trust model | 3 parties, N Verifiers, majority vote | 2 parties, single verifier |
| Language | C | Rust |
| Attestation types | TPM 2.0 | TPM, CCA, virtCCA, iTrustee, Ascend NPU, DICE |
| Transport | CoAP/UDP, optional DTLS (PSK, RPK) | HTTP/HTTPS REST |
| Persistent state | flat files | SQLite / MySQL / PostgreSQL |
| Log redaction | yes, directory-level | none |
| Proof that redaction is honest | `/qualify`, TEE document, or ZK proof | not applicable |
| Policy engine | none — appraisal is the verdict | Rego, opt-in per submission |
| Output | signed verdict per Verifier | signed EAT/JWT token |

Neither design is simply better. GTA covers far more hardware and has the
operational machinery — a real database, versioned and multi-tenant baselines,
a policy language — that CHARRA lacks. CHARRA addresses a problem GTA does not
attempt: allowing a verifier to appraise a log without learning where the
measured files live.

---

## 4. Interoperability experiment: CHARRA-redacted evidence through GTA

### 4.1 Question

CHARRA's redaction rewrites the directory portion of every path and leaves the
filename in the clear. Would a completely independent verifier — one that has
never heard of CHARRA — still accept such a log and match it against a vendor
baseline?

### 4.2 Producing the redacted log

The input was `charra-ressources/evidence/evidence.txt`: 167 IMA measurement
entries from Huawei BTS3900/5900 base-station firmware. It was passed through
CHARRA's own redaction function, `charra_sdk_redact_ima_log()`, producing
`redacted_evidence.txt`. Each entry's n-ng field becomes

```
hex(SHA256(directory || salt)) | label | filename | NUL
```

so that, for example,

```
/usr/lib64/xtables/libxt_tcp.so
```

becomes

```
cb2df68a46c4c9493b596983d333ea78614987cc8cff46ddaaf7da21724355e5/libxt_tcp.so
```

The salt is fresh per entry and never transmitted. The content hash is copied
through unchanged, and the filename is preserved deliberately: it is what
allows a baseline to be matched at all.

### 4.3 Preparing GTA

Four pieces of setup were required.

**A TPM.** GTA's agent needs an attestation key in a TPM. An AK was created in
a software TPM simulator (RSA-2048, RSA-PSS with SHA-256), persisted at handle
`0x81010020`, and a certificate over its public key written to NV index
`0x150001b`, which is where the agent's code expects to find it.

**A trust root.** A CA was generated and its certificate registered with the
server through `POST /cert`, so the server would accept the AK certificate
chain.

**The baseline.** `NODE_evidence_baseline.json` — the vendor's published list
of known-good files — was converted into GTA's format,

```json
{"referenceValues": [{"fileName": "libxt_tcp.so", "sha256": "9c89d11f…"}, …]}
```

Base64-encoded and submitted through `POST /ref_value`. The server parsed it
and wrote one row to `t_ref_value` and 167 rows to `t_ref_value_detail`. The
stored rows were later read back out of the database and compared against the
source file: 156 unique `(fileName, sha256)` pairs on both sides, identical as
sets. (167 entries reduce to 156 unique pairs because the baseline lists some
files more than once, across its GSM, UMTS and LTE variants.)

It is worth being precise about what this means. GTA's verifier never reads
`NODE_evidence_baseline.json`. The file was an *import source*: it was uploaded
once, parsed, and turned into database rows. Verification afterwards queries
the database. The file is not present inside the server's container at all —
this was confirmed by searching its filesystem. This is the opposite of
CHARRA, which opens its baseline file from disk on every single appraisal.

**Pointing the agent at the redacted log.** One line of
`attestation_agent/conf/agent_config.yaml` was changed:

```yaml
- name: "tpm_ima"
  params:
    log_file_path: "/data/redacted_evidence.txt"   # was the kernel IMA path
```

No GTA source code was modified for this. The path was already a configuration
field; the agent's log collector opens whatever file it names.

### 4.4 Running it

GTA's own `attestation_cli` binary — built from source, unmodified — collected
evidence and submitted it:

```
attestation_cli -u test_01 evidence get -s ignore -o evidence.json -t tpm_ima
attestation_cli -u test_01 attest -f evidence.json -o token.json
```

Two facts confirm the agent really read the intended file. The bytes it placed
in the evidence payload were compared with `redacted_evidence.txt` on disk and
were **byte-for-byte identical** (35,823 bytes each). And the kernel IMA path
that the configuration previously named does not exist inside the container, so
had the change not taken effect the agent would have failed rather than
silently falling back.

### 4.5 Result

The server accepted the evidence and issued a signed token:

```json
{
  "status": "pass",
  "ueid": "charra-test-node-1",
  "tpm_ima": {
    "attestation_status": "pass",
    "ima_replayed": true,
    "ima_rv_matched": true,
    "pcrs": { "hash_alg": "sha256",
              "pcr_values": [ { "pcr_index": 10,
                                "pcr_value": "61885869d538970b…" } ] }
  }
}
```

All three findings are positive: the AK certificate chain and quote signature
verified, the log replayed to the quoted PCR value, and **all 167 redacted
entries matched the Huawei baseline held in GTA's database**.

Matching also succeeded without naming a baseline explicitly. When the
submission carries no `ref_value_id`, the server searches every baseline
registered for that user and attester type, and finds the same rows.

### 4.6 What this demonstrates

The redaction is **transparent to GTA**. Its verifier never noticed that the
directory portion of every path had been replaced by a commitment hash,
because the path plays no part in its reference-value matching: only
`file_hash` is used. A log whose paths read
`cb2df68a…55e5/libxt_tcp.so` is, from GTA's perspective, indistinguishable in
outcome from one that reads `/usr/lib64/xtables/libxt_tcp.so`.

This is a genuine interoperability result — CHARRA's privacy-preserving output
was consumed successfully by an unrelated vendor's attestation stack, with no
modification to that stack's code. It is also, read carefully, a comment on
GTA: the property that makes the redaction painless is the same property that
prevents GTA from telling a known-good binary at a legitimate path from the
same binary somewhere it does not belong.

### 4.7 Conditions and limitations

Three qualifications are necessary for the result above to be read correctly.

**The TPM state was constructed to match the redacted log.** A `template_hash`
is computed over the whole IMA record, which includes the path. Redaction
changes the path, so it necessarily changes every `template_hash`, and
therefore the PCR value the log replays to. For this experiment PCR 10 in the
simulator was extended using template hashes computed over the **redacted**
paths, so that the log and the quote agreed.

On real hardware this would not hold. The kernel extends PCR 10 as it measures
files, using the **original** paths, so a redacted log presented against a real
quote would not replay and `ima_replayed` would be false. **GTA cannot verify a
redacted log against genuine TPM state.** This is not a defect that a better
redaction function would fix: it follows from GTA comparing the log directly
against the attester's own quote.

CHARRA resolves this structurally rather than cryptographically. Its Relying
Party replays the redacted log into a *different* PCR on its *own* TPM and
signs a second quote over it, then proves separately — by the `/qualify`
handshake, a TEE document, or a zero-knowledge proof — that the redacted log
derives faithfully from the original. That second quote is precisely the piece
GTA has no place for, because it has no Relying Party.

**`ima_rv_matched` is advisory.** No Rego policy was attached to these
submissions, so `status` would have been `pass` even had the baseline check
failed. This was observed directly: an earlier run reported `ima_replayed:
false` and `ima_rv_matched: false` and still returned `status: pass`.

**Freshness was disabled.** `nonce_type` was `ignore`, which GTA treats as "no
nonce check". This was appropriate for an interoperability test but means the
runs carry no replay protection.

---

## 5. Additional observations about GTA's IMA verification

These were found while establishing the above, and each was confirmed by
experiment rather than by reading alone.

**The `template_hash` field in the log is ignored.** GTA recomputes it from the
line's own `file_hash` and `file_path`. Replacing the field on all 167 entries
with the constant `deadadad…` changed nothing: `ima_replayed` remained `true`.
This is a defensible design — recomputation binds the chain to the content
actually displayed — but it means the field is inert, and a corrupted log is
silently tolerated rather than reported. CHARRA checks the field and rejects a
mismatch.

**The PCR replay stops early, so appended entries are never verified.** The
replay loop exits as soon as the running value equals the quoted PCR:

```rust
if let Some(target) = target_value {
    if current_value == target { break; }
}
```

Because a hash chain only grows forward, anything after that point is parsed,
reported, and reference-checked, but never folded into the chain. Two entries
that no TPM ever measured were appended to an otherwise valid log; the server
returned `ima_replayed: true` and issued a signed token containing them. The
control confirms the mechanism: the *same* forged entry placed at the
*beginning* of the log broke the chain and produced `ima_replayed: false`.

Truncation remains infeasible — reaching the same PCR value at a different
point would require a hash collision — but appending is unrestricted. CHARRA
replays its entire log and compares the resulting composite once, with no early
exit.

**Reference-value matching is hash-only.** Established above; it compounds with
the previous point, since an appended entry needs only to carry some
known-good hash to be reported as matched, whatever path it claims.

---

## 6. Conclusion

GTA and CHARRA-v2 solve overlapping problems from different directions. GTA is
the broader system: more hardware backends, a real database, versioned
multi-tenant baselines, and a policy language. CHARRA is narrower but stricter
in the area it addresses — appraisal is the verdict rather than an annotation,
every check is repeated independently by several verifiers, and the log a
verifier sees has been stripped of information it does not need.

The experiment shows the two can meet: evidence redacted by CHARRA was accepted
and correctly matched against a vendor baseline by GTA's unmodified verifier.
It also shows the limit of that meeting. GTA accepted the redacted log only
because the TPM state had been constructed to match it; against genuine
hardware it could not, and closing that gap requires the second quote and the
binding proof that only a separate Relying Party can provide.
