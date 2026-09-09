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
  evaluates policy, and issues signed tokens. Its `verifier/` subdirectory
  builds **dynamic libraries** (`crate-type = ["rlib", "dylib"]`) that the one
  service process loads at runtime from paths named in `server_config.yaml` —
  `/usr/lib64/libtpm_ima_verifier.so` and seven siblings, all present in the
  running container next to the 35 MB `attestation_service` binary. They are
  plugins inside a single process, **not separately deployable services**: the
  project's Compose file defines two services in total, the service itself and
  an optional `key_manager`.
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
   and `file_path`; the value written in the log is discarded. The one
   exception is an all-zero field, IMA's marker for a file it could not
   measure, which is preserved and later replayed as all-`f` — the same
   convention the kernel follows.
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
entries. The attribution to Huawei BTS3900/5900 base-station firmware comes
from the accompanying baseline rather than from independent analysis —
`NODE_evidence_baseline.json` declares `"productName": ["BTS3900", "BTS5900"]`,
version `BTS3900_5900 V100R022C10SPC050`, under a 2018 Huawei copyright — and
every one of the log's 167 entries matches that baseline on filename and
content hash, with none unmatched. The measured paths are consistent with it:
`GRAT_`, `URAT_` and `LRAT_` prefixes for the GSM, UMTS and LTE radio access
technologies, `ubbp_l2bbmng.so` for the baseband processing unit, and a
`WEBLMT` maintenance-terminal image. The log was passed through
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

**What the redaction costs.** Measured directly over **100 consecutive calls**
on this log (`bin/test_redaction_bench`, linking the same objects a run uses):

| **Commitment** | **Whole log (167 entries)** | **Per entry** | **`log_r`** |
|---|--:|--:|--:|
| SHA-256 — the default, used for this experiment | **1.071 ms ± 0.180** | **0.0064 ms** | 29,644 B |
| Poseidon — `--trust-mode=zk` only | **383.448 ms ± 3.895** | **2.2961 ms** | 29,644 B |

The `log_r` column is the redacted log in CHARRA's **binary** event-log form,
which is what the function returns and what the RP replays into its TPM (`log_a`
is 27,986 bytes in the same form). Rendered back out as an ASCII IMA log — the
shape `redacted_evidence.txt` is stored in, and the shape GTA's attester reads
and Base64-encodes — the same 167 entries occupy 35,823 bytes. Both commitments
give the same size, since each is 32 bytes before hex.

Redaction is therefore not a meaningful cost in itself: a whole 167-entry log
is rewritten in about a millisecond. What it *forces* is expensive. Because the
redacted log no longer replays to the Attester's PCR, the RP must replay it into
its own TPM to obtain a second quote, one `TPM2_PCR_Extend` round trip per
entry:

| **Operation** | **Who performs it** | **Whole log (167 entries)** | **Per entry** |
|---|---|--:|--:|
| Software replay — recompute the chain and compare | GTA's server; CHARRA's Verifiers | **0.065 ms ± 0.012** | **0.0004 ms** |
| TPM replay — `TPM2_PCR_Extend` per entry | CHARRA's RP only | **14,159 ms ± 37** | **84.79 ms ± 0.22** |

The two differ by a factor of roughly **218,000**, and the reason is that they
are not the same task.

*Verifying* a log means recomputing its hash chain and comparing the result
with a value that has already been signed. That is arithmetic; it needs no TPM.
It is what GTA's server does — the server links no TPM library at all, only the
agent does — and it is also what each CHARRA Verifier does. At 0.065 ms for the
whole log, verification is effectively free on both sides. §5 gives the server's
actual fold, and why replaying in software rather than in a TPM is the right
choice for a verifier rather than a shortcut.

CHARRA's Relying Party is not verifying. It is *producing a new attestation*.
Redaction changes every `template_hash`, so `log_r` no longer replays to the
Attester's PCR; the RP must therefore extend the redacted log into a PCR on its
own TPM and sign a fresh quote over the result. That needs real hardware and one
round trip per entry. The 14 s is the price of the second quote — roughly
**13,000 times** the redaction that necessitates it, and about 218,000 times
what checking the result costs. GTA has no equivalent line because it does not
redact.

It is also why this does not reach a real IMA log: at ~85 ms an entry, with the
per-entry cost flat in log length, several thousand entries would take minutes.

**GTA's agent never extends the IMA log at all.** It does use a TPM — that is
what its `tss-esapi` dependency is for — but only to *read* and to *quote*. Its
entire repertoire of TPM operations is `tr_from_tpm_public` to load the AK
handle, `read_public` for its public area, `nv_read_public` and `nv_read` to
retrieve the AK certificate, `pcr_read` to report the current values, and one
`quote`. Every one of those is a read or a signature. There is no `pcr_extend` anywhere
in the agent, and that is not an omission: on a real machine the **kernel**
extends PCR 10 through IMA as it measures each file, long before any
attestation runs. By the time the agent is asked for evidence the PCR already
holds the right value, so the agent simply signs over it. The cost of extending
is real but it is paid by the operating system during normal execution, not by
the attestation.

This is what makes the manual PCR extension described in §4.8 the artificial
step in this experiment. Nothing in GTA extends a PCR, so nothing in GTA could
have produced a PCR 10 matching a redacted log; that state had to be
constructed by hand. And it is the same fact that makes CHARRA's Relying Party
expensive: it *cannot* rely on the kernel, because the log it needs attested is
one the kernel never measured.

Note that this is the **IBM TPM 2.0 software simulator** reached over `mssim`,
not a discrete hardware TPM, and it runs inside the emulated container
described below. The cost is dominated by per-extend round trips to an emulated
process rather than by cryptography, so hardware would plausibly be faster.

*Conditions.* Apple M4 Pro (8 performance + 4 efficiency cores), 24 GiB RAM,
macOS 26.6.2 on `arm64`; Docker Desktop 29.6.2 with 12 CPUs and 7.75 GiB
available. CHARRA runs in a `linux/amd64` image and is therefore **emulated on
this host** (`uname -m` reports `x86_64` inside the container), so these figures
are emulated rather than native. gcc 9.4.0, Ubuntu 20.04.6 LTS. Mean ± sample
standard deviation over 100 iterations.

### 4.3 The protocol, end to end

The sequence that was actually performed, in order. Steps 1–3 happen inside
CHARRA; steps 4–10 happen inside GTA. Every artifact named below is on disk, in
`charra-ressources/evidence/` or in `gta-run-output/`.

```
  CHARRA                                              GTA
  ------                                              ---
  evidence.txt          (vendor, 497 wrapped lines)
       │ 1. unwrap
       ▼
  ima_test_logs.txt     (167 lines, 34,165 B)
       │ 2. charra_sdk_redact_ima_log()
       ▼
  redacted_evidence.txt (167 lines, 35,823 B) ─────┐
       │                                           │ mounted at
       │ 3. an RP run emits the same artifact      │ /data/redacted_evidence.txt
       ▼    via --redacted-log-out                 │
  redacted_ima_logs.txt                            │
                                                   ▼
   4. TPM simulator + AK ──▶ 5. extend PCR 10 from the redacted template hashes
                                        │
   6. POST /cert  ──▶  7. POST /ref_value (NODE_evidence_baseline.json)
                                        │
   8. agent_config.yaml: log_file_path ─▶ /data/redacted_evidence.txt
                                        │
   9. attestation_cli evidence get ──▶ attest ──▶ 10. token: status "pass"
```

**Step 1 — unwrap the vendor log.** `evidence.txt` as supplied is hard-wrapped
at 81 columns: its 167 measurement entries occupy 497 physical lines, each entry
spanning two or three of them. Every consumer downstream is line-oriented —
CHARRA's ASCII reader, GTA's agent, GTA's parser — so the file was rewritten one
entry per line as `ima_test_logs.txt` (167 lines, 34,165 B). No field changed;
only the line breaks did. The vendor's own field layout was kept exactly:

```
pcr_index  template_hash  ima-ng  alg:file_hash  path
```

with **no `PCR` prefix** in front of it. That detail matters for this experiment
and not only for CHARRA: GTA's parser splits each line on whitespace and reads
`parts[0]` as a `u32` PCR index
([measurement_log.rs:461-470](evidence/global-trust-authority/attestation_server/verifier/common/src/measurement_log.rs#L461-L470)),
so a prefixed line would fail on `u32::from_str("PCR")` and be rejected at their
end too — and a prefix would shift every subsequent field by one besides.

**Step 2 — redact with CHARRA.** `ima_test_logs.txt` was passed through
`charra_sdk_redact_ima_log()`, producing `redacted_evidence.txt` (167 lines,
35,823 B) in the n-ng form given in §4.2. The `pcr_index`, `ima-ng` and
`alg:file_hash` fields pass through untouched; the filename passes through
untouched; only the directory is replaced, by a fresh-salted commitment, and the
`template_hash` is recomputed over the rewritten record.

**Step 3 — the RP emits the same artifact in a live run.** The file above was
produced by calling the redaction function over the log directly. CHARRA's
Relying Party now writes the identical artifact as a side effect of an ordinary
cycle: `--redacted-log-out=PATH` (default `redacted_ima_logs.txt`) makes it dump
`log_r` in ASCII IMA form immediately after redacting it and before replaying it
into its own TPM ([rp_evidence.c](../src/rp/rp_evidence.c)). Running
`./scripts/run_daemon.sh` over the same 167-entry log reproduces it.

One field differs between the two, and it is worth stating rather than glossing.
`redacted_evidence.txt` carries **40-hex** `template_hash` values, because it was
redacted straight from the vendor file and CHARRA's redaction preserves whatever
digest width it finds — the vendor's are 20-byte SHA-1. `redacted_ima_logs.txt`
carries **64-hex** values, because in a live run the Attester rebuilds each
`template_data` and recomputes `template_digest` as SHA-256
([attester_ima_log.c:150-154](../src/attester/attester_ima_log.c#L150-L154)),
which is why it is 39,831 B against 35,823 B for the same 167 entries. Entry
count, file hashes, filenames and commitment scheme are identical. The 40-hex
file is the one that went to GTA.

**Step 4 — give GTA's agent a TPM and an AK.** GTA creates no signing key and
ships no provisioning code (§4.4), so the key was made by us, inside a software
TPM simulator, before any GTA process started:

```bash
export TPM2TOOLS_TCTI="mssim:host=gta-tpm-sim,port=2321"
tpm2_createprimary -C o -c primary.ctx -G rsa2048 -g sha256
tpm2_create -C primary.ctx -G rsa2048:rsapss:null -g sha256 -u ak.pub -r ak.priv \
  -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign"
tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx
tpm2_evictcontrol -C o -c ak.ctx 0x81010020      # pin it at the configured handle
tpm2_readpublic  -c 0x81010020 -f pem -o ak_pub.pem   # export the PUBLIC half only
```

The attribute string is the point: `fixedtpm|fixedparent` means the TPM will
never release the private half, to us or to anyone. `tpm2_createprimary` does
not create a key on the host and load it in — it instructs the TPM to derive one
from its own seed, so the private half is born inside and stays there.
`tpm2_readpublic` is the only export, and it exports the public key.

**Step 4b — a CA, and a certificate over the AK's public half.**

```bash
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -out ca.crt -days 3650 -sha256 \
  -subj "/CN=CHARRA-GTA-Test-Root-CA"                       # self-signed root

openssl req -new -newkey rsa:2048 -nodes -keyout throwaway.key -out throwaway.csr \
  -subj "/CN=charra-test-node-1"
openssl x509 -req -in throwaway.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -force_pubkey ak_pub.pem -out ak_cert.pem -days 365 -sha256
```

`-force_pubkey` is what makes this correct: the CSR's own keypair is a throwaway
that exists only because `openssl x509 -req` requires a CSR, and the certificate
that comes out carries **the TPM's** public key, not the throwaway's. Both
checks were run and passed — `openssl verify -CAfile ca.crt ak_cert.pem` → `OK`,
and the certificate's public key compared byte-for-byte against `ak_pub.pem` →
identical.

**Step 4c — store the certificate where the agent looks for it**, NV
`0x150001b`, in DER:

```bash
openssl x509 -in ak_cert.pem -outform DER -out ak_cert.der
SIZE=$(wc -c < ak_cert.der)
tpm2_nvdefine 0x150001b -C o -s $SIZE -a "ownerwrite|ownerread|authread|authwrite"
tpm2_nvwrite  0x150001b -C o -i ak_cert.der
```

**Step 5 — construct PCR 10 to match the redacted log.** The 167 redacted
`template_hash` values were recomputed from `redacted_evidence.txt` and extended
into the simulator's PCR 10, one `tpm2_pcrextend` per entry, so that the log and
the quote GTA's agent would later produce agreed:

```bash
# hashes written to gta-run-output/pcr_extends.txt, then:
while IFS= read -r h; do tpm2_pcrextend "10:sha256=$h"; done < pcr_extends.txt
```

Note what this step is and is not. It sets the TPM's *state*; it does not touch
the quote. The agent, run in step 9, produced its own quote over this PCR and
signed it with its own AK, and the server verified that signature normally.
**This is the artificial step of the experiment**, and §4.8 explains why: on real
hardware the kernel extends PCR 10 from the *original* paths, so no redacted log
could ever replay against a genuine quote.

**Step 6 — register the CA as a trust anchor.** Only the **CA** certificate is
submitted. The AK certificate is never POSTed — it lives in NV and travels
inside every attestation request.

```bash
curl -X POST -H "Content-Type: application/json" -H "User-Id: test_01" \
  -d '{"name":"charra-gta-test-root-ca","type":["tpm_ima"],
       "content":"-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----\n"}' \
  http://<server>:8080/global-trust-authority/service/v1/cert
```

`content` is `ca.crt` as raw PEM — note that `/cert` accepts raw text, whereas
`/ref_value` and `/policy` both require Base64. `type` scopes the anchor to a
subsystem; the accepted values are `refvalue`, `policy`, `tpm`, `tpm_boot`,
`tpm_ima`, `crl` and `ascend_npu`. Nothing secret is transmitted: a certificate
carries only a public key, and `ca.key` never leaves our side.

This one call is what establishes trust, and it does so by *installation* rather
than proof — the server believes the CA because we told it to. Verification then
runs the other way at attestation time, each step resting on the one below:

```
  the log replays to the quoted PCR
      ↑ a PCR value alone could be invented, so —
  that PCR value sits inside a signed quote
      ↑ any key can sign, so —
  the signature verifies under the public key in the AK certificate
      ↑ anyone can mint a certificate, so —
  the AK certificate carries the CA's signature
      ↑ any CA could have signed, so —
  that CA certificate is in the trust anchor store — because step 6 put it there
```

The chain walk itself (`verify_cert_chain`) climbs one hop at a time and every
hop must come out of the database: it reads the certificate's `issuer` name,
queries the stored anchors for that name — scoped by `user_id` and `cert_type` —
and then verifies cryptographically with `agent_cert.verify(&parent_pub_key)`.
The name only selects candidates; OpenSSL decides. It repeats until reaching a
self-signed root.

**Step 7 — import `NODE_evidence_baseline.json` into GTA's database.** The
vendor baseline is not in GTA's format, so its `products[].ccFiles[]` entries
were projected onto the pair GTA stores:

```python
refs = [{"fileName": cc["fileName"], "sha256": cc["sha256"]}
        for prod in data["products"] for cc in prod["ccFiles"]]
```

That document was Base64-encoded and posted:

```bash
curl -X POST -H "Content-Type: application/json" -H "User-Id: test_01" \
  -d '{"name":"charra-gta-baseline","attester_type":"tpm_ima",
       "content":"<base64>","content_type":"base64"}' \
  http://<server>:8080/global-trust-authority/service/v1/ref_value
```

The server parsed it and wrote **one row to `t_ref_value` and 167 rows to
`t_ref_value_detail`**. From this point the baseline lives in the database; the
JSON file plays no further part (§4.4).

**Step 8 — point GTA's agent at the redacted log.** One line of
`agent_config.yaml`, shown in §4.4. No GTA source code was changed.

**Step 9 — collect and submit.** GTA's own unmodified CLI:

```bash
attestation_cli -u test_01 evidence get -s ignore -o evidence.json -t tpm_ima
attestation_cli -u test_01 attest -f evidence.json -o token.json
```

The agent read `/data/redacted_evidence.txt`, Base64-encoded it into
`evidence.logs[0].log_data`, took a quote over PCR 10, and posted both.

**Step 10 — read the token.** The server verified the chain and quote, replayed
the log against the quoted PCR, matched every entry against the rows from step
7, and issued a signed EAT. Decoded in §4.6: `ima_replayed: true`,
`ima_rv_matched: true`, `status: "pass"`.

The remaining subsections give the detail behind steps 4–10 and the conditions
under which the result should be read.

### 4.4 Preparing GTA

Five pieces of setup were required.

**A TPM and an attestation key — supplied entirely by us.** GTA's agent does
not create its signing key. Its configuration names two *locations* and expects
both to be populated already:

```yaml
ak_handle:   0x81010020   # a persistent object handle inside the TPM
ak_nv_index: 0x150001b    # an NV index inside the TPM, holding its certificate
```

Neither is a file path. `0x81010020` is an address in the TPM's own persistent
storage, and the agent reaches it with `tr_from_tpm_public` — "give me a handle
to the object already persisted here". If nothing is there the call fails; there
is no create-on-demand path. The private key is never read: the agent passes the
handle to `ctx.quote(...)` and the TPM signs internally, so the key never enters
the agent's memory, a file, or the network.

**GTA ships no provisioning code at all.** Searching the whole repository — every
file type, not only Rust — finds no `tpm2_createprimary`, `tpm2_evictcontrol`,
`tpm2_nvdefine`, `tpm2_nvwrite` or `tpm2_createak`, and none of the twelve shell
scripts it does ship provisions a key. This is deliberate, and their own
documentation says so: the user guide describes `ak_handle` as *"Attestation Key
handle, **Need to create in advance**"*, citing the TCG handle registry, and
points at the TCG device-identity specification for obtaining an IAK
certificate. Their docs also discuss matching `signature_alg` to "the signing
algorithm of the ak_handle" — phrasing that only makes sense if the key was
created before GTA ever ran.

So the following was done by us, with `tpm2-tools`, before any part of GTA
started: an AK was created in a software TPM simulator (RSA-2048, RSA-PSS with
SHA-256), persisted at `0x81010020` with `tpm2_evictcontrol`, and an X.509
certificate over its public key written to NV `0x150001b` with `tpm2_nvwrite`.
This was not a workaround for a limitation; it is a precondition GTA places
outside its own scope, on the assumption that a real node's AK arrives from
manufacture or an enterprise PKI.

**A trust root — and the distinction between the two certificates.** Two
different X.509 certificates are involved, and only one of them is ever
submitted to the server.

| | **AK certificate** | **CA certificate** |
|---|---|---|
| Whose public key it carries | the attester's AK | the CA's own signing key |
| Where it is stored | inside the TPM, NV `0x150001b` | GTA's database |
| How the server obtains it | arrives inside **every** attestation request, in `evidence.ak_certs` | POSTed **once**, at setup |
| Registered via `POST /cert`? | **no** | **yes** |

A CA was generated (ours, not GTA's), the AK certificate above was signed with
it, and **only the CA certificate** was registered:

```bash
curl -X POST -H "User-Id: test_01" \
  -d '{"name":"charra-gta-test-root-ca","type":["tpm_ima"],"content":"<PEM>"}' \
  .../v1/cert
```

That one call means "trust anything this CA signed". The AK certificate is never
POSTed: the agent reads it out of NV on every run and ships it in the evidence,
and `verify_cert_chain` walks upward from it — "who signed you?", look that
issuer up in the database, verify, repeat — until it reaches a self-signed root
it holds. The server then extracts the public key from the AK certificate and
checks the quote signature with it. No private key is transmitted at any point.

One property of that check is worth recording, because it is not obvious from
the API. The server validates **only** that a presented certificate chains to a
registered CA. It does not tie a certificate to a particular node: the
`node_id` parameter is threaded down as far as `verify_cryptographic` and there
carries the name `_node_id`, with the comment *"currently unused, reserved for
future use"*. Any key whose certificate chains to a registered CA is therefore
accepted as a legitimate attester, whatever node identifier accompanies it.

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

**Making the server reachable.** Two settings in
`attestation_server/conf/.env` were changed for a local container deployment:
`COMMUNICATION_PROTOCOL` from `1` to `0`, selecting plain HTTP because the
HTTPS path expects certificates that the optional `key_manager` service would
provision; and `ATTESTATION_ADDRESS` (with `SCHEDULE_TASK_ADDRESS`) from
`127.0.0.1` to `0.0.0.0`, because binding to the container's own loopback makes
the published port unreachable from outside it. Neither affects verification.

**Pointing the agent at the redacted log.** In
`attestation_agent/conf/agent_config.yaml`, the `tpm_ima` plugin was enabled,
its TCTI set to the simulator, and its log source changed:

```yaml
- name: "tpm_ima"
  enabled: true
  params:
    tcti_config: "mssim"
    log_file_path: "/data/redacted_evidence.txt"   # was the kernel IMA path
```

**No GTA source code was modified at any point in this experiment.** Every
change above is a configuration file — one `.yaml` and one `.env`. The log
path was already a configuration field; the agent's collector opens whatever
file it names, reads it line by line without interpreting it, and Base64-encodes
the bytes into the evidence payload.

### 4.5 Running it

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

**Two levels of use, deliberately separated.** GTA's verifier was exercised
both as *library code* and as a *running service*, because the two answer
different questions.

The first is a direct call into their crate, with no server and no HTTP: a Rust
test links `common_verifier` and hands the redacted log to the same parser entry
point the service uses.

```rust
use common_verifier::ImaLog;
let ima_log = ImaLog::new(&encoded, "sha256").expect(...);
```

It reports `input: 167 non-empty lines → parsed 167 entries`, isolating "does
their parser accept this format" from every other consideration — no TPM, no
quote, no certificate chain.

The second is the deployed service, and **every substantive result in this
document comes from it**: the container runs the `attestation_service` binary
with the eight verifier plugins loaded, and evidence enters over HTTP. Two paths
were used to submit it — through GTA's own agent as shown above, and by POSTing
hand-built JSON directly to `/attest` for cases the agent would never produce,
such as the tampered logs of §5.

**What was supplied by us, and what GTA performed.** The distinction matters for
reading the result, since the interoperability claim rests on GTA's own code
doing the verification.

| Step | Performed by |
|---|---|
| Create the AK, persist it at `0x81010020` | **us** — `tpm2_createprimary`, `tpm2_evictcontrol` |
| Sign an AK certificate and write it to NV `0x150001b` | **us** — our CA, `tpm2_nvwrite` |
| Redact `evidence.txt` into `redacted_evidence.txt` | **us** — CHARRA's `charra_sdk_redact_ima_log()` |
| Extend PCR 10 from the redacted template hashes | **us** — `tpm2_pcrextend` (the artificial step; §4.8) |
| Register the CA as a trust root | us, through **GTA's** `POST /cert` |
| Import the baseline as reference values | us, through **GTA's** `POST /ref_value` |
| Read the AK, quote PCR 10, assemble evidence | **GTA's agent**, unmodified |
| Validate the certificate chain and quote signature | **GTA's service**, unmodified |
| Replay the log, match against the baseline, issue the token | **GTA's service**, unmodified |

The upper rows are inputs and preconditions. Every appraisal step — the part the
experiment is actually about — is GTA's own code, and no GTA source file was
modified at any point.

### 4.6 Result

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

### 4.7 What this demonstrates

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

### 4.8 Conditions and limitations

Three qualifications are necessary for the result above to be read correctly.

**The TPM state was constructed to match the redacted log.** A `template_hash`
is computed over the whole IMA record, which includes the path. Redaction
changes the path, so it necessarily changes every `template_hash`, and
therefore the PCR value the log replays to. For this experiment PCR 10 in the
simulator was extended using template hashes computed over the **redacted**
paths, so that the log and the quote agreed.

Precisely what was and was not done here matters, because the two are easy to
conflate and only one of them would invalidate the result.

*What was done.* The 167 template hashes were recomputed from the redacted
paths and extended into PCR 10 of the TPM simulator with `tpm2_pcrextend`, one
call per entry, **before** the agent was run.

*What was not done.* The agent was not handed a quote. It produced its own,
genuinely signed by its AK inside that simulator, and the server verified that
signature against the CA chain registered in step 6. That gate fails closed
(§2, step 3a), so `status: "pass"` is not reachable with a fabricated quote.
The quote is real, the signature is real, and the agent ran unmodified and
unaware.

The manipulation was therefore **upstream of the quote, not inside it**. The TPM
was placed in a state in which an *honest* quote would happen to agree with the
redacted log. Stated another way, the experiment simulated a machine whose
kernel had measured the redacted paths — and that machine cannot exist.

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

The comparison is worth drawing exactly, because the manual step above is
*mechanically the same operation* CHARRA's RP performs automatically — take
`log_r`, extend it entry by entry into a PCR, quote the result. It is the
14,159 ms measured in §4.2. What differs is whose TPM receives it:

| | Whose TPM receives `log_r` | What the resulting quote proves |
|---|---|---|
| CHARRA's Relying Party | a **second** party's, in a different trust domain from the Attester | that the RP holds `log_r`, with `/qualify`, a TEE document or a ZK proof separately binding `log_r` to the Attester's `log_a` |
| This experiment, against GTA | the agent's **own**, the same one it quotes from | only that a PCR set by hand holds the value set by hand |

In CHARRA the extend happens somewhere other than where the log was produced,
and a distinct mechanism ties the two together. In the GTA run it happened in
the same TPM the agent quotes, with nothing binding it back to the kernel's
real measurements. Every cryptographic operation is valid in both cases; what
the GTA run severs is the chain of custody to the kernel.

Hence the narrow claim this experiment supports: **GTA's verifier accepts and
correctly matches CHARRA-redacted evidence** — its parser, its replay and its
baseline lookup all handle the format without complaint. It is not a claim that
GTA could verify redacted logs in production, which it structurally cannot.

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

**The service replays the log in software, not in a TPM — and this is the
correct design.** GTA's server performs no TPM operation of any kind on the
evidence it receives. It cannot: it links no TPM library at all. `tss-esapi`,
the Rust TSS binding, appears in exactly one manifest in the project, and it is
on the node side —

```
attestation_agent/attester/tpm/common/Cargo.toml:15:   tss-esapi.workspace = true
attestation_server/**                             :   (no match)
```

What the server does instead is fold the log's `template_hash` values together
with OpenSSL
([pcr.rs:356-391](evidence/global-trust-authority/attestation_server/verifier/tpm/common/src/pcr.rs#L356-L391)):

```rust
let mut current_value = hex::decode(initial_value)?;   // 32 zero bytes
for log_value in log_values {
    hasher.update(&current_value)?;                    // current ‖ template_hash
    hasher.update(&log_bytes)?;
    current_value = hasher.finish()?.to_vec();
}
```

That is arithmetically the same recurrence a `TPM2_PCR_Extend` implements,
`PCR ← H(PCR ‖ digest)`, computed in userspace. The result is compared against
the PCR digest inside the agent's signed quote, and that comparison is
`ima_replayed`.

This is worth stating plainly because it is easy to read as a shortcut on GTA's
part, and it is not. **Verifying** a log is arithmetic: you recompute a hash
chain and compare it with a value that hardware has already signed. The
hardware's involvement happened earlier, when it signed the quote. Re-doing the
folds inside a TPM would prove nothing additional and cost four orders of
magnitude more. CHARRA's Verifiers do the identical thing for the identical
reason.

The asymmetry is at CHARRA's Relying Party alone, and it is not a difference of
efficiency but of task — measured figures from §4.2:

| **Party** | **What it is doing** | **Where the fold happens** | **Whole log** | **Per entry** |
|---|---|---|--:|--:|
| GTA's server | verifying a log against an existing quote | software (OpenSSL) | 0.065 ms | 0.0004 ms |
| CHARRA's Verifiers | verifying a log against an existing quote | software (OpenSSL) | 0.065 ms | 0.0004 ms |
| CHARRA's Relying Party | **producing a new quote** over `log_r` | real TPM, one `TPM2_PCR_Extend` per entry | 14,159 ms | 84.79 ms |

The RP is the outlier because it is not checking an attestation, it is making
one. Redaction changes every `template_hash`, so `log_r` no longer replays to
the Attester's PCR; the RP must extend it into a PCR on its own TPM and sign
over the result. A signature over hardware-held state is, by definition, not
something software can produce. GTA has no equivalent row because it never
redacts, and so never needs a second quote — and no party in GTA extends a PCR
at any point, the agent included, since on real hardware the kernel has already
done it through IMA as each file was measured (§4.2).

**The `template_hash` field in the log is ignored.** GTA recomputes it from the
line's own `file_hash` and `file_path`, except where the field is all zeros
(see step 8). Replacing the field on all 167 entries
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
