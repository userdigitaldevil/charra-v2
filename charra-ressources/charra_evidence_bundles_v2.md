# The two evidence bundles, side by side

What the **Attester** hands the Relying Party, and what the **Relying Party** hands a Verifier. Same attestation, one cycle apart.

Every value below is real output from one run — `RP_VERIFIERS=1 RP_CYCLES=1 ./run_daemon.sh`, with `ima_test_logs.txt` as the Attester's measurement log. Nothing here is illustrative.

————————————————————————

## 1. At a glance

+——————--+—————————————+—————————————+
|                    | **Attester → RP** — `Evidence_a`    | **RP → Verifier** — `Evidence_r`    |
+====================+=======================================+=======================================+
| **Quote**          | `Quote_a` — 133 bytes               | `Quote_r` — 145 bytes               |
+——————--+—————————————+—————————————+
| signed by          | AK_a, the Attester's TPM              | AK_r, the RP's *own* TPM              |
+——————--+—————————————+—————————————+
| PCRs quoted        | **{0--7, 10}** — the boot chain     | **{23}** — the RP's replay register |
+——————--+—————————————+—————————————+
| nonce inside       | 20 B, **chosen by the RP**            | 32 B, **chosen by that Verifier**     |
+——————--+—————————————+—————————————+
| **Event log**      | `log_a` — 4728 B, **real paths**    | `log_r` — 4257 B, **paths hashed**  |
+——————--+—————————————+—————————————+
| **"Certificates"** | AK_a public key, 616 B `TPM2B_PUBLIC` | AK_r public key, 616 B `TPM2B_PUBLIC` |
+——————--+—————————————+—————————————+
|                    | *no certificate — see §5*           | *no certificate — see §5*           |
+——————--+—————————————+—————————————+

The Attester's raw `log_a` is **stripped** and never forwarded. `log_r` replaces it. That single substitution is the whole privacy mechanism.

————————————————————————

## 2. The quotes, decoded

Both are `TPMS_ATTEST` structures the TPM built and signed itself — the application never assembles the bytes.

+——————-+——————————————--+——————————————--+
| field             | `Quote_a`                                  | `Quote_r`                                  |
+===================+============================================+============================================+
| `magic`           | `0xff544347` — `TPM_GENERATED_VALUE`     | `0xff544347` — `TPM_GENERATED_VALUE`     |
+——————-+——————————————--+——————————————--+
| `type`            | `0x8018` — `TPM_ST_ATTEST_QUOTE`         | `0x8018` — `TPM_ST_ATTEST_QUOTE`         |
+——————-+——————————————--+——————————————--+
| `extraData`       | `f51af47ed1e57f96d1f43133b97246ca…` (20 B) | `34c40939307c994940719237899f7b5a…` (32 B) |
+——————-+——————————————--+——————————————--+
| PCR selection     | 0, 1, 2, 3, 4, 5, 6, 7, 10                 | 23                                         |
+——————-+——————————————--+——————————————--+
| `pcrDigest`       | `2b24614b17f7ac48f5081665fbc1bdc6…` (32 B) | `b1925d1800afc2e92a7617d0499cea06…` (32 B) |
+——————-+——————————————--+——————————————--+

Two things this table is meant to make obvious:

- `extraData` ***is* the nonce.** It is not a separate wire field — the TPM places the challenge inside the structure it signs. The two are different values *and different lengths*, because two different parties issued them: the RP challenged the Attester, and the Verifier challenged the RP.
- `magic` **is** `TPM_GENERATED_VALUE` **on both.** That constant can only appear in a structure a TPM produced, which is what separates `TPM2_Quote` from signing arbitrary bytes with `TPM2_Sign`.

————————————————————————

## 3. A whole log entry, before and after

An IMA entry has five parts, in this order:

    PCR | template_digest | template_name | file-content digest | pathname

Below are the first three entries of the Attester's log, each shown as the Attester produced it (`log_a`) and as the Verifier receives it (`log_r`). Same entry, same run.

**Entry 0**

    log_a  10 20b2d2a32a705a2c8495d351a5387d442b3505d2a7559996480060853f8fe9ff ima-ng sha256:0000000000000000000000000000000000000000000000000000000000000000 boot_aggregate
    log_r  10 93b5595d42092faefc47ca85461200b9a8584f7f73a84c67b3bfb0eccddc2042 ima-ng sha256:0000000000000000000000000000000000000000000000000000000000000000 155ea1af4e654040f2c35fb1d9f772b45a18048449bbfe6876bd5ae50ccf9133

+——————-+————————————+————————————-+
|                   | `log_a`                            | `log_r`                             |
+===================+====================================+=====================================+
| PCR               | 10                                 | 10                                  |
+——————-+————————————+————————————-+
| `template_digest` | `20b2d2a32a705a2c8495d351…`        | `93b5595d42092faefc47ca85…`         |
+——————-+————————————+————————————-+
| template          | `ima-ng`                           | `ima-ng`                            |
+——————-+————————————+————————————-+
| file digest       | `sha256:000000000000000000000000…` | `sha256:000000000000000000000000…`  |
+——————-+————————————+————————————-+
| path field        | `boot_aggregate`                   | `155ea1af4e654040f2c35fb1d9f772b4…` |
+——————-+————————————+————————————-+

**Entry 1**

    log_a  10 b82f92690571eb8f0b739e3ff99d21dd625d680cf7c976ae48824e04ad8bc104 ima-ng sha256:61cee375b05e8f2666a441322163788f470b2499d785d8d434ae5d68becfd541 /usr/lib/systemd/systemd
    log_r  10 b0c30a6d73544cf2d346fd8ef81a8f1a4a6324a60559c4f1d820068932fa7e6f ima-ng sha256:61cee375b05e8f2666a441322163788f470b2499d785d8d434ae5d68becfd541 4c28124bd3c470c77a11aaccda2ce1dd8c3eae8ca974830ad6988e690616dea8

+——————-+————————————+————————————-+
|                   | `log_a`                            | `log_r`                             |
+===================+====================================+=====================================+
| PCR               | 10                                 | 10                                  |
+——————-+————————————+————————————-+
| `template_digest` | `b82f92690571eb8f0b739e3f…`        | `b0c30a6d73544cf2d346fd8e…`         |
+——————-+————————————+————————————-+
| template          | `ima-ng`                           | `ima-ng`                            |
+——————-+————————————+————————————-+
| file digest       | `sha256:61cee375b05e8f2666a44132…` | `sha256:61cee375b05e8f2666a44132…`  |
+——————-+————————————+————————————-+
| path field        | `/usr/lib/systemd/systemd`         | `4c28124bd3c470c77a11aaccda2ce1dd…` |
+——————-+————————————+————————————-+

**Entry 2**

    log_a  10 c13322eacf6125ad462e483c199560ebf0ff04a02c387810a4752a2c232a4504 ima-ng sha256:0059699e84d5101ceb4c2f1535b2acfe59868f454eca4886cc29ddb69a772be6 /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
    log_r  10 9f606dca98d2c76b007e6ebf8284d089bdf1ef23334a4901b90b30a8ee38bd52 ima-ng sha256:0059699e84d5101ceb4c2f1535b2acfe59868f454eca4886cc29ddb69a772be6 a7676318ee3c6c12ad1fce0b024403f542c3a663f834ec0df0bb841e1303b21d

+——————-+—————————————————-+————————————-+
|                   | `log_a`                                            | `log_r`                             |
+===================+====================================================+=====================================+
| PCR               | 10                                                 | 10                                  |
+——————-+—————————————————-+————————————-+
| `template_digest` | `c13322eacf6125ad462e483c…`                        | `9f606dca98d2c76b007e6ebf…`         |
+——————-+—————————————————-+————————————-+
| template          | `ima-ng`                                           | `ima-ng`                            |
+——————-+—————————————————-+————————————-+
| file digest       | `sha256:0059699e84d5101ceb4c2f15…`                 | `sha256:0059699e84d5101ceb4c2f15…`  |
+——————-+—————————————————-+————————————-+
| path field        | `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1` | `a7676318ee3c6c12ad1fce0b024403f5…` |
+——————-+—————————————————-+————————————-+

Read down the columns rather than across. In every entry:

- **PCR, template name and file-content digest are identical.** The redaction touches none of them. Preserving the file digest is what keeps the RP's whitelist/blacklist check possible — it says *some* file hashed to this value, never where that file lives.
- **The pathname is replaced** by `SHA256(pathname ‖ salt)`, a fixed 32 bytes.
- `template_digest` **changes as a consequence**, because it must equal `SHA256(template_data)` and `template_data` now holds the redacted name.

Note what "pathname" means here: `ima-ng` has **one** name field, holding the complete path *including the filename* — `/usr/lib/systemd/systemd` is a single string. The hash covers all of it. Nothing is split at the last `/`, so the Verifier learns neither the directory nor the file, and cannot tell that two entries live in the same directory.

### The ten paths, and why they matter

The full set of pathnames in the first ten entries:

+——————-+—————————————————————+——————-+
| \#                | pathname in `log_a`                                           | bytes             |
+==================:+===============================================================+==================:+
| 0                 | `boot_aggregate`                                              | 15                |
+——————-+—————————————————————+——————-+
| 1                 | `/usr/lib/systemd/systemd`                                    | 25                |
+——————-+—————————————————————+——————-+
| 2                 | `/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1`            | 49                |
+——————-+—————————————————————+——————-+
| 3                 | `/usr/lib/aarch64-linux-gnu/systemd/libsystemd-core-259.so`   | 58                |
+——————-+—————————————————————+——————-+
| 4                 | `/usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-259.so` | 60                |
+——————-+—————————————————————+——————-+
| 5                 | `/etc/ld.so.cache`                                            | 17                |
+——————-+—————————————————————+——————-+
| 6                 | `/usr/lib/aarch64-linux-gnu/libc.so.6`                        | 37                |
+——————-+—————————————————————+——————-+
| 7                 | `/usr/lib/aarch64-linux-gnu/libm.so.6`                        | 37                |
+——————-+—————————————————————+——————-+
| 8                 | `/usr/lib/aarch64-linux-gnu/libcrypt.so.1.1.0`                | 45                |
+——————-+—————————————————————+——————-+
| 9                 | `/usr/lib/aarch64-linux-gnu/libcrypto.so.3`                   | 42                |
+——————-+—————————————————————+——————-+

Read that column as an attacker would. Ten lines disclose the CPU architecture (**aarch64**), the init system, the exact library set, and **systemd 259** — specific enough to look up known vulnerabilities against that build. This is what must not reach a third-party Verifier, and it is why `log_a` stops at the RP.

Every one of them becomes the same fixed 32 bytes of digest, whatever its original length.

————————————————————————

## 4. `log_r` — the same log, cleaned

An `ima-ng` entry's `template_data` is two length-prefixed fields:

    u32 d_len | "<alg>" NUL <file-content digest>     the d-ng field
    u32 n_len | "<path>" NUL                          the n-ng field

Only the **path** is sensitive. Entry 0, before and after:

+———————-+————————-+—————————-+——————--+
| field                | `log_a`                 | `log_r`                    |                    |
+======================+=========================+============================+====================+
| `pcr_index`          | 10                      | 10                         | unchanged          |
+———————-+————————-+—————————-+——————--+
| `template_name`      | `ima-ng`                | `ima-ng`                   | unchanged          |
+———————-+————————-+—————————-+——————--+
| d-ng — file digest | `736861323536…`         | `736861323536…`            | **byte-identical** |
+———————-+————————-+—————————-+——————--+
| n-ng — the path    | `boot_aggregate` (15 B) | `c85c71e36e4cb9be…` (32 B) | **replaced**       |
+———————-+————————-+—————————-+——————--+
| `template_digest`    | `20b2d2a32a705a2c…`     | `71d51aa346557b37…`        | **recomputed**     |
+———————-+————————-+—————————-+——————--+

**The file-content digest survives on purpose.** On its own it says only that *some* file hashed to some value, never where that file lives — and keeping it is what makes the RP's blacklist check possible at all. Redacting it would throw away the appraisal without buying any privacy.

`template_digest` **has to be recomputed**, because it must equal `SHA256(template_data)` or the log fails its own self-consistency check.

### Why there is a salt

The replacement is `SHA256(path ‖ salt)`, with a **fresh 32-byte random salt per entry that is never transmitted**. Redacting the same log twice:

+—————————--+————————————-+
| run                         | entry 0's replacement               |
+=============================+=====================================+
| first                       | `98a07f3a897b44ce30501d26322aa41e…` |
+—————————--+————————————-+
| second                      | `e9c9ca904fc9a0c66ee4e9082db6e275…` |
+—————————--+————————————-+

Two consequences, both deliberate:

- **Irreversible against a dictionary.** An unsalted `SHA256(path)` is a fixed value anyone can precompute for `/usr/lib/systemd/systemd`; the whole log would reverse in seconds.
- **Not correlatable.** Two entries with the *same* path redact differently, so a Verifier cannot count or link repeated paths.

The one exception is the RP qualification handshake, where the Verifier *does* send its salt — because both sides must produce byte-identical output on a challenge log the Verifier fabricated itself. Safe only because that log is synthetic. Real evidence is always redacted with a fresh salt.

### The consequence that shapes the whole protocol

Because `template_digest` is recomputed, `log_r` **can never replay to the Attester's sealed** `pcrDigest` — mathematically, not by policy. The Attester's TPM is therefore not in the Verifier's chain of trust for the PCR 10 property. Something else has to vouch for the redacted log, and that is exactly what `Quote_r` is: the RP replays `log_r` into PCR 23 of its own TPM and quotes it. The guarantee becomes *"the RP vouches for this, anchored by the RP's own TPM."*

————————————————————————

## 5. "Certificates" — there are none

**In this PoC each entity simply sends its AK public key.** That 616-byte `TPM2B_PUBLIC` in either column *is* the identity claim. There are no certificates anywhere in the implementation — no EK certificate, no AK certificate, no CA, no chain, no expiry, no revocation, nothing provisioned at runtime.

What stands in for them is one file, `keys/trusted_keys.txt`, holding the two public keys under `# attester` and `# relying-party`. The rule is exactly:

> A signing key is trusted **if, and only if, it appears in this file.**

The Verifier checks both bundles with the same call and no role argument, so the lookup answers only *present or absent* — anything in that file is accepted as AK_a **and** AK_r. That is why the Verifier's verdict-signing key lives in its own file instead.

**What this establishes:** that a signature came from a key someone put in the file. **What it does not:** that either key lives in a TPM. Both genuinely are TPM primaries, but nothing checks that at runtime. In a real deployment `TPM2_MakeCredential` / `ActivateCredential` proves that binding against an EK certificate; here the file's existence asserts it. The substitution is "assume the key was vouched for out of band" — fine for a proof of concept, deliberately not for a deployment.

Two practical consequences:

- **The anchor is generated, never committed.** Each key is *derived* from its own TPM's owner-hierarchy seed, so wiping either `NVChip` changes it and invalidates the file. `run_daemon.sh` regenerates it after every reset.
- `provision_trusted_keys --role` **is a security boundary.** Without it one run emits *both* identities from whichever TPM it is pointed at, putting a key the RP's own TPM can derive into the `attester` entry — and since `TPM2_Quote` accepts restricted and unrestricted keys alike, the RP could then issue genuine quotes that pass. One TPM, one role, one key.

Finally, a note on the certificate that does not exist: were the Attester's EK certificate ever added, it **must stop at the RP**. It is a permanent unique identifier for that physical TPM, and forwarding it to every Verifier would leak a stronger identifier than any path redaction protects.

————————————————————————

## 6. Reproducing the numbers

    RP_VERIFIERS=1 RP_CYCLES=1 ./run_daemon.sh

The log sizes and the redaction come from `ima_test_logs.txt` through `charra_sdk_redact_ima_log()`. The quote fields were read from a live cycle by decoding the `TPMS_ATTEST` in `msg_rp_evidence_dto`'s `attestation_data` and `rp_attestation_data`.
