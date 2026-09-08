# `zk/` — the zero-knowledge redaction proof

Everything here serves `--trust-mode=zk`. Nothing in this directory is
compiled by `make`, and none of it runs in the other two trust modes.

The design record is `ZK_REDACTION.md` at the repository root; what each
mechanism proves is in `charra-ressources/charra2-manual-v2.md`; what each
costs is in `charra-ressources/charra_measurements_v2.md`.

## What is here

| Path | Role |
|---|---|
| `circuit/` | The Noir circuit. `main.nr` is the statement being proved; `commit.nr` the Poseidon commitment; `template.nr` rebuilds `template_data`; `sha256_var.nr` a variable-length SHA-256. |
| `vk` | **Committed on purpose.** The verification key every Verifier checks proofs against. It must be the key for the circuit the RP proves with. |
| `proof_watcher.sh` | Runs in the prover container: watches `jobs/`, runs `bb`, writes results back. `run_daemon.sh` starts it. |
| `gen_prover_toml.py` | Turns a witness into the circuit's `Prover.toml`, padding to `N` and emitting `n_real`. Also the `--tamper` modes the soundness test uses. |
| `negative_test.sh` | **The soundness check.** Six tampered witnesses, each of which must be rejected, plus an honest one that must be accepted. |
| `poseidon_ref.py` | A reference Poseidon, used only to keep the circuit testable on its own. |
| `extract_poseidon_consts.py` | Regenerates `src/core/charra_poseidon_consts.h` from the circuit's library. Run only if that library changes. |
| `witness.json` | A captured 33-entry witness, so the circuit can be exercised without a live run. |
| `jobs/` | Transient RP↔prover queue. Gitignored: jobs carry the witness, which is secret. |
| `check_all_entries.sh`, `setup_bb.sh`, `test_watcher.sh`, `verify_binding_test.sh`, `probe*.sh` | Development scaffolding kept for reference. Not part of a run. |

## Running things by hand

All of it needs the prover image, since `bb` cannot run in the charra
container:

    ./docker/build-zk.sh          # once, about two minutes

Then, from the repository root, inside that image:

    docker run --rm --platform linux/arm64 -v "$PWD:/w" -w /w charra-zk:arm64 bash -lc '...'

### Check the circuit is sound

The single most useful command here. Six tampering cases, each of which the
circuit must reject:

    cd zk/circuit && nargo compile
    cd /w && ./zk/negative_test.sh

Expect `All tampering rejected; honest witness accepted.` A case that is
*accepted* means the circuit proves less than it claims.

### Regenerate `zk/vk` after changing the circuit

**Any edit to `circuit/` changes the verification key.** Until it is
regenerated, every proof is rejected — and the failure looks like a dishonest
RP rather than a stale key, so it is worth doing immediately:

    cd zk/circuit
    nargo compile
    bb write_vk -b target/charra_zk.json -o target
    cp target/vk ../vk

Then re-run `negative_test.sh`, and a live cycle:

    TRUST_MODE=zk RP_CYCLES=1 ./run_daemon.sh

### Change the entry ceiling

The circuit is compiled for at most `global N` entries — 167 by default. A
longer log cannot be proved. Raising it means editing three places that must
agree, then regenerating the key:

    zk/circuit/src/main.nr     global N
    zk/gen_prover_toml.py      MAX_N
    src/core/charra_zk.h       CHARRA_ZK_MAX_ENTRIES

Cost grows linearly: about 24,700 gates, 81 ms and 35 MiB of peak RAM per
entry. On a host giving Docker 7.75 GiB the ceiling is around 192 entries;
above that the prover is OOM-killed.

## One thing worth knowing before debugging

A proof that cannot be *checked* and a proof that is *invalid* are different
outcomes, and the Verifier says which. "the proof could not be checked" means
the prover container is not running; "INVALID" means the RP's redaction does
not match what the Attester measured. Both vote NO, but only the second is
evidence against the RP.
