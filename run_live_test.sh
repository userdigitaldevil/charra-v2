#!/usr/bin/env bash
# Full live end-to-end run: fresh TPM simulator state, clean rebuild,
# trust_manager + attester + 5 verifiers (ports 5684-5688) + relying_party,
# with DEBUG logging. Run this from the repo root, in a real terminal (it
# uses `docker run -it`, so it needs one).
#
# What it does, step by step:
#   1. Removes any leftover container named "charra" from a previous run
#      (docker run --name would otherwise refuse to start with a name
#      already in use).
#   2. Starts a fresh charra-dev-env container (same image docker-compose.yml
#      builds/uses), mounting this repo into /home/bob/charra, with
#      --group-add tss so the container user can talk to the TPM simulator
#      device group.
#   3. Inside the container: kills any stray bin/* processes and tpm_server
#      from a previous run, then starts TWO simulators -- one for the
#      Attester (:2321) and one for the RP (:2325), each in its own
#      directory so their NVChip files stay separate -- wiping both and
#      TPM2_Startup(CLEAR)ing each. Two genuinely cold, independent TPMs.
#   4. Rebuilds keys/trusted_keys.txt, reading each role's AK from ITS OWN
#      TPM, and drops qualified_rps.txt. Both are consequences of step 3:
#      an AK is derived from its TPM's hierarchy seed, so wiping NVChip
#      gives that role a new key. Against a stale trust anchor every
#      signature check then fails -- as "this key is not a trusted
#      identity", which reads like a rejected peer rather than a stale
#      file, so it is worth doing unconditionally. qualified_rps.txt goes
#      for the same reason: every fingerprint in it names an RP identity
#      that no longer exists.
#   5. Sanity-checks that PCRs 0-7 and 10 read back all-zero -- confirms the
#      TPM really is freshly reset before anything starts touching it.
#   6. Clean rebuild (make clean && make -j).
#   7. Wipes logs/ entirely and recreates it empty -- so logs/ always
#      reflects exactly this run, nothing left over from some earlier
#      one-off script with a different naming scheme (that's how
#      rp_run1.log/rp_run2.log/rp_run3.log/verifier_5684_restarted.log
#      ended up sitting there stale after unrelated scratch-test scripts).
#   8. Launches trust_manager, attester, and verifier instances on ports
#      5684-5688 (all 5, matching relying_party's own num_verifiers=1..5
#      benchmark loop -- with fewer than 5 real Verifiers running, that loop
#      hangs waiting on whichever ports aren't listening, see
#      CHARRA_V2_NOTES.md), all backgrounded with DEBUG logging to logs/.
#   9. Runs relying_party in the foreground (tee'd to logs/relying_party.log
#      too), which is the actual multi-verifier attestation run.
#      --benchmark is required, not cosmetic: relying_party's default mode
#      is now a daemon that loops until signalled, so without it this script
#      would never return. --benchmark runs the bounded 1..5-verifier sweep
#      and exits, which is what this script has always meant to do (and it
#      is what writes timings_RP_multi_verifiers.txt for
#      plot_multi_verifiers.py). For a bounded *daemon* smoke test instead,
#      swap it for e.g. --duration 120.
#
# Logs land in logs/*.log either way; Ctrl-C stops relying_party, the
# container itself is --rm'd on exit but the background bin/* processes
# inside it are not explicitly killed by this script if you Ctrl-C early --
# re-running the script kills them itself (step 3) before starting fresh.

set -e

docker rm -f charra >/dev/null 2>&1 || true

# Refuse to run while ANOTHER container has this same directory mounted.
# Removing the "charra" container above only handles our own leftovers; a
# container under any other name sharing this checkout shares logs/,
# keys/trusted_keys.txt and qualified_rps.txt too. Worse, its own TPM
# resets would rewrite the trust anchor underneath this run -- silently,
# surfacing only as unexplained attestation failures much later.
mine=${PWD%/}
others=""
for cid in $(docker ps -q); do
    cname=$(docker inspect -f "{{.Name}}" "$cid" 2>/dev/null | sed "s#^/##")
    for src in $(docker inspect -f "{{range .Mounts}}{{.Source}}{{println}}{{end}}" "$cid" 2>/dev/null); do
        if [ "${src%/}" = "$mine" ]; then
            others="$others $cname"
            break
        fi
    done
done
if [ -n "$others" ]; then
    echo "ERROR: these running containers already mount $mine:$others" >&2
    echo "They share logs/ and keys/ with this run and will corrupt it." >&2
    echo "Stop them first:  docker stop$others" >&2
    exit 1
fi

# -t only when there is a terminal, so this stays runnable from CI or a
# non-interactive shell (docker run -t without a TTY fails outright).
tty_flags=""
[ -t 0 ] && tty_flags="-it"

docker run -v "$PWD/:/home/bob/charra" $tty_flags --rm --init \
  --name charra --group-add tss \
  fraunhofer-sit/charra-dev-env:1.9.0 \
  bash -lc '
    set -e
    pkill -9 -f "^bin/" || true
    pkill tpm_server || true

    # One simulator per role, as on real hardware: each AK is derived by
    # the TPM of the role that owns it, from that TPM hierarchy seed.
    # Separate working directories, because tpm_server writes NVChip into
    # whatever directory it was started in.
    ATTESTER_TCTI="mssim:host=127.0.0.1,port=2321"
    RP_TCTI="mssim:host=127.0.0.1,port=2325"
    rm -rf /tmp/tpm_attester /tmp/tpm_rp
    mkdir -p /tmp/tpm_attester /tmp/tpm_rp
    (cd /tmp/tpm_attester && tpm_server -port 2321 > /tmp/tpm_server_2321.log 2>&1 &)
    (cd /tmp/tpm_rp       && tpm_server -port 2325 > /tmp/tpm_server_2325.log 2>&1 &)
    sleep 3
    TPM2TOOLS_TCTI="$ATTESTER_TCTI" tpm2_startup --clear
    TPM2TOOLS_TCTI="$RP_TCTI"       tpm2_startup --clear
    cd ~/charra

    echo "--- PCRs before anything starts (expect all zero, both TPMs) ---"
    echo "  attester TPM (:2321):"
    TPM2TOOLS_TCTI="$ATTESTER_TCTI" tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10
    echo "  RP TPM (:2325):"
    TPM2TOOLS_TCTI="$RP_TCTI" tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10

    cd ~/charra
    make clean
    make -j

    # Every fingerprint on file names an RP identity the reset above just
    # destroyed. Clearing them also means this run actually exercises the
    # /qualify handshake rather than coasting on a stale grant.
    rm -f qualified_rps.txt

    # Regenerate the trust anchor AFTER the TPM resets and BEFORE any role
    # starts -- see step 4 in the comment block at the top of this file.
    # This needs bin/provision_trusted_keys, hence after the build.
    ATTESTER_TCTI="$ATTESTER_TCTI" RP_TCTI="$RP_TCTI" ./keys/gen-trusted-keys.sh

    rm -rf logs
    mkdir -p logs

    # Regenerate verifiers_config.txt for exactly the five ports started
    # below. start_verifiers.sh writes this file too, so a previous
    # "./start_verifiers.sh 3" would otherwise leave a three-row config here
    # and the sweep would fail at 4 and 5 Verifiers with "Verifier ID not
    # found" rather than anything pointing at the config.
    for i in 1 2 3 4 5; do
      echo "$i 127.0.0.1 $((5683 + i))"
    done > verifiers_config.txt

    LOG_LEVEL_CHARRA=DEBUG bin/trust_manager > logs/trust_manager.log 2>&1 &
    LOG_LEVEL_CHARRA=DEBUG CHARRA_TCTI="$ATTESTER_TCTI" \
        bin/attester > logs/attester.log 2>&1 &
    for p in 5684 5685 5686 5687 5688; do
      LOG_LEVEL_CHARRA=DEBUG bin/verifier --port $p > logs/verifier_$p.log 2>&1 &
    done
    sleep 2

    LOG_LEVEL_CHARRA=DEBUG CHARRA_TCTI="$RP_TCTI" \
        bin/relying_party --benchmark 2>&1 | tee logs/relying_party.log

    # A log that is mostly NUL bytes means two processes shared the file:
    # one truncated it while the other held a descriptor at a large offset.
    # That is the fingerprint of a second instance running against this
    # checkout, and it invalidates the whole run -- so say so rather than
    # letting the timings look trustworthy.
    for f in logs/*.log; do
        if [ "$(wc -c < "$f")" -ne "$(tr -d "\0" < "$f" | wc -c)" ]; then
            echo "WARNING: $f contains NUL padding -- more than one process"
            echo "         wrote it. Treat this run as contaminated."
        fi
    done

    echo "--- timings written to timings_RP_multi_verifiers.txt"
    echo "--- plot them on the HOST (matplotlib is not in this image):"
    echo "      python3 plot_multi_verifiers.py"
  '
