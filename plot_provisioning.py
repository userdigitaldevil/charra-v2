"""Plot how long each credential-issuance flow takes, from
timings_provisioning.txt.

Four flows are recorded, and they are not variations on one thing -- each is
a different number of parties talking to each other, which is the whole point
of plotting them side by side:

  * attester_ak_by_rp        AK_a_byRP.  3 legs, RP's own CA.  RP challenges
                             the Attester directly and signs the result
                             itself, so no Verifier is involved and the
                             recorded port is 0.
  * rp_ak_by_verifier        AK_r_byV.  2 legs, /certify_ak.  The shortest
                             flow: the subject IS the requester, so nothing
                             has to be couriered.
  * attester_ak_by_verifier  AK_a_byV.  4 legs.  The CA (a Verifier) and the
                             subject (the Attester) cannot talk to each
                             other, so the RP relays the challenge one way
                             and the echo back.
  * qualification            /qualify + /qualify_submit, plus the AK_r_byV
                             round when that has to run first -- the Verifier
                             will not mark an unknown submitter.

Only successful rounds are recorded, and only when work actually happened: a
cache hit writes nothing, so every point here is a real issuance.

Note on reading the result: at the 5-year AK default these flows run ONCE per
deployment, so an ordinary run yields one sample each. To get a distribution,
force renewal with short lifetimes, e.g.

    VERIFIER_AK_VALIDITY=60 VERIFIER_QUALIFICATION_VALIDITY=45 \\
      RP_ATTESTER_AK_VALIDITY=60 ./run_daemon.sh

Usage:  python3 plot_provisioning.py [timings_provisioning.txt]
"""

import statistics
import sys

import matplotlib.pyplot as plt

FILENAME = sys.argv[1] if len(sys.argv) > 1 else 'timings_provisioning.txt'
OUTPUT = 'provisioning_timing_analysis.png'

# Display order is by leg count -- but note that leg count does NOT predict
# cost, which is the first thing this plot shows. In a 2-Verifier run the
# 2-leg AK_r_byV came out slowest (1.35s mean) and the 4-leg AK_a_byV
# noticeably faster (1.02s): AK_r_byV runs ActivateCredential on the RP's own
# TPM behind rp_tpm_mutex, so sibling Verifier threads queue for a simulator
# that serves one client at a time, while AK_a_byV's activation happens in
# the Attester process. Round trips are cheap here; TPM contention is not.
FLOWS = [
    ('rp_ak_by_verifier', "AK_r_byV\n/certify_ak, 2 legs"),
    ('attester_ak_by_rp', "AK_a_byRP\nRP's own CA, 3 legs"),
    ('attester_ak_by_verifier', "AK_a_byV\nrelayed, 4 legs"),
    ('qualification', '/qualify\n+ /qualify_submit'),
]

try:
    with open(FILENAME) as handle:
        lines = handle.readlines()
except FileNotFoundError:
    raise SystemExit(
        f'{FILENAME} not found. It is written by bin/relying_party as it '
        'provisions credentials -- run ./run_daemon.sh (or the --benchmark '
        'sweep) at least once first.')

# "<flow> <verifier_port> <seconds> <unix_time>", '#' comments and blank
# lines skipped -- same convention as reference-pcrs.txt and the AK ledger.
samples = {flow: [] for flow, _ in FLOWS}
ports = {flow: [] for flow, _ in FLOWS}
skipped = 0
for raw in lines:
    line = raw.split('#', 1)[0].strip()
    if not line:
        continue
    fields = line.split()
    if len(fields) < 3 or fields[0] not in samples:
        skipped += 1
        continue
    try:
        samples[fields[0]].append(float(fields[2]))
        ports[fields[0]].append(int(fields[1]))
    except ValueError:
        skipped += 1

if skipped:
    print(f'{FILENAME}: skipped {skipped} unparseable line(s).')

present = [(flow, label) for flow, label in FLOWS if samples[flow]]
if not present:
    raise SystemExit(
        f'{FILENAME} has no recognised flow records. Expected one or more '
        f'of: {", ".join(flow for flow, _ in FLOWS)}.')

missing = [flow for flow, _ in FLOWS if not samples[flow]]
if missing:
    print(f'No samples for: {", ".join(missing)} -- those flows did not run. '
          'A cached credential records nothing.')

# --- panel 1: mean per flow, with spread ------------------------------------
# Error bars are population stddev, matching calculate_stats() in rp_stats.c.
# A single sample gets no bar rather than a misleading zero-height one.
labels = [label for _, label in present]
means = [statistics.mean(samples[flow]) for flow, _ in present]
errors = [
    statistics.pstdev(samples[flow]) if len(samples[flow]) > 1 else 0.0
    for flow, _ in present
]
counts = [len(samples[flow]) for flow, _ in present]

fig, axes = plt.subplots(1, 2, figsize=(15, 6))

ax = axes[0]
bars = ax.bar(labels, means, yerr=errors, capsize=5,
              color=['#4C78A8', '#F58518', '#54A24B', '#B279A2'][:len(present)])
for rect, mean, n in zip(bars, means, counts):
    ax.annotate(f'{mean:.3f}s\nn={n}',
                (rect.get_x() + rect.get_width() / 2, rect.get_height()),
                textcoords='offset points', xytext=(0, 4),
                ha='center', fontsize=9)
ax.set_title('Cost of one issuance round, by flow')
ax.set_ylabel('Time (seconds)')
ax.grid(True, axis='y', alpha=0.4)
ax.set_axisbelow(True)

# --- panel 2: every sample, in the order it was recorded --------------------
# The mean alone hides the thing worth seeing: the first round of each flow
# is usually the slowest, because the TPM simulator is cold and every later
# round reuses a loaded key.
ax = axes[1]
for (flow, label), colour in zip(
        present, ['#4C78A8', '#F58518', '#54A24B', '#B279A2']):
    values = samples[flow]
    ax.plot(range(1, len(values) + 1), values, marker='o',
            label=label.replace('\n', ' — '), color=colour)
ax.set_title('Each recorded round, in order')
ax.set_xlabel('Nth time this flow ran')
ax.set_ylabel('Time (seconds)')
if max(counts) > 1:
    ax.set_xticks(range(1, max(counts) + 1))
ax.grid(True, alpha=0.4)
ax.set_axisbelow(True)
ax.legend(fontsize=8)

fig.suptitle('CHARRA credential provisioning: cost per issuance flow')
fig.tight_layout()
fig.savefig(OUTPUT, dpi=150)
print(f'Wrote {OUTPUT}')

# A one-line summary so the script is useful without opening the PNG.
print()
for (flow, label), mean, n in zip(present, means, counts):
    spread = (f'  stddev {statistics.pstdev(samples[flow]):.3f}s'
              if n > 1 else '  (single sample)')
    seen = sorted(set(p for p in ports[flow] if p))
    where = f'  ports {seen}' if seen else '  no Verifier involved'
    print(f'{flow:24s} n={n:<3d} mean {mean:.3f}s{spread}{where}')
