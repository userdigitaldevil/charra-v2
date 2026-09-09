"""Plot the RP's multi-verifier sweep from timings_RP_multi_verifiers.txt.

Two panels, because the sweep reports two genuinely different quantities and
blending them hides both:

  * steady state -- the per-cycle cost once every Verifier is already
    certified. This is what "cost per additional Verifier" means, and it is
    averaged over NUM_RUNS samples, so it carries real error bars.
  * onboarding -- the one-off cost of the warm-up cycle at each step, where
    the newly added Verifier runs a full two-leg /certify_ak. One sample by
    construction (it only happens once), so no error bars.
"""

import os
import re
import matplotlib.pyplot as plt

# The RP writes its timings to the repository root and this script lives one
# level under it, so anchor there rather than trusting the caller's cwd -- the
# same thing the shell scripts alongside this one do.
ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))

FILENAME = os.path.join(ROOT, 'timings_RP_multi_verifiers.txt')
OUTPUT = os.path.join(ROOT, 'attestation_timing_analysis.png')

with open(FILENAME) as handle:
    data = handle.read()

# "Average <phase>: <value> seconds (stddev: <value>)" for steady state, and
# "Onboarding <phase>: <value> seconds" for the warm-up cycle.
PHASES = [
    ('Getting verifiers', 'get_verifiers'),
    ('Getting evidence', 'get_evidence'),
    ('Appraising evidence', 'get_attestation_results'),
    ('Total Attestation Duration', 'total_duration'),
]

num_verifiers = [int(n) for n in re.findall(r'Verifiers: (\d+)', data)]
if not num_verifiers:
    raise SystemExit(f'No "Verifiers:" blocks found in {FILENAME}.')

steady, stddevs, onboarding = {}, {}, {}
for phase, label in PHASES:
    pairs = re.findall(
        rf'Average {re.escape(phase)}: ([\d.]+) seconds \(stddev: ([\d.]+)\)',
        data)
    steady[label] = [float(v) for v, _ in pairs]
    stddevs[label] = [float(s) for _, s in pairs]
    onboarding[label] = [
        float(v) for v in
        re.findall(rf'Onboarding {re.escape(phase)}: ([\d.]+) seconds', data)
    ]

missing = [lbl for _, lbl in PHASES if len(steady[lbl]) != len(num_verifiers)]
if missing:
    raise SystemExit(
        f'{FILENAME} has {len(num_verifiers)} Verifier blocks but incomplete '
        f'steady-state data for: {", ".join(missing)}. Regenerate it with '
        'bin/relying_party --benchmark.')

have_onboarding = all(
    len(onboarding[lbl]) == len(num_verifiers) for _, lbl in PHASES)

ncols = 2 if have_onboarding else 1
fig, axes = plt.subplots(1, ncols, figsize=(7 * ncols, 6), squeeze=False)

ax = axes[0][0]
for _, label in PHASES:
    ax.errorbar(num_verifiers, steady[label], yerr=stddevs[label], marker='o',
                capsize=4, label=label)
ax.set_title('Steady state (warm Verifiers)')
ax.set_xlabel('Number of Verifiers')
ax.set_ylabel('Time (seconds)')
ax.set_xticks(num_verifiers)
ax.grid(True)
ax.legend()

if have_onboarding:
    ax = axes[0][1]
    for _, label in PHASES:
        ax.plot(num_verifiers, onboarding[label], marker='s', linestyle='--',
                label=label)
    ax.set_title('Onboarding cycle (newly added Verifier is cold)')
    ax.set_xlabel('Number of Verifiers')
    ax.set_ylabel('Time (seconds)')
    ax.set_xticks(num_verifiers)
    ax.grid(True)
    ax.legend()
else:
    print(f'{FILENAME} has no "Onboarding" lines -- plotting steady state '
          'only. Regenerate with a current bin/relying_party --benchmark to '
          'get the onboarding panel.')

fig.suptitle('RP attestation timing vs Verifier count')
fig.tight_layout()
fig.savefig(OUTPUT, dpi=150)
print(f'Wrote {OUTPUT}')
