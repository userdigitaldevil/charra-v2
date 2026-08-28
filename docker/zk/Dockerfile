# Noir + Barretenberg, for producing and checking the ZK redaction proof.
#
# Built for linux/arm64 ON PURPOSE. bb needs x86 ADX instructions that Rosetta
# does not emulate, so it dies with SIGILL in the linux/amd64 charra image on
# an Apple-silicon host -- reproducibly, exit 132. A native arm64 container
# executes directly on the host CPU with no emulation in the path, and bb runs
# normally. On an x86_64 host there is no Rosetta to begin with; build this
# image for that platform instead.
#
# This runs ALONGSIDE the charra container, not inside it, and the two share
# the checkout. That shared mount is how they talk: the RP writes a job into
# zk/jobs/ and the prover writes the proof back. See src/core/charra_zk_job.h.
FROM ubuntu:24.04

RUN apt-get update -qq \
    && apt-get install -y -qq curl git bash ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-c"]
ENV PATH="/root/.nargo/bin:/root/.bb:${PATH}"

RUN curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/install -o /tmp/noirup-install \
    && bash /tmp/noirup-install \
    && noirup

# Pinned deliberately. bbup's version map does not pair any bb with Noir
# 1.0.0-beta.26, so it refuses to choose one; this nightly does accept that
# ACIR, and is the pairing the circuit was developed and tested against.
# Changing either version can change the verification key, which would
# invalidate zk/vk for every Verifier.
RUN curl -fsSL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install -o /tmp/bbup-install \
    && bash /tmp/bbup-install \
    && bbup -v 5.0.0-nightly.20260522

WORKDIR /home/bob/charra
