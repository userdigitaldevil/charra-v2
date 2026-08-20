#!/bin/bash
#
# Start COUNT Verifiers on consecutive ports, generate verifiers_config.txt to
# match, and forward any other option to every Verifier started.
#
# The Trust Manager resolves the Verifier IDs the RP asks for into {ip, port}
# by reading verifiers_config.txt. That file used to be maintained by hand
# while this script hardcoded its own START_PORT/NUM_INSTANCES, so editing one
# without the other produced a failure that names neither: the RP dials a port
# nobody listens on and stalls until its CoAP timeout, or the Trust Manager
# quietly returns fewer endpoints than were requested. Generating the config
# here makes that mismatch impossible.
#
# The Trust Manager re-opens the file on every lookup, so regenerating it takes
# effect immediately -- a running Trust Manager needs no restart.
#
# This script's own options:
#   -n, --count N          how many Verifiers to start. Default 5.
#   -p, --startingport P   port of the first one; the rest follow
#                          consecutively. Default 5684.
#       --host ADDR        address written into verifiers_config.txt, i.e. the
#                          address the RP will dial. Default 127.0.0.1.
#       --config PATH      config file to generate. Default verifiers_config.txt.
#       --logdir DIR       write each Verifier's output to DIR/verifier_<port>.log
#                          instead of this script's stdout. Without it every
#                          Verifier's output interleaves into one stream, which
#                          is exactly what the per-thread log prefixes exist to
#                          avoid. DIR is created if missing.
#   -h, --help             this message.
#
# ANY OTHER OPTION is passed through unchanged to every Verifier, so
# `bin/verifier --help` is the reference for what else is accepted. --port is
# refused, since this script assigns it. Use `--` to force the remainder
# through if a Verifier option ever collides with one above (notably the
# Verifier's own --ip, which is distinct from --host here).
#
# Examples:
#   ./start_verifiers.sh                            # 5 Verifiers from 5684
#   ./start_verifiers.sh 3 --startingport 5684      # 5684, 5685, 5686
#   (a bare number is the count only as the FIRST argument; use -n otherwise)
#   ./start_verifiers.sh 3 --qualification-validity 300 -v  # 3, with those flags
#   ./start_verifiers.sh 2 -- --ip 10.0.0.4         # pass the Verifier's --ip

set -euo pipefail

COUNT=5
START_PORT=5684
HOST=127.0.0.1
CONFIG=verifiers_config.txt
LOGDIR=
VERIFIER_ARGS=()
FIRST_ARG=1

usage() { sed -n '3,43p' "$0" | sed 's/^#\{1,\} \{0,1\}//;s/^#$//'; exit "${1:-0}"; }

need_value() {
    [ "$2" -ge 2 ] || { echo "$1 needs a value." >&2; exit 1; }
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)   usage 0 ;;
        -n|--count)  need_value "$1" $#; COUNT=$2; shift 2 ;;
        -p|--startingport|--starting-port)
                     need_value "$1" $#; START_PORT=$2; shift 2 ;;
        --host)      need_value "$1" $#; HOST=$2; shift 2 ;;
        --config)    need_value "$1" $#; CONFIG=$2; shift 2 ;;
        --logdir)    need_value "$1" $#; LOGDIR=$2; shift 2 ;;
        --port|--port=*)
            echo "Refusing --port: this script assigns ports from" >&2
            echo "--startingport upward. Use --startingport instead." >&2
            exit 1 ;;
        --)          shift; VERIFIER_ARGS+=("$@"); break ;;
        [0-9]*)
            # A bare number is the count ONLY as the very first argument.
            # Anywhere else it is the value of a pass-through option (e.g.
            # `--qualification-validity 300`), and swallowing it as the count would
            # silently start thousands of Verifiers.
            if [ "$FIRST_ARG" -eq 1 ]; then COUNT=$1; else VERIFIER_ARGS+=("$1"); fi
            shift ;;
        *)           VERIFIER_ARGS+=("$1"); shift ;;   # anything else -> Verifier
    esac
    FIRST_ARG=0
done

case "$COUNT" in ''|*[!0-9]*)
    echo "Count must be a whole number, got '$COUNT'." >&2; exit 1 ;; esac
case "$START_PORT" in ''|*[!0-9]*)
    echo "Port must be a whole number, got '$START_PORT'." >&2; exit 1 ;; esac
[ "$COUNT" -ge 1 ] || { echo "Count must be at least 1." >&2; exit 1; }

LAST_PORT=$((START_PORT + COUNT - 1))
[ "$LAST_PORT" -le 65535 ] ||
    { echo "Port range $START_PORT-$LAST_PORT exceeds 65535." >&2; exit 1; }

# Not fatal -- extra config rows are harmless, but relying_party's --verifiers
# is capped at MAX_VERIFIERS (rp_shared.h), so the rest can run without ever
# being attested against.
[ "$COUNT" -le 10 ] || echo "Note: relying_party accepts --verifiers 1..10, so \
only the first 10 of $COUNT are reachable from it." >&2

# Written via a temporary file so a Trust Manager reading concurrently can
# never observe a half-written config.
[ -n "$LOGDIR" ] && mkdir -p "$LOGDIR"

tmp=$(mktemp "${CONFIG}.XXXXXX")
for ((i = 0; i < COUNT; i++)); do
    echo "$((i + 1)) $HOST $((START_PORT + i))"
done > "$tmp"
mv "$tmp" "$CONFIG"

echo "Wrote $CONFIG:"
sed 's/^/  /' "$CONFIG"
if [ ${#VERIFIER_ARGS[@]} -gt 0 ]; then
    echo "Passing to every Verifier: ${VERIFIER_ARGS[*]}"
fi

for ((i = 0; i < COUNT; i++)); do
    PORT=$((START_PORT + i))
    if [ -n "$LOGDIR" ]; then
        echo "Starting bin/verifier on port $PORT -> $LOGDIR/verifier_$PORT.log"
    else
        echo "Starting bin/verifier on port $PORT"
    fi
    if [ ${#VERIFIER_ARGS[@]} -gt 0 ]; then
        set -- --port "$PORT" "${VERIFIER_ARGS[@]}"
    else
        set -- --port "$PORT"
    fi
    if [ -n "$LOGDIR" ]; then
        bin/verifier "$@" > "$LOGDIR/verifier_$PORT.log" 2>&1 &
    else
        bin/verifier "$@" &
    fi
done

echo "Started IDs 1-$COUNT on ports $START_PORT-$LAST_PORT."
echo "A Verifier that refuses to start is reporting that another instance"
echo "already has that port bound."
