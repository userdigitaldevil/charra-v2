#!/bin/bash

# Script to start 5 instances of bin/verifier on ports 5684 to 5688

# Define the starting port
START_PORT=5684

# Number of instances to start
NUM_INSTANCES=5

# Loop to start each verifier instance on a different port
for ((i=0; i<NUM_INSTANCES; i++)); do
  PORT=$((START_PORT + i))
  echo "Starting bin/verifier on port $PORT"
  bin/verifier --port $PORT &
done

echo "All verifiers started."
