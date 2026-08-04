import subprocess
import sys
import numpy as np
import time

def run_processes(n):
    # Start the attester (server) in the background
    attester_process = subprocess.Popen(["bin/attester"])

    verifier_times = []

    for _ in range(n):
        # Run the verifier (client) process
        subprocess.run(["bin/verifier_old"])

    # Stop the attester process
    attester_process.terminate()
    attester_process.wait()

def read_timings(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
    return [float(line.strip()) for line in lines]

def compute_statistics(times):
    average = np.mean(times)
    std_dev = np.std(times)
    return average, std_dev

def main(n):
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'numpy'])
    run_processes(n)

    try:
        attester_times = read_timings("timings_attester.txt")
        verifier_times = read_timings("timings_verifier.txt")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

    if len(attester_times) > n-1:
        attester_avg, attester_std = compute_statistics(attester_times)
        print(f"Generating evidence - Avg: {attester_avg:.2f}, Std: {attester_std:.2f}")
    else:
        print(f"Expected at least {n} attester timings, but found {len(attester_times)}")

    if len(verifier_times) > n-1:
        verifier_avg, verifier_std = compute_statistics(verifier_times)
        print(f"Appraising evidence - Avg: {verifier_avg:.2f}, Std: {verifier_std:.2f}")
    else:
        print(f"Expected at least {n} verifier timings, but found {len(verifier_times)}")

if __name__ == "__main__":
    N = 10  # Number of times to run the processes
    main(N)
