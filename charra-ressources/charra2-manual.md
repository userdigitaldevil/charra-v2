# Installation Tips

1. **Download Extensions:**
   - Download and install the Docker extension and the Dev Container extension for VS Code.

3. **Attach VS Code to Container:**
   - After following the installation steps in INSTALL.md, and once your container  is  running:
   - Click on the Docker extension icon in the left sidebar of VS Code.
   - Right-click on your running container and select "Attach Visual Studio Code" to connect a VS Code instance to it.

# Remote Attestation Process

To complete a full round of remote attestation, follow these steps:

1. **Start the Attester:**
   - Open an integrated terminal and run:
     bin/attester (default port number is 5863)

   - To specify a specific port, run:
     bin/attester --port <port_number>

2. **Start the Trust Manager:**
   - Open an integrated terminal and run:
     bin/trust_manager (default port number is 6000)

3. **Start the Verifier:**
   - Open an integrated terminal and run:
     bin/verifier

   - To specify a specific port, run:
     bin/verifier --port <port_number>

   - To start multiple verifiers at once, run the script:
     ./start_verifiers

     This script will start 5 verifiers simultaneously.

4. **Start the Relying Party:**
   - Ensure the attester, trust manager, and verifier(s) are all running. Then, open an integrated terminal and run:
     bin/relying_party

**Note:** Steps 1 to 3 can be performed in any order, but all must be completed before starting the relying party.

# Generating Measurements

The old `timing_atomic.py` has been removed. It drove `bin/verifier_old` (the
v1 active-client baseline) and read `timings_verifier.txt`, a file the current
passive Verifier never writes, so it could not measure the v2 design at all.
Per-phase Verifier timings now go to `durations_verifier-<port>.txt`, written
on every `/appraise` and intended for reading by eye.

To measure the overall process, including getting verifiers, getting evidence, appraising evidence, and total durations, follow these steps:

1. **Configure Parameters:**
   - Navigate to the `src/relying_party` directory.
   - Set `NUM_RUNS` to the number of runs over which you want your statistics computed (currently set to 1).
   - Set `num_used_verifiers` to the number of verifiers you want to use. Ensure `verifier_list` has an equal size (currently set to 5 verifiers).

2. **Save and Compile:**
   - Save your changes and compile by running:
     make

3. **Start the Components:**
   - Open an integrated terminal and start the attester:
     bin/attester

   - Open another integrated terminal and start the trust manager:
     bin/trust_manager

   - Open another integrated terminal and start the verifiers:
     ./start_verifiers

   - Open another integrated terminal and start the relying party:
     bin/relying_party


4. **Plot the Results:**
   - Once the above steps are complete, plot the results by running:
     python3 plot_multi_verifiers

# Other notes:
- To change the Ip addresses and port numbers of the verifiers modify the file verifiers_config.txt
