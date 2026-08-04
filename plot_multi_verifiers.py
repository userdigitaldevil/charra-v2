import matplotlib.pyplot as plt
import re

# Read the data from the file
filename = 'timings_RP_multi_verifiers.txt'
with open(filename, 'r') as file:
    data = file.read()

# Define patterns to extract the data
patterns = {
    'num_verifiers': re.compile(r'Verifiers: (\d+)'),
    'getting_verifiers': re.compile(r'Average Getting verifiers: ([\d.]+) seconds'),
    'getting_evidence': re.compile(r'Average Getting evidence: ([\d.]+) seconds'),
    'appraising_evidence': re.compile(r'Average Appraising evidence: ([\d.]+) seconds'),
    'total_duration': re.compile(r'Average Total Attestation Duration: ([\d.]+) seconds')
}

# Extract data
num_verifiers = patterns['num_verifiers'].findall(data)
getting_verifiers = patterns['getting_verifiers'].findall(data)
getting_evidence = patterns['getting_evidence'].findall(data)
appraising_evidence = patterns['appraising_evidence'].findall(data)
total_duration = patterns['total_duration'].findall(data)

# Convert extracted data to float and integers
num_verifiers = [int(nv) for nv in num_verifiers]
getting_verifiers = [float(gv) for gv in getting_verifiers]
getting_evidence = [float(ge) for ge in getting_evidence]
appraising_evidence = [float(ae) for ae in appraising_evidence]
total_duration = [float(td) for td in total_duration]

# Plotting
plt.figure(figsize=(10, 6))
plt.plot(num_verifiers, getting_verifiers, marker='o', label='get_verifiers')
plt.plot(num_verifiers, getting_evidence, marker='o', label='get_evidence')
plt.plot(num_verifiers, appraising_evidence, marker='o', label='get_attestation_results')
plt.plot(num_verifiers, total_duration, marker='o', label='total_duration')

plt.xticks(range(1, 6))
plt.xlabel('Number of Verifiers')
plt.ylabel('Time (seconds)')
plt.title('Attestation Timing Analysis')
plt.legend()
plt.grid(True)
output_filename = 'attestation_timing_analysis.png'
plt.savefig(output_filename)
