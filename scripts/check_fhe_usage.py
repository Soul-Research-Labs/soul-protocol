import os
import re

# Read STUB_MAPPING from run_coverage.py
stub_mapping = {}
with open('scripts/run_coverage.py', 'r') as f:
    content = f.read()
    # Extract the dictionary content crudely
    start = content.find('STUB_MAPPING = {')
    end = content.find('}', start)
    dict_str = content[start:end+1]
    # Parse lines
    for line in dict_str.split('\n'):
        if ':' in line:
            parts = line.split(':')
            key = parts[0].strip().strip('"').strip("'")
            stub_mapping[key] = True

# Find usages of FHETypes
print("Checking contracts using FHETypes that are NOT stubbed:")
cmd = 'grep -r "FHETypes" contracts/ | cut -d: -f1 | sort | uniq'
stream = os.popen(cmd)
files = stream.read().splitlines()

for f in files:
    if f not in stub_mapping and f != "contracts/fhe/FHETypes.sol":
        size = os.path.getsize(f)
        print(f"{f} ({size} bytes)")
