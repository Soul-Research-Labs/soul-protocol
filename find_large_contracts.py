
import os
import re

# Parse run_coverage.py to get stubbed contracts
stubbed_contracts = set()
with open("scripts/run_coverage.py", "r") as f:
    content = f.read()
    # Find all "contracts/...": "coverage-stubs/..." pairs
    matches = re.findall(r'"(contracts/[^"]+)":', content)
    for m in matches:
        stubbed_contracts.add(os.path.abspath(m))

# Walk contracts directory
contracts_dir = os.path.abspath("contracts")
files_with_size = []

for root, dirs, files in os.walk(contracts_dir):
    for file in files:
        if file.endswith(".sol"):
            full_path = os.path.join(root, file)
            if full_path not in stubbed_contracts:
                size = os.path.getsize(full_path)
                files_with_size.append((full_path, size))

# Sort by size descending
files_with_size.sort(key=lambda x: x[1], reverse=True)

for path, size in files_with_size[:20]:
    print(f"{size} {path}")
