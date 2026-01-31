import sys
import os

# Read STUB_MAPPING from run_coverage.py
stub_mapping = {}
with open('scripts/run_coverage.py', 'r') as f:
    content = f.read()
    start = content.find('STUB_MAPPING = {')
    end = content.find('}', start)
    dict_str = content[start:end+1]
    for line in dict_str.split('\n'):
        if ':' in line:
            parts = line.split(':')
            key = parts[0].strip().strip('"').strip("'")
            stub_mapping[key] = True

print(f"Loaded {len(stub_mapping)} stubs.")

# Find all contracts > limit that are NOT stubbed
limit = 10000
if len(sys.argv) > 1:
    limit = int(sys.argv[1])
print(f"Listing non-stubbed contracts > {limit} bytes:")

large_files = []
for dirpath, _, filenames in os.walk("contracts"):
    for f in filenames:
        if f.endswith(".sol"):
            path = os.path.join(dirpath, f)
            if path in stub_mapping:
                continue
            
            size = os.path.getsize(path)
            if size > limit:
                large_files.append((path, size))

large_files.sort(key=lambda x: x[1], reverse=True)

for path, size in large_files:
    print(f"{path} ({size} bytes)")
