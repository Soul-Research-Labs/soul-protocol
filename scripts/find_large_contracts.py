import os
import sys

def find_large_contracts(root_dir, limit=100):
    contracts = []
    for dirpath, _, filenames in os.walk(root_dir):
        if 'node_modules' in dirpath or 'lib' in dirpath:
            continue
        for f in filenames:
            if f.endswith('.sol'):
                path = os.path.join(dirpath, f)
                try:
                    with open(path, 'r', encoding='utf-8') as file:
                        lines = len(file.readlines())
                        size = os.path.getsize(path)
                        contracts.append({'path': path, 'lines': lines, 'size': size})
                except Exception as e:
                    pass
    
    # Sort by size (descending)
    contracts.sort(key=lambda x: x['size'], reverse=True)
    
    print(f"Top {limit} largest contracts:")
    for i, c in enumerate(contracts[:limit]):
        print(f"{i+1}. {c['path']} ({c['lines']} lines, {c['size']} bytes)")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "contracts"
    find_large_contracts(path)
