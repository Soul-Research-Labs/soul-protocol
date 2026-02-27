#!/usr/bin/env python3
"""
Soul Protocol - Contract Dependency Analyzer

Generates a dependency graph of Solidity contracts showing:
- Import relationships
- Circular dependencies
- Module coupling metrics
- Dependency depth per contract

Usage:
  python3 scripts/analyze_dependencies.py [--dir contracts/] [--format text|json|dot]
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict, deque


def extract_imports(filepath: str, base_dir: str) -> list:
    """Extract import paths from a Solidity file."""
    imports = []
    with open(filepath, 'r') as f:
        for line in f:
            # Match: import "path"; or import {X} from "path";
            match = re.search(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+)["\']', line)
            if match:
                import_path = match.group(1)
                # Resolve relative to remappings
                if import_path.startswith('@openzeppelin/'):
                    imports.append(('openzeppelin', import_path))
                elif import_path.startswith('forge-std/'):
                    imports.append(('forge-std', import_path))
                elif import_path.startswith('../') or import_path.startswith('./'):
                    # Resolve relative path
                    resolved = os.path.normpath(os.path.join(os.path.dirname(filepath), import_path))
                    if resolved.startswith(base_dir):
                        rel = os.path.relpath(resolved, base_dir)
                        imports.append(('internal', rel))
                    else:
                        imports.append(('external', import_path))
                else:
                    imports.append(('external', import_path))
    return imports


def build_dependency_graph(base_dir: str) -> dict:
    """Build a complete dependency graph of all Solidity files."""
    graph = {}  # file -> list of dependencies
    all_files = sorted(Path(base_dir).rglob('*.sol'))

    # Skip generated, mocks, test files
    all_files = [
        f for f in all_files
        if '/generated/' not in str(f) and '/mocks/' not in str(f)
    ]

    for filepath in all_files:
        rel_path = os.path.relpath(str(filepath), base_dir)
        imports = extract_imports(str(filepath), base_dir)
        graph[rel_path] = {
            'internal_deps': [p for t, p in imports if t == 'internal'],
            'external_deps': [p for t, p in imports if t in ('openzeppelin', 'forge-std', 'external')],
            'total_imports': len(imports),
        }

    return graph


def find_circular_deps(graph: dict) -> list:
    """Find circular dependencies using DFS."""
    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node, path):
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for dep in graph.get(node, {}).get('internal_deps', []):
            if dep in rec_stack:
                # Found cycle
                cycle_start = path.index(dep) if dep in path else -1
                if cycle_start >= 0:
                    cycle = path[cycle_start:] + [dep]
                    cycles.append(cycle)
            elif dep not in visited and dep in graph:
                dfs(dep, path)

        path.pop()
        rec_stack.discard(node)

    for node in graph:
        if node not in visited:
            dfs(node, [])

    return cycles


def compute_depth(graph: dict) -> dict:
    """Compute dependency depth (longest path from a leaf) for each node."""
    depths = {}
    computing = set()

    def get_depth(node):
        if node in depths:
            return depths[node]
        if node in computing:
            return 0  # Cycle detected, break
        computing.add(node)

        max_dep_depth = 0
        for dep in graph.get(node, {}).get('internal_deps', []):
            if dep in graph:
                max_dep_depth = max(max_dep_depth, get_depth(dep) + 1)

        computing.discard(node)
        depths[node] = max_dep_depth
        return max_dep_depth

    for node in graph:
        get_depth(node)

    return depths


def get_module(filepath: str) -> str:
    """Extract module name from file path."""
    parts = filepath.split('/')
    if len(parts) >= 2:
        return parts[0]
    return 'root'


def main():
    parser = argparse.ArgumentParser(description='Analyze Solidity contract dependencies')
    parser.add_argument('--dir', default='contracts/', help='Directory to analyze')
    parser.add_argument('--format', choices=['text', 'json', 'dot'], default='text')
    parser.add_argument('--max-depth', type=int, default=4, help='Maximum acceptable dependency depth')
    parser.add_argument('--fail-on-cycle', action='store_true', help='Exit 1 if cycles found')
    args = parser.parse_args()

    graph = build_dependency_graph(args.dir)
    cycles = find_circular_deps(graph)
    depths = compute_depth(graph)

    if args.format == 'json':
        print(json.dumps({
            'total_files': len(graph),
            'cycles': cycles,
            'depths': depths,
            'graph': graph,
        }, indent=2))
        return

    if args.format == 'dot':
        print('digraph dependencies {')
        print('  rankdir=LR;')
        print('  node [shape=box, fontsize=10];')
        for node, info in graph.items():
            module = get_module(node)
            for dep in info['internal_deps']:
                dep_module = get_module(dep)
                color = 'red' if module != dep_module else 'black'
                print(f'  "{node}" -> "{dep}" [color={color}];')
        print('}')
        return

    # Text output
    print("═══════════════════════════════════════════════════════")
    print("  SOUL PROTOCOL - DEPENDENCY ANALYSIS")
    print("═══════════════════════════════════════════════════════")
    print(f"  Files analyzed:     {len(graph)}")
    print(f"  Max depth found:    {max(depths.values()) if depths else 0}")
    print(f"  Circular deps:      {len(cycles)}")
    print("═══════════════════════════════════════════════════════")
    print()

    # Module coupling
    module_coupling = defaultdict(lambda: {'internal': 0, 'external': 0, 'cross_module': 0})
    for node, info in graph.items():
        module = get_module(node)
        module_coupling[module]['internal'] += len(info['internal_deps'])
        module_coupling[module]['external'] += len(info['external_deps'])
        for dep in info['internal_deps']:
            dep_module = get_module(dep)
            if dep_module != module:
                module_coupling[module]['cross_module'] += 1

    print("Module Coupling:")
    print(f"  {'Module':<25} {'Internal':>8} {'External':>8} {'Cross-Mod':>10}")
    print(f"  {'─'*25} {'─'*8} {'─'*8} {'─'*10}")
    for module in sorted(module_coupling.keys()):
        c = module_coupling[module]
        print(f"  {module:<25} {c['internal']:>8} {c['external']:>8} {c['cross_module']:>10}")
    print()

    # Deep dependency chains
    deep = [(k, v) for k, v in depths.items() if v > args.max_depth]
    if deep:
        print(f"Files exceeding max depth ({args.max_depth}):")
        for filepath, depth in sorted(deep, key=lambda x: x[1], reverse=True)[:20]:
            print(f"  {filepath}: depth {depth}")
        print()

    # Circular dependencies
    if cycles:
        print(f"⚠️  Circular Dependencies ({len(cycles)}):")
        for i, cycle in enumerate(cycles[:10]):
            print(f"  {i+1}. {' → '.join(cycle)}")
        print()

    # Most depended-on files (fan-in)
    fan_in = defaultdict(int)
    for node, info in graph.items():
        for dep in info['internal_deps']:
            fan_in[dep] += 1

    if fan_in:
        print("Most Depended-On Files (Top 15):")
        for filepath, count in sorted(fan_in.items(), key=lambda x: x[1], reverse=True)[:15]:
            print(f"  {filepath}: {count} dependents")
        print()

    if not cycles and not deep:
        print("✅ No circular dependencies or excessive depth found")

    if args.fail_on_cycle and cycles:
        sys.exit(1)


if __name__ == '__main__':
    main()
