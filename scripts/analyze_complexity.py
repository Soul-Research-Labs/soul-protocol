#!/usr/bin/env python3
"""
Zaseon - Contract Complexity Analyzer

Analyzes Solidity contracts for:
- Cyclomatic complexity per function
- Contract size (lines of code)
- Function count per contract
- Inheritance depth
- External dependency count

Usage:
  python3 scripts/analyze_complexity.py [--threshold 10] [--dir contracts/]
"""

import os
import re
import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict


def count_decision_points(source: str) -> int:
    """Count decision points (if, for, while, ternary, require, &&, ||) in a block of code."""
    patterns = [
        r'\bif\s*\(',
        r'\bfor\s*\(',
        r'\bwhile\s*\(',
        r'\brequire\s*\(',
        r'\brevert\s+\w+\s*\(',
        r'\?',          # ternary
        r'&&',
        r'\|\|',
    ]
    count = 0
    for pattern in patterns:
        count += len(re.findall(pattern, source))
    return count


def extract_functions(source: str) -> list:
    """Extract function names and their bodies from Solidity source."""
    functions = []
    # Match function declarations
    func_pattern = re.compile(
        r'function\s+(\w+)\s*\([^)]*\)[^{]*\{',
        re.MULTILINE
    )

    for match in func_pattern.finditer(source):
        name = match.group(1)
        start = match.end()
        depth = 1
        pos = start
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        body = source[start:pos]
        complexity = count_decision_points(body) + 1  # +1 for the function itself
        functions.append({
            'name': name,
            'complexity': complexity,
            'lines': body.count('\n') + 1,
        })

    return functions


def analyze_contract(filepath: str) -> dict:
    """Analyze a single Solidity file."""
    with open(filepath, 'r') as f:
        source = f.read()

    total_lines = source.count('\n') + 1
    blank_lines = len([l for l in source.split('\n') if l.strip() == ''])
    comment_lines = len(re.findall(r'^\s*(//|/?\*)', source, re.MULTILINE))
    code_lines = total_lines - blank_lines - comment_lines

    # Count contract/interface definitions
    contracts = re.findall(r'\b(?:contract|library|interface)\s+(\w+)', source)

    # Count imports
    imports = re.findall(r'^import\s+', source, re.MULTILINE)

    # Count inheritance
    inheritance = re.findall(r'\bis\s+([^{]+)\{', source)
    max_parents = 0
    for inh in inheritance:
        parents = [p.strip() for p in inh.split(',') if p.strip()]
        max_parents = max(max_parents, len(parents))

    # Extract functions
    functions = extract_functions(source)
    max_complexity = max((f['complexity'] for f in functions), default=0)
    avg_complexity = sum(f['complexity'] for f in functions) / len(functions) if functions else 0

    return {
        'file': filepath,
        'total_lines': total_lines,
        'code_lines': code_lines,
        'contracts': contracts,
        'function_count': len(functions),
        'import_count': len(imports),
        'max_inheritance': max_parents,
        'max_complexity': max_complexity,
        'avg_complexity': round(avg_complexity, 2),
        'functions': functions,
        'high_complexity': [f for f in functions if f['complexity'] > 10],
    }


def main():
    parser = argparse.ArgumentParser(description='Analyze Solidity contract complexity')
    parser.add_argument('--dir', default='contracts/', help='Directory to analyze')
    parser.add_argument('--threshold', type=int, default=10, help='Complexity threshold')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--fail-on-violation', action='store_true', help='Exit 1 if thresholds exceeded')
    args = parser.parse_args()

    # Find all .sol files
    sol_files = sorted(Path(args.dir).rglob('*.sol'))

    # Skip generated verifiers and mocks
    sol_files = [
        f for f in sol_files
        if '/generated/' not in str(f) and '/mocks/' not in str(f)
    ]

    results = []
    violations = []
    total_functions = 0
    total_high_complexity = 0

    for filepath in sol_files:
        result = analyze_contract(str(filepath))
        results.append(result)
        total_functions += result['function_count']

        for func in result['high_complexity']:
            violations.append({
                'file': str(filepath),
                'function': func['name'],
                'complexity': func['complexity'],
            })
            total_high_complexity += 1

    if args.json:
        print(json.dumps({
            'total_files': len(results),
            'total_functions': total_functions,
            'violations': violations,
            'results': results,
        }, indent=2))
        return

    # Print summary
    print("═══════════════════════════════════════════════════════")
    print("  ZASEON - CONTRACT COMPLEXITY ANALYSIS")
    print("═══════════════════════════════════════════════════════")
    print(f"  Files analyzed:        {len(results)}")
    print(f"  Total functions:       {total_functions}")
    print(f"  Complexity threshold:  {args.threshold}")
    print(f"  Violations:            {total_high_complexity}")
    print("═══════════════════════════════════════════════════════")
    print()

    # Top 10 most complex files
    by_complexity = sorted(results, key=lambda r: r['max_complexity'], reverse=True)[:10]
    print("Top 10 Most Complex Files:")
    print(f"  {'File':<60} {'Funcs':>6} {'MaxCC':>6} {'AvgCC':>6}")
    print(f"  {'─'*60} {'─'*6} {'─'*6} {'─'*6}")
    for r in by_complexity:
        shortpath = str(r['file']).replace('contracts/', '')
        print(f"  {shortpath:<60} {r['function_count']:>6} {r['max_complexity']:>6} {r['avg_complexity']:>6}")
    print()

    # Violations
    if violations:
        print(f"Functions exceeding complexity threshold ({args.threshold}):")
        print(f"  {'File':<50} {'Function':<30} {'CC':>4}")
        print(f"  {'─'*50} {'─'*30} {'─'*4}")
        for v in sorted(violations, key=lambda x: x['complexity'], reverse=True):
            shortpath = v['file'].replace('contracts/', '')
            print(f"  {shortpath:<50} {v['function']:<30} {v['complexity']:>4}")
        print()

    # Thresholds check
    large_contracts = [r for r in results if r['function_count'] > 30]
    deep_inheritance = [r for r in results if r['max_inheritance'] > 4]

    if large_contracts:
        print(f"Contracts with >30 functions ({len(large_contracts)}):")
        for r in large_contracts:
            print(f"  {r['file']}: {r['function_count']} functions")
        print()

    if deep_inheritance:
        print(f"Contracts with >4 inheritance depth ({len(deep_inheritance)}):")
        for r in deep_inheritance:
            print(f"  {r['file']}: {r['max_inheritance']} parents")
        print()

    if args.fail_on_violation and violations:
        print(f"❌ {len(violations)} functions exceed complexity threshold {args.threshold}")
        sys.exit(1)

    if not violations and not large_contracts and not deep_inheritance:
        print("✅ All contracts within complexity thresholds")


if __name__ == '__main__':
    main()
