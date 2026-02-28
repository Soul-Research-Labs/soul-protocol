#!/usr/bin/env python3
"""
NatSpec Coverage Checker for Zaseon

Analyzes Solidity contracts for NatSpec documentation coverage.
Reports on functions missing @notice, @param, @return documentation.

Usage:
    python scripts/check_natspec_coverage.py
    python scripts/check_natspec_coverage.py --threshold 90
    python scripts/check_natspec_coverage.py --verbose
    python scripts/check_natspec_coverage.py --path contracts/crosschain
"""

import argparse
import re
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class FunctionDoc:
    """Represents documentation status for a function."""
    name: str
    file: str
    line: int
    has_notice: bool
    has_dev: bool
    param_count: int
    documented_params: int
    return_count: int
    documented_returns: int
    visibility: str


@dataclass
class ContractDoc:
    """Represents documentation status for a contract."""
    name: str
    file: str
    has_title: bool
    has_author: bool
    has_notice: bool
    has_dev: bool
    functions: List[FunctionDoc]


def strip_comments(content: str) -> str:
    """
    Strip all comments from Solidity source, replacing them with whitespace
    of the same length so that character offsets remain valid.
    """
    result = list(content)
    i = 0
    while i < len(content) - 1:
        # Single-line comment
        if content[i] == '/' and content[i + 1] == '/':
            j = i
            while j < len(content) and content[j] != '\n':
                result[j] = ' '
                j += 1
            i = j
        # Multi-line / NatSpec comment
        elif content[i] == '/' and content[i + 1] == '*':
            j = i + 2
            while j < len(content) - 1:
                if content[j] == '*' and content[j + 1] == '/':
                    j += 2
                    break
                j += 1
            else:
                j = len(content)
            for k in range(i, j):
                if content[k] != '\n':
                    result[k] = ' '
            i = j
        # Skip string literals
        elif content[i] == '"':
            i += 1
            while i < len(content) and content[i] != '"':
                if content[i] == '\\':
                    i += 1
                i += 1
            i += 1
        else:
            i += 1
    return ''.join(result)


def parse_function_signature(content: str, start_idx: int) -> Tuple[str, int, int, str]:
    """
    Parse a function signature starting at start_idx.
    Returns (name, param_count, return_count, visibility).
    """
    func_match = re.search(r'function\s+(\w+)\s*\(', content[start_idx:])
    if not func_match:
        return ("", 0, 0, "")

    name = func_match.group(1)

    # Count named parameters (unnamed params can't be documented)
    paren_start = content.find('(', start_idx)
    paren_end = find_matching_paren(content, paren_start)
    params_str = content[paren_start + 1:paren_end]

    param_count = 0
    if params_str.strip():
        for p in params_str.split(','):
            p = p.strip()
            if not p:
                continue
            parts = p.split()
            if len(parts) >= 2:
                last = parts[-1]
                # If last token is memory/storage/calldata, param is unnamed
                if last in ('memory', 'storage', 'calldata'):
                    continue
                param_count += 1
            # Single token = just a type with no name (unnamed param)
            # Don't count it

    # Find visibility and returns
    after_params = content[paren_end:paren_end + 500]

    visibility = "internal"
    if 'external' in after_params[:200]:
        visibility = "external"
    elif 'public' in after_params[:200]:
        visibility = "public"
    elif 'private' in after_params[:200]:
        visibility = "private"

    return_count = 0
    # Stop at opening brace or semicolon to avoid matching next function
    sig_after = after_params
    for stop_char in ('{', ';'):
        pos = sig_after.find(stop_char)
        if pos >= 0:
            sig_after = sig_after[:pos]
    returns_match = re.search(r'returns\s*\(([^)]+)\)', sig_after)
    if returns_match:
        returns_str = returns_match.group(1)
        return_count = len([r for r in returns_str.split(',') if r.strip()])

    return (name, param_count, return_count, visibility)


def find_matching_paren(content: str, start: int) -> int:
    """Find the matching closing parenthesis."""
    count = 1
    i = start + 1
    while i < len(content) and count > 0:
        if content[i] == '(':
            count += 1
        elif content[i] == ')':
            count -= 1
        i += 1
    return i - 1


def extract_natspec_before(content: str, position: int) -> dict:
    """Extract NatSpec comments before a given position in the ORIGINAL content."""
    search_start = max(0, position - 8000)
    block = content[search_start:position]

    result = {
        'has_notice': False,
        'has_dev': False,
        'has_title': False,
        'has_author': False,
        'param_count': 0,
        'return_count': 0,
    }

    # Find last /** ... */ block
    last_comment = None
    for match in re.finditer(r'/\*\*[\s\S]*?\*/', block):
        last_comment = match

    if not last_comment:
        return result

    comment_text = last_comment.group()

    # Ensure the comment is immediately before the declaration (only whitespace between)
    after_comment = block[last_comment.end():]
    if after_comment.strip():
        return result

    result['has_notice'] = '@notice' in comment_text
    result['has_dev'] = '@dev' in comment_text
    result['has_title'] = '@title' in comment_text
    result['has_author'] = '@author' in comment_text
    result['param_count'] = comment_text.count('@param')
    result['return_count'] = comment_text.count('@return')

    return result


def analyze_contract(file_path: Path) -> Optional[ContractDoc]:
    """Analyze a single Solidity file for NatSpec coverage."""
    content = file_path.read_text()

    # Strip comments so we don't match 'contract' inside comment blocks
    stripped = strip_comments(content)

    # Find contract/interface/library declaration - name must start with uppercase
    contract_match = re.search(
        r'\b(contract|interface|library)\s+([A-Z]\w*)',
        stripped
    )
    if not contract_match:
        return None

    contract_name = contract_match.group(2)
    contract_pos = contract_match.start()

    # Check contract-level docs (use original content for NatSpec extraction)
    contract_docs = extract_natspec_before(content, contract_pos)

    # Find all functions in the comment-stripped source
    functions = []
    for match in re.finditer(r'\bfunction\s+(\w+)\s*\(', stripped):
        func_start = match.start()
        name, param_count, return_count, visibility = parse_function_signature(
            stripped, func_start
        )

        # Skip internal/private functions for documentation requirements
        if visibility not in ('external', 'public'):
            continue

        # Skip common auto-generated / boilerplate functions
        if name in ('supportsInterface', '_authorizeUpgrade'):
            continue

        # Get line number
        line_num = content[:func_start].count('\n') + 1

        # Get docs before this function (from original content)
        func_docs = extract_natspec_before(content, func_start)

        functions.append(FunctionDoc(
            name=name,
            file=str(file_path),
            line=line_num,
            has_notice=func_docs['has_notice'],
            has_dev=func_docs['has_dev'],
            param_count=param_count,
            documented_params=func_docs['param_count'],
            return_count=return_count,
            documented_returns=func_docs['return_count'],
            visibility=visibility,
        ))

    return ContractDoc(
        name=contract_name,
        file=str(file_path),
        has_title=contract_docs['has_title'],
        has_author=contract_docs['has_author'],
        has_notice=contract_docs['has_notice'],
        has_dev=contract_docs['has_dev'],
        functions=functions,
    )


def calculate_coverage(contracts: List[ContractDoc]) -> dict:
    """Calculate overall coverage statistics."""
    total_functions = 0
    functions_with_notice = 0
    functions_with_dev = 0
    total_params = 0
    documented_params = 0
    total_returns = 0
    documented_returns = 0

    contracts_with_title = 0
    contracts_with_author = 0
    contracts_with_notice = 0

    for contract in contracts:
        if contract.has_title:
            contracts_with_title += 1
        if contract.has_author:
            contracts_with_author += 1
        if contract.has_notice:
            contracts_with_notice += 1

        for func in contract.functions:
            total_functions += 1
            if func.has_notice:
                functions_with_notice += 1
            if func.has_dev:
                functions_with_dev += 1
            total_params += func.param_count
            documented_params += min(func.documented_params, func.param_count)
            total_returns += func.return_count
            documented_returns += min(func.documented_returns, func.return_count)

    return {
        'total_contracts': len(contracts),
        'contracts_with_title': contracts_with_title,
        'contracts_with_author': contracts_with_author,
        'contracts_with_notice': contracts_with_notice,
        'total_functions': total_functions,
        'functions_with_notice': functions_with_notice,
        'functions_with_dev': functions_with_dev,
        'total_params': total_params,
        'documented_params': documented_params,
        'total_returns': total_returns,
        'documented_returns': documented_returns,
    }


def print_report(contracts: List[ContractDoc], stats: dict, verbose: bool = False) -> float:
    """Print coverage report."""
    print("\n" + "=" * 70)
    print("ZASEON - NATSPEC COVERAGE REPORT")
    print("=" * 70)

    tc = stats['total_contracts']
    print("\nCONTRACT-LEVEL DOCUMENTATION")
    print("-" * 40)

    title_pct = (stats['contracts_with_title'] / tc * 100) if tc > 0 else 0
    author_pct = (stats['contracts_with_author'] / tc * 100) if tc > 0 else 0
    notice_pct = (stats['contracts_with_notice'] / tc * 100) if tc > 0 else 0

    print(f"  @title:  {stats['contracts_with_title']:4d}/{tc:4d} ({title_pct:5.1f}%)")
    print(f"  @author: {stats['contracts_with_author']:4d}/{tc:4d} ({author_pct:5.1f}%)")
    print(f"  @notice: {stats['contracts_with_notice']:4d}/{tc:4d} ({notice_pct:5.1f}%)")

    tf = stats['total_functions']
    tp = stats['total_params']
    tr = stats['total_returns']
    print("\nFUNCTION-LEVEL DOCUMENTATION")
    print("-" * 40)

    fn_pct = (stats['functions_with_notice'] / tf * 100) if tf > 0 else 0
    fd_pct = (stats['functions_with_dev'] / tf * 100) if tf > 0 else 0
    pp_pct = (stats['documented_params'] / tp * 100) if tp > 0 else 0
    rr_pct = (stats['documented_returns'] / tr * 100) if tr > 0 else 0

    print(f"  @notice: {stats['functions_with_notice']:4d}/{tf:4d} ({fn_pct:5.1f}%)")
    print(f"  @dev:    {stats['functions_with_dev']:4d}/{tf:4d} ({fd_pct:5.1f}%)")
    print(f"  @param:  {stats['documented_params']:4d}/{tp:4d} ({pp_pct:5.1f}%)")
    print(f"  @return: {stats['documented_returns']:4d}/{tr:4d} ({rr_pct:5.1f}%)")

    # Overall coverage: weighted combination of contract-level + function-level
    # Contract-level: title + notice (author is optional, dev is bonus)
    contract_items = tc * 2
    contract_documented = stats['contracts_with_title'] + stats['contracts_with_notice']

    # Function-level: notice + params + returns
    func_items = tf + tp + tr
    func_documented = stats['functions_with_notice'] + stats['documented_params'] + stats['documented_returns']

    total_items = contract_items + func_items
    total_documented = contract_documented + func_documented
    overall_pct = (total_documented / total_items * 100) if total_items > 0 else 0

    print("\n" + "=" * 40)
    print(f"OVERALL COVERAGE: {overall_pct:.1f}%")
    print("=" * 40)

    if verbose:
        undoc_contracts = [
            c for c in contracts if not c.has_title or not c.has_notice
        ]
        if undoc_contracts:
            print("\nCONTRACTS MISSING DOCUMENTATION")
            print("-" * 40)
            for contract in undoc_contracts:
                missing = []
                if not contract.has_title:
                    missing.append("@title")
                if not contract.has_author:
                    missing.append("@author")
                if not contract.has_notice:
                    missing.append("@notice")
                print(f"  {contract.name} ({contract.file}): missing {', '.join(missing)}")

        undoc_func_contracts = [
            c for c in contracts if any(not f.has_notice for f in c.functions)
        ]
        if undoc_func_contracts:
            print("\nFUNCTIONS MISSING @notice")
            print("-" * 40)
            for contract in undoc_func_contracts:
                undoc_funcs = [f for f in contract.functions if not f.has_notice]
                if undoc_funcs:
                    print(f"\n  {contract.name}:")
                    for func in undoc_funcs[:10]:
                        print(f"    - {func.name}() [line {func.line}]")
                    if len(undoc_funcs) > 10:
                        print(f"    ... and {len(undoc_funcs) - 10} more")

    return overall_pct


# Default directories to exclude from analysis
DEFAULT_EXCLUDES = [
    'mocks',
    'test',
    'interfaces',
    'verifiers/generated',
    'coverage-stubs',
]


def main():
    parser = argparse.ArgumentParser(description='Check NatSpec documentation coverage')
    parser.add_argument('--path', default='contracts', help='Path to contracts directory')
    parser.add_argument(
        '--threshold', type=float, default=40.0,
        help='Minimum coverage threshold (default: 40)',
    )
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed missing docs')
    parser.add_argument(
        '--exclude', nargs='+', default=DEFAULT_EXCLUDES,
        help='Directory name fragments to exclude',
    )

    args = parser.parse_args()

    contracts_path = Path(args.path)
    if not contracts_path.exists():
        print(f"Error: Path {contracts_path} does not exist")
        sys.exit(1)

    sol_files = list(contracts_path.rglob("*.sol"))

    sol_files = [
        f for f in sol_files
        if not any(excl in str(f) for excl in args.exclude)
    ]

    print(f"Analyzing {len(sol_files)} Solidity files...")

    contracts: List[ContractDoc] = []
    for sol_file in sorted(sol_files):
        contract = analyze_contract(sol_file)
        if contract:
            contracts.append(contract)

    if not contracts:
        print("No contracts found.")
        sys.exit(1)

    stats = calculate_coverage(contracts)
    coverage = print_report(contracts, stats, args.verbose)

    if coverage < args.threshold:
        print(f"\nFAILED: Coverage {coverage:.1f}% is below threshold {args.threshold}%")
        sys.exit(1)
    else:
        print(f"\nPASSED: Coverage {coverage:.1f}% meets threshold {args.threshold}%")
        sys.exit(0)


if __name__ == "__main__":
    main()
