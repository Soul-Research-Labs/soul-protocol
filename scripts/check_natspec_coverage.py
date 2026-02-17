#!/usr/bin/env python3
"""
NatSpec Coverage Checker for Soul Protocol

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
from typing import List, Tuple


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


def parse_function_signature(content: str, start_idx: int) -> Tuple[str, int, int, str]:
    """
    Parse a function signature starting at start_idx.
    Returns (name, param_count, return_count, visibility).
    """
    # Find function name
    func_match = re.search(r'function\s+(\w+)\s*\(', content[start_idx:])
    if not func_match:
        return ("", 0, 0, "")
    
    name = func_match.group(1)
    
    # Count parameters
    paren_start = content.find('(', start_idx)
    paren_end = find_matching_paren(content, paren_start)
    params_str = content[paren_start+1:paren_end]
    
    # Count non-empty parameters
    param_count = 0
    if params_str.strip():
        param_count = len([p for p in params_str.split(',') if p.strip()])
    
    # Find visibility and returns
    after_params = content[paren_end:paren_end+500]
    
    visibility = "internal"
    if 'external' in after_params[:100]:
        visibility = "external"
    elif 'public' in after_params[:100]:
        visibility = "public"
    elif 'private' in after_params[:100]:
        visibility = "private"
    
    # Count returns
    return_count = 0
    returns_match = re.search(r'returns\s*\(([^)]+)\)', after_params)
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
    """Extract NatSpec comments before a given position."""
    # Look backwards for /** ... */
    search_start = max(0, position - 2000)
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
        last_comment = match.group()
    
    if last_comment:
        result['has_notice'] = '@notice' in last_comment
        result['has_dev'] = '@dev' in last_comment
        result['has_title'] = '@title' in last_comment
        result['has_author'] = '@author' in last_comment
        result['param_count'] = last_comment.count('@param')
        result['return_count'] = last_comment.count('@return')
    
    return result


def analyze_contract(file_path: Path) -> ContractDoc:
    """Analyze a single Solidity file for NatSpec coverage."""
    content = file_path.read_text()
    
    # Find contract/interface/library declaration
    contract_match = re.search(r'(contract|interface|library)\s+(\w+)', content)
    if not contract_match:
        return None
    
    contract_name = contract_match.group(2)
    contract_pos = contract_match.start()
    
    # Check contract-level docs
    contract_docs = extract_natspec_before(content, contract_pos)
    
    # Find all functions
    functions = []
    for match in re.finditer(r'function\s+\w+\s*\(', content):
        func_start = match.start()
        name, param_count, return_count, visibility = parse_function_signature(content, func_start)
        
        # Skip internal/private functions for documentation requirements
        if visibility not in ('external', 'public'):
            continue
        
        # Get line number
        line_num = content[:func_start].count('\n') + 1
        
        # Get docs before this function
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


def print_report(contracts: List[ContractDoc], stats: dict, verbose: bool = False):
    """Print coverage report."""
    print("\n" + "=" * 70)
    print("SOUL PROTOCOL - NATSPEC COVERAGE REPORT")
    print("=" * 70)
    
    # Contract-level stats
    print("\n📄 CONTRACT-LEVEL DOCUMENTATION")
    print("-" * 40)
    
    title_pct = (stats['contracts_with_title'] / stats['total_contracts'] * 100) if stats['total_contracts'] > 0 else 0
    author_pct = (stats['contracts_with_author'] / stats['total_contracts'] * 100) if stats['total_contracts'] > 0 else 0
    notice_pct = (stats['contracts_with_notice'] / stats['total_contracts'] * 100) if stats['total_contracts'] > 0 else 0
    
    print(f"  @title:  {stats['contracts_with_title']:3}/{stats['total_contracts']:3} ({title_pct:5.1f}%)")
    print(f"  @author: {stats['contracts_with_author']:3}/{stats['total_contracts']:3} ({author_pct:5.1f}%)")
    print(f"  @notice: {stats['contracts_with_notice']:3}/{stats['total_contracts']:3} ({notice_pct:5.1f}%)")
    
    # Function-level stats
    print("\n📋 FUNCTION-LEVEL DOCUMENTATION")
    print("-" * 40)
    
    func_notice_pct = (stats['functions_with_notice'] / stats['total_functions'] * 100) if stats['total_functions'] > 0 else 0
    func_dev_pct = (stats['functions_with_dev'] / stats['total_functions'] * 100) if stats['total_functions'] > 0 else 0
    param_pct = (stats['documented_params'] / stats['total_params'] * 100) if stats['total_params'] > 0 else 0
    return_pct = (stats['documented_returns'] / stats['total_returns'] * 100) if stats['total_returns'] > 0 else 0
    
    print(f"  @notice: {stats['functions_with_notice']:3}/{stats['total_functions']:3} ({func_notice_pct:5.1f}%)")
    print(f"  @dev:    {stats['functions_with_dev']:3}/{stats['total_functions']:3} ({func_dev_pct:5.1f}%)")
    print(f"  @param:  {stats['documented_params']:3}/{stats['total_params']:3} ({param_pct:5.1f}%)")
    print(f"  @return: {stats['documented_returns']:3}/{stats['total_returns']:3} ({return_pct:5.1f}%)")
    
    # Overall coverage
    total_items = stats['total_functions'] + stats['total_params'] + stats['total_returns']
    documented_items = stats['functions_with_notice'] + stats['documented_params'] + stats['documented_returns']
    overall_pct = (documented_items / total_items * 100) if total_items > 0 else 0
    
    print("\n" + "=" * 40)
    print(f"📊 OVERALL COVERAGE: {overall_pct:.1f}%")
    print("=" * 40)
    
    # Verbose output - list missing docs
    if verbose:
        print("\n⚠️  CONTRACTS MISSING DOCUMENTATION")
        print("-" * 40)
        
        for contract in contracts:
            missing = []
            if not contract.has_title:
                missing.append("@title")
            if not contract.has_author:
                missing.append("@author")
            if not contract.has_notice:
                missing.append("@notice")
            
            if missing:
                print(f"  {contract.name}: missing {', '.join(missing)}")
        
        print("\n⚠️  FUNCTIONS MISSING @notice")
        print("-" * 40)
        
        for contract in contracts:
            undoc_funcs = [f for f in contract.functions if not f.has_notice]
            if undoc_funcs:
                print(f"\n  {contract.name}:")
                for func in undoc_funcs[:5]:  # Limit output
                    print(f"    - {func.name}() [line {func.line}]")
                if len(undoc_funcs) > 5:
                    print(f"    ... and {len(undoc_funcs) - 5} more")
    
    return overall_pct


def main():
    parser = argparse.ArgumentParser(description='Check NatSpec documentation coverage')
    parser.add_argument('--path', default='contracts', help='Path to contracts directory')
    parser.add_argument('--threshold', type=float, default=80.0, help='Minimum coverage threshold (in percent)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed missing docs')
    parser.add_argument('--exclude', nargs='+', default=['mocks', 'test', 'interfaces'], 
                        help='Directories to exclude')
    
    args = parser.parse_args()
    
    contracts_path = Path(args.path)
    if not contracts_path.exists():
        print(f"Error: Path {contracts_path} does not exist")
        sys.exit(1)
    
    # Find all Solidity files
    sol_files = list(contracts_path.rglob("*.sol"))
    
    # Exclude specified directories
    sol_files = [f for f in sol_files if not any(excl in str(f) for excl in args.exclude)]
    
    print(f"Analyzing {len(sol_files)} Solidity files...")
    
    # Analyze each file
    contracts = []
    for sol_file in sol_files:
        contract = analyze_contract(sol_file)
        if contract:
            contracts.append(contract)
    
    # Calculate and print stats
    stats = calculate_coverage(contracts)
    coverage = print_report(contracts, stats, args.verbose)
    
    # Check threshold
    if coverage < args.threshold:
        print(f"\n❌ FAILED: Coverage {coverage:.1f}% is below threshold {args.threshold}%")
        sys.exit(1)
    else:
        print(f"\n✅ PASSED: Coverage {coverage:.1f}% meets threshold {args.threshold}%")
        sys.exit(0)


if __name__ == "__main__":
    main()
