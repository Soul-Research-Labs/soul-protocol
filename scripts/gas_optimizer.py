#!/usr/bin/env python3
"""
Zaseon - Gas Optimization Analyzer

Profiles gas usage across core operations and identifies optimization opportunities.
Targets: <500K gas per privacy operation (current ~800K).

Usage:
    python3 scripts/gas_optimizer.py [--detailed] [--save]
"""

import subprocess
import json
import re
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent

# Core operations to benchmark
BENCHMARK_TARGETS = {
    "ZKBoundStateLocks": {
        "contract": "contracts/primitives/ZKBoundStateLocks.sol",
        "operations": ["createLock", "unlock", "extendLock", "claimExpiredLock"],
        "target_gas": 500_000,
    },
    "ConfidentialStateContainer": {
        "contract": "contracts/core/ConfidentialStateContainerV3.sol",
        "operations": ["transferState", "updateState", "verifyState"],
        "target_gas": 500_000,
    },
    "CrossChainProofHub": {
        "contract": "contracts/bridge/CrossChainProofHubV3.sol",
        "operations": ["submitProof", "challengeProof", "finalizeProof"],
        "target_gas": 500_000,
    },
    "NullifierRegistry": {
        "contract": "contracts/security/NullifierRegistryV3.sol",
        "operations": ["consumeNullifier", "verifyNullifier"],
        "target_gas": 200_000,
    },
    "SoulAtomicSwap": {
        "contract": "contracts/core/SoulAtomicSwapV2.sol",
        "operations": ["createSwap", "claimSwap", "refundSwap"],
        "target_gas": 500_000,
    },
    "StealthAddressRegistry": {
        "contract": "contracts/privacy/StealthAddressRegistry.sol",
        "operations": ["publishStealthAddress", "scanForPayments"],
        "target_gas": 300_000,
    },
}

# Known gas optimization patterns
OPTIMIZATION_PATTERNS = {
    "storage_packing": {
        "description": "Pack related state variables into single storage slots",
        "savings": "~2,100 gas per SSTORE saved",
        "patterns": [
            r"uint256\s+\w+;\s*\n\s*uint256\s+\w+;\s*\n\s*uint256\s+\w+;",
            r"bool\s+\w+;\s*\n\s*uint256\s+\w+;",
        ],
    },
    "calldata_over_memory": {
        "description": "Use calldata instead of memory for read-only function params",
        "savings": "~60 gas per parameter",
        "patterns": [
            r"function\s+\w+\([^)]*\bmemory\b[^)]*\)\s+(external|public)",
        ],
    },
    "unchecked_math": {
        "description": "Use unchecked blocks for safe arithmetic (post-validation)",
        "savings": "~60-120 gas per operation",
        "patterns": [
            r"(\w+)\s*\+\+;",
            r"(\w+)\s*\+=\s*1;",
        ],
    },
    "custom_errors": {
        "description": "Use custom errors instead of require strings",
        "savings": "~50 gas per error",
        "patterns": [
            r'require\([^,]+,\s*"[^"]+"\);',
        ],
    },
    "immutable_variables": {
        "description": "Mark constructor-set state as immutable",
        "savings": "~2,100 gas per SLOAD saved",
        "patterns": [
            r"constructor[^{]*{[^}]*\b(\w+)\s*=\s*\w+;[^}]*}",
        ],
    },
}


def run_gas_report():
    """Run forge gas report and parse results."""
    print("Running forge gas report...")
    result = subprocess.run(
        ["forge", "test", "--gas-report", "--fuzz-runs", "5"],
        capture_output=True, text=True, cwd=PROJECT_DIR,
        timeout=300,
    )
    return result.stdout


def parse_gas_report(output: str) -> dict:
    """Parse gas report output into structured data."""
    results = {}
    current_contract = None

    for line in output.split("\n"):
        # Match contract header: | ContractName | ... |
        header_match = re.match(r'\|\s*(\w+)\s*\|', line)
        if header_match and "Function Name" not in line and "---" not in line:
            # Check if this looks like a function row
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 5:
                contract_or_fn = parts[0]
                # If it starts lowercase, it's a function under current contract
                if contract_or_fn[0].islower() or contract_or_fn.startswith("_"):
                    if current_contract:
                        fn_name = parts[0]
                        try:
                            avg_gas = int(parts[2]) if parts[2].isdigit() else 0
                            results.setdefault(current_contract, {})[fn_name] = avg_gas
                        except (IndexError, ValueError):
                            pass
                else:
                    current_contract = contract_or_fn

    return results


def scan_for_optimizations(contract_path: str) -> list:
    """Scan a contract for optimization opportunities."""
    full_path = PROJECT_DIR / contract_path
    if not full_path.exists():
        return []

    content = full_path.read_text()
    opportunities = []

    for opt_name, opt_info in OPTIMIZATION_PATTERNS.items():
        for pattern in opt_info["patterns"]:
            matches = re.findall(pattern, content)
            if matches:
                opportunities.append({
                    "type": opt_name,
                    "description": opt_info["description"],
                    "savings": opt_info["savings"],
                    "occurrences": len(matches),
                })

    return opportunities


def generate_report(gas_data: dict, detailed: bool = False, save: bool = False):
    """Generate optimization report."""
    print("\n" + "=" * 70)
    print("ZASEON - GAS OPTIMIZATION REPORT")
    print("=" * 70)

    all_optimizations = {}

    for name, info in BENCHMARK_TARGETS.items():
        print(f"\n── {name} ──")
        print(f"  Target: < {info['target_gas']:,} gas")

        # Check gas data
        if name in gas_data:
            for fn, gas in gas_data[name].items():
                status = "✅" if gas <= info["target_gas"] else "⚠️"
                print(f"  {fn}: {gas:,} gas {status}")
        else:
            print("  No gas data available (run with forge test --gas-report)")

        # Scan for optimizations
        opts = scan_for_optimizations(info["contract"])
        if opts:
            print(f"  Optimization opportunities:")
            for opt in opts:
                print(f"    • {opt['type']}: {opt['occurrences']}x ({opt['savings']})")
        all_optimizations[name] = opts

    # Summary
    print("\n" + "=" * 70)
    print("OPTIMIZATION SUMMARY")
    print("=" * 70)

    total_opts = sum(len(v) for v in all_optimizations.values())
    print(f"\nTotal optimization opportunities: {total_opts}")
    print("\nPriority optimizations:")
    print("  1. Storage packing - combine related uint256/bool into packed structs")
    print("  2. Batch verification - amortize proof verification across multiple ops")
    print("  3. Lazy evaluation - defer non-critical state updates")
    print("  4. Assembly hot paths - hand-optimize critical keccak256 sequences")
    print("  5. EIP-1153 transient storage - use TSTORE/TLOAD for reentrancy guards")

    if save:
        report_path = PROJECT_DIR / "gas-optimization-report.json"
        with open(report_path, "w") as f:
            json.dump({
                "benchmarks": BENCHMARK_TARGETS,
                "gas_data": gas_data,
                "optimizations": {k: v for k, v in all_optimizations.items()},
            }, f, indent=2, default=str)
        print(f"\nReport saved to: {report_path}")


def main():
    detailed = "--detailed" in sys.argv
    save = "--save" in sys.argv

    gas_output = run_gas_report()
    gas_data = parse_gas_report(gas_output)
    generate_report(gas_data, detailed, save)


if __name__ == "__main__":
    main()
