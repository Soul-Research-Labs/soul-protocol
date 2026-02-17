#!/usr/bin/env python3
"""
Validate that coverage stubs maintain ABI compatibility with their production originals.

Usage:
    python3 scripts/validate_stubs.py          # validate all stubs
    python3 scripts/validate_stubs.py --verbose # show per-function details

If any stub's public/external ABI diverges from the original,
this script exits non-zero and prints the mismatches.
"""

import json
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent

# Mirror of run_coverage.py STUB_MAPPING  
STUB_MAPPING = {
    "contracts/verifiers/GasOptimizedVerifier.sol": "coverage-stubs/verifiers/GasOptimizedVerifier.sol",
    "contracts/verifiers/OptimizedGroth16Verifier.sol": "coverage-stubs/verifiers/OptimizedGroth16Verifier.sol",
    "contracts/verifiers/Groth16VerifierBN254.sol": "coverage-stubs/verifiers/Groth16VerifierBN254.sol",
    "contracts/libraries/CryptoLib.sol": "coverage-stubs/libraries/CryptoLib.sol",
    "contracts/libraries/GasOptimizations.sol": "coverage-stubs/libraries/GasOptimizations.sol",
    "contracts/privacy/GasOptimizedPrivacy.sol": "coverage-stubs/privacy/GasOptimizedPrivacy.sol",
    "contracts/experimental/privacy/ConstantTimeOperations.sol": "coverage-stubs/privacy/ConstantTimeOperations.sol",
    "contracts/verifiers/StateTransferVerifier.sol": "coverage-stubs/verifiers/StateTransferVerifier.sol",
    "contracts/verifiers/CrossChainProofVerifier.sol": "coverage-stubs/verifiers/CrossChainProofVerifier.sol",
    "contracts/verifiers/StateCommitmentVerifier.sol": "coverage-stubs/verifiers/StateCommitmentVerifier.sol",
    "contracts/verifiers/ProofAggregator.sol": "coverage-stubs/verifiers/ProofAggregator.sol",
    "contracts/verifiers/VerifierRegistry.sol": "coverage-stubs/verifiers/VerifierRegistry.sol",
    "contracts/crosschain/L2ChainAdapter.sol": "coverage-stubs/crosschain/L2ChainAdapter.sol",
    "contracts/crosschain/L2ProofRouter.sol": "coverage-stubs/crosschain/L2ProofRouter.sol",
    "contracts/crosschain/CrossChainMessageRelay.sol": "coverage-stubs/crosschain/CrossChainMessageRelay.sol",
    "contracts/experimental/privacy/RecursiveProofAggregator.sol": "coverage-stubs/privacy/RecursiveProofAggregator.sol",
}

GREEN = "\033[0;32m"
RED = "\033[0;31m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def extract_contract_name(sol_path: str) -> str:
    """Extract the primary contract name from a Solidity file path."""
    return Path(sol_path).stem


def get_abi_signatures(sol_path: str) -> set:
    """
    Parse the Solidity file and extract function/event signatures 
    from function definitions (simple regex-based approach).
    Returns a set of 'function name(type1,type2,...)' strings.
    """
    import re

    path = PROJECT_DIR / sol_path
    if not path.exists():
        return set()

    content = path.read_text()

    # Match function declarations: function name(params) visibility ...
    fn_pattern = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:external|public)',
        re.MULTILINE
    )

    sigs = set()
    for match in fn_pattern.finditer(content):
        name = match.group(1)
        params_raw = match.group(2).strip()
        
        if not params_raw:
            sigs.add(f"function {name}()")
            continue
        
        # Extract parameter types (ignore names and storage qualifiers)
        param_types = []
        for param in params_raw.split(','):
            param = param.strip()
            if not param:
                continue
            # First word is the type (possibly with memory/calldata/storage)
            parts = param.split()
            ptype = parts[0]
            # Skip storage qualifiers
            if len(parts) > 1 and parts[1] in ('memory', 'calldata', 'storage'):
                pass  # type is parts[0]
            param_types.append(ptype)
        
        sigs.add(f"function {name}({','.join(param_types)})")

    # Match event declarations
    event_pattern = re.compile(
        r'event\s+(\w+)\s*\(([^)]*)\)',
        re.MULTILINE
    )
    for match in event_pattern.finditer(content):
        name = match.group(1)
        sigs.add(f"event {name}")

    return sigs


def validate_all(verbose: bool = False) -> int:
    """Validate all stubs. Returns count of mismatches."""
    mismatches = 0
    checked = 0

    for original, stub in sorted(STUB_MAPPING.items()):
        original_path = PROJECT_DIR / original
        stub_path = PROJECT_DIR / stub

        if not original_path.exists():
            print(f"{YELLOW}  ⚠ Original not found: {original}{NC}")
            continue
        if not stub_path.exists():
            print(f"{YELLOW}  ⚠ Stub not found: {stub}{NC}")
            continue

        orig_sigs = get_abi_signatures(original)
        stub_sigs = get_abi_signatures(stub)

        checked += 1

        # Functions in original but missing from stub
        missing = orig_sigs - stub_sigs
        # Functions in stub but not in original (extra — less critical)
        extra = stub_sigs - orig_sigs

        if missing:
            mismatches += 1
            print(f"{RED}  ✗ {original}{NC}")
            print(f"    Missing from stub ({len(missing)}):")
            for sig in sorted(missing):
                print(f"      - {sig}")
            if extra and verbose:
                print(f"    Extra in stub ({len(extra)}):")
                for sig in sorted(extra):
                    print(f"      + {sig}")
        elif verbose:
            print(f"{GREEN}  ✓ {original} ({len(orig_sigs)} signatures match){NC}")

    return mismatches, checked


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("=" * 60)
    print("   Coverage Stub ABI Validator")
    print("=" * 60)
    print()

    mismatches, checked = validate_all(verbose)

    print()
    if mismatches == 0:
        print(f"{GREEN}✅ All {checked} stubs have ABI-compatible signatures.{NC}")
        return 0
    else:
        print(f"{RED}❌ {mismatches}/{checked} stubs have ABI mismatches.{NC}")
        print("   Update stubs in coverage-stubs/ to match their originals.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
