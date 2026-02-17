#!/usr/bin/env python3
"""
Soul Coverage Runner v3

Works around Foundry coverage "stack too deep" errors by temporarily
replacing assembly-heavy contracts with simplified stubs.

See: https://github.com/foundry-rs/foundry/issues/3357

Usage:
    python scripts/run_coverage.py [--report=summary|lcov|full]
    python scripts/run_coverage.py --restore   # recover after interruption
    python scripts/run_coverage.py --dry-run   # validate stubs without running

Coverage output:
    lcov.info written to project root (uploadable to Codecov / Coveralls)
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Project paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_DIR = SCRIPT_DIR.parent
BACKUP_DIR = PROJECT_DIR / ".coverage-backup"
SENTINEL = PROJECT_DIR / ".coverage-in-progress"

# ── Minimal viable stub set (16 contracts) ─────────────────────────────
# Only contracts with inline assembly, assembly-library deps,
# or extreme size / deep inheritance that cause stack-too-deep.
# Excluded from stubs (test suites too tightly coupled to exact ABI):
#   ZKBoundStateLocks, CrossChainProofHubV3, ConfidentialStateContainerV3,
#   DirectL2Messenger, StealthAddressRegistry, PrivateRelayerNetwork,
#   ViewKeyRegistry, NullifierRegistryV3
STUB_MAPPING = {
    # Group A – heavy assembly (verifiers & libraries)
    "contracts/verifiers/GasOptimizedVerifier.sol": "coverage-stubs/verifiers/GasOptimizedVerifier.sol",
    "contracts/verifiers/OptimizedGroth16Verifier.sol": "coverage-stubs/verifiers/OptimizedGroth16Verifier.sol",
    "contracts/verifiers/Groth16VerifierBN254.sol": "coverage-stubs/verifiers/Groth16VerifierBN254.sol",
    "contracts/libraries/CryptoLib.sol": "coverage-stubs/libraries/CryptoLib.sol",
    "contracts/libraries/GasOptimizations.sol": "coverage-stubs/libraries/GasOptimizations.sol",
    "contracts/privacy/GasOptimizedPrivacy.sol": "coverage-stubs/privacy/GasOptimizedPrivacy.sol",
    "contracts/experimental/privacy/ConstantTimeOperations.sol": "coverage-stubs/privacy/ConstantTimeOperations.sol",
    # Group B – snarkJS verifiers & supporting contracts
    "contracts/verifiers/StateTransferVerifier.sol": "coverage-stubs/verifiers/StateTransferVerifier.sol",
    "contracts/verifiers/CrossChainProofVerifier.sol": "coverage-stubs/verifiers/CrossChainProofVerifier.sol",
    "contracts/verifiers/StateCommitmentVerifier.sol": "coverage-stubs/verifiers/StateCommitmentVerifier.sol",
    "contracts/verifiers/ProofAggregator.sol": "coverage-stubs/verifiers/ProofAggregator.sol",
    "contracts/verifiers/VerifierRegistry.sol": "coverage-stubs/verifiers/VerifierRegistry.sol",
    "contracts/crosschain/L2ChainAdapter.sol": "coverage-stubs/crosschain/L2ChainAdapter.sol",
    # Group C – assembly-lib dependants
    "contracts/crosschain/L2ProofRouter.sol": "coverage-stubs/crosschain/L2ProofRouter.sol",
    "contracts/crosschain/CrossChainMessageRelay.sol": "coverage-stubs/crosschain/CrossChainMessageRelay.sol",
    "contracts/experimental/privacy/RecursiveProofAggregator.sol": "coverage-stubs/privacy/RecursiveProofAggregator.sol",
}

# ANSI colors
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
CYAN = "\033[0;36m"
NC = "\033[0m"


def print_colored(msg: str, color: str = NC):
    print(f"{color}{msg}{NC}")


def backup_and_stub():
    """Backup original contracts and replace with stubs."""
    print_colored("\n📦 Backing up contracts and applying stubs...", CYAN)

    # Crash-safety sentinel: if this file exists, contracts are in stubbed state
    if SENTINEL.exists():
        print_colored("\n⚠ WARNING: .coverage-in-progress sentinel found!", YELLOW)
        print_colored("  A previous coverage run may have been interrupted.", YELLOW)
        print_colored("  Run: python3 scripts/run_coverage.py --restore", YELLOW)
        return 0

    SENTINEL.write_text(f"Coverage run started at {__import__('datetime').datetime.now().isoformat()}\n")
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    
    success = 0
    for original, stub in STUB_MAPPING.items():
        original_path = PROJECT_DIR / original
        stub_path = PROJECT_DIR / stub
        backup_path = BACKUP_DIR / original
        
        if not original_path.exists():
            print_colored(f"  ⚠ Original not found: {original}", YELLOW)
            continue
            
        if not stub_path.exists():
            print_colored(f"  ⚠ Stub not found: {stub}", YELLOW)
            continue
        
        # Backup original
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(original_path), str(backup_path))
        
        # Replace with stub
        shutil.copy2(str(stub_path), str(original_path))
        
        success += 1
        print(f"  ✓ Replaced: {original}")
    
    print_colored(f"\n✓ Replaced {success} contracts with stubs.", GREEN)
    return success


def restore_contracts():
    """Restore backed up contracts."""
    print_colored("\n🔄 Restoring original contracts...", CYAN)

    # Remove crash-safety sentinel
    if SENTINEL.exists():
        SENTINEL.unlink()
        print_colored("  ✓ Removed .coverage-in-progress sentinel", GREEN)
    
    if not BACKUP_DIR.exists():
        print_colored("No backup directory found.", YELLOW)
        return
    
    restored = 0
    for original in STUB_MAPPING.keys():
        backup_path = BACKUP_DIR / original
        original_path = PROJECT_DIR / original
        
        if backup_path.exists():
            shutil.copy2(str(backup_path), str(original_path))
            restored += 1
            print(f"  ✓ Restored: {original}")
    
    # Clean up backup directory
    shutil.rmtree(BACKUP_DIR, ignore_errors=True)
    print_colored(f"\n✓ Restored {restored} contracts.", GREEN)


def validate_stubs():
    """Validate that all stubs referenced in STUB_MAPPING exist."""
    missing = []
    for original, stub in STUB_MAPPING.items():
        stub_path = PROJECT_DIR / stub
        if not stub_path.exists():
            missing.append(stub)
    return missing


def run_coverage(report_type: str = "summary", extra_args: list = None):
    """Run forge coverage with proper error handling."""
    print_colored("\n🔍 Running forge coverage...", CYAN)

    cmd = [
        "forge", "coverage", "--ir-minimum",
        f"--report={report_type}",
    ]

    if extra_args:
        cmd.extend(extra_args)

    # Exclude test contracts that directly exercise stubbed/assembly contracts.
    # Stubs have dummy logic so their dedicated tests will fail — exclude them.
    # Also exclude tests that indirectly depend on stubbed libraries (CryptoLib,
    # GasOptimizations) or that are gas-sensitive and break under --ir-minimum.
    if not any("--no-match-contract" in arg for arg in (extra_args or [])):
        exclude_contracts = "|".join([
            # Always excluded (massive assembly / not real contracts)
            "UltraHonk", "Groth16", "SolverLib", "MockEthereumL1Bridge",
            # Test suites for Group A stubbed contracts
            "CryptoLib", "GasOptimiz", "ConstantTime",
            # Test suites for Group B stubbed contracts
            "StateTransferVerifier", "CrossChainProofVerifier",
            "StateCommitmentVerifier", "ProofAggregator", "VerifierRegistry",
            # Test suites for Group C stubbed contracts
            "L2ChainAdapter", "L2ProofRouter", "CrossChainMessageRelay",
            "RecursiveProofAggregator",
            # Tests that indirectly use stubbed CryptoLib / GasOptimizations
            "CryptoValidation", "CLSAGIntegration", "LibraryTests",
            # Gas-sensitive tests that break under --ir-minimum
            "PrivacyAttackSimulation", "GasLimitStress",
        ])
        cmd.extend(["--no-match-contract", exclude_contracts])

    # Exclude individual tests that OOG under ir-minimum coverage
    if not any("--no-match-test" in arg for arg in (extra_args or [])):
        cmd.extend([
            "--no-match-test",
            "test_createContainer_revertsPayloadTooLarge",
        ])

    print(f"  Running: {' '.join(cmd)}")
    print()

    env = os.environ.copy()
    env["FOUNDRY_PROFILE"] = "coverage"

    result = subprocess.run(cmd, cwd=str(PROJECT_DIR), env=env)

    # Check for lcov.info regardless of exit code — forge writes it
    # even when some tests fail, which is expected with stubs.
    if report_type == "lcov":
        lcov_path = PROJECT_DIR / "lcov.info"
        if lcov_path.exists():
            size = lcov_path.stat().st_size
            print_colored(f"\n📄 lcov.info written ({size:,} bytes)", GREEN)
        else:
            print_colored("\n⚠ lcov.info not found after coverage run", YELLOW)

    if result.returncode != 0:
        print_colored(f"\n⚠ Coverage exited with code {result.returncode}", YELLOW)

    return result.returncode


def main():
    """Main entry point."""
    args = sys.argv[1:]

    # Parse arguments
    report_type = "summary"
    restore_only = False
    dry_run = False
    extra_args = []

    for arg in args:
        if arg.startswith("--report="):
            report_type = arg.split("=")[1]
        elif arg == "--restore":
            restore_only = True
        elif arg == "--dry-run":
            dry_run = True
        else:
            extra_args.append(arg)

    print_colored("=" * 60, CYAN)
    print_colored("   Soul Coverage Runner v3", CYAN)
    print_colored(f"   Stubs: {len(STUB_MAPPING)} contracts", CYAN)
    print_colored("=" * 60, CYAN)

    # Just restore if requested
    if restore_only:
        restore_contracts()
        return 0

    # Pre-flight: validate all stubs exist
    missing = validate_stubs()
    if missing:
        print_colored(f"\n❌ Missing {len(missing)} stub file(s):", RED)
        for m in missing:
            print(f"   {m}")
        print_colored("Create stubs before running coverage.", YELLOW)
        return 1

    if dry_run:
        print_colored("\n✅ Dry-run OK: all stubs present.", GREEN)
        for orig, stub in sorted(STUB_MAPPING.items()):
            print(f"  {orig} → {stub}")
        return 0

    try:
        # Step 1: Backup and apply stubs
        count = backup_and_stub()
        if count == 0:
            print_colored("\n❌ No contracts were stubbed. Check paths.", RED)
            return 1

        # Step 2: Run coverage
        exit_code = run_coverage(report_type, extra_args)

        if exit_code == 0:
            print_colored("\n✅ Coverage completed successfully!", GREEN)

        return exit_code

    except KeyboardInterrupt:
        print_colored("\n\n⚠ Interrupted by user", YELLOW)
        return 130

    except Exception as e:
        print_colored(f"\n❌ Error: {e}", RED)
        return 1

    finally:
        # Always restore contracts
        restore_contracts()


if __name__ == "__main__":
    sys.exit(main())
