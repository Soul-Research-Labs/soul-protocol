#!/usr/bin/env python3
"""
Generate UltraHonk Solidity verifiers from binary VK files.

Workaround for the barretenberg `on_curve` assertion in bb < 3.1.0.
Extracts VK data from compiled binary files and constructs Solidity
verifiers using the same BaseZKHonkVerifier pattern as bb codegen.

Usage:
    python3 scripts/generate_verifiers_from_vk.py
"""

import os
import sys
from pathlib import Path

# BN254 curve prime (Fq)
BN254_FQ = 21888242871839275222246405745257275088696311157297823662689037894645226208583

# VK binary format: 3 header fields (32B each) + G1 points (128B each)
HEADER_SIZE = 96  # 3 × 32 bytes
G1_SIZE = 128     # 4 × 32 bytes (x_lo, x_hi, y_lo, y_hi in 136-bit limbs)

# Standard UltraHonk VK: 28 G1 points = 3680 bytes
STANDARD_NUM_POINTS = 28
STANDARD_VK_SIZE = HEADER_SIZE + STANDARD_NUM_POINTS * G1_SIZE  # 3680 bytes

# Recursive/Aggregator UltraHonk VK: 32 G1 points = 4192 bytes
# Recursive circuits add 4 extra IPA accumulator commitments:
#   ipaClaimRemainder, ipaClaimQuotient, ipaClaimS0, ipaClaimS1
RECURSIVE_NUM_POINTS = 32
RECURSIVE_VK_SIZE = HEADER_SIZE + RECURSIVE_NUM_POINTS * G1_SIZE  # 4192 bytes

# Binary serialization order of G1 commitments (from barretenberg ultra_flavor.hpp)
BINARY_POINT_NAMES_STANDARD = [
    "qm", "qc", "ql", "qr", "qo", "q4",
    "qLookup", "qArith", "qDeltaRange", "qElliptic", "qMemory", "qNnf",
    "qPoseidon2External", "qPoseidon2Internal",
    "s1", "s2", "s3", "s4",
    "id1", "id2", "id3", "id4",
    "t1", "t2", "t3", "t4",
    "lagrangeFirst", "lagrangeLast",
]

# Recursive circuits have 4 extra IPA accumulator points
BINARY_POINT_NAMES_RECURSIVE = BINARY_POINT_NAMES_STANDARD + [
    "ipaClaimRemainder", "ipaClaimQuotient", "ipaClaimS0", "ipaClaimS1",
]

# Solidity field order in loadVerificationKey() (must match Honk.VerificationKey struct)
SOL_FIELD_ORDER_STANDARD = [
    "ql", "qr", "qo", "q4", "qm", "qc",
    "qLookup", "qArith", "qDeltaRange", "qElliptic", "qMemory", "qNnf",
    "qPoseidon2External", "qPoseidon2Internal",
    "s1", "s2", "s3", "s4",
    "t1", "t2", "t3", "t4",
    "id1", "id2", "id3", "id4",
    "lagrangeFirst", "lagrangeLast",
]

SOL_FIELD_ORDER_RECURSIVE = SOL_FIELD_ORDER_STANDARD + [
    "ipaClaimRemainder", "ipaClaimQuotient", "ipaClaimS0", "ipaClaimS1",
]

# Circuits known to use recursive verification (variable-size VK)
RECURSIVE_CIRCUITS = {"aggregator"}

# Circuits that need verifier generation (currently stubs)
STUB_CIRCUITS = [
    "accredited_investor",
    "aggregator",
    "balance_proof",
    "compliance_proof",
    "encrypted_transfer",
    "merkle_proof",
    "pedersen_commitment",
    "policy_bound_proof",
    "ring_signature",
    "sanctions_check",
    "shielded_pool",
    "swap_proof",
]


def snake_to_pascal(name: str) -> str:
    """Convert snake_case to PascalCase: shielded_pool -> ShieldedPool"""
    return "".join(word.capitalize() for word in name.split("_"))


def read_uint256(data: bytes, offset: int) -> int:
    """Read a big-endian 256-bit integer from bytes."""
    return int.from_bytes(data[offset:offset + 32], "big")


def read_g1_point(data: bytes, point_index: int) -> tuple:
    """
    Read a G1 point from VK binary using 136-bit limb split.
    Returns (x, y) as Python ints.
    """
    off = HEADER_SIZE + point_index * G1_SIZE
    x_lo = read_uint256(data, off)
    x_hi = read_uint256(data, off + 32)
    y_lo = read_uint256(data, off + 64)
    y_hi = read_uint256(data, off + 96)

    x = (x_hi << 136) | x_lo
    y = (y_hi << 136) | y_lo
    return (x, y)


def verify_on_curve(x: int, y: int) -> bool:
    """Check if (x, y) is on BN254: y^2 = x^3 + 3 (mod Fq)."""
    if x == 0 and y == 0:
        return True  # Point at infinity
    lhs = pow(y, 2, BN254_FQ)
    rhs = (pow(x, 3, BN254_FQ) + 3) % BN254_FQ
    return lhs == rhs


def parse_vk(vk_path: str, circuit_name: str = "") -> dict:
    """Parse a binary VK file into structured data.
    
    Supports both standard (28-point) and recursive (32-point) VK formats.
    Recursive circuits like the aggregator have 4 extra IPA accumulator commitments.
    """
    with open(vk_path, "rb") as f:
        data = f.read()

    is_recursive = circuit_name in RECURSIVE_CIRCUITS

    if is_recursive:
        expected = RECURSIVE_VK_SIZE
        point_names = BINARY_POINT_NAMES_RECURSIVE
        num_points = RECURSIVE_NUM_POINTS
    else:
        expected = STANDARD_VK_SIZE
        point_names = BINARY_POINT_NAMES_STANDARD
        num_points = STANDARD_NUM_POINTS

    # Auto-detect format if size doesn't match expected
    if len(data) == RECURSIVE_VK_SIZE and not is_recursive:
        print(f"  NOTE: VK file is {len(data)} bytes — auto-detected as recursive format")
        point_names = BINARY_POINT_NAMES_RECURSIVE
        num_points = RECURSIVE_NUM_POINTS
        is_recursive = True
    elif len(data) == STANDARD_VK_SIZE and is_recursive:
        print(f"  NOTE: VK file is {len(data)} bytes — using standard format for recursive circuit")
        point_names = BINARY_POINT_NAMES_STANDARD
        num_points = STANDARD_NUM_POINTS
        is_recursive = False
    elif len(data) != expected:
        raise ValueError(
            f"VK file size {len(data)} != expected {expected} "
            f"(standard={STANDARD_VK_SIZE}, recursive={RECURSIVE_VK_SIZE})"
        )

    log_n = read_uint256(data, 0)
    num_public_inputs = read_uint256(data, 32)
    # pub_inputs_offset at offset 64, always 1

    n = 1 << log_n

    points = {}
    for i, name in enumerate(point_names):
        x, y = read_g1_point(data, i)
        if not verify_on_curve(x, y):
            raise ValueError(f"Point {name} is not on BN254 curve! x=0x{x:064x}, y=0x{y:064x}")
        points[name] = (x, y)

    return {
        "n": n,
        "log_n": log_n,
        "num_public_inputs": num_public_inputs,
        "points": points,
        "is_recursive": is_recursive,
    }


def read_vk_hash(vk_hash_path: str) -> str:
    """Read the 32-byte VK hash and return as 0x-prefixed hex string."""
    with open(vk_hash_path, "rb") as f:
        data = f.read()
    return "0x" + data.hex()


def format_point(name: str, x: int, y: int, indent: str = "            ") -> str:
    """Format a G1Point assignment for Solidity."""
    return (
        f"{indent}{name}: Honk.G1Point({{ \n"
        f"{indent}   x: uint256(0x{x:064x}),\n"
        f"{indent}   y: uint256(0x{y:064x})\n"
        f"{indent}}})"
    )


def generate_vk_library(circuit_name: str, vk_data: dict, vk_hash: str) -> str:
    """Generate the HonkVerificationKey library and constants for a circuit."""
    pascal_name = snake_to_pascal(circuit_name)
    n = vk_data["n"]
    log_n = vk_data["log_n"]
    num_pi = vk_data["num_public_inputs"]
    points = vk_data["points"]
    is_recursive = vk_data.get("is_recursive", False)

    sol_field_order = SOL_FIELD_ORDER_RECURSIVE if is_recursive else SOL_FIELD_ORDER_STANDARD

    lines = []
    lines.append(f"uint256 constant N = {n};")
    lines.append(f"uint256 constant LOG_N = {log_n};")
    lines.append(f"uint256 constant NUMBER_OF_PUBLIC_INPUTS = {num_pi};")
    lines.append(f"uint256 constant VK_HASH = {vk_hash};")
    if is_recursive:
        lines.append("uint256 constant IS_RECURSIVE = 1;")

    lines.append("library HonkVerificationKey {")
    lines.append("    function loadVerificationKey() internal pure returns (Honk.VerificationKey memory) {")
    lines.append("        Honk.VerificationKey memory vk = Honk.VerificationKey({")
    lines.append(f"            circuitSize: uint256({n}),")
    lines.append(f"            logCircuitSize: uint256({log_n}),")
    lines.append(f"            publicInputsSize: uint256({num_pi}),")

    # Emit points in Solidity field order
    point_lines = []
    for name in sol_field_order:
        x, y = points[name]
        point_lines.append(format_point(name, x, y))

    lines.append(",\n".join(point_lines))
    lines.append("        });")
    lines.append("        return vk;")
    lines.append("    }")
    lines.append("}")

    return "\n".join(lines)


def generate_verifier_sol(circuit_name: str, vk_data: dict, vk_hash: str, base_contract_code: str) -> str:
    """Generate a complete Solidity verifier file."""
    pascal_name = snake_to_pascal(circuit_name)
    contract_name = f"{pascal_name}Verifier"

    header = (
        "// SPDX-License-Identifier: Apache-2.0\n"
        "// Copyright 2022 Aztec\n"
        f"// Auto-generated UltraHonk verifier for {circuit_name} circuit\n"
        f"// Generated from VK at noir/target/{circuit_name}_vk/vk\n"
        "pragma solidity ^0.8.24;\n\n"
    )

    vk_lib = generate_vk_library(circuit_name, vk_data, vk_hash)

    footer = (
        f"\ncontract {contract_name} is BaseZKHonkVerifier(N, LOG_N, VK_HASH, NUMBER_OF_PUBLIC_INPUTS) {{\n"
        f"     function loadVerificationKey() internal pure override returns (Honk.VerificationKey memory) {{\n"
        f"       return HonkVerificationKey.loadVerificationKey();\n"
        f"    }}\n"
        f"}}\n"
    )

    return header + vk_lib + "\n\n" + base_contract_code + footer


def extract_base_contract(reference_verifier_path: str) -> str:
    """Extract the shared BaseZKHonkVerifier code from a working verifier."""
    with open(reference_verifier_path, "r") as f:
        lines = f.readlines()

    # Find the start of shared code (after HonkVerificationKey library closing brace)
    # and end (before the final contract declaration)
    start_line = None
    end_line = None

    for i, line in enumerate(lines):
        # The shared code starts with the IVerifier interface (line after VK library)
        if line.strip().startswith("interface IVerifier"):
            start_line = i
        # The final contract line
        if line.strip().startswith("contract ") and "is BaseZKHonkVerifier" in line:
            end_line = i
            break

    if start_line is None or end_line is None:
        raise ValueError("Could not find shared code boundaries in reference verifier")

    # Include everything from IVerifier to just before the final contract
    return "".join(lines[start_line:end_line])


def main():
    project_root = Path(__file__).parent.parent
    target_dir = project_root / "noir" / "target"
    generated_dir = project_root / "contracts" / "verifiers" / "generated"
    reference_verifier = generated_dir / "ContainerVerifier.sol"

    if not reference_verifier.exists():
        print(f"ERROR: Reference verifier not found at {reference_verifier}")
        sys.exit(1)

    print("Extracting BaseZKHonkVerifier from ContainerVerifier.sol...")
    base_contract_code = extract_base_contract(str(reference_verifier))
    print(f"  Extracted {len(base_contract_code)} chars of shared code")

    success_count = 0
    fail_count = 0

    for circuit_name in STUB_CIRCUITS:
        vk_dir = target_dir / f"{circuit_name}_vk"
        vk_file = vk_dir / "vk"
        vk_hash_file = vk_dir / "vk_hash"

        if not vk_file.exists():
            is_recursive = circuit_name in RECURSIVE_CIRCUITS
            hint = (
                " (recursive circuit — compile with `nargo compile` then "
                "`bb write_vk_ultra_honk -b target/aggregator.json -o target/aggregator_vk/vk`)"
                if is_recursive
                else ""
            )
            print(f"SKIP: {circuit_name} — no VK file at {vk_file}{hint}")
            fail_count += 1
            continue

        print(f"\nProcessing: {circuit_name}")

        try:
            vk_data = parse_vk(str(vk_file), circuit_name)
            print(f"  N={vk_data['n']}, LOG_N={vk_data['log_n']}, PUBLIC_INPUTS={vk_data['num_public_inputs']}")

            if vk_hash_file.exists():
                vk_hash = read_vk_hash(str(vk_hash_file))
            else:
                vk_hash = "0x0000000000000000000000000000000000000000000000000000000000000000"
                print(f"  WARNING: No vk_hash file, using zero hash")

            sol_code = generate_verifier_sol(circuit_name, vk_data, vk_hash, base_contract_code)

            pascal_name = snake_to_pascal(circuit_name)
            output_file = generated_dir / f"{pascal_name}Verifier.sol"
            with open(output_file, "w") as f:
                f.write(sol_code)

            print(f"  -> Generated {output_file.name} ({len(sol_code)} chars)")
            success_count += 1

        except Exception as e:
            print(f"  ERROR: {e}")
            fail_count += 1

    print(f"\n{'='*60}")
    print(f"Generated: {success_count}/{len(STUB_CIRCUITS)} verifiers")
    if fail_count > 0:
        print(f"Failed: {fail_count}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
