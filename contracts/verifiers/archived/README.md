# Archived Verifiers

These verifiers have been superseded by Noir UltraHonk verifiers generated
with `bb` (Barretenberg) and placed in `contracts/verifiers/generated/`.

| File                           | Original Type              | Replaced By                                         |
| ------------------------------ | -------------------------- | --------------------------------------------------- |
| `CrossChainProofVerifier.sol`  | snarkJS Groth16 (Circom)   | `generated/CrossChainProofVerifier.sol` (UltraHonk) |
| `StateCommitmentVerifier.sol`  | snarkJS Groth16 (Circom)   | `generated/StateCommitmentVerifier.sol` (UltraHonk) |
| `StateTransferVerifier.sol`    | snarkJS Groth16 (Circom)   | `generated/StateTransferVerifier.sol` (UltraHonk)   |
| `OptimizedGroth16Verifier.sol` | Hand-written BN254 Groth16 | All circuits now use UltraHonk via `generated/`     |

**Why archived?**

- Zero production imports (only referenced in old tests)
- Same contract names as generated replacements caused compilation shadowing
- Groth16/Circom proving stack superseded by Noir/UltraHonk
