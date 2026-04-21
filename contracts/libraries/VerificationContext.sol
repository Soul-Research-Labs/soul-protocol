// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title VerificationContext
 * @author ZASEON
 * @notice Domain-separation & binding helper for ZK proof verification.
 * @dev The library derives a deterministic "context tag" that callers must
 *      commit to as the last public input of their proof. This binds a
 *      proof to:
 *        - the chain it was verified on (cross-chain replay protection),
 *        - the registry deployment (prevents cross-registry replay),
 *        - the specific circuit id AND its pinned vkey hash (forces
 *          circuit-identity binding),
 *        - a caller-supplied opaque context (nonces, lock-ids, intent-ids).
 *
 *      The router enforces `publicInputs[last] == contextTag(...)` when a
 *      circuit is registered with `requiresContextBinding = true`.
 *
 *      Tag is truncated to the BN254 scalar field so that it is a valid
 *      public input for Groth16 / UltraHonk proofs.
 */
library VerificationContext {
    /// @dev BN254 scalar field modulus (r).
    uint256 internal constant BN254_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Domain separator byte string. Bumping the version invalidates
    ///      all previously-bound proofs — this is intentional.
    bytes32 internal constant DOMAIN_TAG = keccak256("ZASEON_VERIFY_V1");

    /**
     * @notice Compute the binding tag for a single verification call.
     * @param registry   The registry address the router reads from.
     * @param circuitId  The circuit id being verified.
     * @param vkeyHash   The pinned vkey hash for that circuit.
     * @param callerCtx  Opaque caller context (e.g., lock id, nonce).
     * @return tag BN254-field reduced tag; safe to use as a public input.
     */
    function contextTag(
        address registry,
        bytes32 circuitId,
        bytes32 vkeyHash,
        bytes32 callerCtx
    ) internal view returns (uint256 tag) {
        tag =
            uint256(
                keccak256(
                    abi.encode(
                        DOMAIN_TAG,
                        block.chainid,
                        registry,
                        circuitId,
                        vkeyHash,
                        callerCtx
                    )
                )
            ) %
            BN254_SCALAR_FIELD;
    }

    /**
     * @notice Assert every element of `inputs` is < BN254 scalar field.
     * @dev Router-level defense: prevents malformed public inputs from
     *      being silently reduced modulo r by the verifier and forging
     *      acceptance. O(n) loop; each check is a single comparison.
     */
    function assertFieldElements(uint256[] memory inputs) internal pure {
        uint256 n = inputs.length;
        for (uint256 i = 0; i < n; ) {
            if (inputs[i] >= BN254_SCALAR_FIELD) {
                revert FieldElementOutOfRange(i, inputs[i]);
            }
            unchecked {
                ++i;
            }
        }
    }

    error FieldElementOutOfRange(uint256 index, uint256 value);
}
