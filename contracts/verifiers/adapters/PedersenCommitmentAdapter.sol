// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title PedersenCommitmentAdapter
 * @notice Adapter for Pedersen commitment circuit verification
 * @dev Public inputs: [commitment, owner_pubkey, result]
 *      The circuit verifies: C = vG + rH where v=value, r=blinding
 *      Pedersen commitments are additively homomorphic and perfectly hiding
 *
 * Circuit location: noir/pedersen_commitment/src/main.nr
 * Gas estimate: ~48,000 per verification
 */
contract PedersenCommitmentAdapter is NoirVerifierAdapter {
    /// @notice Number of public inputs for this circuit
    uint256 public constant PUBLIC_INPUT_COUNT = 3;

    /// @notice Public input indices
    uint256 private constant IDX_COMMITMENT = 0;
    uint256 private constant IDX_OWNER_PUBKEY = 1;
    uint256 private constant IDX_RESULT = 2;

    /// @notice Emitted when a commitment is verified
    event CommitmentVerified(
        bytes32 indexed commitment,
        bytes32 indexed ownerPubkey
    );

    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    /**
     * @notice Verify a Pedersen commitment proof
     * @param proof The UltraPlonk proof bytes
     * @param publicInputs ABI-encoded (commitment, ownerPubkey, result)
     * @return Whether the proof is valid
     */
    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);

        require(
            inputs.length == PUBLIC_INPUT_COUNT,
            "PCA: SIGNAL_COUNT_MISMATCH"
        );

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    /**
     * @notice Verify commitment with explicit parameters
     * @param proof The UltraPlonk proof bytes
     * @param commitment The Pedersen commitment C = vG + rH
     * @param ownerPubkey The public key derived from owner's secret
     * @return valid Whether the commitment proof is valid
     */
    function verifyCommitment(
        bytes calldata proof,
        bytes32 commitment,
        bytes32 ownerPubkey
    ) external view returns (bool valid) {
        bytes32[] memory signals = new bytes32[](PUBLIC_INPUT_COUNT);
        signals[IDX_COMMITMENT] = commitment;
        signals[IDX_OWNER_PUBKEY] = ownerPubkey;
        signals[IDX_RESULT] = bytes32(uint256(1)); // Expected result: true

        return INoirVerifier(noirVerifier).verify(proof, signals);
    }

    /**
     * @notice Batch verify multiple commitments (helper for efficiency)
     * @dev Each proof is verified individually; for true batching use AggregatorAdapter
     * @param proofs Array of proof bytes
     * @param commitments Array of commitments
     * @param ownerPubkeys Array of owner public keys
     * @return allValid True if all proofs verify
     */
    function batchVerifyCommitments(
        bytes[] calldata proofs,
        bytes32[] calldata commitments,
        bytes32[] calldata ownerPubkeys
    ) external view returns (bool allValid) {
        require(
            proofs.length == commitments.length &&
                commitments.length == ownerPubkeys.length,
            "PCA: LENGTH_MISMATCH"
        );

        bytes32[] memory signals = new bytes32[](PUBLIC_INPUT_COUNT);
        signals[IDX_RESULT] = bytes32(uint256(1));

        for (uint256 i = 0; i < proofs.length; i++) {
            signals[IDX_COMMITMENT] = commitments[i];
            signals[IDX_OWNER_PUBKEY] = ownerPubkeys[i];

            if (!INoirVerifier(noirVerifier).verify(proofs[i], signals)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @inheritdoc NoirVerifierAdapter
     */
    function getPublicInputCount() public pure override returns (uint256) {
        return PUBLIC_INPUT_COUNT;
    }
}
