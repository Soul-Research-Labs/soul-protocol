// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title PrivateOrderAdapter
 * @notice Adapter for the Private Order Noir circuit
 * @dev Mapped to 4 public signals: [order_commitment, nullifier_hash, merkle_root, min_amount_out]
 */
contract PrivateOrderAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Exact count validation: 4 public signals
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: PRIVATE_ORDER");
        
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 4;
    }
}
