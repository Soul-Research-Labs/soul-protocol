// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title BalanceProofAdapter
 * @notice Adapter for the Balance Proof Noir circuit
 * @dev Mapped to 6 public signals: [old_root, new_root, nullifier_hash, amount, token, is_deposit]
 */
contract BalanceProofAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Exact count validation: 6 public inputs
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: BALANCE_PROOF");
        
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 6;
    }
}
