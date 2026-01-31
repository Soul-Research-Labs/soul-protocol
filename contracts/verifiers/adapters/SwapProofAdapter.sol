// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title SwapProofAdapter
 * @notice Adapter for the Swap Proof Noir circuit
 * @dev Mapped to 11 public signals:
 *      Inputs: [old_root, new_root, pool_id, nullifier, min_out, fee] (6)
 *      Pool: [res_in, res_out, new_in, new_out, fee_rate] (5)
 */
contract SwapProofAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Exact count validation: 11 public signals
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: SWAP_PROOF");
        
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 11;
    }
}
