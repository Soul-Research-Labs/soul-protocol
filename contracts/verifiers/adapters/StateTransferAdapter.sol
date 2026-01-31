// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title StateTransferAdapter
 * @notice Adapter for the State Transfer Noir circuit
 * @dev Mapped to 7 public signals: [isValid, old_com, new_com, old_null, sender_pub, recip_pub, value]
 */
contract StateTransferAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Exact count validation as per exhaustive spec
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: STATE_TRANSFER");
        
        // Signal[0] is the return boolean from Noir main
        bool circuitPassed = uint256(inputs[0]) == 1;
        
        if (!circuitPassed) return false;

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 7;
    }
}
