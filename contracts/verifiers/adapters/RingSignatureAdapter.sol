// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title RingSignatureAdapter
 * @notice Adapter for the Ring Signature Noir circuit
 * @dev Mapped to 19 public signals:
 *      Struct members: [ring[8]*2, message_hash, key_image_x, key_image_y]
 */
contract RingSignatureAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Ring signature has a return bool + PublicInputs struct
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: RING_SIGNATURE");
        
        // Signal[0] is the return boolean from Noir main
        bool circuitPassed = uint256(inputs[0]) == 1;
        
        if (!circuitPassed) return false;

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 20;
    }
}
