// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title PrivateTransferAdapter
 * @notice Adapter for the Private Transfer Noir circuit
 * @dev Mapped to 16 public signals:
 *      Inputs: [merkle_root, nullifier[2], commitment[2], fee] (6)
 *      Outputs Struct: [key_images[2], stealth[2], eph_x[2], eph_y[2], tags[2]] (10)
 */
contract PrivateTransferAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Total signals: 16 (Inputs + Struct members mapped to flat array)
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: PRIVATE_TRANSFER");
        
        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 16;
    }
}
