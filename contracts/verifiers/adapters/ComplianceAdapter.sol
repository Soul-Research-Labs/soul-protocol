// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./NoirVerifierAdapter.sol";

/**
 * @title ComplianceAdapter
 * @notice Adapter for the Compliance Proof Noir circuit
 * @dev Mapped to 16 public signals:
 *      Inputs: [commitment, issuer, holder, timestamp, jurisdictions[8], min_type, policy_id] (14)
 *      Outputs: [isValid, proof_hash] (2)
 */
contract ComplianceAdapter is NoirVerifierAdapter {
    constructor(address _noirVerifier) NoirVerifierAdapter(_noirVerifier) {}

    function verify(
        bytes32 /* circuitHash */,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view override returns (bool) {
        bytes32[] memory inputs = _prepareSignals(publicInputs);
        
        // Exact count validation: 14 inputs + 2 outputs
        require(inputs.length == getPublicInputCount(), "SIG_COUNT_MISMATCH: COMPLIANCE");
        
        // Signal[0] is the return boolean from Noir main
        bool circuitPassed = uint256(inputs[0]) == 1;
        
        if (!circuitPassed) return false;

        return INoirVerifier(noirVerifier).verify(proof, inputs);
    }

    function getPublicInputCount() public pure override returns (uint256) {
        return 16;
    }
}
