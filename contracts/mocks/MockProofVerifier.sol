// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MockProofVerifier
/// @notice Mock verifier for testing - always returns true
/// @dev DO NOT use in production
contract MockProofVerifier {
    bool public shouldVerify = true;

    /// @notice Sets whether verification should pass or fail
    /// @param _shouldVerify True to pass all verifications
    function setVerificationResult(bool _shouldVerify) external {
        shouldVerify = _shouldVerify;
    }

    /// @notice Verifies a proof (mock implementation)
    /// @param proof The proof bytes (ignored)
    /// @param publicInputs The public inputs (ignored)
    /// @return valid Always returns shouldVerify value
    function verifyProof(
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool valid) {
        // Silence unused variable warnings
        proof;
        publicInputs;
        return shouldVerify;
    }
}
