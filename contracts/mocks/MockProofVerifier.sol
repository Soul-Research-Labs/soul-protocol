// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title MockProofVerifier
 * @notice Mock proof verifier with configurable results for testing
 * @dev Used in integration tests that require a proof verifier contract
 */
contract MockProofVerifier is IProofVerifier {
    /// @notice The result to return for verification calls
    bool public verificationResult = true;

    /// @notice Set the verification result
    /// @param result The result to return for future verification calls
    function setVerificationResult(bool result) external {
        verificationResult = result;
    }

    /// @notice Single-arg verify used by CrossChainPrivacyHub._delegateVerify
    function verify(bytes calldata /* proof */) external view returns (bool) {
        return verificationResult;
    }

    /// @inheritdoc IProofVerifier
    function verifyProof(
        bytes calldata /* proof */,
        bytes calldata /* publicInputs */
    ) external view override returns (bool) {
        return verificationResult;
    }

    /// @notice Alternative verification signature with bytes32 array
    function verifyProof(
        bytes calldata /* proof */,
        bytes32[] calldata /* publicInputs */
    ) external view returns (bool) {
        return verificationResult;
    }

    /// @notice IZKVerifier compatible interface
    function verifyProof(
        bytes calldata /* proof */,
        uint256[] calldata /* publicInputs */
    ) external view returns (bool) {
        return verificationResult;
    }

    /// @notice Noir verifier interface
    function verify(
        bytes calldata /* proof */,
        bytes32[] calldata /* signals */
    ) external view returns (bool) {
        return verificationResult;
    }

    /// @inheritdoc IProofVerifier
    function verify(
        bytes calldata /* proof */,
        uint256[] calldata /* publicInputs */
    ) external view override returns (bool) {
        return verificationResult;
    }

    /// @inheritdoc IProofVerifier
    function verifySingle(
        bytes calldata /* proof */,
        uint256 /* publicInput */
    ) external view override returns (bool) {
        return verificationResult;
    }

    /// @inheritdoc IProofVerifier
    function getPublicInputCount() external pure override returns (uint256) {
        return 1;
    }

    /// @inheritdoc IProofVerifier
    function isReady() external pure override returns (bool) {
        return true;
    }

    /// @notice Get verification key hash (mock)
    function getVerificationKeyHash() external pure returns (bytes32) {
        return keccak256("MOCK_VK_HASH");
    }
}
