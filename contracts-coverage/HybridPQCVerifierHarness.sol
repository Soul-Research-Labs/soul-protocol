// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {HybridPQCVerifier} from "../contracts/pqc/HybridPQCVerifier.sol";

/**
 * @title HybridPQCVerifierHarness
 * @author Soul Protocol
 * @notice Test harness for coverage of HybridPQCVerifier
 * @dev Exposes internal functions for testing and provides simplified interfaces
 */
contract HybridPQCVerifierHarness is HybridPQCVerifier {
    constructor(
        address admin,
        VerificationMode initialMode
    ) HybridPQCVerifier(admin, initialMode) {}

    /**
     * @notice Exposes internal _verifySolidity for testing
     */
    function exposed_verifySolidity(
        VerificationRequest calldata request
    ) external view returns (bool) {
        return _verifySolidity(request);
    }

    /**
     * @notice Exposes internal _isPrecompileAvailable for testing
     */
    function exposed_isPrecompileAvailable() external view returns (bool) {
        return _isPrecompileAvailable();
    }

    /**
     * @notice Exposes internal _isCacheValid for testing
     */
    function exposed_isCacheValid(
        bytes32 requestHash
    ) external view returns (bool) {
        return _isCacheValid(requestHash);
    }

    /**
     * @notice Sets mode directly for testing (bypasses controls)
     */
    function setModeForTesting(
        VerificationMode mode
    ) external onlyRole(ADMIN_ROLE) {
        currentMode = mode;
    }

    /**
     * @notice Clears cache for testing
     */
    function clearCache(bytes32 requestHash) external onlyRole(ADMIN_ROLE) {
        delete verificationCache[requestHash];
        delete cacheTimestamps[requestHash];
    }

    /**
     * @notice Creates a test verification request
     */
    function createTestRequest(
        SignatureAlgorithm algo
    ) external pure returns (VerificationRequest memory) {
        bytes memory testPK = new bytes(
            algo == SignatureAlgorithm.DILITHIUM3 ? 1952 : 2592
        );
        bytes memory testMsg = new bytes(32);
        bytes memory testSig = new bytes(
            algo == SignatureAlgorithm.DILITHIUM3 ? 3293 : 4595
        );

        return
            VerificationRequest({
                algorithm: algo,
                publicKey: testPK,
                message: testMsg,
                signature: testSig
            });
    }
}
