// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title MockSolanaGuardianOracle
 * @notice Mock oracle for verifying Wormhole Guardian attestations in tests
 * @dev Simulates the Wormhole Guardian Network and signature verification.
 *      In production, this would verify actual ECDSA/Ed25519 signatures
 *      from Wormhole Guardians against the current Guardian set.
 *
 * Wormhole Guardian Network:
 * - 19 Guardians observe cross-chain events across supported chains
 * - They sign VAAs (Verified Action Approvals) for cross-chain messages
 * - Verification requires ≥13/19 Guardian signatures (2/3 + 1 supermajority)
 * - Guardians rotate via governance proposals
 *
 * This mock allows tests to:
 * 1. Register/remove Guardians
 * 2. Configure whether attestation verification succeeds or fails
 * 3. Track verification call counts for assertions
 */
contract MockSolanaGuardianOracle is AccessControl {
    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Set of registered Guardian public keys
    mapping(bytes32 => bool) public guardians;

    /// @notice Number of registered Guardians
    uint256 public guardianCount;

    /// @notice Whether verification should succeed (test toggle)
    bool public verificationResult;

    /// @notice Count of verification calls (for test assertions)
    uint256 public verifyCallCount;

    /// @notice Per-Guardian call count
    mapping(bytes32 => uint256) public guardianCallCount;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event GuardianRegistered(bytes32 indexed pubKey);
    event GuardianRemoved(bytes32 indexed pubKey);
    event AttestationVerified(
        bytes32 indexed blockHash,
        bytes32 indexed guardianPubKey,
        bool result
    );

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        verificationResult = true; // Default: verifications succeed
    }

    /*//////////////////////////////////////////////////////////////
                     GUARDIAN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a Guardian public key
    function registerGuardian(
        bytes32 pubKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!guardians[pubKey], "Already registered");
        guardians[pubKey] = true;
        guardianCount++;
        emit GuardianRegistered(pubKey);
    }

    /// @notice Remove a Guardian public key
    function removeGuardian(
        bytes32 pubKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(guardians[pubKey], "Not registered");
        guardians[pubKey] = false;
        guardianCount--;
        emit GuardianRemoved(pubKey);
    }

    /// @notice Batch register Guardians
    function registerGuardians(
        bytes32[] calldata pubKeys
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < pubKeys.length; i++) {
            if (!guardians[pubKeys[i]]) {
                guardians[pubKeys[i]] = true;
                guardianCount++;
                emit GuardianRegistered(pubKeys[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                     VERIFICATION (CALLED BY BRIDGE)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a Guardian's attestation of a block hash
     * @dev Called by SolanaBridgeAdapter via staticcall
     * @param blockHash The block hash being attested to
     * @param guardianPubKey The Guardian's public key
     * @param signature The signature (ignored in mock)
     * @return valid Whether the attestation is valid
     */
    function verifyAttestation(
        bytes32 blockHash,
        bytes32 guardianPubKey,
        bytes calldata signature
    ) external view returns (bool valid) {
        // Suppress unused variable warnings
        blockHash;
        signature;

        // In mock: check if Guardian is registered + global toggle
        if (!guardians[guardianPubKey]) return false;
        return verificationResult;
    }

    /**
     * @notice Non-view version for testing (tracks call counts)
     */
    function verifyAttestationAndTrack(
        bytes32 blockHash,
        bytes32 guardianPubKey,
        bytes calldata signature
    ) external returns (bool valid) {
        signature; // suppress warning
        verifyCallCount++;
        guardianCallCount[guardianPubKey]++;

        bool result = guardians[guardianPubKey] && verificationResult;
        emit AttestationVerified(blockHash, guardianPubKey, result);
        return result;
    }

    /*//////////////////////////////////////////////////////////////
                        TEST CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Set whether verification should succeed or fail
    function setVerificationResult(
        bool _result
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        verificationResult = _result;
    }

    /// @notice Check if a public key is a registered Guardian
    function isGuardian(bytes32 pubKey) external view returns (bool) {
        return guardians[pubKey];
    }
}
