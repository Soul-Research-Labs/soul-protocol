// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title MockXRPLValidatorOracle
 * @notice Mock oracle for verifying XRPL validator attestations in tests
 * @dev Simulates the UNL (Unique Node List) validator set and Ed25519 signature
 *      verification. In production, this would verify actual Ed25519 signatures
 *      from XRPL validators against the current UNL.
 *
 * XRPL Consensus:
 * - Validators sign validated ledger headers with Ed25519
 * - The UNL defines which validators are trusted
 * - Consensus requires ≥80% of the UNL to agree
 *
 * This mock allows tests to:
 * 1. Register/remove validators from the UNL
 * 2. Configure whether attestation verification succeeds or fails
 * 3. Track verification call counts for assertions
 */
contract MockXRPLValidatorOracle is AccessControl {
    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Set of registered validator public keys
    mapping(bytes32 => bool) public validators;

    /// @notice Number of registered validators
    uint256 public validatorCount;

    /// @notice Whether verification should succeed (test toggle)
    bool public verificationResult;

    /// @notice Count of verification calls (for test assertions)
    uint256 public verifyCallCount;

    /// @notice Per-validator call count
    mapping(bytes32 => uint256) public validatorCallCount;

    /*//////////////////////////////////////////////////////////////
                            EVENTS
    //////////////////////////////////////////////////////////////*/

    event ValidatorRegistered(bytes32 indexed pubKey);
    event ValidatorRemoved(bytes32 indexed pubKey);
    event AttestationVerified(
        bytes32 indexed ledgerHash,
        bytes32 indexed validatorPubKey,
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
                     VALIDATOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a validator public key
    function registerValidator(
        bytes32 pubKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(!validators[pubKey], "Already registered");
        validators[pubKey] = true;
        validatorCount++;
        emit ValidatorRegistered(pubKey);
    }

    /// @notice Remove a validator public key
    function removeValidator(
        bytes32 pubKey
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(validators[pubKey], "Not registered");
        validators[pubKey] = false;
        validatorCount--;
        emit ValidatorRemoved(pubKey);
    }

    /// @notice Batch register validators
    function registerValidators(
        bytes32[] calldata pubKeys
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < pubKeys.length; i++) {
            if (!validators[pubKeys[i]]) {
                validators[pubKeys[i]] = true;
                validatorCount++;
                emit ValidatorRegistered(pubKeys[i]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                     VERIFICATION (CALLED BY BRIDGE)
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a validator's attestation of a ledger hash
     * @dev Called by XRPLBridgeAdapter via staticcall
     * @param ledgerHash The ledger hash being attested to
     * @param validatorPubKey The validator's Ed25519 public key
     * @param signature The Ed25519 signature (ignored in mock)
     * @return valid Whether the attestation is valid
     */
    function verifyAttestation(
        bytes32 ledgerHash,
        bytes32 validatorPubKey,
        bytes calldata signature
    ) external view returns (bool valid) {
        // Suppress unused variable warnings
        ledgerHash;
        signature;

        // In mock: check if validator is registered + global toggle
        if (!validators[validatorPubKey]) return false;
        return verificationResult;
    }

    /**
     * @notice Non-view version for testing (tracks call counts)
     */
    function verifyAttestationAndTrack(
        bytes32 ledgerHash,
        bytes32 validatorPubKey,
        bytes calldata signature
    ) external returns (bool valid) {
        signature; // suppress warning
        verifyCallCount++;
        validatorCallCount[validatorPubKey]++;

        bool result = validators[validatorPubKey] && verificationResult;
        emit AttestationVerified(ledgerHash, validatorPubKey, result);
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

    /// @notice Check if a public key is a registered validator
    function isValidator(bytes32 pubKey) external view returns (bool) {
        return validators[pubKey];
    }

    /// @notice Reset call counters
    function resetCounters() external onlyRole(DEFAULT_ADMIN_ROLE) {
        verifyCallCount = 0;
    }
}
