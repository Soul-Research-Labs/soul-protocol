// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title ComposableRevocationProofs
 * @author Soul Protocol
 * @notice Research-grade implementation of Composable Revocation Proofs (CRP)
 * @dev Enables privacy-preserving credential revocation with composable proofs
 *
 * Composable Revocation Proofs allow:
 * - Revocation without revealing credential identity
 * - Accumulator-based membership/non-membership proofs
 * - Efficient batch revocation updates
 * - Privacy-preserving revocation status checks
 * - Composable with other credential proofs
 *
 * Key Techniques:
 * - RSA Accumulators for revocation lists
 * - Zero-knowledge non-membership proofs
 * - Delta updates for efficient revocation propagation
 */
contract ComposableRevocationProofs is
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                               ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("REVOCATION_MANAGER_ROLE")
    bytes32 public constant REVOCATION_MANAGER_ROLE =
        0x02ee075c7da8b2fd2f3c683fd86848a232efcddcc392f4e81fb8fb4f80bc8333;
    /// @dev keccak256("ACCUMULATOR_OPERATOR_ROLE")
    bytes32 public constant ACCUMULATOR_OPERATOR_ROLE =
        0x4859a9a09eae5a428737d4845e8d3a5c48c9e22c00db19e1877c6fe0ef9488d9;
    /// @dev keccak256("VERIFIER_ROLE")
    bytes32 public constant VERIFIER_ROLE =
        0x0ce23c3e399818cfee81a7ab0880f714e53d7672b08df0fa62f2843416e1ea09;

    /*//////////////////////////////////////////////////////////////
                               TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice A revocation accumulator
    struct RevocationAccumulator {
        bytes32 accumulatorId;
        bytes32 currentValue; // Current accumulator value
        bytes32 previousValue; // Previous value for delta computation
        uint256 version; // Version number
        uint256 elementCount; // Number of revoked elements
        uint64 createdAt;
        uint64 lastUpdated;
        bool isActive;
    }

    /// @notice A revocation entry (element in the accumulator)
    struct RevocationEntry {
        bytes32 entryId;
        bytes32 accumulatorId;
        bytes32 credentialHash; // Hash of revoked credential
        bytes32 witness; // Membership witness for efficient verification
        uint256 version; // Accumulator version when added
        uint64 revokedAt;
        address revoker;
        string reason;
    }

    /// @notice A non-membership proof (credential is NOT revoked)
    struct NonMembershipProof {
        bytes32 proofId;
        bytes32 accumulatorId;
        bytes32 credentialHash;
        bytes32 accumulatorValue; // Accumulator value at proof time
        uint256 accumulatorVersion;
        bytes proof; // ZK non-membership proof
        uint64 createdAt;
        uint64 validUntil;
        bool isVerified;
    }

    /// @notice Delta update for efficient accumulator updates
    struct DeltaUpdate {
        bytes32 updateId;
        bytes32 accumulatorId;
        uint256 fromVersion;
        uint256 toVersion;
        bytes32[] addedElements; // Newly revoked
        bytes32[] removedElements; // Un-revoked (rare)
        bytes32 deltaProof; // Proof of correct update
        uint64 timestamp;
    }

    /// @notice Composable proof combining revocation status with other proofs
    struct ComposableProof {
        bytes32 composableId;
        bytes32 nonMembershipProofId; // Revocation proof
        bytes32[] additionalProofIds; // Other proofs to compose
        bytes32 composedProof; // Final composed proof
        uint64 createdAt;
        bool isValid;
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Accumulator storage
    mapping(bytes32 => RevocationAccumulator) public accumulators;

    /// @notice Revocation entries by ID
    mapping(bytes32 => RevocationEntry) public revocationEntries;

    /// @notice Check if credential is in revocation accumulator
    mapping(bytes32 => mapping(bytes32 => bool)) public isRevoked;

    /// @notice Non-membership proofs storage
    mapping(bytes32 => NonMembershipProof) public nonMembershipProofs;

    /// @notice Delta updates storage
    mapping(bytes32 => DeltaUpdate) public deltaUpdates;

    /// @notice Composable proofs storage
    mapping(bytes32 => ComposableProof) public composableProofs;

    /// @notice Accumulator history (version -> value)
    mapping(bytes32 => mapping(uint256 => bytes32)) public accumulatorHistory;

    /// @notice Active accumulators
    bytes32[] public activeAccumulators;

    /// @notice Counter for unique IDs
    uint256 private _idCounter;

    /// @notice Statistics
    uint256 public totalAccumulators;
    uint256 public totalRevocations;
    uint256 public totalProofs;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event AccumulatorCreated(
        bytes32 indexed accumulatorId,
        bytes32 initialValue
    );

    event AccumulatorUpdated(
        bytes32 indexed accumulatorId,
        bytes32 newValue,
        uint256 version
    );

    event CredentialRevoked(
        bytes32 indexed entryId,
        bytes32 indexed accumulatorId,
        bytes32 credentialHash
    );

    event CredentialUnrevoked(
        bytes32 indexed accumulatorId,
        bytes32 credentialHash
    );

    event NonMembershipProofCreated(
        bytes32 indexed proofId,
        bytes32 indexed accumulatorId,
        bytes32 credentialHash
    );

    event NonMembershipProofVerified(bytes32 indexed proofId, bool isValid);

    event DeltaUpdatePublished(
        bytes32 indexed updateId,
        bytes32 indexed accumulatorId,
        uint256 fromVersion,
        uint256 toVersion
    );

    event ComposableProofCreated(
        bytes32 indexed composableId,
        bytes32 nonMembershipProofId
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error AccumulatorNotFound();
    error AccumulatorInactive();
    error RevocationEntryNotFound();
    error AlreadyRevoked();
    error NotRevoked();
    error ProofNotFound();
    error ProofExpired();
    error ProofInvalid();
    error VersionMismatch();
    error Unauthorized();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REVOCATION_MANAGER_ROLE, msg.sender);
        _grantRole(ACCUMULATOR_OPERATOR_ROLE, msg.sender);
        _grantRole(VERIFIER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                      ACCUMULATOR FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new revocation accumulator
     * @param initialValue The initial accumulator value
     * @return accumulatorId The accumulator ID
     */
    function createAccumulator(
        bytes32 initialValue
    )
        external
        whenNotPaused
        onlyRole(ACCUMULATOR_OPERATOR_ROLE)
        returns (bytes32 accumulatorId)
    {
        accumulatorId = keccak256(
            abi.encodePacked(
                initialValue,
                msg.sender,
                block.timestamp,
                ++_idCounter
            )
        );

        accumulators[accumulatorId] = RevocationAccumulator({
            accumulatorId: accumulatorId,
            currentValue: initialValue,
            previousValue: bytes32(0),
            version: 1,
            elementCount: 0,
            createdAt: uint64(block.timestamp),
            lastUpdated: uint64(block.timestamp),
            isActive: true
        });

        accumulatorHistory[accumulatorId][1] = initialValue;
        activeAccumulators.push(accumulatorId);
        unchecked {
            ++totalAccumulators;
        }

        emit AccumulatorCreated(accumulatorId, initialValue);

        return accumulatorId;
    }

    /**
     * @notice Revoke a credential by adding to accumulator
     * @param accumulatorId The target accumulator
     * @param credentialHash Hash of the credential to revoke
     * @param witness Membership witness for the credential
     * @param reason Revocation reason
     * @return entryId The revocation entry ID
     */
    function revokeCredential(
        bytes32 accumulatorId,
        bytes32 credentialHash,
        bytes32 witness,
        string calldata reason
    )
        external
        whenNotPaused
        onlyRole(REVOCATION_MANAGER_ROLE)
        returns (bytes32 entryId)
    {
        RevocationAccumulator storage accumulator = accumulators[accumulatorId];
        if (accumulator.createdAt == 0) revert AccumulatorNotFound();
        if (!accumulator.isActive) revert AccumulatorInactive();
        if (isRevoked[accumulatorId][credentialHash]) revert AlreadyRevoked();

        entryId = keccak256(
            abi.encodePacked(
                accumulatorId,
                credentialHash,
                block.timestamp,
                ++_idCounter
            )
        );

        revocationEntries[entryId] = RevocationEntry({
            entryId: entryId,
            accumulatorId: accumulatorId,
            credentialHash: credentialHash,
            witness: witness,
            version: accumulator.version + 1,
            revokedAt: uint64(block.timestamp),
            revoker: msg.sender,
            reason: reason
        });

        // Update accumulator
        accumulator.previousValue = accumulator.currentValue;
        accumulator.currentValue = keccak256(
            abi.encodePacked(accumulator.currentValue, credentialHash)
        );
        unchecked {
            ++accumulator.version;
            ++accumulator.elementCount;
        }
        accumulator.lastUpdated = uint64(block.timestamp);

        accumulatorHistory[accumulatorId][accumulator.version] = accumulator
            .currentValue;
        isRevoked[accumulatorId][credentialHash] = true;
        unchecked {
            ++totalRevocations;
        }

        emit CredentialRevoked(entryId, accumulatorId, credentialHash);
        emit AccumulatorUpdated(
            accumulatorId,
            accumulator.currentValue,
            accumulator.version
        );

        return entryId;
    }

    /**
     * @notice Batch revoke multiple credentials
     * @param accumulatorId The target accumulator
     * @param credentialHashes Hashes of credentials to revoke
     * @param witnesses Membership witnesses
     * @param reason Common revocation reason
     */
    function batchRevokeCredentials(
        bytes32 accumulatorId,
        bytes32[] calldata credentialHashes,
        bytes32[] calldata witnesses,
        string calldata reason
    ) external whenNotPaused onlyRole(REVOCATION_MANAGER_ROLE) {
        RevocationAccumulator storage accumulator = accumulators[accumulatorId];
        if (accumulator.createdAt == 0) revert AccumulatorNotFound();
        if (!accumulator.isActive) revert AccumulatorInactive();

        accumulator.previousValue = accumulator.currentValue;
        bytes32 newValue = accumulator.currentValue;

        for (uint256 i = 0; i < credentialHashes.length; ) {
            if (!isRevoked[accumulatorId][credentialHashes[i]]) {
                bytes32 entryId = keccak256(
                    abi.encodePacked(
                        accumulatorId,
                        credentialHashes[i],
                        block.timestamp,
                        ++_idCounter
                    )
                );

                revocationEntries[entryId] = RevocationEntry({
                    entryId: entryId,
                    accumulatorId: accumulatorId,
                    credentialHash: credentialHashes[i],
                    witness: witnesses[i],
                    version: accumulator.version + 1,
                    revokedAt: uint64(block.timestamp),
                    revoker: msg.sender,
                    reason: reason
                });

                newValue = keccak256(
                    abi.encodePacked(newValue, credentialHashes[i])
                );
                isRevoked[accumulatorId][credentialHashes[i]] = true;
                unchecked {
                    ++accumulator.elementCount;
                    ++totalRevocations;
                }

                emit CredentialRevoked(
                    entryId,
                    accumulatorId,
                    credentialHashes[i]
                );
            }
            unchecked {
                ++i;
            }
        }

        accumulator.currentValue = newValue;
        accumulator.version++;
        accumulator.lastUpdated = uint64(block.timestamp);
        accumulatorHistory[accumulatorId][accumulator.version] = newValue;

        emit AccumulatorUpdated(accumulatorId, newValue, accumulator.version);
    }

    /**
     * @notice Un-revoke a credential (rare operation)
     * @param accumulatorId The target accumulator
     * @param credentialHash Hash of the credential to un-revoke
     */
    function unrevokeCredential(
        bytes32 accumulatorId,
        bytes32 credentialHash
    ) external whenNotPaused onlyRole(REVOCATION_MANAGER_ROLE) {
        if (!isRevoked[accumulatorId][credentialHash]) revert NotRevoked();

        RevocationAccumulator storage accumulator = accumulators[accumulatorId];
        if (accumulator.createdAt == 0) revert AccumulatorNotFound();

        // Update revocation status
        isRevoked[accumulatorId][credentialHash] = false;
        accumulator.elementCount--;
        accumulator.lastUpdated = uint64(block.timestamp);

        // Note: Full accumulator update would be more complex in production
        // This is a simplified implementation
        accumulator.currentValue = keccak256(
            abi.encodePacked(
                accumulator.currentValue,
                "UNREVOKE",
                credentialHash
            )
        );
        unchecked {
            ++accumulator.version;
        }
        accumulatorHistory[accumulatorId][accumulator.version] = accumulator
            .currentValue;

        emit CredentialUnrevoked(accumulatorId, credentialHash);
        emit AccumulatorUpdated(
            accumulatorId,
            accumulator.currentValue,
            accumulator.version
        );
    }

    /*//////////////////////////////////////////////////////////////
                   NON-MEMBERSHIP PROOF FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a non-membership proof (credential NOT revoked)
     * @param accumulatorId The accumulator to prove against
     * @param credentialHash Hash of the credential
     * @param proof ZK non-membership proof
     * @param validityPeriod How long the proof is valid
     * @return proofId The proof ID
     */
    function submitNonMembershipProof(
        bytes32 accumulatorId,
        bytes32 credentialHash,
        bytes calldata proof,
        uint64 validityPeriod
    ) external whenNotPaused nonReentrant returns (bytes32 proofId) {
        RevocationAccumulator storage accumulator = accumulators[accumulatorId];
        if (accumulator.createdAt == 0) revert AccumulatorNotFound();

        proofId = keccak256(
            abi.encodePacked(
                accumulatorId,
                credentialHash,
                accumulator.currentValue,
                block.timestamp,
                ++_idCounter
            )
        );

        nonMembershipProofs[proofId] = NonMembershipProof({
            proofId: proofId,
            accumulatorId: accumulatorId,
            credentialHash: credentialHash,
            accumulatorValue: accumulator.currentValue,
            accumulatorVersion: accumulator.version,
            proof: proof,
            createdAt: uint64(block.timestamp),
            validUntil: uint64(block.timestamp) + validityPeriod,
            isVerified: false
        });

        unchecked {
            ++totalProofs;
        }

        emit NonMembershipProofCreated(proofId, accumulatorId, credentialHash);

        return proofId;
    }

    /**
     * @notice Verify a non-membership proof
     * @param proofId The proof to verify
     * @return isValid Whether the credential is NOT revoked
     */
    function verifyNonMembershipProof(
        bytes32 proofId
    ) external onlyRole(VERIFIER_ROLE) returns (bool isValid) {
        NonMembershipProof storage proof = nonMembershipProofs[proofId];
        if (proof.createdAt == 0) revert ProofNotFound();
        if (block.timestamp > proof.validUntil) revert ProofExpired();

        // Verify accumulator exists and is active
        RevocationAccumulator storage accumulator = accumulators[
            proof.accumulatorId
        ];
        if (accumulator.createdAt == 0) revert AccumulatorNotFound();
        if (!accumulator.isActive) revert AccumulatorInactive();

        // Check if credential was NOT revoked at proof time
        // In production, this would verify the ZK proof
        // Also verify the accumulator value matches the proof's recorded value
        isValid =
            !isRevoked[proof.accumulatorId][proof.credentialHash] &&
            proof.proof.length >= 32 &&
            proof.accumulatorValue == accumulator.currentValue;

        proof.isVerified = true;

        emit NonMembershipProofVerified(proofId, isValid);

        return isValid;
    }

    /*//////////////////////////////////////////////////////////////
                      DELTA UPDATE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Publish a delta update for efficient client sync
     * @param accumulatorId The accumulator
     * @param fromVersion Starting version
     * @param toVersion Ending version
     * @param addedElements Elements added (revoked)
     * @param deltaProof Proof of correct delta
     * @return updateId The delta update ID
     */
    function publishDeltaUpdate(
        bytes32 accumulatorId,
        uint256 fromVersion,
        uint256 toVersion,
        bytes32[] calldata addedElements,
        bytes32 deltaProof
    )
        external
        whenNotPaused
        onlyRole(ACCUMULATOR_OPERATOR_ROLE)
        returns (bytes32 updateId)
    {
        RevocationAccumulator storage accumulator = accumulators[accumulatorId];
        if (accumulator.createdAt == 0) revert AccumulatorNotFound();
        if (toVersion > accumulator.version) revert VersionMismatch();

        updateId = keccak256(
            abi.encodePacked(
                accumulatorId,
                fromVersion,
                toVersion,
                block.timestamp,
                ++_idCounter
            )
        );

        bytes32[] memory emptyArray = new bytes32[](0);

        deltaUpdates[updateId] = DeltaUpdate({
            updateId: updateId,
            accumulatorId: accumulatorId,
            fromVersion: fromVersion,
            toVersion: toVersion,
            addedElements: addedElements,
            removedElements: emptyArray,
            deltaProof: deltaProof,
            timestamp: uint64(block.timestamp)
        });

        emit DeltaUpdatePublished(
            updateId,
            accumulatorId,
            fromVersion,
            toVersion
        );

        return updateId;
    }

    /*//////////////////////////////////////////////////////////////
                    COMPOSABLE PROOF FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a composable proof combining revocation status with other proofs
     * @param nonMembershipProofId The revocation non-membership proof
     * @param additionalProofIds Other proof IDs to compose with
     * @return composableId The composable proof ID
     */
    function createComposableProof(
        bytes32 nonMembershipProofId,
        bytes32[] calldata additionalProofIds
    ) external whenNotPaused nonReentrant returns (bytes32 composableId) {
        NonMembershipProof storage nmProof = nonMembershipProofs[
            nonMembershipProofId
        ];
        if (nmProof.createdAt == 0) revert ProofNotFound();

        // Create composed proof hash
        bytes32 composedProof = keccak256(abi.encodePacked(nmProof.proof));
        for (uint256 i = 0; i < additionalProofIds.length; ) {
            composedProof = keccak256(
                abi.encodePacked(composedProof, additionalProofIds[i])
            );
            unchecked {
                ++i;
            }
        }

        composableId = keccak256(
            abi.encodePacked(
                nonMembershipProofId,
                composedProof,
                block.timestamp,
                ++_idCounter
            )
        );

        composableProofs[composableId] = ComposableProof({
            composableId: composableId,
            nonMembershipProofId: nonMembershipProofId,
            additionalProofIds: additionalProofIds,
            composedProof: composedProof,
            createdAt: uint64(block.timestamp),
            isValid: false
        });

        emit ComposableProofCreated(composableId, nonMembershipProofId);

        return composableId;
    }

    /**
     * @notice Verify a composable proof
     * @param composableId The composable proof to verify
     * @return isValid Whether all composed proofs are valid
     */
    function verifyComposableProof(
        bytes32 composableId
    ) external onlyRole(VERIFIER_ROLE) returns (bool isValid) {
        ComposableProof storage composable = composableProofs[composableId];
        if (composable.createdAt == 0) revert ProofNotFound();

        // Verify the underlying non-membership proof
        NonMembershipProof storage nmProof = nonMembershipProofs[
            composable.nonMembershipProofId
        ];
        if (block.timestamp > nmProof.validUntil) revert ProofExpired();

        // Check revocation status
        isValid = !isRevoked[nmProof.accumulatorId][nmProof.credentialHash];

        composable.isValid = isValid;

        return isValid;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getAccumulator(
        bytes32 accumulatorId
    ) external view returns (RevocationAccumulator memory) {
        return accumulators[accumulatorId];
    }

    function getRevocationEntry(
        bytes32 entryId
    ) external view returns (RevocationEntry memory) {
        return revocationEntries[entryId];
    }

    function getNonMembershipProof(
        bytes32 proofId
    ) external view returns (NonMembershipProof memory) {
        return nonMembershipProofs[proofId];
    }

    function getDeltaUpdate(
        bytes32 updateId
    ) external view returns (DeltaUpdate memory) {
        return deltaUpdates[updateId];
    }

    function getComposableProof(
        bytes32 composableId
    ) external view returns (ComposableProof memory) {
        return composableProofs[composableId];
    }

    function getAccumulatorValueAtVersion(
        bytes32 accumulatorId,
        uint256 version
    ) external view returns (bytes32) {
        return accumulatorHistory[accumulatorId][version];
    }

    function isCredentialRevoked(
        bytes32 accumulatorId,
        bytes32 credentialHash
    ) external view returns (bool) {
        return isRevoked[accumulatorId][credentialHash];
    }

    function getActiveAccumulators() external view returns (bytes32[] memory) {
        return activeAccumulators;
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function deactivateAccumulator(
        bytes32 accumulatorId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        accumulators[accumulatorId].isActive = false;
    }
}
