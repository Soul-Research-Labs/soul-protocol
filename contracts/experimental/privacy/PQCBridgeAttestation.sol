// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../../interfaces/IPQCVerifier.sol";

/**
 * @title PQCBridgeAttestation
 * @author ZASEON
 * @notice Post-quantum bridge message attestation layer
 * @dev Phase 2 PQC migration: Adds hybrid ECDSA+PQC attestations to
 *      cross-chain bridge messages. Each bridge message can optionally
 *      carry a PQC attestation alongside the classical signature.
 *
 * ══════════════════════════════════════════════════════════════════════════
 *                 HYBRID BRIDGE ATTESTATION FLOW
 * ══════════════════════════════════════════════════════════════════════════
 *
 * Classical bridge flow:
 *   Validator signs message with ECDSA → adapters verify via ecrecover
 *
 * Hybrid bridge flow (Phase 2):
 *   Validator signs with ECDSA + Falcon-512 →
 *   PQCBridgeAttestation stores PQC attestation →
 *   Bridge adapters check ECDSA on-chain + query PQC attestation status →
 *   Message verified only if both pass (HYBRID mode)
 *
 * FUTURE (Phase 3+):
 *   When EVM PQC precompiles ship, PQC attestations will be verified
 *   on-chain and the oracle-based flow will be deprecated.
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract PQCBridgeAttestation is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ATTESTOR_ROLE = keccak256("ATTESTOR_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                             CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant BRIDGE_ATTESTATION_DOMAIN =
        keccak256("ZASEON_PQC_BRIDGE_ATTESTATION_V1");

    /// @notice Attestation expiry period
    uint256 public constant ATTESTATION_EXPIRY = 24 hours;

    /// @notice Minimum required attestations for quorum
    uint256 public constant MIN_QUORUM = 2;

    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice PQC attestation for a bridge message
    struct BridgeAttestation {
        bytes32 messageHash; // Bridge message hash being attested
        address attestor; // Validator/attestor address
        IPQCVerifier.PQCAlgorithm algorithm; // PQC algorithm used
        bytes32 pqcSigHash; // Hash of PQC signature (actual sig stored off-chain)
        bytes32 pqcKeyHash; // Hash of attestor's PQC public key
        uint256 sourceChainId;
        uint256 destChainId;
        uint256 timestamp;
        bool verified; // Oracle-verified PQC signature
    }

    /// @notice Aggregated attestation status for a message
    struct MessageAttestationStatus {
        bytes32 messageHash;
        uint256 totalAttestations;
        uint256 verifiedAttestations;
        uint256 firstAttestedAt;
        uint256 lastAttestedAt;
        bool quorumReached;
    }

    /*//////////////////////////////////////////////////////////////
                               STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Attestations per message hash
    mapping(bytes32 => BridgeAttestation[]) public messageAttestations;

    /// @notice Attestation status per message
    mapping(bytes32 => MessageAttestationStatus) public attestationStatus;

    /// @notice Whether an attestor has already attested a specific message
    mapping(bytes32 => mapping(address => bool)) public hasAttested;

    /// @notice Registered PQC attestors with their algorithm preference
    mapping(address => IPQCVerifier.PQCAlgorithm) public attestorAlgorithm;

    /// @notice PQC key hashes for registered attestors
    mapping(address => bytes32) public attestorKeyHash;

    /// @notice Total attestations submitted
    uint256 public totalAttestations;

    /// @notice Total messages with quorum
    uint256 public totalQuorumReached;

    /// @notice Quorum threshold (configurable)
    uint256 public quorumThreshold;

    /// @notice HybridPQCVerifier reference for oracle lookups
    address public hybridPQCVerifier;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event AttestorRegistered(
        address indexed attestor,
        IPQCVerifier.PQCAlgorithm algorithm,
        bytes32 keyHash
    );

    event AttestorRemoved(address indexed attestor);

    event BridgeAttestationSubmitted(
        bytes32 indexed messageHash,
        address indexed attestor,
        IPQCVerifier.PQCAlgorithm algorithm,
        uint256 sourceChainId,
        uint256 destChainId
    );

    event AttestationVerified(
        bytes32 indexed messageHash,
        address indexed attestor,
        bool pqcValid
    );

    event QuorumReached(
        bytes32 indexed messageHash,
        uint256 attestationCount,
        uint256 timestamp
    );

    event QuorumThresholdUpdated(uint256 oldThreshold, uint256 newThreshold);
    event HybridPQCVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotAttestor();
    error AlreadyAttested(bytes32 messageHash, address attestor);
    error AttestorNotRegistered(address attestor);
    error AttestationExpired(bytes32 messageHash);
    error InvalidQuorumThreshold(uint256 threshold);
    error ZeroAddress();
    error InvalidMessageHash();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _admin,
        address _hybridPQCVerifier,
        uint256 _quorumThreshold
    ) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_quorumThreshold < MIN_QUORUM)
            revert InvalidQuorumThreshold(_quorumThreshold);

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(ATTESTOR_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        hybridPQCVerifier = _hybridPQCVerifier;
        quorumThreshold = _quorumThreshold;
    }

    /*//////////////////////////////////////////////////////////////
                     ATTESTOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a PQC attestor (bridge validator)
     * @param attestor Address of the attestor
     * @param algorithm Preferred PQC algorithm
     * @param keyHash Hash of the attestor's PQC public key
     */
    function registerAttestor(
        address attestor,
        IPQCVerifier.PQCAlgorithm algorithm,
        bytes32 keyHash
    ) external onlyRole(OPERATOR_ROLE) {
        if (attestor == address(0)) revert ZeroAddress();

        _grantRole(ATTESTOR_ROLE, attestor);
        attestorAlgorithm[attestor] = algorithm;
        attestorKeyHash[attestor] = keyHash;

        emit AttestorRegistered(attestor, algorithm, keyHash);
    }

    /**
     * @notice Remove an attestor
     * @param attestor Address to remove
     */
    function removeAttestor(address attestor) external onlyRole(OPERATOR_ROLE) {
        _revokeRole(ATTESTOR_ROLE, attestor);
        delete attestorAlgorithm[attestor];
        delete attestorKeyHash[attestor];

        emit AttestorRemoved(attestor);
    }

    /*//////////////////////////////////////////////////////////////
                     ATTESTATION SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit a PQC attestation for a bridge message
     * @dev The attestor signs the message hash with their PQC key off-chain,
     *      then submits the signature hash here. The oracle verifies the PQC
     *      signature and calls markAttestationVerified().
     *
     * @param messageHash The bridge message hash
     * @param pqcSigHash Hash of the PQC signature
     * @param sourceChainId Source chain
     * @param destChainId Destination chain
     */
    function submitAttestation(
        bytes32 messageHash,
        bytes32 pqcSigHash,
        uint256 sourceChainId,
        uint256 destChainId
    ) external onlyRole(ATTESTOR_ROLE) nonReentrant whenNotPaused {
        if (messageHash == bytes32(0)) revert InvalidMessageHash();
        if (hasAttested[messageHash][msg.sender]) {
            revert AlreadyAttested(messageHash, msg.sender);
        }

        hasAttested[messageHash][msg.sender] = true;

        BridgeAttestation memory attestation = BridgeAttestation({
            messageHash: messageHash,
            attestor: msg.sender,
            algorithm: attestorAlgorithm[msg.sender],
            pqcSigHash: pqcSigHash,
            pqcKeyHash: attestorKeyHash[msg.sender],
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            timestamp: block.timestamp,
            verified: false
        });

        messageAttestations[messageHash].push(attestation);

        // Update status
        MessageAttestationStatus storage status = attestationStatus[
            messageHash
        ];
        if (status.firstAttestedAt == 0) {
            status.messageHash = messageHash;
            status.firstAttestedAt = block.timestamp;
        }
        status.totalAttestations++;
        status.lastAttestedAt = block.timestamp;

        totalAttestations++;

        emit BridgeAttestationSubmitted(
            messageHash,
            msg.sender,
            attestorAlgorithm[msg.sender],
            sourceChainId,
            destChainId
        );
    }

    /**
     * @notice Mark an attestation as verified (oracle callback)
     * @dev Called by the PQC oracle after off-chain verification
     * @param messageHash The bridge message hash
     * @param attestorIndex Index of the attestation in the array
     * @param pqcValid Whether the PQC signature was valid
     */
    function markAttestationVerified(
        bytes32 messageHash,
        uint256 attestorIndex,
        bool pqcValid
    ) external onlyRole(OPERATOR_ROLE) {
        BridgeAttestation[] storage attestations = messageAttestations[
            messageHash
        ];
        require(attestorIndex < attestations.length, "Invalid index");

        attestations[attestorIndex].verified = pqcValid;

        MessageAttestationStatus storage status = attestationStatus[
            messageHash
        ];

        if (pqcValid) {
            status.verifiedAttestations++;

            // Check if quorum reached
            if (
                !status.quorumReached &&
                status.verifiedAttestations >= quorumThreshold
            ) {
                status.quorumReached = true;
                totalQuorumReached++;

                emit QuorumReached(
                    messageHash,
                    status.verifiedAttestations,
                    block.timestamp
                );
            }
        }

        emit AttestationVerified(
            messageHash,
            attestations[attestorIndex].attestor,
            pqcValid
        );
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a bridge message has PQC attestation quorum
     * @param messageHash The bridge message hash
     * @return hasQuorum Whether quorum has been reached
     * @return verifiedCount Number of verified attestations
     */
    function checkQuorum(
        bytes32 messageHash
    ) external view returns (bool hasQuorum, uint256 verifiedCount) {
        MessageAttestationStatus storage status = attestationStatus[
            messageHash
        ];
        return (status.quorumReached, status.verifiedAttestations);
    }

    /**
     * @notice Check if a message attestation is still valid (not expired)
     * @param messageHash The bridge message hash
     * @return valid True if not expired
     */
    function isAttestationValid(
        bytes32 messageHash
    ) external view returns (bool valid) {
        MessageAttestationStatus storage status = attestationStatus[
            messageHash
        ];
        if (status.firstAttestedAt == 0) return false;
        return block.timestamp <= status.lastAttestedAt + ATTESTATION_EXPIRY;
    }

    /**
     * @notice Get attestation count for a message
     * @param messageHash The bridge message hash
     * @return count Number of attestations
     */
    function getAttestationCount(
        bytes32 messageHash
    ) external view returns (uint256 count) {
        return messageAttestations[messageHash].length;
    }

    /**
     * @notice Get full attestation status for a message
     * @param messageHash The bridge message hash
     * @return status The attestation status
     */
    function getAttestationStatus(
        bytes32 messageHash
    ) external view returns (MessageAttestationStatus memory status) {
        return attestationStatus[messageHash];
    }

    /**
     * @notice Get statistics
     */
    function getStats()
        external
        view
        returns (uint256 _totalAttestations, uint256 _totalQuorum)
    {
        return (totalAttestations, totalQuorumReached);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setQuorumThreshold(
        uint256 newThreshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newThreshold < MIN_QUORUM)
            revert InvalidQuorumThreshold(newThreshold);
        uint256 old = quorumThreshold;
        quorumThreshold = newThreshold;
        emit QuorumThresholdUpdated(old, newThreshold);
    }

    function setHybridPQCVerifier(
        address _verifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        address old = hybridPQCVerifier;
        hybridPQCVerifier = _verifier;
        emit HybridPQCVerifierUpdated(old, _verifier);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}
