// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title SharedSequencerIntegration
 * @author Soul Protocol
 * @notice Integration with shared sequencers (Espresso, Astria, Radius) for atomic L2 ordering
 * @dev Provides atomic inclusion guarantees across participating L2s
 *
 * SHARED SEQUENCER ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                   Shared Sequencer Integration                          │
 * │                                                                         │
 * │   ┌─────────────────────────────────────────────────────────────────┐  │
 * │   │               SEQUENCER PROVIDERS                                │  │
 * │   │                                                                  │  │
 * │   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │  │
 * │   │  │   ESPRESSO   │  │   ASTRIA     │  │   RADIUS     │          │  │
 * │   │  │ Sequencer    │  │ Sequencer    │  │ Sequencer    │          │  │
 * │   │  │              │  │              │  │              │          │  │
 * │   │  │ • HotShot    │  │ • Celestia   │  │ • Encrypted  │          │  │
 * │   │  │   Consensus  │  │   DA         │  │   Mempool    │          │  │
 * │   │  │ • Tiramisu   │  │ • Astria     │  │ • PVDE       │          │  │
 * │   │  │   DA         │  │   Rollup     │  │   Protocol   │          │  │
 * │   │  └──────────────┘  └──────────────┘  └──────────────┘          │  │
 * │   │          │                │                │                    │  │
 * │   │          └────────────────┼────────────────┘                    │  │
 * │   │                           ▼                                     │  │
 * │   │           ┌───────────────────────────────┐                     │  │
 * │   │           │   Unified Sequencer Interface │                     │  │
 * │   │           └───────────────────────────────┘                     │  │
 * │   └──────────────────────────────────────────────────────────────────┘  │
 * │                                                                         │
 * │   ATOMIC ORDERING GUARANTEE:                                            │
 * │   ┌─────────────────────────────────────────────────────────────────┐  │
 * │   │                                                                  │  │
 * │   │    Transaction A (L2a)                Transaction B (L2b)       │  │
 * │   │    ────────────────────────────────────────────────────────     │  │
 * │   │           │                                   │                  │  │
 * │   │           └────────────┐     ┌────────────────┘                  │  │
 * │   │                        ▼     ▼                                   │  │
 * │   │              ┌───────────────────────┐                           │  │
 * │   │              │    Shared Sequencer   │                           │  │
 * │   │              │   (Atomic Ordering)   │                           │  │
 * │   │              └───────────────────────┘                           │  │
 * │   │                        │     │                                   │  │
 * │   │           ┌────────────┘     └────────────┐                      │  │
 * │   │           ▼                               ▼                      │  │
 * │   │    Include A then B            Include B then A                  │  │
 * │   │    on BOTH chains              on BOTH chains                    │  │
 * │   │    (consistent order)          (consistent order)                │  │
 * │   │                                                                  │  │
 * │   └──────────────────────────────────────────────────────────────────┘  │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract SharedSequencerIntegration is
    ReentrancyGuard,
    AccessControl,
    Pausable
{
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidSequencer();
    error SequencerNotActive();
    error InvalidCommitment();
    error CommitmentExpired();
    error InvalidProof();
    error TransactionAlreadyIncluded();
    error InvalidChainSet();
    error QuorumNotReached();
    error InclusionFailed();
    error InvalidSignature();
    error TransactionNotFound();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event SequencerRegistered(
        address indexed sequencer,
        SequencerType sequencerType,
        uint256[] supportedChains
    );

    event SequencerDeactivated(address indexed sequencer);

    event AtomicBundleSubmitted(
        bytes32 indexed bundleId,
        address indexed submitter,
        uint256[] chainIds,
        uint256 transactionCount
    );

    event AtomicBundleCommitted(
        bytes32 indexed bundleId,
        address indexed sequencer,
        bytes32 commitmentRoot
    );

    event AtomicBundleFinalized(
        bytes32 indexed bundleId,
        bytes32[] transactionHashes,
        uint256 timestamp
    );

    event InclusionProofVerified(
        bytes32 indexed bundleId,
        bytes32 indexed transactionHash,
        uint256 indexed chainId
    );

    event CrossChainMessageOrdered(
        bytes32 indexed messageId,
        uint256 sourceChainId,
        uint256 destChainId,
        uint256 sequenceNumber
    );

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported sequencer types
    enum SequencerType {
        ESPRESSO, // Espresso Systems (HotShot consensus)
        ASTRIA, // Astria (Celestia DA)
        RADIUS, // Radius (encrypted mempool)
        CUSTOM // Custom sequencer
    }

    /// @notice Bundle status
    enum BundleStatus {
        PENDING, // Awaiting sequencer commitment
        COMMITTED, // Sequencer committed to ordering
        FINALIZED, // Included in all target chains
        FAILED // Inclusion failed
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Sequencer configuration
    struct SequencerConfig {
        address sequencerAddress;
        SequencerType sequencerType;
        uint256[] supportedChains;
        uint256 quorumThreshold; // BFT threshold (e.g., 6667 = 66.67%)
        address[] validators;
        bool active;
        uint256 registeredAt;
    }

    /// @notice Cross-chain atomic transaction
    struct AtomicTransaction {
        bytes32 transactionHash;
        uint256 targetChainId;
        address target;
        bytes data;
        uint256 value;
        uint256 gasLimit;
        bytes32 nullifierBinding;
    }

    /// @notice Atomic bundle (multiple txs across chains)
    struct AtomicBundle {
        bytes32 bundleId;
        address submitter;
        AtomicTransaction[] transactions;
        uint256[] targetChainIds;
        BundleStatus status;
        bytes32 commitmentRoot;
        address committedSequencer;
        uint256 submittedAt;
        uint256 committedAt;
        uint256 finalizedAt;
        uint256 deadline;
    }

    /// @notice Espresso-specific data
    struct EspressoCommitment {
        uint64 blockHeight;
        bytes32 blockCommitment;
        bytes32 namespaceRoot;
        bytes signature; // BLS signature
    }

    /// @notice Astria-specific data
    struct AstriaCommitment {
        uint64 sequenceHeight;
        bytes32 actionRoot;
        bytes32 rollupDataRoot;
        bytes signature; // Ed25519 signature
    }

    /// @notice Radius-specific data
    struct RadiusCommitment {
        uint64 encryptedSlot;
        bytes32 pvdeCommitment;
        bytes32 decryptionKey;
        bytes signature;
    }

    /// @notice Inclusion proof
    struct InclusionProof {
        bytes32 transactionHash;
        uint256 chainId;
        bytes32[] merkleProof;
        uint256 leafIndex;
        bytes32 blockHash;
        uint64 blockNumber;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant SEQUENCER_ROLE = keccak256("SEQUENCER_ROLE");

    /// @notice Current chain ID
    uint256 public immutable currentChainId;

    /// @notice Default deadline for bundle inclusion
    uint256 public constant DEFAULT_DEADLINE = 5 minutes;

    /// @notice Maximum transactions per bundle
    uint256 public constant MAX_BUNDLE_SIZE = 50;

    /// @notice Maximum chains per bundle
    uint256 public constant MAX_CHAINS_PER_BUNDLE = 10;

    /// @notice Sequencer configurations
    mapping(address => SequencerConfig) public sequencers;
    address[] public sequencerList;

    /// @notice Atomic bundles
    mapping(bytes32 => AtomicBundle) public bundles;

    /// @notice Espresso commitments
    mapping(bytes32 => EspressoCommitment) public espressoCommitments;

    /// @notice Astria commitments
    mapping(bytes32 => AstriaCommitment) public astriaCommitments;

    /// @notice Radius commitments
    mapping(bytes32 => RadiusCommitment) public radiusCommitments;

    /// @notice Processed transactions (prevent replay)
    mapping(bytes32 => bool) public processedTransactions;

    /// @notice Sequence numbers per chain pair
    mapping(uint256 => mapping(uint256 => uint256)) public sequenceNumbers;

    /// @notice Bundle nonce
    uint256 public bundleNonce;

    /// @notice Espresso contract address
    address public espressoLightClient;

    /// @notice Astria contract address
    address public astriaSequencer;

    /// @notice Radius contract address
    address public radiusEnclave;

    /// @notice Soul Hub for nullifier binding
    address public soulHub;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _soulHub) {
        currentChainId = block.chainid;
        soulHub = _soulHub;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                       SEQUENCER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a shared sequencer
     * @param sequencerAddress Sequencer contract address
     * @param sequencerType Type of sequencer
     * @param supportedChains Array of supported chain IDs
     * @param quorumThreshold BFT quorum threshold (basis points)
     * @param validators Array of validator addresses
     */
    function registerSequencer(
        address sequencerAddress,
        SequencerType sequencerType,
        uint256[] calldata supportedChains,
        uint256 quorumThreshold,
        address[] calldata validators
    ) external onlyRole(OPERATOR_ROLE) {
        if (sequencerAddress == address(0)) revert InvalidSequencer();
        if (supportedChains.length == 0) revert InvalidChainSet();

        sequencers[sequencerAddress] = SequencerConfig({
            sequencerAddress: sequencerAddress,
            sequencerType: sequencerType,
            supportedChains: supportedChains,
            quorumThreshold: quorumThreshold,
            validators: validators,
            active: true,
            registeredAt: block.timestamp
        });

        sequencerList.push(sequencerAddress);
        _grantRole(SEQUENCER_ROLE, sequencerAddress);

        emit SequencerRegistered(
            sequencerAddress,
            sequencerType,
            supportedChains
        );
    }

    /**
     * @notice Deactivate a sequencer
     */
    function deactivateSequencer(
        address sequencerAddress
    ) external onlyRole(OPERATOR_ROLE) {
        if (!sequencers[sequencerAddress].active) revert SequencerNotActive();

        sequencers[sequencerAddress].active = false;
        _revokeRole(SEQUENCER_ROLE, sequencerAddress);

        emit SequencerDeactivated(sequencerAddress);
    }

    /*//////////////////////////////////////////////////////////////
                        ATOMIC BUNDLE SUBMISSION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Submit an atomic bundle for cross-chain execution
     * @param transactions Array of atomic transactions
     * @param preferredSequencer Preferred sequencer (or address(0) for any)
     * @return bundleId Unique bundle identifier
     */
    function submitAtomicBundle(
        AtomicTransaction[] calldata transactions,
        address preferredSequencer
    ) external nonReentrant whenNotPaused returns (bytes32 bundleId) {
        if (transactions.length == 0 || transactions.length > MAX_BUNDLE_SIZE) {
            revert InvalidChainSet();
        }

        // Collect unique chain IDs
        uint256[] memory chainIds = _collectUniqueChainIds(transactions);
        if (chainIds.length > MAX_CHAINS_PER_BUNDLE) revert InvalidChainSet();

        // Validate sequencer supports all chains
        if (preferredSequencer != address(0)) {
            _validateSequencerSupport(preferredSequencer, chainIds);
        }

        // Generate bundle ID
        bundleId = keccak256(
            abi.encodePacked(
                currentChainId,
                msg.sender,
                ++bundleNonce,
                block.timestamp
            )
        );

        // Create bundle
        AtomicBundle storage bundle = bundles[bundleId];
        bundle.bundleId = bundleId;
        bundle.submitter = msg.sender;
        bundle.targetChainIds = chainIds;
        bundle.status = BundleStatus.PENDING;
        bundle.submittedAt = block.timestamp;
        bundle.deadline = block.timestamp + DEFAULT_DEADLINE;

        // Copy transactions
        for (uint256 i = 0; i < transactions.length; i++) {
            bundle.transactions.push(transactions[i]);
        }

        emit AtomicBundleSubmitted(
            bundleId,
            msg.sender,
            chainIds,
            transactions.length
        );
    }

    /**
     * @notice Collect unique chain IDs from transactions
     */
    function _collectUniqueChainIds(
        AtomicTransaction[] calldata transactions
    ) internal pure returns (uint256[] memory) {
        uint256[] memory tempChainIds = new uint256[](transactions.length);
        uint256 uniqueCount = 0;

        for (uint256 i = 0; i < transactions.length; i++) {

            bool found = false;
            for (uint256 j = 0; j < uniqueCount; j++) {
                if (tempChainIds[j] == transactions[i].targetChainId) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                tempChainIds[uniqueCount++] = transactions[i].targetChainId;
            }
        }

        uint256[] memory chainIds = new uint256[](uniqueCount);
        for (uint256 i = 0; i < uniqueCount; i++) {
            chainIds[i] = tempChainIds[i];
        }

        return chainIds;
    }

    /**
     * @notice Validate sequencer supports required chains
     */
    function _validateSequencerSupport(
        address sequencerAddress,
        uint256[] memory chainIds
    ) internal view {
        SequencerConfig storage config = sequencers[sequencerAddress];
        if (!config.active) revert SequencerNotActive();

        for (uint256 i = 0; i < chainIds.length; i++) {
            bool supported = false;
            for (uint256 j = 0; j < config.supportedChains.length; j++) {
                if (config.supportedChains[j] == chainIds[i]) {
                    supported = true;
                    break;
                }
            }
            if (!supported) revert InvalidChainSet();
        }
    }

    /*//////////////////////////////////////////////////////////////
                       SEQUENCER COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit to bundle ordering (Espresso)
     * @param bundleId Bundle identifier
     * @param commitment Espresso commitment data
     */
    function commitBundleEspresso(
        bytes32 bundleId,
        EspressoCommitment calldata commitment
    ) external onlyRole(SEQUENCER_ROLE) nonReentrant {
        AtomicBundle storage bundle = bundles[bundleId];
        if (bundle.status != BundleStatus.PENDING) revert InvalidCommitment();
        if (block.timestamp > bundle.deadline) revert CommitmentExpired();

        // Verify Espresso commitment
        _verifyEspressoCommitment(bundleId, commitment);

        // Store commitment
        espressoCommitments[bundleId] = commitment;

        // Update bundle
        bundle.status = BundleStatus.COMMITTED;
        bundle.commitmentRoot = commitment.blockCommitment;
        bundle.committedSequencer = msg.sender;
        bundle.committedAt = block.timestamp;

        emit AtomicBundleCommitted(
            bundleId,
            msg.sender,
            commitment.blockCommitment
        );
    }

    /**
     * @notice Commit to bundle ordering (Astria)
     * @param bundleId Bundle identifier
     * @param commitment Astria commitment data
     */
    function commitBundleAstria(
        bytes32 bundleId,
        AstriaCommitment calldata commitment
    ) external onlyRole(SEQUENCER_ROLE) nonReentrant {
        AtomicBundle storage bundle = bundles[bundleId];
        if (bundle.status != BundleStatus.PENDING) revert InvalidCommitment();
        if (block.timestamp > bundle.deadline) revert CommitmentExpired();

        // Verify Astria commitment
        _verifyAstriaCommitment(bundleId, commitment);

        // Store commitment
        astriaCommitments[bundleId] = commitment;

        // Update bundle
        bundle.status = BundleStatus.COMMITTED;
        bundle.commitmentRoot = commitment.actionRoot;
        bundle.committedSequencer = msg.sender;
        bundle.committedAt = block.timestamp;

        emit AtomicBundleCommitted(bundleId, msg.sender, commitment.actionRoot);
    }

    /**
     * @notice Commit to bundle ordering (Radius)
     * @param bundleId Bundle identifier
     * @param commitment Radius commitment data
     */
    function commitBundleRadius(
        bytes32 bundleId,
        RadiusCommitment calldata commitment
    ) external onlyRole(SEQUENCER_ROLE) nonReentrant {
        AtomicBundle storage bundle = bundles[bundleId];
        if (bundle.status != BundleStatus.PENDING) revert InvalidCommitment();
        if (block.timestamp > bundle.deadline) revert CommitmentExpired();

        // Verify Radius commitment
        _verifyRadiusCommitment(bundleId, commitment);

        // Store commitment
        radiusCommitments[bundleId] = commitment;

        // Update bundle
        bundle.status = BundleStatus.COMMITTED;
        bundle.commitmentRoot = commitment.pvdeCommitment;
        bundle.committedSequencer = msg.sender;
        bundle.committedAt = block.timestamp;

        emit AtomicBundleCommitted(
            bundleId,
            msg.sender,
            commitment.pvdeCommitment
        );
    }

    /**
     * @notice Verify Espresso commitment via light client
     */
    function _verifyEspressoCommitment(
        bytes32 /* bundleId */,
        EspressoCommitment calldata commitment
    ) internal view {
        if (espressoLightClient == address(0)) revert InvalidSequencer();

        // Verify with Espresso light client
        // In production, this would call the actual Espresso light client
        bool valid = IEspressoLightClient(espressoLightClient)
            .verifyBlockCommitment(
                commitment.blockHeight,
                commitment.blockCommitment,
                commitment.signature
            );

        if (!valid) revert InvalidProof();
    }

    /**
     * @notice Verify Astria commitment
     */
    function _verifyAstriaCommitment(
        bytes32 /* bundleId */,
        AstriaCommitment calldata commitment
    ) internal view {
        if (astriaSequencer == address(0)) revert InvalidSequencer();

        // Verify with Astria sequencer contract
        bool valid = IAstriaSequencer(astriaSequencer).verifySequenceAction(
            commitment.sequenceHeight,
            commitment.actionRoot,
            commitment.signature
        );

        if (!valid) revert InvalidProof();
    }

    /**
     * @notice Verify Radius commitment
     */
    function _verifyRadiusCommitment(
        bytes32 /* bundleId */,
        RadiusCommitment calldata commitment
    ) internal view {
        if (radiusEnclave == address(0)) revert InvalidSequencer();

        // Verify with Radius enclave
        bool valid = IRadiusEnclave(radiusEnclave).verifyPVDECommitment(
            commitment.encryptedSlot,
            commitment.pvdeCommitment,
            commitment.signature
        );

        if (!valid) revert InvalidProof();
    }

    /*//////////////////////////////////////////////////////////////
                        BUNDLE FINALIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Finalize bundle with inclusion proofs
     * @param bundleId Bundle identifier
     * @param proofs Inclusion proofs for each transaction
     */
    function finalizeBundle(
        bytes32 bundleId,
        InclusionProof[] calldata proofs
    ) external nonReentrant whenNotPaused {
        AtomicBundle storage bundle = bundles[bundleId];
        if (bundle.status != BundleStatus.COMMITTED) revert InvalidCommitment();

        // Verify all inclusion proofs
        if (proofs.length != bundle.transactions.length) revert InvalidProof();

        bytes32[] memory txHashes = new bytes32[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            // Verify proof matches transaction
            if (
                proofs[i].transactionHash !=
                bundle.transactions[i].transactionHash
            ) {
                revert InvalidProof();
            }
            if (proofs[i].chainId != bundle.transactions[i].targetChainId) {
                revert InvalidProof();
            }

            // Verify Merkle inclusion
            bool valid = _verifyInclusion(proofs[i], bundle.commitmentRoot);
            if (!valid) revert InvalidProof();

            // Mark as processed
            processedTransactions[proofs[i].transactionHash] = true;
            txHashes[i] = proofs[i].transactionHash;

            emit InclusionProofVerified(
                bundleId,
                proofs[i].transactionHash,
                proofs[i].chainId
            );
        }

        // Update bundle
        bundle.status = BundleStatus.FINALIZED;
        bundle.finalizedAt = block.timestamp;

        // Update sequence numbers
        for (uint256 i = 0; i < bundle.targetChainIds.length; i++) {
            sequenceNumbers[currentChainId][bundle.targetChainIds[i]]++;
        }

        emit AtomicBundleFinalized(bundleId, txHashes, block.timestamp);
    }

    /**
     * @notice Verify Merkle inclusion proof
     */
    function _verifyInclusion(
        InclusionProof calldata proof,
        bytes32 root
    ) internal pure returns (bool) {
        bytes32 computedHash = proof.transactionHash;
        uint256 index = proof.leafIndex;

        for (uint256 i = 0; i < proof.merkleProof.length; i++) {
            bytes32 proofElement = proof.merkleProof[i];

            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, proofElement)
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(proofElement, computedHash)
                );
            }
            index = index / 2;
        }

        return computedHash == root;
    }

    /*//////////////////////////////////////////////////////////////
                     CROSS-CHAIN MESSAGE ORDERING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Request ordered cross-chain message delivery
     * @param destChainId Destination chain ID
     * @param messageId Message identifier
     * @param preferredSequencer Preferred sequencer
     * @return sequenceNumber Assigned sequence number
     */
    function requestOrderedMessage(
        uint256 destChainId,
        bytes32 messageId,
        address preferredSequencer
    ) external nonReentrant whenNotPaused returns (uint256 sequenceNumber) {
        // Find active sequencer
        address sequencer = preferredSequencer;
        if (sequencer == address(0)) {
            sequencer = _findActiveSequencer(destChainId);
        }
        if (sequencer == address(0)) revert SequencerNotActive();

        // Assign sequence number
        sequenceNumber = ++sequenceNumbers[currentChainId][destChainId];

        emit CrossChainMessageOrdered(
            messageId,
            currentChainId,
            destChainId,
            sequenceNumber
        );
    }

    /**
     * @notice Find an active sequencer supporting the target chain
     */
    function _findActiveSequencer(
        uint256 targetChainId
    ) internal view returns (address) {
        for (uint256 i = 0; i < sequencerList.length; i++) {
            SequencerConfig storage config = sequencers[sequencerList[i]];
            if (!config.active) continue;

            for (uint256 j = 0; j < config.supportedChains.length; j++) {
                if (config.supportedChains[j] == targetChainId) {
                    return sequencerList[i];
                }
            }
        }
        return address(0);
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set Espresso light client address
     */
    function setEspressoLightClient(
        address lightClient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {

        espressoLightClient = lightClient;
    }

    /**
     * @notice Set Astria sequencer address
     */
    function setAstriaSequencer(
        address sequencer
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        astriaSequencer = sequencer;
    }

    /**
     * @notice Set Radius enclave address
     */
    function setRadiusEnclave(
        address enclave
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        radiusEnclave = enclave;
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/

    function getBundle(
        bytes32 bundleId
    ) external view returns (AtomicBundle memory) {
        return bundles[bundleId];
    }

    function getSequencer(
        address sequencerAddress
    ) external view returns (SequencerConfig memory) {
        return sequencers[sequencerAddress];
    }

    function getSequenceNumber(
        uint256 sourceChainId,
        uint256 destChainId
    ) external view returns (uint256) {
        return sequenceNumbers[sourceChainId][destChainId];
    }

    function isTransactionProcessed(
        bytes32 txHash
    ) external view returns (bool) {
        return processedTransactions[txHash];
    }

    function getSequencerCount() external view returns (uint256) {
        return sequencerList.length;
    }

    function getActiveSequencers() external view returns (address[] memory) {
        uint256 activeCount = 0;
        for (uint256 i = 0; i < sequencerList.length; i++) {
            if (sequencers[sequencerList[i]].active) activeCount++;
        }

        address[] memory active = new address[](activeCount);
        uint256 index = 0;
        for (uint256 i = 0; i < sequencerList.length; i++) {
            if (sequencers[sequencerList[i]].active) {
                active[index++] = sequencerList[i];
            }
        }

        return active;
    }
}

/*//////////////////////////////////////////////////////////////
                         INTERFACES
//////////////////////////////////////////////////////////////*/

interface IEspressoLightClient {
    function verifyBlockCommitment(
        uint64 blockHeight,
        bytes32 blockCommitment,
        bytes calldata signature
    ) external view returns (bool);
}

interface IAstriaSequencer {
    function verifySequenceAction(
        uint64 sequenceHeight,
        bytes32 actionRoot,
        bytes calldata signature
    ) external view returns (bool);
}

interface IRadiusEnclave {
    function verifyPVDECommitment(
        uint64 encryptedSlot,
        bytes32 pvdeCommitment,
        bytes calldata signature
    ) external view returns (bool);
}
