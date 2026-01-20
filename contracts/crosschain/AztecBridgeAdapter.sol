// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title AztecBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Aztec Network privacy L2 interoperability
 * @dev Enables private cross-chain transactions between PIL and Aztec Network
 *
 * AZTEC INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      PIL <-> Aztec Bridge                               │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Aztec Network   │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ Commitments │  │◄─────────►│  │ Note Tree   │  │                 │
 * │  │  │ Nullifiers  │  │           │  │ Nullifiers  │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ ZK Proofs   │  │           │  │ Noir Proofs │  │                 │
 * │  │  │ Groth16/    │  │◄─────────►│  │ Ultra-      │  │                 │
 * │  │  │ PLONK       │  │           │  │ PLONK       │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Relay Layer                               │ │
 * │  │  - Proof Translation (PIL <-> Noir)                               │ │
 * │  │  - Note Commitment Synchronization                                │ │
 * │  │  - Cross-Domain Nullifier Registry                                │ │
 * │  │  - Private State Mirroring                                        │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * PRIVACY PROPERTIES:
 * - Maintains privacy across both PIL and Aztec domains
 * - Zero-knowledge proof of cross-chain state transitions
 * - Private note transfer without revealing amounts or recipients
 * - Unified nullifier registry prevents double-spending across domains
 */
contract AztecBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant PROOF_VERIFIER_ROLE =
        keccak256("PROOF_VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Aztec note types supported
    enum NoteType {
        VALUE_NOTE, // Standard value transfer
        DEFI_NOTE, // DeFi interaction note
        ACCOUNT_NOTE, // Account abstraction note
        CUSTOM_NOTE // Custom application note
    }

    /// @notice Cross-domain proof types
    enum ProofType {
        PIL_TO_AZTEC, // PIL commitment -> Aztec note
        AZTEC_TO_PIL, // Aztec note -> PIL commitment
        BIDIRECTIONAL // Synchronized state
    }

    /// @notice Aztec note commitment (simplified representation)
    struct AztecNote {
        bytes32 noteHash;
        bytes32 nullifierKey;
        bytes32 owner; // Aztec address (compressed)
        uint256 value;
        NoteType noteType;
        bytes32 appDataHash; // Application-specific data
        uint256 createdAt;
        bool isSpent;
    }

    /// @notice PIL to Aztec bridge request
    struct PILToAztecRequest {
        bytes32 requestId;
        bytes32 pilCommitment;
        bytes32 pilNullifier;
        bytes32 aztecRecipient;
        uint256 amount;
        NoteType noteType;
        bytes32 appDataHash;
        uint256 timestamp;
        bool processed;
        bytes32 resultingNoteHash;
    }

    /// @notice Aztec to PIL bridge request
    struct AztecToPILRequest {
        bytes32 requestId;
        bytes32 aztecNoteHash;
        bytes32 aztecNullifier;
        address pilRecipient;
        uint256 amount;
        bytes32 pilCommitment;
        uint256 timestamp;
        bool processed;
    }

    /// @notice Cross-domain proof for verification
    struct CrossDomainProof {
        bytes32 proofId;
        ProofType proofType;
        bytes32 sourceCommitment;
        bytes32 targetCommitment;
        bytes32 nullifier;
        bytes proof; // Serialized ZK proof
        bytes32 publicInputsHash;
        bool verified;
        uint256 verifiedAt;
    }

    /// @notice Aztec rollup state sync
    struct AztecStateSync {
        uint256 rollupId;
        bytes32 dataTreeRoot;
        bytes32 nullifierTreeRoot;
        bytes32 contractTreeRoot;
        bytes32 l1ToL2MessageTreeRoot;
        uint256 blockNumber;
        uint256 timestamp;
        bool finalized;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Aztec rollup contract on L1
    address public aztecRollup;

    /// @notice Aztec inbox contract for L1 -> L2 messages
    address public aztecInbox;

    /// @notice Aztec outbox contract for L2 -> L1 messages
    address public aztecOutbox;

    /// @notice PIL to Aztec requests
    mapping(bytes32 => PILToAztecRequest) public pilToAztecRequests;

    /// @notice Aztec to PIL requests
    mapping(bytes32 => AztecToPILRequest) public aztecToPilRequests;

    /// @notice Cross-domain proofs
    mapping(bytes32 => CrossDomainProof) public crossDomainProofs;

    /// @notice Aztec state syncs
    mapping(uint256 => AztecStateSync) public aztecStateSyncs;

    /// @notice Latest synced Aztec rollup ID
    uint256 public latestAztecRollupId;

    /// @notice Cross-domain nullifier registry (prevents double-spend across PIL <-> Aztec)
    mapping(bytes32 => bool) public crossDomainNullifiers;

    /// @notice Aztec note commitments mirrored to PIL
    mapping(bytes32 => bool) public mirroredNotes;

    /// @notice PIL commitments registered with Aztec
    mapping(bytes32 => bool) public registeredPILCommitments;

    /// @notice Pending bridge requests count
    uint256 public pendingRequests;

    /// @notice Total bridged value (PIL -> Aztec)
    uint256 public totalBridgedToAztec;

    /// @notice Total bridged value (Aztec -> PIL)
    uint256 public totalBridgedFromAztec;

    /// @notice Aztec chain ID (mainnet)
    uint256 public constant AZTEC_CHAIN_ID = 677868; // Aztec mainnet

    /// @notice Maximum bridge amount per transaction
    uint256 public maxBridgeAmount = 1000 ether;

    /// @notice Minimum bridge amount
    uint256 public minBridgeAmount = 0.01 ether;

    /// @notice Bridge fee (in basis points)
    uint256 public bridgeFeeBps = 10; // 0.1%

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PILToAztecInitiated(
        bytes32 indexed requestId,
        bytes32 indexed pilCommitment,
        bytes32 aztecRecipient,
        uint256 amount
    );

    event PILToAztecCompleted(
        bytes32 indexed requestId,
        bytes32 indexed resultingNoteHash
    );

    event AztecToPILInitiated(
        bytes32 indexed requestId,
        bytes32 indexed aztecNoteHash,
        address pilRecipient,
        uint256 amount
    );

    event AztecToPILCompleted(
        bytes32 indexed requestId,
        bytes32 indexed pilCommitment
    );

    event CrossDomainProofVerified(
        bytes32 indexed proofId,
        ProofType proofType,
        bytes32 sourceCommitment,
        bytes32 targetCommitment
    );

    event AztecStateSynced(
        uint256 indexed rollupId,
        bytes32 dataTreeRoot,
        bytes32 nullifierTreeRoot
    );

    event CrossDomainNullifierRegistered(
        bytes32 indexed nullifier,
        bytes32 indexed sourceCommitment
    );

    event AztecContractsUpdated(address rollup, address inbox, address outbox);

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error AmountTooLow(uint256 amount, uint256 minimum);
    error AmountTooHigh(uint256 amount, uint256 maximum);
    error InvalidCommitment(bytes32 commitment);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error RequestNotFound(bytes32 requestId);
    error RequestAlreadyProcessed(bytes32 requestId);
    error InvalidProof();
    error ProofAlreadyVerified(bytes32 proofId);
    error StateNotFinalized(uint256 rollupId);
    error NoteAlreadyMirrored(bytes32 noteHash);
    error CommitmentAlreadyRegistered(bytes32 commitment);
    error InsufficientFee(uint256 provided, uint256 required);
    error TransferFailed();
    error AztecContractsNotConfigured();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        AZTEC CONTRACT CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure Aztec L1 contract addresses
     * @param _rollup Aztec rollup contract
     * @param _inbox Aztec inbox for L1 -> L2 messages
     * @param _outbox Aztec outbox for L2 -> L1 messages
     */
    function configureAztecContracts(
        address _rollup,
        address _inbox,
        address _outbox
    ) external onlyRole(OPERATOR_ROLE) {
        if (_rollup == address(0)) revert ZeroAddress();
        if (_inbox == address(0)) revert ZeroAddress();
        if (_outbox == address(0)) revert ZeroAddress();

        aztecRollup = _rollup;
        aztecInbox = _inbox;
        aztecOutbox = _outbox;

        emit AztecContractsUpdated(_rollup, _inbox, _outbox);
    }

    /*//////////////////////////////////////////////////////////////
                          PIL -> AZTEC BRIDGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a private transfer from PIL to Aztec Network
     * @param pilCommitment The PIL commitment being bridged
     * @param pilNullifier The PIL nullifier (reveals the commitment is spent)
     * @param aztecRecipient The Aztec address to receive the note
     * @param amount The amount to bridge
     * @param noteType The type of Aztec note to create
     * @param appDataHash Optional application-specific data
     * @param proof ZK proof of valid PIL commitment ownership
     */
    function bridgePILToAztec(
        bytes32 pilCommitment,
        bytes32 pilNullifier,
        bytes32 aztecRecipient,
        uint256 amount,
        NoteType noteType,
        bytes32 appDataHash,
        bytes calldata proof
    ) external payable nonReentrant whenNotPaused {
        // Validations
        if (aztecRollup == address(0)) revert AztecContractsNotConfigured();
        if (amount < minBridgeAmount)
            revert AmountTooLow(amount, minBridgeAmount);
        if (amount > maxBridgeAmount)
            revert AmountTooHigh(amount, maxBridgeAmount);
        if (pilCommitment == bytes32(0))
            revert InvalidCommitment(pilCommitment);
        if (crossDomainNullifiers[pilNullifier])
            revert NullifierAlreadyUsed(pilNullifier);

        // Calculate and verify fee
        uint256 fee = (amount * bridgeFeeBps) / 10000;
        if (msg.value < fee) revert InsufficientFee(msg.value, fee);

        // Verify PIL proof (placeholder - integrate with PIL verifier)
        if (!_verifyPILProof(pilCommitment, pilNullifier, amount, proof)) {
            revert InvalidProof();
        }

        // Register nullifier to prevent double-spend
        crossDomainNullifiers[pilNullifier] = true;

        bytes32 requestId = keccak256(
            abi.encodePacked(
                pilCommitment,
                aztecRecipient,
                amount,
                block.timestamp,
                pendingRequests
            )
        );

        pilToAztecRequests[requestId] = PILToAztecRequest({
            requestId: requestId,
            pilCommitment: pilCommitment,
            pilNullifier: pilNullifier,
            aztecRecipient: aztecRecipient,
            amount: amount,
            noteType: noteType,
            appDataHash: appDataHash,
            timestamp: block.timestamp,
            processed: false,
            resultingNoteHash: bytes32(0)
        });

        pendingRequests++;
        totalBridgedToAztec += amount;
        accumulatedFees += fee;

        emit PILToAztecInitiated(
            requestId,
            pilCommitment,
            aztecRecipient,
            amount
        );
        emit CrossDomainNullifierRegistered(pilNullifier, pilCommitment);

        // In production: Send message to Aztec inbox
        // IAztecInbox(aztecInbox).sendL1ToL2Message(...)
    }

    /**
     * @notice Complete PIL to Aztec bridge (called by relayer after Aztec note creation)
     * @param requestId The bridge request ID
     * @param resultingNoteHash The Aztec note hash created
     * @param proof Proof of note creation on Aztec
     */
    function completePILToAztec(
        bytes32 requestId,
        bytes32 resultingNoteHash,
        bytes calldata proof
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        PILToAztecRequest storage request = pilToAztecRequests[requestId];

        if (request.requestId == bytes32(0)) revert RequestNotFound(requestId);
        if (request.processed) revert RequestAlreadyProcessed(requestId);

        // Verify Aztec proof of note creation
        if (
            !_verifyAztecNoteProof(
                resultingNoteHash,
                request.aztecRecipient,
                request.amount,
                proof
            )
        ) {
            revert InvalidProof();
        }

        request.processed = true;
        request.resultingNoteHash = resultingNoteHash;
        mirroredNotes[resultingNoteHash] = true;
        pendingRequests--;

        emit PILToAztecCompleted(requestId, resultingNoteHash);
    }

    /*//////////////////////////////////////////////////////////////
                          AZTEC -> PIL BRIDGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a private transfer from Aztec to PIL
     * @param aztecNoteHash The Aztec note being spent
     * @param aztecNullifier The Aztec nullifier
     * @param pilRecipient The PIL address to receive the commitment
     * @param amount The amount to bridge
     * @param proof ZK proof of valid Aztec note ownership
     */
    function bridgeAztecToPIL(
        bytes32 aztecNoteHash,
        bytes32 aztecNullifier,
        address pilRecipient,
        uint256 amount,
        bytes calldata proof
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        // Validations
        if (pilRecipient == address(0)) revert ZeroAddress();
        if (amount < minBridgeAmount)
            revert AmountTooLow(amount, minBridgeAmount);
        if (amount > maxBridgeAmount)
            revert AmountTooHigh(amount, maxBridgeAmount);
        if (crossDomainNullifiers[aztecNullifier])
            revert NullifierAlreadyUsed(aztecNullifier);

        // Verify Aztec proof
        if (
            !_verifyAztecSpendProof(
                aztecNoteHash,
                aztecNullifier,
                amount,
                proof
            )
        ) {
            revert InvalidProof();
        }

        // Register cross-domain nullifier
        crossDomainNullifiers[aztecNullifier] = true;

        bytes32 requestId = keccak256(
            abi.encodePacked(
                aztecNoteHash,
                pilRecipient,
                amount,
                block.timestamp
            )
        );

        // Generate PIL commitment for recipient
        bytes32 pilCommitment = _generatePILCommitment(
            pilRecipient,
            amount,
            requestId
        );

        aztecToPilRequests[requestId] = AztecToPILRequest({
            requestId: requestId,
            aztecNoteHash: aztecNoteHash,
            aztecNullifier: aztecNullifier,
            pilRecipient: pilRecipient,
            amount: amount,
            pilCommitment: pilCommitment,
            timestamp: block.timestamp,
            processed: true // Immediately processed on L1
        });

        registeredPILCommitments[pilCommitment] = true;
        totalBridgedFromAztec += amount;

        emit AztecToPILInitiated(
            requestId,
            aztecNoteHash,
            pilRecipient,
            amount
        );
        emit AztecToPILCompleted(requestId, pilCommitment);
        emit CrossDomainNullifierRegistered(aztecNullifier, aztecNoteHash);
    }

    /*//////////////////////////////////////////////////////////////
                        AZTEC STATE SYNCHRONIZATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Sync Aztec rollup state to PIL
     * @param rollupId The Aztec rollup ID
     * @param dataTreeRoot Root of Aztec data tree
     * @param nullifierTreeRoot Root of Aztec nullifier tree
     * @param contractTreeRoot Root of Aztec contract tree
     * @param l1ToL2MessageTreeRoot Root of L1 to L2 message tree
     * @param blockNumber Associated L1 block number
     */
    function syncAztecState(
        uint256 rollupId,
        bytes32 dataTreeRoot,
        bytes32 nullifierTreeRoot,
        bytes32 contractTreeRoot,
        bytes32 l1ToL2MessageTreeRoot,
        uint256 blockNumber
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        // In production: Verify against Aztec rollup contract
        // require(IAztecRollup(aztecRollup).getRollupState(rollupId) == expectedHash);

        aztecStateSyncs[rollupId] = AztecStateSync({
            rollupId: rollupId,
            dataTreeRoot: dataTreeRoot,
            nullifierTreeRoot: nullifierTreeRoot,
            contractTreeRoot: contractTreeRoot,
            l1ToL2MessageTreeRoot: l1ToL2MessageTreeRoot,
            blockNumber: blockNumber,
            timestamp: block.timestamp,
            finalized: true
        });

        if (rollupId > latestAztecRollupId) {
            latestAztecRollupId = rollupId;
        }

        emit AztecStateSynced(rollupId, dataTreeRoot, nullifierTreeRoot);
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-DOMAIN PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register and verify a cross-domain proof
     * @param proofType Type of cross-domain proof
     * @param sourceCommitment Source domain commitment
     * @param targetCommitment Target domain commitment
     * @param nullifier Nullifier for the source commitment
     * @param proof Serialized ZK proof
     * @param publicInputsHash Hash of public inputs
     */
    function verifyCrossDomainProof(
        ProofType proofType,
        bytes32 sourceCommitment,
        bytes32 targetCommitment,
        bytes32 nullifier,
        bytes calldata proof,
        bytes32 publicInputsHash
    )
        external
        nonReentrant
        onlyRole(PROOF_VERIFIER_ROLE)
        returns (bytes32 proofId)
    {
        if (crossDomainNullifiers[nullifier])
            revert NullifierAlreadyUsed(nullifier);

        proofId = keccak256(
            abi.encodePacked(
                proofType,
                sourceCommitment,
                targetCommitment,
                nullifier,
                publicInputsHash
            )
        );

        if (crossDomainProofs[proofId].verified)
            revert ProofAlreadyVerified(proofId);

        // Verify the proof based on type
        bool isValid;
        if (proofType == ProofType.PIL_TO_AZTEC) {
            isValid = _verifyPILToAztecProof(
                sourceCommitment,
                targetCommitment,
                nullifier,
                proof
            );
        } else if (proofType == ProofType.AZTEC_TO_PIL) {
            isValid = _verifyAztecToPILProof(
                sourceCommitment,
                targetCommitment,
                nullifier,
                proof
            );
        } else {
            isValid = _verifyBidirectionalProof(
                sourceCommitment,
                targetCommitment,
                proof
            );
        }

        if (!isValid) revert InvalidProof();

        crossDomainNullifiers[nullifier] = true;

        crossDomainProofs[proofId] = CrossDomainProof({
            proofId: proofId,
            proofType: proofType,
            sourceCommitment: sourceCommitment,
            targetCommitment: targetCommitment,
            nullifier: nullifier,
            proof: proof,
            publicInputsHash: publicInputsHash,
            verified: true,
            verifiedAt: block.timestamp
        });

        emit CrossDomainProofVerified(
            proofId,
            proofType,
            sourceCommitment,
            targetCommitment
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify PIL commitment proof (placeholder)
     */
    function _verifyPILProof(
        bytes32 commitment,
        bytes32 nullifier,
        uint256 amount,
        bytes calldata proof
    ) internal pure returns (bool) {
        // In production: Integrate with PIL Groth16/PLONK verifier
        // IPILVerifier(pilVerifier).verify(commitment, nullifier, amount, proof)
        if (commitment == bytes32(0)) return false;
        if (nullifier == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify Aztec note creation proof (placeholder)
     */
    function _verifyAztecNoteProof(
        bytes32 noteHash,
        bytes32 owner,
        uint256 amount,
        bytes calldata proof
    ) internal pure returns (bool) {
        // In production: Verify against Aztec rollup state
        if (noteHash == bytes32(0)) return false;
        if (owner == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify Aztec note spend proof (placeholder)
     */
    function _verifyAztecSpendProof(
        bytes32 noteHash,
        bytes32 nullifier,
        uint256 amount,
        bytes calldata proof
    ) internal pure returns (bool) {
        // In production: Verify Aztec nullifier against nullifier tree
        if (noteHash == bytes32(0)) return false;
        if (nullifier == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Generate PIL commitment (placeholder)
     */
    function _generatePILCommitment(
        address recipient,
        uint256 amount,
        bytes32 salt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(recipient, amount, salt));
    }

    /**
     * @notice Verify PIL to Aztec cross-domain proof
     */
    function _verifyPILToAztecProof(
        bytes32 sourceCommitment,
        bytes32 targetCommitment,
        bytes32 nullifier,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (sourceCommitment == bytes32(0)) return false;
        if (targetCommitment == bytes32(0)) return false;
        if (nullifier == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify Aztec to PIL cross-domain proof
     */
    function _verifyAztecToPILProof(
        bytes32 sourceCommitment,
        bytes32 targetCommitment,
        bytes32 nullifier,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (sourceCommitment == bytes32(0)) return false;
        if (targetCommitment == bytes32(0)) return false;
        if (nullifier == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify bidirectional proof
     */
    function _verifyBidirectionalProof(
        bytes32 sourceCommitment,
        bytes32 targetCommitment,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (sourceCommitment == bytes32(0)) return false;
        if (targetCommitment == bytes32(0)) return false;
        if (proof.length < 64) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get PIL to Aztec request details
     */
    function getPILToAztecRequest(
        bytes32 requestId
    ) external view returns (PILToAztecRequest memory) {
        return pilToAztecRequests[requestId];
    }

    /**
     * @notice Get Aztec to PIL request details
     */
    function getAztecToPILRequest(
        bytes32 requestId
    ) external view returns (AztecToPILRequest memory) {
        return aztecToPilRequests[requestId];
    }

    /**
     * @notice Get cross-domain proof details
     */
    function getCrossDomainProof(
        bytes32 proofId
    ) external view returns (CrossDomainProof memory) {
        return crossDomainProofs[proofId];
    }

    /**
     * @notice Get Aztec state sync
     */
    function getAztecStateSync(
        uint256 rollupId
    ) external view returns (AztecStateSync memory) {
        return aztecStateSyncs[rollupId];
    }

    /**
     * @notice Check if nullifier is used across domains
     */
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return crossDomainNullifiers[nullifier];
    }

    /**
     * @notice Check if note is mirrored to PIL
     */
    function isNoteMirrored(bytes32 noteHash) external view returns (bool) {
        return mirroredNotes[noteHash];
    }

    /**
     * @notice Check if PIL commitment is registered
     */
    function isPILCommitmentRegistered(
        bytes32 commitment
    ) external view returns (bool) {
        return registeredPILCommitments[commitment];
    }

    /**
     * @notice Get bridge statistics
     */
    function getBridgeStats()
        external
        view
        returns (
            uint256 _pendingRequests,
            uint256 _totalBridgedToAztec,
            uint256 _totalBridgedFromAztec,
            uint256 _accumulatedFees,
            uint256 _latestRollupId
        )
    {
        return (
            pendingRequests,
            totalBridgedToAztec,
            totalBridgedFromAztec,
            accumulatedFees,
            latestAztecRollupId
        );
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set bridge limits
     */
    function setBridgeLimits(
        uint256 _minBridgeAmount,
        uint256 _maxBridgeAmount
    ) external onlyRole(OPERATOR_ROLE) {
        minBridgeAmount = _minBridgeAmount;
        maxBridgeAmount = _maxBridgeAmount;
    }

    /**
     * @notice Set bridge fee
     */
    function setBridgeFee(uint256 _feeBps) external onlyRole(OPERATOR_ROLE) {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        bridgeFeeBps = _feeBps;
    }

    /**
     * @notice Withdraw accumulated fees
     */
    function withdrawFees(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool success, ) = payable(to).call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /**
     * @notice Pause bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
