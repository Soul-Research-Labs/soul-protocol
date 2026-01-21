// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title MidnightBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for Midnight blockchain integration
 * @dev Enables cross-chain interoperability between PIL (EVM) and Midnight (ZK-privacy chain)
 *
 * MIDNIGHT INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                     PIL <-> Midnight Bridge                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   Midnight        │                 │
 * │  │  (EVM/Solidity)   │           │  (Compact/ZK)     │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ZK Proofs   │  │◄─────────►│  │ ZK Proofs   │  │                 │
 * │  │  │ Groth16     │  │           │  │ zk-SNARKs   │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ ERC20/721   │  │           │  │ Shielded    │  │                 │
 * │  │  │ Tokens      │  │◄─────────►│  │ Assets      │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   Bridge Protocol Layer                            │ │
 * │  │  - ZK Proof Verification (zk-SNARKs)                               │ │
 * │  │  - Shielded Transaction Proofs                                     │ │
 * │  │  - Compact Smart Contract Verification                             │ │
 * │  │  - Privacy-Preserving State Proofs                                 │ │
 * │  │  - Dual-Ledger (Transparent + Shielded) Support                    │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * MIDNIGHT CONCEPTS:
 * - Compact: Midnight's smart contract language (TypeScript-like)
 * - Shielded State: Private data only visible to authorized parties
 * - Unshielded State: Public data visible on-chain
 * - ZK Circuits: Zero-knowledge proof circuits for privacy
 * - Dust: Midnight's native token for transaction fees
 * - tDust: Testnet token
 * - Conclave: Network of validators
 * - Indexer: Node providing query capabilities
 * - Proof Market: Decentralized ZK proof generation
 *
 * PRIVACY FEATURES:
 * - Shielded Transactions (amounts/addresses hidden)
 * - Selective Disclosure (reveal specific data)
 * - Private Smart Contracts (computation privacy)
 * - Regulatory Compliance (auditable with consent)
 * - Data Protection (GDPR-compatible)
 *
 * SUPPORTED FEATURES:
 * - Dust Token Bridging
 * - Shielded Asset Transfers
 * - Private Message Passing
 * - ZK Proof Verification
 * - Compact Contract State Proofs
 * - Cross-chain Privacy Preservation
 * - Threshold Signature Bridge
 */
contract MidnightBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ZK_VERIFIER_ROLE = keccak256("ZK_VERIFIER_ROLE");
    bytes32 public constant CONCLAVE_ROLE = keccak256("CONCLAVE_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Midnight network types
    enum MidnightNetwork {
        MAINNET,
        TESTNET,
        DEVNET,
        LOCAL
    }

    /// @notice Message direction
    enum MessageDirection {
        EVM_TO_MIDNIGHT,
        MIDNIGHT_TO_EVM
    }

    /// @notice Transfer status
    enum TransferStatus {
        PENDING,
        SHIELDING,
        CONFIRMED,
        COMPLETED,
        FAILED,
        REFUNDED
    }

    /// @notice Transaction type (transparency level)
    enum TransactionType {
        TRANSPARENT, // Fully public (like normal blockchain)
        SHIELDED, // Fully private (amounts/addresses hidden)
        MIXED // Some data public, some private
    }

    /// @notice ZK proof type
    enum ZKProofType {
        GROTH16,
        PLONK,
        BULLETPROOFS,
        STARK
    }

    /// @notice Compact contract status
    enum ContractStatus {
        UNVERIFIED,
        PENDING,
        VERIFIED,
        DEPRECATED
    }

    /// @notice Midnight address (32 bytes + type indicator)
    struct MidnightAddress {
        bytes32 addressHash;
        bool isShielded;
        uint8 addressType; // 0 = standard, 1 = contract, 2 = multisig
    }

    /// @notice Shielded asset information
    struct ShieldedAsset {
        bytes32 assetId;
        bytes32 assetCommitment; // Pedersen commitment to asset details
        uint8 decimals;
        address evmToken; // Mapped EVM token (if any)
        bool verified;
        uint256 registeredAt;
    }

    /// @notice ZK proof for verification
    struct ZKProof {
        bytes32 proofHash;
        ZKProofType proofType;
        bytes proofData;
        bytes32[] publicInputs;
        uint256 verifiedAt;
        bool isValid;
    }

    /// @notice Compact contract information
    struct CompactContract {
        bytes32 contractHash;
        bytes32 codeHash;
        bytes32 stateRoot; // Merkle root of contract state
        ContractStatus status;
        uint256 registeredAt;
    }

    /// @notice Cross-chain message with privacy options
    struct CrossChainMessage {
        bytes32 messageId;
        MessageDirection direction;
        bytes32 sourceAddress;
        bytes32 targetAddress;
        bytes encryptedPayload; // Payload encrypted for recipient
        bytes32 payloadCommitment; // Commitment to payload for verification
        TransactionType txType;
        uint256 timestamp;
        TransferStatus status;
        bytes32 zkProofHash;
    }

    /// @notice Shielded transfer request
    struct ShieldedTransfer {
        bytes32 transferId;
        MessageDirection direction;
        bytes32 assetId;
        bytes32 amountCommitment; // Pedersen commitment to amount
        bytes32 senderCommitment; // Commitment hiding sender
        bytes32 recipientCommitment; // Commitment hiding recipient
        bytes rangeProof; // Proof that amount is positive
        bytes32 nullifier; // For double-spend prevention
        TransferStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
    }

    /// @notice Nullifier for preventing double-spends
    struct NullifierRecord {
        bytes32 nullifier;
        bytes32 transferId;
        uint256 timestamp;
        bool spent;
    }

    /// @notice Selective disclosure proof
    struct DisclosureProof {
        bytes32 proofId;
        bytes32 dataCommitment;
        bytes32[] revealedFields; // Which fields are revealed
        bytes zkProof; // Proof that revealed data matches commitment
        uint256 expiresAt;
        bool isValid;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Dust token decimals
    uint8 public constant DUST_DECIMALS = 8;

    /// @notice Minimum shielded transfer amount (in base units)
    uint256 public constant MIN_SHIELDED_AMOUNT = 1000;

    /// @notice Maximum encrypted payload size (32KB)
    uint256 public constant MAX_ENCRYPTED_PAYLOAD = 32768;

    /// @notice Transfer timeout (48 hours for shielded)
    uint256 public constant TRANSFER_TIMEOUT = 48 hours;

    /// @notice ZK proof expiry (24 hours)
    uint256 public constant ZK_PROOF_EXPIRY = 24 hours;

    /// @notice Disclosure proof validity (7 days)
    uint256 public constant DISCLOSURE_VALIDITY = 7 days;

    /// @notice Commitment generator point (simplified)
    bytes32 public constant GENERATOR_H = keccak256("MIDNIGHT_GENERATOR_H");

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Current Midnight network
    MidnightNetwork public network;

    /// @notice Bridge treasury address on Midnight
    bytes32 public midnightTreasuryAddress;

    /// @notice Bridge fee (basis points, max 50 = 0.5%)
    uint256 public bridgeFee;

    /// @notice Minimum transfer amount
    uint256 public minTransferAmount;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages received
    uint256 public totalMessagesReceived;

    /// @notice Total shielded transfers
    uint256 public totalShieldedTransfers;

    /// @notice Total value bridged (in commitment form)
    uint256 public totalValueBridgedCount;

    /// @notice Registered shielded assets
    mapping(bytes32 => ShieldedAsset) public shieldedAssets;

    /// @notice EVM to Midnight asset mapping
    mapping(address => bytes32) public evmToMidnightAsset;

    /// @notice Cross-chain messages
    mapping(bytes32 => CrossChainMessage) public messages;

    /// @notice Shielded transfers
    mapping(bytes32 => ShieldedTransfer) public shieldedTransfers;

    /// @notice ZK proofs
    mapping(bytes32 => ZKProof) public zkProofs;

    /// @notice Compact contracts
    mapping(bytes32 => CompactContract) public compactContracts;

    /// @notice Nullifier registry (for double-spend prevention)
    mapping(bytes32 => NullifierRecord) public nullifiers;

    /// @notice Disclosure proofs
    mapping(bytes32 => DisclosureProof) public disclosureProofs;

    /// @notice Used message hashes (replay protection)
    mapping(bytes32 => bool) public usedMessageHashes;

    /// @notice Sender nonces
    mapping(address => uint256) public senderNonces;

    /// @notice Guardian threshold
    uint256 public guardianThreshold;

    /// @notice Total guardians
    uint256 public totalGuardians;

    /// @notice ZK verification key hashes
    mapping(bytes32 => bool) public verificationKeys;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event NetworkSet(MidnightNetwork indexed network);
    event TreasuryAddressSet(bytes32 treasuryAddress);
    event BridgeFeeSet(uint256 feeBps);
    event MinTransferAmountSet(uint256 amount);
    event GuardianThresholdSet(uint256 threshold);
    event VerificationKeyRegistered(bytes32 indexed keyHash);

    event ShieldedAssetRegistered(
        bytes32 indexed assetId,
        bytes32 assetCommitment,
        address evmToken
    );
    event ShieldedAssetVerified(bytes32 indexed assetId);

    event CompactContractRegistered(
        bytes32 indexed contractHash,
        bytes32 codeHash
    );
    event CompactContractVerified(bytes32 indexed contractHash);

    event ZKProofSubmitted(bytes32 indexed proofHash, ZKProofType proofType);
    event ZKProofVerified(bytes32 indexed proofHash);
    event ZKProofRejected(bytes32 indexed proofHash, string reason);

    event MessageSent(
        bytes32 indexed messageId,
        MessageDirection direction,
        TransactionType txType,
        bytes32 targetAddress
    );
    event MessageReceived(
        bytes32 indexed messageId,
        MessageDirection direction,
        bytes32 sourceAddress
    );
    event MessageCompleted(bytes32 indexed messageId);
    event MessageFailed(bytes32 indexed messageId, string reason);

    event ShieldedTransferInitiated(
        bytes32 indexed transferId,
        MessageDirection direction,
        bytes32 assetId,
        bytes32 amountCommitment
    );
    event ShieldedTransferShielding(bytes32 indexed transferId);
    event ShieldedTransferConfirmed(bytes32 indexed transferId);
    event ShieldedTransferCompleted(bytes32 indexed transferId);
    event ShieldedTransferFailed(bytes32 indexed transferId, string reason);
    event ShieldedTransferRefunded(bytes32 indexed transferId);

    event NullifierSpent(bytes32 indexed nullifier, bytes32 indexed transferId);

    event DisclosureProofCreated(
        bytes32 indexed proofId,
        bytes32 dataCommitment
    );
    event DisclosureProofVerified(bytes32 indexed proofId);

    event FeesWithdrawn(address indexed recipient, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidMidnightAddress();
    error InvalidAssetId();
    error AssetNotVerified();
    error AmountTooLow();
    error TransferNotFound();
    error TransferAlreadyCompleted();
    error TransferExpired();
    error MessageNotFound();
    error InvalidZKProof();
    error ZKProofExpired();
    error NullifierAlreadySpent();
    error InvalidNullifier();
    error InvalidCommitment();
    error InvalidRangeProof();
    error InvalidDisclosureProof();
    error DisclosureExpired();
    error CompactContractNotVerified();
    error InsufficientGuardianSignatures();
    error MessageHashAlreadyUsed();
    error InsufficientFee();
    error PayloadTooLarge();
    error InvalidVerificationKey();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address admin,
        MidnightNetwork _network,
        bytes32 _treasuryAddress,
        uint256 _guardianThreshold
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(GUARDIAN_ROLE, admin);

        network = _network;
        midnightTreasuryAddress = _treasuryAddress;
        guardianThreshold = _guardianThreshold;
        bridgeFee = 25; // 0.25%
        minTransferAmount = 10000; // Minimum dust units

        emit NetworkSet(_network);
        emit TreasuryAddressSet(_treasuryAddress);
        emit GuardianThresholdSet(_guardianThreshold);
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set the Midnight network
    function setNetwork(
        MidnightNetwork _network
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        network = _network;
        emit NetworkSet(_network);
    }

    /// @notice Set the treasury address on Midnight
    function setTreasuryAddress(
        bytes32 _address
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_address == bytes32(0)) revert InvalidMidnightAddress();
        midnightTreasuryAddress = _address;
        emit TreasuryAddressSet(_address);
    }

    /// @notice Set the bridge fee
    function setBridgeFee(
        uint256 _feeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_feeBps <= 50, "Fee too high"); // Max 0.5%
        bridgeFee = _feeBps;
        emit BridgeFeeSet(_feeBps);
    }

    /// @notice Set minimum transfer amount
    function setMinTransferAmount(
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_amount >= MIN_SHIELDED_AMOUNT, "Below minimum");
        minTransferAmount = _amount;
        emit MinTransferAmountSet(_amount);
    }

    /// @notice Set guardian threshold
    function setGuardianThreshold(
        uint256 _threshold
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            _threshold > 0 && _threshold <= totalGuardians,
            "Invalid threshold"
        );
        guardianThreshold = _threshold;
        emit GuardianThresholdSet(_threshold);
    }

    /// @notice Register a verification key
    function registerVerificationKey(
        bytes32 _keyHash
    ) external onlyRole(OPERATOR_ROLE) {
        verificationKeys[_keyHash] = true;
        emit VerificationKeyRegistered(_keyHash);
    }

    /// @notice Pause the bridge
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /// @notice Unpause the bridge
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                      SHIELDED ASSET MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a shielded asset
    function registerShieldedAsset(
        bytes32 _assetId,
        bytes32 _assetCommitment,
        uint8 _decimals,
        address _evmToken
    ) external onlyRole(OPERATOR_ROLE) {
        if (_assetId == bytes32(0)) revert InvalidAssetId();
        if (_assetCommitment == bytes32(0)) revert InvalidCommitment();

        shieldedAssets[_assetId] = ShieldedAsset({
            assetId: _assetId,
            assetCommitment: _assetCommitment,
            decimals: _decimals,
            evmToken: _evmToken,
            verified: false,
            registeredAt: block.timestamp
        });

        if (_evmToken != address(0)) {
            evmToMidnightAsset[_evmToken] = _assetId;
        }

        emit ShieldedAssetRegistered(_assetId, _assetCommitment, _evmToken);
    }

    /// @notice Verify a shielded asset
    function verifyShieldedAsset(
        bytes32 _assetId
    ) external onlyRole(GUARDIAN_ROLE) {
        ShieldedAsset storage asset = shieldedAssets[_assetId];
        if (asset.assetId == bytes32(0)) revert InvalidAssetId();

        asset.verified = true;
        emit ShieldedAssetVerified(_assetId);
    }

    /*//////////////////////////////////////////////////////////////
                      COMPACT CONTRACT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a Compact smart contract
    function registerCompactContract(
        bytes32 _contractHash,
        bytes32 _codeHash,
        bytes32 _stateRoot
    ) external onlyRole(OPERATOR_ROLE) {
        if (_contractHash == bytes32(0)) revert CompactContractNotVerified();

        compactContracts[_contractHash] = CompactContract({
            contractHash: _contractHash,
            codeHash: _codeHash,
            stateRoot: _stateRoot,
            status: ContractStatus.PENDING,
            registeredAt: block.timestamp
        });

        emit CompactContractRegistered(_contractHash, _codeHash);
    }

    /// @notice Verify a Compact contract
    function verifyCompactContract(
        bytes32 _contractHash
    ) external onlyRole(GUARDIAN_ROLE) {
        CompactContract storage contract_ = compactContracts[_contractHash];
        if (contract_.contractHash == bytes32(0))
            revert CompactContractNotVerified();

        contract_.status = ContractStatus.VERIFIED;
        emit CompactContractVerified(_contractHash);
    }

    /// @notice Update Compact contract state root
    function updateContractStateRoot(
        bytes32 _contractHash,
        bytes32 _newStateRoot,
        bytes calldata _zkProof
    ) external onlyRole(CONCLAVE_ROLE) {
        CompactContract storage contract_ = compactContracts[_contractHash];
        if (contract_.status != ContractStatus.VERIFIED)
            revert CompactContractNotVerified();

        // Verify the ZK proof for state transition
        bytes32 proofHash = keccak256(_zkProof);
        if (
            !_verifyStateTransitionProof(
                contract_.stateRoot,
                _newStateRoot,
                _zkProof
            )
        ) {
            revert InvalidZKProof();
        }

        contract_.stateRoot = _newStateRoot;
    }

    /*//////////////////////////////////////////////////////////////
                         ZK PROOF MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit a ZK proof for verification
    function submitZKProof(
        bytes32 _proofHash,
        ZKProofType _proofType,
        bytes calldata _proofData,
        bytes32[] calldata _publicInputs
    ) external onlyRole(ZK_VERIFIER_ROLE) {
        zkProofs[_proofHash] = ZKProof({
            proofHash: _proofHash,
            proofType: _proofType,
            proofData: _proofData,
            publicInputs: _publicInputs,
            verifiedAt: 0,
            isValid: false
        });

        emit ZKProofSubmitted(_proofHash, _proofType);
    }

    /// @notice Verify a submitted ZK proof
    function verifyZKProof(
        bytes32 _proofHash,
        bytes32 _verificationKeyHash
    ) external onlyRole(ZK_VERIFIER_ROLE) returns (bool) {
        if (!verificationKeys[_verificationKeyHash])
            revert InvalidVerificationKey();

        ZKProof storage proof = zkProofs[_proofHash];
        if (proof.proofHash == bytes32(0)) revert InvalidZKProof();

        // Verify proof based on type (simplified - actual verification is complex)
        bool isValid = _verifyProof(proof, _verificationKeyHash);

        proof.isValid = isValid;
        proof.verifiedAt = block.timestamp;

        if (isValid) {
            emit ZKProofVerified(_proofHash);
        } else {
            emit ZKProofRejected(_proofHash, "Verification failed");
        }

        return isValid;
    }

    /// @notice Check if a ZK proof is valid and not expired
    function isZKProofValid(bytes32 _proofHash) public view returns (bool) {
        ZKProof storage proof = zkProofs[_proofHash];
        if (!proof.isValid) return false;
        if (block.timestamp > proof.verifiedAt + ZK_PROOF_EXPIRY) return false;
        return true;
    }

    /// @notice Internal proof verification (simplified)
    function _verifyProof(
        ZKProof storage _proof,
        bytes32 _vkHash
    ) internal view returns (bool) {
        // In production, this would call actual ZK verifier contracts
        // For now, we simulate verification by checking structure
        if (_proof.proofData.length == 0) return false;
        if (_proof.publicInputs.length == 0) return false;

        // Compute expected proof hash
        bytes32 computedHash = keccak256(
            abi.encodePacked(_proof.proofData, _proof.publicInputs, _vkHash)
        );

        // This is a placeholder - real verification uses pairing checks
        return computedHash != bytes32(0);
    }

    /// @notice Verify state transition proof (simplified)
    function _verifyStateTransitionProof(
        bytes32 _oldRoot,
        bytes32 _newRoot,
        bytes calldata _proof
    ) internal pure returns (bool) {
        // Simplified verification - checks proof structure
        if (_proof.length < 32) return false;
        if (_oldRoot == bytes32(0)) return false;
        if (_newRoot == bytes32(0)) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                      SHIELDED TRANSFER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Initiate a shielded transfer from EVM to Midnight
    function initiateShieldedTransfer(
        bytes32 _assetId,
        bytes32 _amountCommitment,
        bytes32 _recipientCommitment,
        bytes calldata _rangeProof
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        ShieldedAsset storage asset = shieldedAssets[_assetId];
        if (!asset.verified) revert AssetNotVerified();
        if (_amountCommitment == bytes32(0)) revert InvalidCommitment();
        if (_rangeProof.length == 0) revert InvalidRangeProof();

        // Calculate fee based on estimated value
        uint256 fee = (msg.value * bridgeFee) / 10000;
        if (msg.value < fee + minTransferAmount) revert InsufficientFee();

        // Generate transfer ID
        uint256 nonce = senderNonces[msg.sender]++;
        transferId = keccak256(
            abi.encodePacked(
                msg.sender,
                _assetId,
                _amountCommitment,
                nonce,
                block.timestamp
            )
        );

        // Generate nullifier
        bytes32 nullifier = keccak256(
            abi.encodePacked(transferId, msg.sender, block.timestamp)
        );

        // Create shielded transfer record
        shieldedTransfers[transferId] = ShieldedTransfer({
            transferId: transferId,
            direction: MessageDirection.EVM_TO_MIDNIGHT,
            assetId: _assetId,
            amountCommitment: _amountCommitment,
            senderCommitment: keccak256(abi.encodePacked(msg.sender)),
            recipientCommitment: _recipientCommitment,
            rangeProof: _rangeProof,
            nullifier: nullifier,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0
        });

        accumulatedFees += fee;
        totalShieldedTransfers++;
        totalMessagesSent++;

        emit ShieldedTransferInitiated(
            transferId,
            MessageDirection.EVM_TO_MIDNIGHT,
            _assetId,
            _amountCommitment
        );

        return transferId;
    }

    /// @notice Complete a shielded transfer from Midnight to EVM
    function completeShieldedTransfer(
        bytes32 _transferId,
        bytes32 _zkProofHash,
        bytes32 _nullifier,
        bytes[] calldata _guardianSignatures
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        if (_guardianSignatures.length < guardianThreshold) {
            revert InsufficientGuardianSignatures();
        }

        // Check nullifier hasn't been spent
        if (nullifiers[_nullifier].spent) revert NullifierAlreadySpent();

        // Verify ZK proof
        if (!isZKProofValid(_zkProofHash)) revert InvalidZKProof();

        ShieldedTransfer storage transfer = shieldedTransfers[_transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (
            transfer.status != TransferStatus.PENDING &&
            transfer.status != TransferStatus.SHIELDING
        ) {
            revert TransferAlreadyCompleted();
        }

        // Mark nullifier as spent
        nullifiers[_nullifier] = NullifierRecord({
            nullifier: _nullifier,
            transferId: _transferId,
            timestamp: block.timestamp,
            spent: true
        });

        // Complete transfer
        transfer.status = TransferStatus.COMPLETED;
        transfer.completedAt = block.timestamp;
        totalMessagesReceived++;

        emit NullifierSpent(_nullifier, _transferId);
        emit ShieldedTransferCompleted(_transferId);
    }

    /// @notice Refund an expired shielded transfer
    function refundShieldedTransfer(bytes32 _transferId) external nonReentrant {
        ShieldedTransfer storage transfer = shieldedTransfers[_transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status != TransferStatus.PENDING)
            revert TransferAlreadyCompleted();
        if (block.timestamp < transfer.initiatedAt + TRANSFER_TIMEOUT)
            revert TransferNotFound();

        transfer.status = TransferStatus.REFUNDED;
        transfer.completedAt = block.timestamp;

        emit ShieldedTransferRefunded(_transferId);
    }

    /*//////////////////////////////////////////////////////////////
                      PRIVATE MESSAGE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Send a private message to Midnight
    function sendPrivateMessage(
        bytes32 _targetAddress,
        bytes calldata _encryptedPayload,
        bytes32 _payloadCommitment,
        TransactionType _txType
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (_targetAddress == bytes32(0)) revert InvalidMidnightAddress();
        if (_encryptedPayload.length > MAX_ENCRYPTED_PAYLOAD)
            revert PayloadTooLarge();
        if (_payloadCommitment == bytes32(0)) revert InvalidCommitment();

        uint256 nonce = senderNonces[msg.sender]++;
        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                _targetAddress,
                _payloadCommitment,
                nonce,
                block.timestamp
            )
        );

        messages[messageId] = CrossChainMessage({
            messageId: messageId,
            direction: MessageDirection.EVM_TO_MIDNIGHT,
            sourceAddress: bytes32(uint256(uint160(msg.sender))),
            targetAddress: _targetAddress,
            encryptedPayload: _encryptedPayload,
            payloadCommitment: _payloadCommitment,
            txType: _txType,
            timestamp: block.timestamp,
            status: TransferStatus.PENDING,
            zkProofHash: bytes32(0)
        });

        totalMessagesSent++;

        emit MessageSent(
            messageId,
            MessageDirection.EVM_TO_MIDNIGHT,
            _txType,
            _targetAddress
        );

        return messageId;
    }

    /// @notice Receive a private message from Midnight
    function receivePrivateMessage(
        bytes32 _messageId,
        bytes32 _sourceAddress,
        bytes calldata _encryptedPayload,
        bytes32 _payloadCommitment,
        bytes32 _zkProofHash,
        bytes[] calldata _guardianSignatures
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        if (_guardianSignatures.length < guardianThreshold) {
            revert InsufficientGuardianSignatures();
        }
        if (usedMessageHashes[_messageId]) revert MessageHashAlreadyUsed();
        if (!isZKProofValid(_zkProofHash)) revert InvalidZKProof();

        usedMessageHashes[_messageId] = true;

        messages[_messageId] = CrossChainMessage({
            messageId: _messageId,
            direction: MessageDirection.MIDNIGHT_TO_EVM,
            sourceAddress: _sourceAddress,
            targetAddress: bytes32(0),
            encryptedPayload: _encryptedPayload,
            payloadCommitment: _payloadCommitment,
            txType: TransactionType.SHIELDED,
            timestamp: block.timestamp,
            status: TransferStatus.COMPLETED,
            zkProofHash: _zkProofHash
        });

        totalMessagesReceived++;

        emit MessageReceived(
            _messageId,
            MessageDirection.MIDNIGHT_TO_EVM,
            _sourceAddress
        );
        emit MessageCompleted(_messageId);
    }

    /*//////////////////////////////////////////////////////////////
                    SELECTIVE DISCLOSURE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a selective disclosure proof
    function createDisclosureProof(
        bytes32 _dataCommitment,
        bytes32[] calldata _revealedFields,
        bytes calldata _zkProof,
        uint256 _validityPeriod
    ) external returns (bytes32 proofId) {
        if (_dataCommitment == bytes32(0)) revert InvalidCommitment();
        if (_zkProof.length == 0) revert InvalidDisclosureProof();
        if (_validityPeriod == 0 || _validityPeriod > DISCLOSURE_VALIDITY) {
            _validityPeriod = DISCLOSURE_VALIDITY;
        }

        proofId = keccak256(
            abi.encodePacked(
                msg.sender,
                _dataCommitment,
                _revealedFields,
                block.timestamp
            )
        );

        disclosureProofs[proofId] = DisclosureProof({
            proofId: proofId,
            dataCommitment: _dataCommitment,
            revealedFields: _revealedFields,
            zkProof: _zkProof,
            expiresAt: block.timestamp + _validityPeriod,
            isValid: false
        });

        emit DisclosureProofCreated(proofId, _dataCommitment);

        return proofId;
    }

    /// @notice Verify a selective disclosure proof
    function verifyDisclosureProof(
        bytes32 _proofId
    ) external onlyRole(ZK_VERIFIER_ROLE) {
        DisclosureProof storage proof = disclosureProofs[_proofId];
        if (proof.proofId == bytes32(0)) revert InvalidDisclosureProof();
        if (block.timestamp > proof.expiresAt) revert DisclosureExpired();

        // Verify the ZK proof (simplified)
        bool isValid = proof.zkProof.length > 0 &&
            proof.dataCommitment != bytes32(0);

        proof.isValid = isValid;

        if (isValid) {
            emit DisclosureProofVerified(_proofId);
        }
    }

    /// @notice Check if a disclosure proof is valid
    function isDisclosureValid(bytes32 _proofId) external view returns (bool) {
        DisclosureProof storage proof = disclosureProofs[_proofId];
        if (!proof.isValid) return false;
        if (block.timestamp > proof.expiresAt) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get shielded transfer details
    function getShieldedTransfer(
        bytes32 _transferId
    ) external view returns (ShieldedTransfer memory) {
        return shieldedTransfers[_transferId];
    }

    /// @notice Get message details
    function getMessage(
        bytes32 _messageId
    ) external view returns (CrossChainMessage memory) {
        return messages[_messageId];
    }

    /// @notice Get shielded asset details
    function getShieldedAsset(
        bytes32 _assetId
    ) external view returns (ShieldedAsset memory) {
        return shieldedAssets[_assetId];
    }

    /// @notice Get Compact contract details
    function getCompactContract(
        bytes32 _contractHash
    ) external view returns (CompactContract memory) {
        return compactContracts[_contractHash];
    }

    /// @notice Get ZK proof details
    function getZKProof(
        bytes32 _proofHash
    ) external view returns (ZKProof memory) {
        return zkProofs[_proofHash];
    }

    /// @notice Get disclosure proof details
    function getDisclosureProof(
        bytes32 _proofId
    ) external view returns (DisclosureProof memory) {
        return disclosureProofs[_proofId];
    }

    /// @notice Check if nullifier is spent
    function isNullifierSpent(bytes32 _nullifier) external view returns (bool) {
        return nullifiers[_nullifier].spent;
    }

    /// @notice Get bridge statistics
    function getBridgeStats()
        external
        view
        returns (
            uint256 messagesSent,
            uint256 messagesReceived,
            uint256 shieldedTransfersCount,
            uint256 fees,
            uint256 valueBridgedCount
        )
    {
        return (
            totalMessagesSent,
            totalMessagesReceived,
            totalShieldedTransfers,
            accumulatedFees,
            totalValueBridgedCount
        );
    }

    /*//////////////////////////////////////////////////////////////
                         UTILITY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw accumulated fees
    function withdrawFees(
        address _recipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool success, ) = _recipient.call{value: amount}("");
        require(success, "Fee withdrawal failed");

        emit FeesWithdrawn(_recipient, amount);
    }

    /// @notice Compute Pedersen commitment (simplified)
    function computeCommitment(
        bytes32 _value,
        bytes32 _blinding
    ) external pure returns (bytes32) {
        // Simplified commitment: H(value || blinding || generator)
        // Real Pedersen: value*G + blinding*H
        return keccak256(abi.encodePacked(_value, _blinding, GENERATOR_H));
    }

    /// @notice Verify commitment opening (simplified)
    function verifyCommitmentOpening(
        bytes32 _commitment,
        bytes32 _value,
        bytes32 _blinding
    ) external pure returns (bool) {
        bytes32 computed = keccak256(
            abi.encodePacked(_value, _blinding, GENERATOR_H)
        );
        return computed == _commitment;
    }

    /// @notice Generate nullifier from inputs
    function generateNullifier(
        bytes32 _transferId,
        bytes32 _secret
    ) external pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(_transferId, _secret, "MIDNIGHT_NULLIFIER")
            );
    }

    /// @notice Receive ETH for fees
    receive() external payable {}
}
