// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./FHEGateway.sol";
import "./FHETypes.sol";

/**
 * @title FHEBridgeAdapter
 * @author Soul Protocol
 * @notice Cross-chain bridge adapter for encrypted value transfers using FHE
 * @dev Enables confidential cross-chain transfers where amounts remain encrypted
 *
 * Architecture:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      FHE Cross-Chain Bridge                             │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │   Source Chain                             Destination Chain            │
 * │   ┌──────────────┐                        ┌──────────────┐             │
 * │   │ FHEBridge    │                        │ FHEBridge    │             │
 * │   │ Adapter      │                        │ Adapter      │             │
 * │   └──────┬───────┘                        └──────┬───────┘             │
 * │          │                                       │                      │
 * │          │  1. Lock enc(amount)                  │                      │
 * │          │  2. Generate proof                    │                      │
 * │          ▼                                       │                      │
 * │   ┌──────────────┐    Encrypted Proof     ┌──────────────┐             │
 * │   │  Message     │ ─────────────────────► │  Verifier    │             │
 * │   │  Relay       │                        │              │             │
 * │   └──────────────┘                        └──────┬───────┘             │
 * │                                                  │                      │
 * │                                                  │ 3. Verify proof      │
 * │                                                  │ 4. Mint enc(amount)  │
 * │                                                  ▼                      │
 * │                                           ┌──────────────┐             │
 * │                                           │  Recipient   │             │
 * │                                           │  (encrypted  │             │
 * │                                           │   balance)   │             │
 * │                                           └──────────────┘             │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * Privacy Guarantees:
 * - Transfer amounts are always encrypted
 * - Neither relayers nor validators can see amounts
 * - Only sender and recipient can decrypt values
 * - Cross-chain proofs verify amount conservation without revealing values
 */
contract FHEBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    using FHETypes for uint8;
    using FHETypes for bytes32;

    // ============================================
    // Roles
    // ============================================

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");

    // ============================================
    // Types
    // ============================================

    /// @notice Transfer status
    enum TransferStatus {
        Pending,
        Locked,
        Relayed,
        Completed,
        Refunded,
        Failed
    }

    /// @notice Outbound transfer (source chain)
    struct OutboundTransfer {
        bytes32 transferId;
        address sender;
        bytes32 recipient; // Encrypted recipient on destination
        bytes32 encryptedAmount; // FHE encrypted amount
        address token; // Source token address
        uint256 destinationChainId;
        bytes32 destinationToken; // Token identifier on destination
        uint64 timestamp;
        uint64 expiry;
        TransferStatus status;
        bytes32 proofHash; // Hash of encrypted proof
    }

    /// @notice Inbound transfer (destination chain)
    struct InboundTransfer {
        bytes32 transferId;
        uint256 sourceChainId;
        bytes32 sender; // Sender on source chain
        address recipient; // Recipient on this chain
        bytes32 encryptedAmount; // Re-encrypted for this chain's keys
        address token; // Token on this chain
        uint64 timestamp;
        TransferStatus status;
        bytes32 sourceProofHash;
    }

    /// @notice Bridge proof for cross-chain verification
    struct BridgeProof {
        bytes32 transferId;
        uint256 sourceChainId;
        uint256 destinationChainId;
        bytes32 encryptedAmount;
        bytes32 amountRangeProof; // ZK proof that amount is within valid range
        bytes32 conservationProof; // ZK proof of amount conservation
        bytes zkProof; // Full ZK proof data
        bytes32[] validatorSigs; // Validator signatures
        uint64 timestamp;
    }

    /// @notice Chain configuration
    struct ChainConfig {
        uint256 chainId;
        bytes32 bridgeAdapter; // Address of bridge adapter on chain
        bytes32 fhePublicKey; // FHE public key for that chain
        bool active;
        uint256 minTransfer;
        uint256 maxTransfer;
        uint64 transferDelay;
    }

    /// @notice Token mapping
    struct TokenMapping {
        address sourceToken;
        bytes32 destinationToken;
        uint256 destinationChainId;
        bool active;
        uint256 lockedAmount; // Total locked (encrypted tracking)
    }

    // ============================================
    // Constants
    // ============================================

    /// @notice Minimum number of validators for proof verification
    uint256 public constant MIN_VALIDATORS = 3;

    /// @notice Quorum for validator consensus (basis points)
    uint256 public constant QUORUM_BPS = 6667; // 66.67%

    /// @notice Maximum transfer expiry
    uint64 public constant MAX_EXPIRY = 7 days;

    /// @notice Default transfer expiry
    uint64 public constant DEFAULT_EXPIRY = 1 days;

    // ============================================
    // State Variables
    // ============================================

    /// @notice FHE Gateway
    FHEGateway public immutable fheGateway;

    /// @notice This chain ID
    uint256 public immutable chainId;

    /// @notice Transfer counter
    uint256 public transferCounter;

    /// @notice Supported chains
    mapping(uint256 => ChainConfig) public chainConfigs;

    /// @notice Active chain IDs
    uint256[] public activeChains;

    /// @notice Token mappings: sourceToken => destinationChainId => TokenMapping
    mapping(address => mapping(uint256 => TokenMapping)) public tokenMappings;

    /// @notice Outbound transfers
    mapping(bytes32 => OutboundTransfer) public outboundTransfers;

    /// @notice Inbound transfers
    mapping(bytes32 => InboundTransfer) public inboundTransfers;

    /// @notice Transfer proofs
    mapping(bytes32 => BridgeProof) public bridgeProofs;

    /// @notice Validators
    address[] public validators;
    mapping(address => bool) public isValidator;

    /// @notice Used nullifiers (prevent replay)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Pending re-encryption requests
    mapping(bytes32 => bytes32) public reencryptionToTransfer;

    /// @notice Total encrypted locked per token (for conservation verification)
    mapping(address => bytes32) public totalEncryptedLocked;

    // ============================================
    // Events
    // ============================================

    event TransferInitiated(
        bytes32 indexed transferId,
        address indexed sender,
        bytes32 encryptedRecipient,
        bytes32 encryptedAmount,
        uint256 destinationChainId
    );

    event TransferLocked(bytes32 indexed transferId, bytes32 proofHash);

    event TransferRelayed(
        bytes32 indexed transferId,
        uint256 sourceChainId,
        bytes32 encryptedAmount
    );

    event TransferCompleted(
        bytes32 indexed transferId,
        address indexed recipient,
        bytes32 encryptedAmount
    );

    event TransferRefunded(bytes32 indexed transferId, address indexed sender);

    event ChainConfigured(
        uint256 indexed chainId,
        bytes32 bridgeAdapter,
        bool active
    );

    event TokenMapped(
        address indexed sourceToken,
        bytes32 destinationToken,
        uint256 indexed destinationChainId
    );

    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);

    event ProofSubmitted(
        bytes32 indexed transferId,
        bytes32 proofHash,
        uint256 validatorCount
    );

    // ============================================
    // Errors
    // ============================================

    error InvalidGateway();
    error InvalidChain();
    error ChainNotActive();
    error TokenNotMapped();
    error InvalidAmount();
    error TransferNotFound();
    error TransferExpired();
    error TransferNotPending();
    error InvalidProof();
    error InsufficientValidators();
    error QuorumNotReached();
    error NullifierAlreadyUsed();
    error Unauthorized();
    error InvalidExpiry();
    error TransferBelowMinimum();
    error TransferAboveMaximum();

    // ============================================
    // Constructor
    // ============================================

    constructor(address _fheGateway, uint256 _chainId) {
        if (_fheGateway == address(0)) revert InvalidGateway();

        fheGateway = FHEGateway(_fheGateway);
        chainId = _chainId;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
    }

    // ============================================
    // Outbound Transfers (Source Chain)
    // ============================================

    /**
     * @notice Initiate encrypted cross-chain transfer
     * @param encryptedAmount FHE encrypted transfer amount
     * @param encryptedRecipient Encrypted recipient address
     * @param token Source token address
     * @param destinationChainId Target chain ID
     * @param expiry Transfer expiry (0 for default)
     */
    function initiateTransfer(
        bytes32 encryptedAmount,
        bytes32 encryptedRecipient,
        address token,
        uint256 destinationChainId,
        uint64 expiry
    ) external whenNotPaused nonReentrant returns (bytes32 transferId) {
        // Validate destination chain
        ChainConfig storage destChain = chainConfigs[destinationChainId];
        if (!destChain.active) revert ChainNotActive();

        // Validate token mapping
        TokenMapping storage mapping_ = tokenMappings[token][
            destinationChainId
        ];
        if (!mapping_.active) revert TokenNotMapped();

        // Validate expiry
        if (expiry == 0) expiry = DEFAULT_EXPIRY;
        if (expiry > MAX_EXPIRY) revert InvalidExpiry();

        // Generate transfer ID
        transferCounter++;
        transferId = keccak256(
            abi.encode(
                chainId,
                transferCounter,
                msg.sender,
                encryptedAmount,
                block.timestamp
            )
        );

        // Store outbound transfer
        outboundTransfers[transferId] = OutboundTransfer({
            transferId: transferId,
            sender: msg.sender,
            recipient: encryptedRecipient,
            encryptedAmount: encryptedAmount,
            token: token,
            destinationChainId: destinationChainId,
            destinationToken: mapping_.destinationToken,
            timestamp: uint64(block.timestamp),
            expiry: uint64(block.timestamp) + expiry,
            status: TransferStatus.Pending,
            proofHash: bytes32(0)
        });

        // Lock encrypted amount (in encrypted form)
        _lockEncryptedAmount(token, encryptedAmount);

        emit TransferInitiated(
            transferId,
            msg.sender,
            encryptedRecipient,
            encryptedAmount,
            destinationChainId
        );
    }

    /**
     * @notice Initiate transfer with plaintext amount (encrypts automatically)
     */
    function initiateTransferPlain(
        uint256 amount,
        address recipient,
        address token,
        uint256 destinationChainId,
        uint64 expiry
    ) external whenNotPaused nonReentrant returns (bytes32 transferId) {
        // Validate amounts
        ChainConfig storage destChain = chainConfigs[destinationChainId];
        if (!destChain.active) revert ChainNotActive();
        if (amount < destChain.minTransfer) revert TransferBelowMinimum();
        if (amount > destChain.maxTransfer) revert TransferAboveMaximum();

        // Encrypt amount and recipient
        bytes32 encAmount = fheGateway.trivialEncrypt(
            amount,
            FHETypes.TYPE_EUINT64
        );
        bytes32 encRecipient = fheGateway.trivialEncrypt(
            uint256(uint160(recipient)),
            FHETypes.TYPE_EADDRESS
        );

        // Delegate to main function
        return
            this.initiateTransfer(
                encAmount,
                encRecipient,
                token,
                destinationChainId,
                expiry
            );
    }

    /**
     * @notice Lock encrypted amount
     */
    function _lockEncryptedAmount(
        address token,
        bytes32 encryptedAmount
    ) internal {
        // Add to total locked (encrypted addition)
        bytes32 currentLocked = totalEncryptedLocked[token];
        if (currentLocked == bytes32(0)) {
            totalEncryptedLocked[token] = encryptedAmount;
        } else {
            totalEncryptedLocked[token] = fheGateway.fheAdd(
                currentLocked,
                encryptedAmount
            );
        }
    }

    /**
     * @notice Generate and submit bridge proof for transfer
     * @param transferId Transfer ID
     * @param zkProof ZK proof of amount conservation
     */
    function submitProof(
        bytes32 transferId,
        bytes calldata zkProof
    ) external onlyRole(RELAYER_ROLE) {
        OutboundTransfer storage transfer = outboundTransfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status != TransferStatus.Pending)
            revert TransferNotPending();
        if (block.timestamp > transfer.expiry) revert TransferExpired();

        // Generate proof hash
        bytes32 proofHash = keccak256(
            abi.encode(
                transferId,
                transfer.encryptedAmount,
                transfer.destinationChainId,
                zkProof
            )
        );

        // Create bridge proof
        bridgeProofs[transferId] = BridgeProof({
            transferId: transferId,
            sourceChainId: chainId,
            destinationChainId: transfer.destinationChainId,
            encryptedAmount: transfer.encryptedAmount,
            amountRangeProof: bytes32(0), // Will be set by validators
            conservationProof: bytes32(0),
            zkProof: zkProof,
            validatorSigs: new bytes32[](0),
            timestamp: uint64(block.timestamp)
        });

        transfer.proofHash = proofHash;
        transfer.status = TransferStatus.Locked;

        emit TransferLocked(transferId, proofHash);
    }

    /**
     * @notice Validator signs proof
     * @param transferId Transfer ID
     * @param signature Validator signature
     */
    function signProof(
        bytes32 transferId,
        bytes32 signature
    ) external onlyRole(VALIDATOR_ROLE) {
        BridgeProof storage proof = bridgeProofs[transferId];
        if (proof.transferId == bytes32(0)) revert TransferNotFound();

        proof.validatorSigs.push(signature);

        emit ProofSubmitted(
            transferId,
            proof.amountRangeProof,
            proof.validatorSigs.length
        );
    }

    /**
     * @notice Refund expired transfer
     * @param transferId Transfer ID
     */
    function refundTransfer(bytes32 transferId) external nonReentrant {
        OutboundTransfer storage transfer = outboundTransfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.sender != msg.sender) revert Unauthorized();
        if (block.timestamp <= transfer.expiry) revert TransferNotPending();
        if (
            transfer.status != TransferStatus.Pending &&
            transfer.status != TransferStatus.Locked
        ) revert TransferNotPending();

        transfer.status = TransferStatus.Refunded;

        // Unlock encrypted amount
        _unlockEncryptedAmount(transfer.token, transfer.encryptedAmount);

        emit TransferRefunded(transferId, msg.sender);
    }

    /**
     * @notice Unlock encrypted amount
     */
    function _unlockEncryptedAmount(
        address token,
        bytes32 encryptedAmount
    ) internal {
        bytes32 currentLocked = totalEncryptedLocked[token];
        if (currentLocked != bytes32(0)) {
            totalEncryptedLocked[token] = fheGateway.fheSub(
                currentLocked,
                encryptedAmount
            );
        }
    }

    // ============================================
    // Inbound Transfers (Destination Chain)
    // ============================================

    /**
     * @notice Process inbound transfer from another chain
     * @param transferId Original transfer ID
     * @param sourceChainId Source chain ID
     * @param sender Source sender (encrypted)
     * @param recipient Recipient on this chain
     * @param encryptedAmount Encrypted amount (re-encrypted for this chain)
     * @param proof Bridge proof
     */
    function processInbound(
        bytes32 transferId,
        uint256 sourceChainId,
        bytes32 sender,
        address recipient,
        bytes32 encryptedAmount,
        BridgeProof calldata proof
    ) external onlyRole(RELAYER_ROLE) whenNotPaused nonReentrant {
        // Validate source chain
        ChainConfig storage sourceChain = chainConfigs[sourceChainId];
        if (!sourceChain.active) revert ChainNotActive();

        // Validate nullifier (prevent replay)
        bytes32 nullifier = keccak256(abi.encode(transferId, sourceChainId));
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        usedNullifiers[nullifier] = true;

        // Verify proof signatures
        if (!_verifyProof(proof)) revert InvalidProof();

        // Store inbound transfer
        inboundTransfers[transferId] = InboundTransfer({
            transferId: transferId,
            sourceChainId: sourceChainId,
            sender: sender,
            recipient: recipient,
            encryptedAmount: encryptedAmount,
            token: address(0), // Will be set based on token mapping
            timestamp: uint64(block.timestamp),
            status: TransferStatus.Relayed,
            sourceProofHash: proof.amountRangeProof
        });

        emit TransferRelayed(transferId, sourceChainId, encryptedAmount);
    }

    /**
     * @notice Complete inbound transfer (mint/release to recipient)
     * @param transferId Transfer ID
     * @param destinationToken Token on this chain
     */
    function completeInbound(
        bytes32 transferId,
        address destinationToken
    ) external onlyRole(RELAYER_ROLE) whenNotPaused {
        InboundTransfer storage transfer = inboundTransfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();
        if (transfer.status != TransferStatus.Relayed)
            revert TransferNotPending();

        transfer.token = destinationToken;
        transfer.status = TransferStatus.Completed;

        // Mint/release encrypted amount to recipient
        // In production, this would interact with EncryptedERC20 or similar
        // For now, just mark as completed

        emit TransferCompleted(
            transferId,
            transfer.recipient,
            transfer.encryptedAmount
        );
    }

    /**
     * @notice Verify bridge proof
     */
    function _verifyProof(
        BridgeProof calldata proof
    ) internal view returns (bool) {
        // Check minimum validators
        if (proof.validatorSigs.length < MIN_VALIDATORS) return false;

        // Check quorum
        uint256 required = (validators.length * QUORUM_BPS) / 10000;
        if (proof.validatorSigs.length < required) return false;

        // Verify ZK proof (placeholder - would call actual verifier)
        if (proof.zkProof.length == 0) return false;

        // In production:
        // 1. Verify each validator signature
        // 2. Verify ZK proof of amount conservation
        // 3. Verify range proof
        // 4. Verify source chain state root

        return true;
    }

    // ============================================
    // Re-encryption for Cross-Chain
    // ============================================

    /**
     * @notice Request re-encryption for destination chain
     * @param transferId Transfer ID
     * @param destinationChainId Destination chain ID
     */
    function requestReencryption(
        bytes32 transferId,
        uint256 destinationChainId
    ) external onlyRole(RELAYER_ROLE) {
        OutboundTransfer storage transfer = outboundTransfers[transferId];
        if (transfer.transferId == bytes32(0)) revert TransferNotFound();

        ChainConfig storage destChain = chainConfigs[destinationChainId];
        if (!destChain.active) revert ChainNotActive();

        // Request re-encryption with destination chain's public key
        bytes32 requestId = fheGateway.requestReencryption(
            transfer.encryptedAmount,
            destChain.fhePublicKey,
            3600 // TTL of 1 hour
        );

        reencryptionToTransfer[requestId] = transferId;
    }

    /**
     * @notice Callback for re-encryption completion
     * @param requestId Request ID
     * @param reencryptedValue Re-encrypted value
     */
    function onReencrypted(
        bytes32 requestId,
        bytes32 reencryptedValue
    ) external {
        require(msg.sender == address(fheGateway), "Unauthorized");

        bytes32 transferId = reencryptionToTransfer[requestId];
        if (transferId == bytes32(0)) return;

        OutboundTransfer storage transfer = outboundTransfers[transferId];

        // Store re-encrypted amount (would be used by relayer)
        // In production, emit event with re-encrypted value for relayer
    }

    // ============================================
    // Chain Configuration
    // ============================================

    /**
     * @notice Configure destination chain
     */
    function configureChain(
        uint256 _chainId,
        bytes32 _bridgeAdapter,
        bytes32 _fhePublicKey,
        uint256 _minTransfer,
        uint256 _maxTransfer,
        uint64 _transferDelay
    ) external onlyRole(ADMIN_ROLE) {
        if (_chainId == 0) revert InvalidChain();
        if (_chainId == chainId) revert InvalidChain();

        bool wasActive = chainConfigs[_chainId].active;

        chainConfigs[_chainId] = ChainConfig({
            chainId: _chainId,
            bridgeAdapter: _bridgeAdapter,
            fhePublicKey: _fhePublicKey,
            active: true,
            minTransfer: _minTransfer,
            maxTransfer: _maxTransfer,
            transferDelay: _transferDelay
        });

        if (!wasActive) {
            activeChains.push(_chainId);
        }

        emit ChainConfigured(_chainId, _bridgeAdapter, true);
    }

    /**
     * @notice Deactivate chain
     */
    function deactivateChain(uint256 _chainId) external onlyRole(ADMIN_ROLE) {
        chainConfigs[_chainId].active = false;
        emit ChainConfigured(
            _chainId,
            chainConfigs[_chainId].bridgeAdapter,
            false
        );
    }

    // ============================================
    // Token Mapping
    // ============================================

    /**
     * @notice Map source token to destination token
     */
    function mapToken(
        address sourceToken,
        bytes32 destinationToken,
        uint256 destinationChainId
    ) external onlyRole(ADMIN_ROLE) {
        if (!chainConfigs[destinationChainId].active) revert ChainNotActive();

        tokenMappings[sourceToken][destinationChainId] = TokenMapping({
            sourceToken: sourceToken,
            destinationToken: destinationToken,
            destinationChainId: destinationChainId,
            active: true,
            lockedAmount: 0
        });

        emit TokenMapped(sourceToken, destinationToken, destinationChainId);
    }

    /**
     * @notice Deactivate token mapping
     */
    function deactivateToken(
        address sourceToken,
        uint256 destinationChainId
    ) external onlyRole(ADMIN_ROLE) {
        tokenMappings[sourceToken][destinationChainId].active = false;
    }

    // ============================================
    // Validator Management
    // ============================================

    /**
     * @notice Add validator
     */
    function addValidator(address validator) external onlyRole(ADMIN_ROLE) {
        if (!isValidator[validator]) {
            validators.push(validator);
            isValidator[validator] = true;
            _grantRole(VALIDATOR_ROLE, validator);
            emit ValidatorAdded(validator);
        }
    }

    /**
     * @notice Remove validator
     */
    function removeValidator(address validator) external onlyRole(ADMIN_ROLE) {
        if (isValidator[validator]) {
            isValidator[validator] = false;
            _revokeRole(VALIDATOR_ROLE, validator);

            // Remove from array
            for (uint256 i = 0; i < validators.length; i++) {
                if (validators[i] == validator) {
                    validators[i] = validators[validators.length - 1];
                    validators.pop();
                    break;
                }
            }

            emit ValidatorRemoved(validator);
        }
    }

    // ============================================
    // Admin Functions
    // ============================================

    /**
     * @notice Pause bridge
     */
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge
     */
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
    }

    // ============================================
    // View Functions
    // ============================================

    /**
     * @notice Get outbound transfer
     */
    function getOutboundTransfer(
        bytes32 transferId
    ) external view returns (OutboundTransfer memory) {
        return outboundTransfers[transferId];
    }

    /**
     * @notice Get inbound transfer
     */
    function getInboundTransfer(
        bytes32 transferId
    ) external view returns (InboundTransfer memory) {
        return inboundTransfers[transferId];
    }

    /**
     * @notice Get bridge proof
     */
    function getBridgeProof(
        bytes32 transferId
    ) external view returns (BridgeProof memory) {
        return bridgeProofs[transferId];
    }

    /**
     * @notice Get chain config
     */
    function getChainConfig(
        uint256 _chainId
    ) external view returns (ChainConfig memory) {
        return chainConfigs[_chainId];
    }

    /**
     * @notice Get all active chains
     */
    function getActiveChains() external view returns (uint256[] memory) {
        return activeChains;
    }

    /**
     * @notice Get validator count
     */
    function getValidatorCount() external view returns (uint256) {
        return validators.length;
    }

    /**
     * @notice Get all validators
     */
    function getValidators() external view returns (address[] memory) {
        return validators;
    }

    /**
     * @notice Check if transfer is expired
     */
    function isTransferExpired(
        bytes32 transferId
    ) external view returns (bool) {
        return block.timestamp > outboundTransfers[transferId].expiry;
    }
}
