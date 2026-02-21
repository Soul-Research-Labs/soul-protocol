// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title HyperlaneAdapter
 * @author Soul Protocol
 * @notice Hyperlane Interchain Security Module (ISM) integration
 * @dev Implements Hyperlane's modular security for cross-chain messaging
 *
 * HYPERLANE ISM ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    Hyperlane Integration                        │
 * │                                                                  │
 * │  Source Chain                          Destination Chain        │
 * │  ┌────────────┐     ┌──────────┐      ┌────────────┐           │
 * │  │ Mailbox    │────▶│ Relayer  │─────▶│ Mailbox    │           │
 * │  │            │     │          │      │            │           │
 * │  └────────────┘     └────┬─────┘      └─────┬──────┘           │
 * │                          │                  │                   │
 * │                    ┌─────▼──────────────────▼─────┐            │
 * │                    │    Interchain Security       │            │
 * │                    │    Module (ISM)              │            │
 * │                    │                              │            │
 * │                    │  ┌─────────────────────────┐ │            │
 * │                    │  │ Multisig ISM           │ │            │
 * │                    │  │ • m-of-n validator set │ │            │
 * │                    │  │ • Merkle proof verify  │ │            │
 * │                    │  └─────────────────────────┘ │            │
 * │                    │                              │            │
 * │                    │  ┌─────────────────────────┐ │            │
 * │                    │  │ Aggregation ISM        │ │            │
 * │                    │  │ • Combine multiple ISMs│ │            │
 * │                    │  │ • AND/OR logic         │ │            │
 * │                    │  └─────────────────────────┘ │            │
 * │                    └──────────────────────────────┘            │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract HyperlaneAdapter is ReentrancyGuard, AccessControl, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidMailbox();
    error InvalidISM();
    error InvalidDomain();
    error MessageNotVerified();
    error InsufficientValidators();
    error InvalidMerkleProof();
    error UntrustedSender();
    error MessageAlreadyProcessed();
    error InvalidSignature();
    error ThresholdNotMet();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event MessageDispatched(
        bytes32 indexed messageId,
        uint32 indexed destinationDomain,
        bytes32 recipient,
        bytes message
    );

    event MessageProcessed(
        bytes32 indexed messageId,
        uint32 indexed originDomain,
        bytes32 sender,
        bytes message
    );

    event ISMConfigured(uint32 indexed domain, address ism, ISMType ismType);

    event ValidatorSet(
        uint32 indexed domain,
        address[] validators,
        uint8 threshold
    );

    event MerkleRootStored(uint32 indexed domain, bytes32 root, uint256 index);

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum ISMType {
        MULTISIG,
        MERKLE,
        AGGREGATION,
        ROUTING,
        PAUSABLE,
        CUSTOM
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice ISM Configuration
    struct ISMConfig {
        address ism;
        ISMType ismType;
        bool enabled;
        uint8 threshold;
        address[] validators;
    }

    /// @notice Multisig ISM parameters
    struct MultisigISMParams {
        address[] validators;
        uint8 threshold;
        bytes32 commitment; // Commitment to validator set
    }

    /// @notice Merkle proof for message verification
    struct MerkleProof {
        bytes32[] path;
        uint256 index;
        bytes32 leaf;
    }

    /// @notice Message metadata
    struct MessageMetadata {
        uint32 originDomain;
        uint32 destinationDomain;
        bytes32 sender;
        bytes32 recipient;
        uint256 nonce;
        bytes body;
        bytes32 messageId;
        uint256 timestamp;
        bool verified;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");

    /// @notice Hyperlane Mailbox address
    address public immutable mailbox;

    /// @notice Local domain ID
    uint32 public immutable localDomain;

    /// @notice ISM configurations per domain
    mapping(uint32 => ISMConfig) public ismConfigs;

    /// @notice Trusted senders per domain
    mapping(uint32 => bytes32) public trustedSenders;

    /// @notice Processed message IDs
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Message metadata
    mapping(bytes32 => MessageMetadata) public messages;

    /// @notice Multisig ISM parameters per domain
    mapping(uint32 => MultisigISMParams) public multisigParams;

    /// @notice Merkle roots per domain
    mapping(uint32 => bytes32[]) public merkleRoots;

    /// @notice Validator signatures per message
    mapping(bytes32 => mapping(address => bytes)) public validatorSignatures;

    /// @notice Signature count per message
    mapping(bytes32 => uint8) public signatureCount;

    /// @notice Outbound nonce per domain
    mapping(uint32 => uint256) public outboundNonce;

    /// @notice Inbound nonce per domain
    mapping(uint32 => uint256) public inboundNonce;

    /// @notice Soul hub addresses per domain
    mapping(uint32 => address) public soulHubs;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initializes the adapter with a Hyperlane Mailbox and local domain
    /// @param _mailbox Address of the Hyperlane Mailbox contract
    /// @param _localDomain Local Hyperlane domain ID for this chain
    /// @param _admin Address to receive operator and guardian roles
    constructor(address _mailbox, uint32 _localDomain, address _admin) {
        if (_mailbox == address(0)) revert InvalidMailbox();

        mailbox = _mailbox;
        localDomain = _localDomain;

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                         MESSAGE DISPATCHING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Dispatch a message to another chain via Hyperlane
     * @param destinationDomain Target domain ID
     * @param recipient Recipient address as bytes32
     * @param message Message body
     * @return messageId Unique message identifier
     */
    function dispatch(
        uint32 destinationDomain,
        bytes32 recipient,
        bytes calldata message
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (trustedSenders[destinationDomain] == bytes32(0))
            revert InvalidDomain();

        uint256 nonce = ++outboundNonce[destinationDomain];

        // Generate message ID (matches Hyperlane format)
        messageId = keccak256(
            abi.encodePacked(
                localDomain,
                bytes32(uint256(uint160(msg.sender))),
                destinationDomain,
                recipient,
                nonce,
                message // FIX: Using original message for ID generation
            )
        );

        // FIX: Encode nonce into payload to ensure uniqueness on destination
        bytes memory payload = abi.encodePacked(nonce, message);

        // Store message metadata
        messages[messageId] = MessageMetadata({
            originDomain: localDomain,
            destinationDomain: destinationDomain,
            sender: bytes32(uint256(uint160(msg.sender))),
            recipient: recipient,
            nonce: nonce,
            body: message,
            messageId: messageId,
            timestamp: block.timestamp,
            verified: false
        });

        // Dispatch via mailbox
        _dispatchToMailbox(destinationDomain, recipient, payload);

        emit MessageDispatched(
            messageId,
            destinationDomain,
            recipient,
            message
        );

        return messageId;
    }

    /**
     * @notice Quote the fee for dispatching a message
     * @param message Message body
     * @return fee Required fee
     */
    function quoteDispatch(
        uint32, // destinationDomain (unused)
        bytes calldata message
    ) external pure returns (uint256 fee) {
        // Simplified fee calculation
        // In production, call mailbox.quoteDispatch()
        uint256 baseFee = 0.0005 ether;
        uint256 messageFee = (message.length * 500 gwei) / 32;

        return baseFee + messageFee;
    }

    /*//////////////////////////////////////////////////////////////
                         MESSAGE PROCESSING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Process an incoming message from Hyperlane
     * @param origin Origin domain ID
     * @param sender Sender address as bytes32
     * @param message Message body
     */
    function handle(
        uint32 origin,
        bytes32 sender,
        bytes calldata message
    ) external {
        // Only accept from mailbox
        if (msg.sender != mailbox) revert InvalidMailbox();

        // Verify trusted sender
        if (trustedSenders[origin] != sender) revert UntrustedSender();

        // FIX: Extract nonce and body from message payload
        if (message.length < 32) revert MessageNotVerified();

        uint256 nonce;
        // Extract nonce (first 32 bytes)
        assembly {
            nonce := calldataload(message.offset)
        }

        // Extract actual message body
        bytes calldata body = message[32:];

        bytes32 messageId = keccak256(
            abi.encodePacked(
                origin,
                sender,
                localDomain,
                bytes32(uint256(uint160(address(this)))),
                nonce,
                body
            )
        );

        // Check not already processed
        if (processedMessages[messageId]) revert MessageAlreadyProcessed();
        processedMessages[messageId] = true;

        // Store message
        messages[messageId] = MessageMetadata({
            originDomain: origin,
            destinationDomain: localDomain,
            sender: sender,
            recipient: bytes32(uint256(uint160(address(this)))),
            nonce: nonce,
            body: body,
            messageId: messageId,
            timestamp: block.timestamp,
            verified: true
        });

        emit MessageProcessed(messageId, origin, sender, message);

        // Process the message
        _handleMessage(origin, sender, body);
    }

    /*//////////////////////////////////////////////////////////////
                         ISM VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a message using the configured ISM
     * @param messageId Message ID to verify
     * @param metadata ISM-specific verification metadata
     * @return verified True if verification passed
     */
    function verify(
        bytes32 messageId,
        bytes calldata metadata
    ) external returns (bool verified) {
        MessageMetadata storage msg_ = messages[messageId];
        if (msg_.verified) return true;

        ISMConfig storage config = ismConfigs[msg_.originDomain];
        if (!config.enabled) revert InvalidISM();

        if (config.ismType == ISMType.MULTISIG) {
            verified = _verifyMultisig(messageId, metadata, msg_.originDomain);
        } else if (config.ismType == ISMType.MERKLE) {
            verified = _verifyMerkle(messageId, metadata, msg_.originDomain);
        } else if (config.ismType == ISMType.AGGREGATION) {
            verified = _verifyAggregation(
                messageId,
                metadata,
                msg_.originDomain
            );
        } else {
            // CEI: mark verified before external custom ISM call
            msg_.verified = true;
            verified = _verifyCustom(messageId, metadata, config.ism);
            if (!verified) revert InvalidISM();
            return true;
        }

        if (verified) {
            msg_.verified = true;
        }

        return verified;
    }

    /**
     * @notice Submit validator signature for multisig ISM
     * @param messageId Message ID
     * @param signature Validator signature
     */
    function submitValidatorSignature(
        bytes32 messageId,
        bytes calldata signature
    ) external onlyRole(VALIDATOR_ROLE) {
        if (validatorSignatures[messageId][msg.sender].length > 0) {
            return; // Already signed
        }

        validatorSignatures[messageId][msg.sender] = signature;
        signatureCount[messageId]++;
    }

    function _verifyMultisig(
        bytes32 messageId,
        bytes memory metadata,
        uint32 originDomain
    ) internal view returns (bool) {
        MultisigISMParams storage params = multisigParams[originDomain];

        // FIX: Verify signatures from metadata
        bytes[] memory signatures = abi.decode(metadata, (bytes[]));

        if (signatures.length < params.threshold) {
            return false;
        }

        uint8 validSignatures = 0;
        address lastSigner = address(0);

        // Validators sign the messageId, not the commitment
        // This ensures each message is individually verified
        bytes32 digest = keccak256(
            abi.encodePacked(messageId, originDomain, params.commitment)
        );

        for (uint256 i = 0; i < signatures.length; i++) {
            // Recover signer from the message-specific digest
            address signer = ECDSA.recover(digest, signatures[i]);

            // Check duplications (signatures must be sorted/unique)
            if (signer <= lastSigner) continue;
            lastSigner = signer;

            // Check if signer is validator
            bool isValidator = false;
            for (uint256 j = 0; j < params.validators.length; ) {
                if (params.validators[j] == signer) {
                    isValidator = true;
                    break;
                }
                unchecked {
                    ++j;
                }
            }

            if (isValidator) {
                validSignatures++;
            }
        }

        return validSignatures >= params.threshold;
    }

    function _verifyMerkle(
        bytes32 messageId,
        bytes calldata metadata,
        uint32 originDomain
    ) internal view returns (bool) {
        // Decode merkle proof from metadata
        (bytes32[] memory path, uint256 index) = abi.decode(
            metadata,
            (bytes32[], uint256)
        );

        // Get stored root
        bytes32[] storage roots = merkleRoots[originDomain];
        if (roots.length == 0) return false;

        bytes32 root = roots[roots.length - 1];

        // Verify proof
        bytes32 computedHash = messageId;
        for (uint256 i = 0; i < path.length; ) {
            if (index % 2 == 0) {
                computedHash = keccak256(
                    abi.encodePacked(computedHash, path[i])
                );
            } else {
                computedHash = keccak256(
                    abi.encodePacked(path[i], computedHash)
                );
            }
            index = index / 2;
            unchecked {
                ++i;
            }
        }

        return computedHash == root;
    }

    function _verifyAggregation(
        bytes32 messageId,
        bytes calldata metadata,
        uint32 originDomain
    ) internal view returns (bool) {
        // Decode sub-ISM verifications from metadata
        bytes[] memory subMetadata = abi.decode(metadata, (bytes[]));

        ISMConfig storage config = ismConfigs[originDomain];
        uint8 verified = 0;

        // Verify with each sub-ISM (simplified)
        for (uint256 i = 0; i < subMetadata.length; ) {
            if (_verifyMultisig(messageId, subMetadata[i], originDomain)) {
                verified++;
            }
            unchecked {
                ++i;
            }
        }

        return verified >= config.threshold;
    }

    function _verifyCustom(
        bytes32 messageId,
        bytes calldata metadata,
        address ism
    ) internal returns (bool) {
        // Call custom ISM verify function
        (bool success, bytes memory result) = ism.call(
            abi.encodeWithSignature(
                "verify(bytes32,bytes)",
                messageId,
                metadata
            )
        );

        if (!success) return false;
        return abi.decode(result, (bool));
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _dispatchToMailbox(
        uint32 destinationDomain,
        bytes32 recipient,
        bytes memory message
    ) internal {
        // FIX: Call actual mailbox
        IMailbox(mailbox).dispatch{value: msg.value}(
            destinationDomain,
            recipient,
            message
        );
    }

    function _handleMessage(
        uint32 origin,
        bytes32 sender,
        bytes calldata message
    ) internal virtual {
        // Override in derived contracts
    }

    /*//////////////////////////////////////////////////////////////
                         CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure ISM for a domain
     * @param domain Domain ID
     * @param config ISM configuration
     */
    function setISMConfig(
        uint32 domain,
        ISMConfig calldata config
    ) external onlyRole(OPERATOR_ROLE) {
        ismConfigs[domain] = config;

        emit ISMConfigured(domain, config.ism, config.ismType);

        if (config.ismType == ISMType.MULTISIG) {
            emit ValidatorSet(domain, config.validators, config.threshold);
        }
    }

    /**
     * @notice Set multisig ISM parameters
     * @param domain Domain ID
     * @param validators Validator addresses
     * @param threshold Signature threshold
     */
    function setMultisigParams(
        uint32 domain,
        address[] calldata validators,
        uint8 threshold
    ) external onlyRole(OPERATOR_ROLE) {
        if (threshold > validators.length) revert ThresholdNotMet();

        multisigParams[domain] = MultisigISMParams({
            validators: validators,
            threshold: threshold,
            commitment: keccak256(abi.encodePacked(validators, threshold))
        });

        emit ValidatorSet(domain, validators, threshold);
    }

    /**
     * @notice Store a new Merkle root
     * @param domain Domain ID
     * @param root Merkle root
     */
    function storeMerkleRoot(
        uint32 domain,
        bytes32 root
    ) external onlyRole(OPERATOR_ROLE) {
        merkleRoots[domain].push(root);
        emit MerkleRootStored(domain, root, merkleRoots[domain].length - 1);
    }

    /**
     * @notice Set trusted sender for a domain
     * @param domain Domain ID
     * @param sender Sender address as bytes32
     */
    function setTrustedSender(
        uint32 domain,
        bytes32 sender
    ) external onlyRole(OPERATOR_ROLE) {
        trustedSenders[domain] = sender;
    }

    /**
     * @notice Set Soul hub for a domain
     * @param domain Domain ID
     * @param hub Soul hub address
     */
    function setPilHub(
        uint32 domain,
        address hub
    ) external onlyRole(OPERATOR_ROLE) {
        soulHubs[domain] = hub;
    }

    /**
     * @notice Add a validator
     * @param validator Validator address
     */
    function addValidator(address validator) external onlyRole(OPERATOR_ROLE) {
        _grantRole(VALIDATOR_ROLE, validator);
    }

    /**
     * @notice Remove a validator
     * @param validator Validator address
     */
    function removeValidator(
        address validator
    ) external onlyRole(OPERATOR_ROLE) {
        _revokeRole(VALIDATOR_ROLE, validator);
    }

    /**
     * @notice Pause the adapter
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the adapter
     */
    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /**
     * @notice Get merkle roots for a domain
     * @param domain Domain ID
     * @return roots Array of merkle roots
     */
    function getMerkleRoots(
        uint32 domain
    ) external view returns (bytes32[] memory) {
        return merkleRoots[domain];
    }

    /**
     * @notice Receive native tokens
     */
    receive() external payable {}
}

interface IMailbox {
    function dispatch(
        uint32 destinationDomain,
        bytes32 recipientBody,
        bytes calldata messageBody
    ) external payable returns (bytes32 messageId);
}
