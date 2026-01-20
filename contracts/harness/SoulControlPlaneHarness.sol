// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SoulControlPlaneHarness
 * @notice Simplified harness for Certora verification of SoulControlPlane properties
 * @dev Contains core 5-stage lifecycle properties without deep stack complexity
 */
contract SoulControlPlaneHarness is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant CONTROL_ADMIN_ROLE =
        keccak256("CONTROL_ADMIN_ROLE");
    bytes32 public constant BACKEND_ROLE = keccak256("BACKEND_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    /*//////////////////////////////////////////////////////////////
                               DATA TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice 5-stage proof-bound message lifecycle
    enum MessageStage {
        NonExistent, // 0: Not created
        IntentCommitted, // 1: Payload + policy committed
        Executed, // 2: Backend processed
        ProofGenerated, // 3: Policy-bound proof created
        Verified, // 4: Kernel verification passed
        Materialized // 5: State updated on destination
    }

    /// @notice Simplified message struct
    struct SimpleMessage {
        bytes32 messageId;
        bytes32 sender;
        bytes32 recipient;
        bytes32 payloadCommitment;
        bytes32 nullifier;
        MessageStage stage;
        uint64 createdAt;
        uint64 expiresAt;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Message registry
    mapping(bytes32 => SimpleMessage) public messages;

    /// @notice Nullifier registry (idempotent execution)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Retry count
    mapping(bytes32 => uint256) public retryCount;

    /// @notice Counters
    uint256 public totalMessages;
    uint256 public totalExecutions;
    uint256 public totalMaterializations;

    /// @notice Maximum retry attempts
    uint256 public maxRetries = 3;

    /// @notice Default message validity period
    uint256 public defaultMessageValidity = 24 hours;

    /// @notice Nonce for nullifier generation
    uint256 private _nullifierNonce;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(CONTROL_ADMIN_ROLE, msg.sender);
        _grantRole(BACKEND_ROLE, msg.sender);
        _grantRole(RELAYER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 1: INTENT COMMITMENT
    //////////////////////////////////////////////////////////////*/

    function commitIntent(
        bytes32 recipient,
        bytes32 payloadCommitment
    ) external whenNotPaused returns (bytes32 messageId) {
        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                payloadCommitment,
                block.timestamp
            )
        );

        require(
            messages[messageId].stage == MessageStage.NonExistent,
            "Message exists"
        );

        bytes32 nullifier = keccak256(
            abi.encodePacked(messageId, block.number, ++_nullifierNonce)
        );

        messages[messageId] = SimpleMessage({
            messageId: messageId,
            sender: bytes32(uint256(uint160(msg.sender))),
            recipient: recipient,
            payloadCommitment: payloadCommitment,
            nullifier: nullifier,
            stage: MessageStage.IntentCommitted,
            createdAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + defaultMessageValidity)
        });

        totalMessages++;
        return messageId;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 2: EXECUTION
    //////////////////////////////////////////////////////////////*/

    function submitExecution(
        bytes32 messageId
    ) external onlyRole(BACKEND_ROLE) nonReentrant whenNotPaused {
        SimpleMessage storage message = messages[messageId];
        require(message.stage == MessageStage.IntentCommitted, "Invalid stage");
        require(block.timestamp <= message.expiresAt, "Message expired");

        message.stage = MessageStage.Executed;
        totalExecutions++;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 3-4: PROOF & VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function submitProofAndVerify(
        bytes32 messageId
    ) external onlyRole(BACKEND_ROLE) nonReentrant whenNotPaused {
        SimpleMessage storage message = messages[messageId];
        require(message.stage == MessageStage.Executed, "Invalid stage");

        message.stage = MessageStage.Verified;
    }

    /*//////////////////////////////////////////////////////////////
                    STAGE 5: MATERIALIZATION
    //////////////////////////////////////////////////////////////*/

    function materialize(
        bytes32 messageId
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        SimpleMessage storage message = messages[messageId];
        require(message.stage == MessageStage.Verified, "Invalid stage");

        // Mark nullifier as used
        usedNullifiers[message.nullifier] = true;

        message.stage = MessageStage.Materialized;
        totalMaterializations++;
    }

    /*//////////////////////////////////////////////////////////////
                         RETRY MECHANISM
    //////////////////////////////////////////////////////////////*/

    function retryMessage(
        bytes32 messageId
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        SimpleMessage storage message = messages[messageId];
        require(message.stage != MessageStage.NonExistent, "Message not found");
        require(
            message.stage != MessageStage.Materialized,
            "Already materialized"
        );
        require(retryCount[messageId] < maxRetries, "Max retries exceeded");

        retryCount[messageId]++;
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    function getMessageStage(
        bytes32 messageId
    ) external view returns (MessageStage) {
        return messages[messageId].stage;
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    function getMessageSender(
        bytes32 messageId
    ) external view returns (bytes32) {
        return messages[messageId].sender;
    }
}
