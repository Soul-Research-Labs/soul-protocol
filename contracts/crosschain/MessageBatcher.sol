// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./SoulCrossChainRelay.sol";

/**
 * @title MessageBatcher
 * @notice Aggregates cross-chain messages into batches to save gas.
 */
contract MessageBatcher is AccessControl, ReentrancyGuard {
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    SoulCrossChainRelay public relay;

    struct QueuedMessage {
        bytes payload;
        uint256 value;
    }

    // specific destination -> queue
    mapping(uint64 => QueuedMessage[]) public queues;

    // Config
    uint256 public maxBatchSize = 10;

    event MessageQueued(uint64 indexed destChainId, uint256 index);
    event BatchSent(
        uint64 indexed destChainId,
        uint256 count,
        bytes32 messageId
    );

    /// @notice Initializes the batcher with a relay contract and admin
    /// @param _relay Address of the SoulCrossChainRelay contract
    /// @param _admin Address to receive the default admin role
    constructor(address _relay, address _admin) {
        relay = SoulCrossChainRelay(_relay);
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
    }

    /**
     * @notice Queue a proof for batch relay.
     *         User sends ETH to cover their share of the bridge fee.
     */
    function queueProof(
        bytes32 proofId,
        bytes calldata proof,
        bytes calldata publicInputs,
        bytes32 commitment,
        uint64 destChainId,
        bytes32 proofType
    ) external payable {
        // Encode payload matching SoulCrossChainRelay relayProof format internal decoding
        // But wait, relayBatch expects ARRAY of payloads.
        // Each payload in existing system is:
        // abi.encode(MSG_PROOF_RELAY, proofId, proof, publicInputs, commitment, srcChainId, proofType)
        // SrcChainId is usually filled by Relay.
        // But here Batcher constructs it?
        // SoulCrossChainRelay._processBatch decodes:
        // (uint8 msgType, bytes32 proofId, ...)

        bytes memory payload = abi.encode(
            relay.MSG_PROOF_RELAY(),
            proofId,
            proof,
            publicInputs,
            commitment,
            uint64(block.chainid), // srcChainId
            proofType
        );

        queues[destChainId].push(
            QueuedMessage({payload: payload, value: msg.value})
        );

        emit MessageQueued(destChainId, queues[destChainId].length - 1);

        // Auto-send if full
        if (queues[destChainId].length >= maxBatchSize) {
            _sendBatch(destChainId);
        }
    }

    /**
     * @notice Manually trigger batch sending (e.g. by keeper if time aligns)
     */
    function sendBatch(uint64 destChainId) external nonReentrant {
        // Only allow if not empty
        require(queues[destChainId].length > 0, "Queue empty");
        _sendBatch(destChainId);
    }

    function _sendBatch(uint64 destChainId) internal {
        QueuedMessage[] storage queue = queues[destChainId];
        uint256 count = queue.length;
        if (count == 0) return;

        bytes[] memory payloads = new bytes[](count);
        uint256 totalValue = 0;

        for (uint256 i = 0; i < count; i++) {
            payloads[i] = queue[i].payload;
            totalValue += queue[i].value;
        }

        delete queues[destChainId];

        // Call relayBatch - we need to send value
        bytes32 msgId = relay.relayBatch{value: totalValue}(
            destChainId,
            payloads
        );

        emit BatchSent(destChainId, count, msgId);
    }

    /// @notice Update the maximum number of messages per batch
    /// @param _size New maximum batch size
    function setMaxBatchSize(
        uint256 _size
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxBatchSize = _size;
    }

    /// @notice Rescue stuck tokens or ETH from the contract
    /// @param token Token address (address(0) for native ETH)
    /// @param amount Amount to rescue
    function rescueFunds(
        address token,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (token == address(0)) {
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
        } else {
            (bool success, ) = token.call(
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    msg.sender,
                    amount
                )
            );
            require(success, "Transfer failed");
        }
    }
}
