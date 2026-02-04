// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title BitcoinHTLC
 * @author Soul Protocol
 * @notice Hash Time-Locked Contract for Bitcoin atomic swaps
 * @dev Enables trustless cross-chain swaps between Bitcoin and Ethereum
 *
 * ATOMIC SWAP FLOW:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                   BTC ↔ ETH Atomic Swap                         │
 * ├─────────────────────────────────────────────────────────────────┤
 * │                                                                  │
 * │  Alice (has BTC, wants ETH)    Bob (has ETH, wants BTC)         │
 * │                                                                  │
 * │  1. Alice generates secret S, computes H = hash(S)              │
 * │                                                                  │
 * │  2. Alice creates BTC HTLC:                                     │
 * │     - Locked to hash H                                           │
 * │     - Bob can claim with preimage S                              │
 * │     - Alice can refund after 48 hours                            │
 * │                                                                  │
 * │  3. Bob creates ETH HTLC (this contract):                       │
 * │     - Locked to same hash H                                      │
 * │     - Alice can claim with preimage S                            │
 * │     - Bob can refund after 24 hours                              │
 * │                                                                  │
 * │  4. Alice claims ETH by revealing S                             │
 * │                                                                  │
 * │  5. Bob sees S on-chain, claims BTC                             │
 * │                                                                  │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract BitcoinHTLC is ReentrancyGuard {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct Swap {
        bytes32 swapId;
        address sender;
        address recipient;
        uint256 amount;
        bytes32 hashlock;
        uint256 timelock;
        bytes32 preimage;
        bool redeemed;
        bool refunded;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice All swaps by ID
    mapping(bytes32 => Swap) public swaps;

    /// @notice User's swap IDs (as sender)
    mapping(address => bytes32[]) public userSwapsAsSender;

    /// @notice User's swap IDs (as recipient)
    mapping(address => bytes32[]) public userSwapsAsRecipient;

    /// @notice Total swaps created
    uint256 public totalSwaps;

    /// @notice Total volume swapped
    uint256 public totalVolume;

    /// @notice Total redeemed
    uint256 public totalRedeemed;

    /// @notice Total refunded
    uint256 public totalRefunded;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SwapCreated(
        bytes32 indexed swapId,
        address indexed sender,
        address indexed recipient,
        uint256 amount,
        bytes32 hashlock,
        uint256 timelock
    );

    event SwapRedeemed(
        bytes32 indexed swapId,
        address indexed redeemer,
        bytes32 preimage
    );

    event SwapRefunded(
        bytes32 indexed swapId,
        address indexed sender
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidAmount();
    error InvalidHashlock();
    error InvalidTimelock();
    error InvalidRecipient();
    error SwapNotFound();
    error SwapAlreadyExists();
    error SwapAlreadyRedeemed();
    error SwapAlreadyRefunded();
    error InvalidPreimage();
    error TimelockNotExpired();
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                          CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new HTLC swap
     * @param recipient Address that can redeem with preimage
     * @param hashlock Hash of the secret preimage
     * @param timelock Duration in seconds until refund allowed
     * @return swapId The swap identifier
     */
    function createSwap(
        address recipient,
        bytes32 hashlock,
        uint256 timelock
    ) external payable nonReentrant returns (bytes32 swapId) {
        if (msg.value == 0) revert InvalidAmount();
        if (hashlock == bytes32(0)) revert InvalidHashlock();
        if (timelock == 0 || timelock > 30 days) revert InvalidTimelock();
        if (recipient == address(0)) revert InvalidRecipient();

        swapId = keccak256(
            abi.encodePacked(
                msg.sender,
                recipient,
                msg.value,
                hashlock,
                block.timestamp
            )
        );

        if (swaps[swapId].sender != address(0)) revert SwapAlreadyExists();

        swaps[swapId] = Swap({
            swapId: swapId,
            sender: msg.sender,
            recipient: recipient,
            amount: msg.value,
            hashlock: hashlock,
            timelock: block.timestamp + timelock,
            preimage: bytes32(0),
            redeemed: false,
            refunded: false
        });

        userSwapsAsSender[msg.sender].push(swapId);
        userSwapsAsRecipient[recipient].push(swapId);

        totalSwaps++;
        totalVolume += msg.value;

        emit SwapCreated(
            swapId,
            msg.sender,
            recipient,
            msg.value,
            hashlock,
            block.timestamp + timelock
        );
    }

    /**
     * @notice Redeem a swap by providing the preimage
     * @param swapId The swap to redeem
     * @param preimage The secret that hashes to the hashlock
     */
    function redeem(
        bytes32 swapId,
        bytes32 preimage
    ) external nonReentrant {
        Swap storage swap = swaps[swapId];

        if (swap.sender == address(0)) revert SwapNotFound();
        if (swap.redeemed) revert SwapAlreadyRedeemed();
        if (swap.refunded) revert SwapAlreadyRefunded();

        // Verify preimage
        if (keccak256(abi.encodePacked(preimage)) != swap.hashlock) {
            revert InvalidPreimage();
        }

        swap.redeemed = true;
        swap.preimage = preimage;

        totalRedeemed++;

        // Transfer to recipient
        (bool success, ) = swap.recipient.call{value: swap.amount}("");
        if (!success) revert TransferFailed();

        emit SwapRedeemed(swapId, swap.recipient, preimage);
    }

    /**
     * @notice Refund a timed-out swap
     * @param swapId The swap to refund
     */
    function refund(bytes32 swapId) external nonReentrant {
        Swap storage swap = swaps[swapId];

        if (swap.sender == address(0)) revert SwapNotFound();
        if (swap.redeemed) revert SwapAlreadyRedeemed();
        if (swap.refunded) revert SwapAlreadyRefunded();
        if (block.timestamp < swap.timelock) revert TimelockNotExpired();

        swap.refunded = true;

        totalRefunded++;

        // Return to sender
        (bool success, ) = swap.sender.call{value: swap.amount}("");
        if (!success) revert TransferFailed();

        emit SwapRefunded(swapId, swap.sender);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getSwap(bytes32 swapId) external view returns (Swap memory) {
        return swaps[swapId];
    }

    function getUserSwapsAsSender(address user) external view returns (bytes32[] memory) {
        return userSwapsAsSender[user];
    }

    function getUserSwapsAsRecipient(address user) external view returns (bytes32[] memory) {
        return userSwapsAsRecipient[user];
    }

    function isSwapRedeemable(bytes32 swapId) external view returns (bool) {
        Swap storage swap = swaps[swapId];
        return swap.sender != address(0) && !swap.redeemed && !swap.refunded;
    }

    function isSwapRefundable(bytes32 swapId) external view returns (bool) {
        Swap storage swap = swaps[swapId];
        return swap.sender != address(0) && 
               !swap.redeemed && 
               !swap.refunded && 
               block.timestamp >= swap.timelock;
    }

    function getStats() external view returns (
        uint256 swapsTotal,
        uint256 volumeTotal,
        uint256 redeemedCount,
        uint256 refundedCount
    ) {
        return (totalSwaps, totalVolume, totalRedeemed, totalRefunded);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Generate a hashlock from a preimage
     * @param preimage The secret preimage
     * @return hashlock The hash to use in swap creation
     */
    function computeHashlock(bytes32 preimage) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(preimage));
    }
}
