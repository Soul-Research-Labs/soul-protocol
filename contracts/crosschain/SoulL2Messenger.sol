// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title SoulL2Messenger
/// @author Soul Protocol
/// @notice Privacy-preserving cross-L2 messaging per RIP-7755
/// @dev Aligns with Ethereum's "The Surge" roadmap for cross-L2 interoperability
///
/// RIP-7755 INTEGRATION (per Vitalik's Possible Futures Part 2):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Soul Cross-L2 Privacy Messaging                       │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                          │
/// │   L2-A (Arbitrum)              L1 Relay              L2-B (Optimism)    │
/// │   ┌────────────┐           ┌───────────┐           ┌────────────┐       │
/// │   │ SoulL2     │           │ Proof     │           │ SoulL2     │       │
/// │   │ Messenger  │──────────▶│ Hub       │──────────▶│ Messenger  │       │
/// │   │            │           │           │           │            │       │
/// │   │ Encrypted  │           │ Verify +  │           │ Decrypt +  │       │
/// │   │ calldata   │           │ Relay     │           │ Execute    │       │
/// │   └────────────┘           └───────────┘           └────────────┘       │
/// │                                                                          │
/// │   Features:                                                              │
/// │   • Privacy-preserving calldata (encrypted)                             │
/// │   • ZK proof of valid call                                              │
/// │   • Gas payment via RIP-7755 fulfiller                                  │
/// │   • L1SLOAD for keystore wallet support                                 │
/// │                                                                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// References:
/// - RIP-7755: https://github.com/wilsoncusack/RIPs/blob/cross-l2-call-standard/RIPS/rip-7755.md
/// - L1SLOAD: https://ethereum-magicians.org/t/rip-7728-l1sload-precompile/20388
/// - https://vitalik.eth.limo/general/2024/10/17/futures2.html
contract SoulL2Messenger is ReentrancyGuard, AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant FULFILLER_ROLE = keccak256("FULFILLER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Message status
    enum MessageStatus {
        PENDING,
        FULFILLED,
        FAILED,
        EXPIRED
    }

    /// @notice Cross-L2 privacy message (RIP-7755 compatible)
    struct PrivacyMessage {
        bytes32 messageId;
        uint256 sourceChainId;
        uint256 destChainId;
        address sender;
        address target;
        bytes encryptedCalldata; // Privacy: encrypted call data
        bytes32 calldataCommitment; // Commitment for verification
        bytes32 nullifier; // Prevents replay
        uint256 value; // ETH to send
        uint256 gasLimit;
        uint64 deadline;
        MessageStatus status;
    }

    /// @notice Fulfillment proof
    struct FulfillmentProof {
        bytes32 messageId;
        bytes32 executionResultHash;
        bytes zkProof; // Proof of correct execution
        address fulfiller;
        uint64 fulfilledAt;
    }

    /// @notice RIP-7755 Call structure
    struct Call {
        address to;
        bytes data;
        uint256 value;
    }

    /// @notice RIP-7755 Request structure
    struct CrossL2Request {
        Call[] calls;
        uint256 sourceChainId;
        uint256 destinationChainId;
        address inbox;
        uint256 l2GasLimit;
        address l2GasToken;
        uint256 maxL2GasPrice;
        uint256 maxPriorityFeePerGas;
        uint256 rewardAmount;
        address rewardToken;
        uint256 deadline;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Messages by ID
    mapping(bytes32 => PrivacyMessage) public messages;

    /// @notice Fulfillment proofs by message ID
    mapping(bytes32 => FulfillmentProof) public fulfillments;

    /// @notice Used nullifiers
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Registered fulfillers
    mapping(address => uint256) public fulfillerBonds;

    /// @notice Counterpart messengers on other chains
    mapping(uint256 => address) public counterpartMessengers;

    /// @notice L1 proof hub address
    address public proofHub;

    /// @notice Minimum fulfiller bond
    uint256 public minFulfillerBond = 0.05 ether;

    /// @notice Default gas limit
    uint256 public defaultGasLimit = 500000;

    /// @notice Total messages sent
    uint256 public totalMessagesSent;

    /// @notice Total messages fulfilled
    uint256 public totalMessagesFulfilled;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrivacyMessageSent(
        bytes32 indexed messageId,
        uint256 indexed destChainId,
        address indexed sender,
        address target
    );

    event PrivacyMessageFulfilled(
        bytes32 indexed messageId,
        address indexed fulfiller,
        bytes32 executionResultHash
    );

    event PrivacyMessageFailed(bytes32 indexed messageId, string reason);

    event CounterpartSet(uint256 indexed chainId, address messenger);

    event FulfillerRegistered(address indexed fulfiller, uint256 bond);

    event ProofHubUpdated(address indexed oldHub, address indexed newHub);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error MessageNotFound();
    error MessageAlreadyExists();
    error NullifierAlreadyUsed();
    error MessageExpired();
    error InvalidProof();
    error InsufficientBond();
    error InvalidDestinationChain();
    error InvalidCounterpart();
    error ExecutionFailed();
    error NotFulfiller();
    error InsufficientGas();
    error InsufficientValue();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _proofHub) {
        if (_proofHub == address(0)) revert ZeroAddress();
        proofHub = _proofHub;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                            MESSAGE SENDING
    //////////////////////////////////////////////////////////////*/

    /// @notice Send a privacy-preserving cross-L2 call
    /// @param destChainId Destination chain
    /// @param target Target contract on destination
    /// @param encryptedCalldata Encrypted call data
    /// @param calldataCommitment Commitment for verification
    /// @param nullifier Unique nullifier
    /// @param gasLimit Gas limit for execution
    /// @return messageId Unique message identifier
    function sendPrivacyMessage(
        uint256 destChainId,
        address target,
        bytes calldata encryptedCalldata,
        bytes32 calldataCommitment,
        bytes32 nullifier,
        uint256 gasLimit
    ) external payable nonReentrant returns (bytes32 messageId) {
        return
            _sendPrivacyMessageInternal(
                destChainId,
                target,
                encryptedCalldata,
                calldataCommitment,
                nullifier,
                gasLimit
            );
    }

    /// @notice Internal implementation of privacy message sending
    function _sendPrivacyMessageInternal(
        uint256 destChainId,
        address target,
        bytes memory encryptedCalldata,
        bytes32 calldataCommitment,
        bytes32 nullifier,
        uint256 gasLimit
    ) internal returns (bytes32 messageId) {
        if (counterpartMessengers[destChainId] == address(0)) {
            revert InvalidDestinationChain();
        }
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (gasLimit == 0) gasLimit = defaultGasLimit;

        messageId = keccak256(
            abi.encode(
                block.chainid,
                destChainId,
                msg.sender,
                target,
                calldataCommitment,
                nullifier,
                block.timestamp
            )
        );

        if (messages[messageId].calldataCommitment != bytes32(0)) {
            revert MessageAlreadyExists();
        }

        messages[messageId] = PrivacyMessage({
            messageId: messageId,
            sourceChainId: block.chainid,
            destChainId: destChainId,
            sender: msg.sender,
            target: target,
            encryptedCalldata: encryptedCalldata,
            calldataCommitment: calldataCommitment,
            nullifier: nullifier,
            value: msg.value,
            gasLimit: gasLimit,
            deadline: uint64(block.timestamp + 1 hours),
            status: MessageStatus.PENDING
        });

        usedNullifiers[nullifier] = true;
        totalMessagesSent++;

        emit PrivacyMessageSent(messageId, destChainId, msg.sender, target);
    }

    /// @notice RIP-7755 compatible: Request cross-L2 call execution
    /// @param request The cross-L2 request
    /// @return requestId The request identifier
    function requestL2Call(
        CrossL2Request calldata request
    ) external payable nonReentrant returns (bytes32 requestId) {
        if (request.calls.length == 0) revert ExecutionFailed();
        if (msg.value < request.rewardAmount) revert InsufficientValue();

        // Encode first call as privacy message
        Call memory firstCall = request.calls[0];

        bytes32 nullifier = keccak256(
            abi.encode(
                msg.sender,
                block.timestamp,
                block.chainid,
                request.destinationChainId
            )
        );

        requestId = _sendPrivacyMessageInternal(
            request.destinationChainId,
            firstCall.to,
            firstCall.data,
            keccak256(firstCall.data),
            nullifier,
            request.l2GasLimit
        );
    }

    /*//////////////////////////////////////////////////////////////
                           MESSAGE FULFILLMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Fulfill a privacy message on destination chain
    /// @param messageId The message to fulfill
    /// @param decryptedCalldata The decrypted call data
    /// @param zkProof Proof that decryption is correct
    function fulfillMessage(
        bytes32 messageId,
        bytes calldata decryptedCalldata,
        bytes calldata zkProof
    ) external nonReentrant {
        if (fulfillerBonds[msg.sender] < minFulfillerBond) {
            revert InsufficientBond();
        }

        PrivacyMessage storage message = messages[messageId];
        if (message.calldataCommitment == bytes32(0)) {
            revert MessageNotFound();
        }
        if (message.status != MessageStatus.PENDING) {
            revert MessageNotFound();
        }
        if (block.timestamp > message.deadline) {
            revert MessageExpired();
        }

        // Verify decryption proof
        if (
            !_verifyDecryptionProof(
                message.calldataCommitment,
                decryptedCalldata,
                zkProof
            )
        ) {
            revert InvalidProof();
        }

        // Mark as fulfilled before external call to prevent reentrancy
        message.status = MessageStatus.FULFILLED;

        // Execute the call
        (bool success, bytes memory result) = message.target.call{
            value: message.value,
            gas: message.gasLimit
        }(decryptedCalldata);

        bytes32 resultHash = keccak256(result);

        if (!success) revert ExecutionFailed();

        fulfillments[messageId] = FulfillmentProof({
            messageId: messageId,
            executionResultHash: resultHash,
            zkProof: zkProof,
            fulfiller: msg.sender,
            fulfilledAt: uint64(block.timestamp)
        });

        totalMessagesFulfilled++;

        emit PrivacyMessageFulfilled(messageId, msg.sender, resultHash);
    }

    /// @notice Receive message from counterpart messenger (via L1)
    /// @param sourceChainId Origin chain
    /// @param messageId Original message ID
    /// @param target Target contract
    /// @param decryptedCalldata Decrypted call data
    /// @param value ETH value
    function receiveMessage(
        uint256 sourceChainId,
        bytes32 messageId,
        address target,
        bytes calldata decryptedCalldata,
        uint256 value
    ) external payable nonReentrant {
        // Verify sender is proof hub or counterpart
        if (
            msg.sender != proofHub &&
            msg.sender != counterpartMessengers[sourceChainId]
        ) {
            revert InvalidCounterpart();
        }

        // Execute
        (bool success, ) = target.call{value: value}(decryptedCalldata);

        if (!success) {
            emit PrivacyMessageFailed(messageId, "Execution failed");
        } else {
            emit PrivacyMessageFulfilled(
                messageId,
                msg.sender,
                keccak256(decryptedCalldata)
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                           L1SLOAD SUPPORT
    //////////////////////////////////////////////////////////////*/

    /// @notice Read L1 state for keystore wallet support
    /// @dev Uses L1SLOAD precompile when available (RIP-7728)
    /// @param l1Contract L1 contract address
    /// @param slot Storage slot to read
    /// @return value The storage value
    function readL1State(
        address l1Contract,
        bytes32 slot
    ) external view returns (bytes32 value) {
        // L1SLOAD precompile address (when available)
        address L1SLOAD_PRECOMPILE = 0x0000000000000000000000000000000000000101;

        // Check if precompile exists
        uint256 size;
        assembly {
            size := extcodesize(L1SLOAD_PRECOMPILE)
        }

        if (size > 0) {
            // Call L1SLOAD precompile
            (bool success, bytes memory result) = L1SLOAD_PRECOMPILE.staticcall(
                abi.encode(l1Contract, slot)
            );

            if (success && result.length == 32) {
                value = abi.decode(result, (bytes32));
            }
        }

        // Fallback: would need oracle or relay
        // For now, return zero if precompile not available
    }

    /// @notice Verify keystore wallet key from L1
    /// @param wallet The wallet address
    /// @param expectedKeyHash Expected key hash
    /// @return valid Whether the key matches
    function verifyKeystoreWallet(
        address wallet,
        bytes32 expectedKeyHash
    ) external view returns (bool valid) {
        // L1 keystore slot (simplified)
        bytes32 slot = keccak256(abi.encode(wallet, uint256(0)));
        bytes32 l1KeyHash = this.readL1State(wallet, slot);

        return l1KeyHash == expectedKeyHash;
    }

    /*//////////////////////////////////////////////////////////////
                          FULFILLER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register as a fulfiller
    function registerFulfiller() external payable {
        if (msg.value < minFulfillerBond) revert InsufficientBond();
        fulfillerBonds[msg.sender] += msg.value;
        _grantRole(FULFILLER_ROLE, msg.sender);

        emit FulfillerRegistered(msg.sender, fulfillerBonds[msg.sender]);
    }

    /// @notice Withdraw fulfiller bond
    /// @param amount The amount of bond to withdraw (in wei)
    function withdrawBond(uint256 amount) external nonReentrant {
        if (fulfillerBonds[msg.sender] < amount) revert InsufficientBond();
        fulfillerBonds[msg.sender] -= amount;

        if (fulfillerBonds[msg.sender] < minFulfillerBond) {
            _revokeRole(FULFILLER_ROLE, msg.sender);
        }

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        if (!success) revert ExecutionFailed();
    }

    /*//////////////////////////////////////////////////////////////
                              ADMIN
    //////////////////////////////////////////////////////////////*/

    /// @notice Set counterpart messenger for a chain
    /// @param chainId The chain ID of the counterpart network
    /// @param messenger The address of the messenger contract on the counterpart chain
    function setCounterpart(
        uint256 chainId,
        address messenger
    ) external onlyRole(OPERATOR_ROLE) {
        counterpartMessengers[chainId] = messenger;
        emit CounterpartSet(chainId, messenger);
    }

    /// @notice Set proof hub address
    /// @param _proofHub The address of the CrossChainProofHubV3 contract
    function setProofHub(address _proofHub) external onlyRole(OPERATOR_ROLE) {
        if (_proofHub == address(0)) revert ZeroAddress();
        address oldHub = proofHub;
        proofHub = _proofHub;
        emit ProofHubUpdated(oldHub, _proofHub);
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNALS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify decryption proof
     * @custom:security PLACEHOLDER — This is NOT real ZK verification.
     *   It only checks that the proof bytes contain expected hashes.
     *   Replace with a real verifier contract call before production.
     */
    function _verifyDecryptionProof(
        bytes32 calldataCommitment,
        bytes calldata decryptedCalldata,
        bytes calldata zkProof
    ) internal pure returns (bool) {
        // If the commitment matches the hash of decrypted data, no ZK proof needed
        if (keccak256(decryptedCalldata) == calldataCommitment) {
            return true;
        }

        // For encrypted data, verify the ZK proof
        // The proof must demonstrate knowledge of the decryption key
        // and that decryptedCalldata is the correct plaintext
        if (zkProof.length < 128) revert("ZK proof too short");

        // Verify proof structure: first 32 bytes must commit to the calldata hash
        bytes32 proofCommitment = bytes32(zkProof[0:32]);
        if (proofCommitment != keccak256(decryptedCalldata)) return false;

        // Verify proof binds to the original commitment
        bytes32 proofBinding = bytes32(zkProof[32:64]);
        if (proofBinding != calldataCommitment) return false;

        return true;
    }
}
