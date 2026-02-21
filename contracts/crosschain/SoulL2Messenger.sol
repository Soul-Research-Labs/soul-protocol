// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IProofVerifier} from "../interfaces/IProofVerifier.sol";
import {ISoulL2Messenger} from "../interfaces/ISoulL2Messenger.sol";

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
contract SoulL2Messenger is ReentrancyGuard, AccessControl, ISoulL2Messenger {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant FULFILLER_ROLE = keccak256("FULFILLER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @dev L1SLOAD precompile address (RIP-7728)
    address private constant L1SLOAD_PRECOMPILE =
        0x0000000000000000000000000000000000000101;

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Fulfillment proof
    struct FulfillmentProof {
        bytes32 messageId;
        bytes32 executionResultHash;
        bytes zkProof; // Proof of correct execution
        address fulfiller;
        uint64 fulfilledAt;
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

    /// @notice ZK decryption proof verifier (IProofVerifier)
    /// @dev When set to address(0), falls back to hash-based commitment check.
    address public decryptionVerifier;

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

    event CounterpartSet(uint256 indexed chainId, address messenger);

    event FulfillerRegistered(address indexed fulfiller, uint256 bond);

    event ProofHubUpdated(address indexed oldHub, address indexed newHub);

    event DecryptionVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

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
    error DecryptionVerificationFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Initialize the Soul L2 messenger
    /// @param _proofHub Address of the CrossChainProofHubV3 contract
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

        // SECURITY FIX M-7: Include nonce to prevent nullifier collisions
        bytes32 nullifier = keccak256(
            abi.encode(
                msg.sender,
                block.timestamp,
                block.chainid,
                request.destinationChainId,
                totalMessagesSent
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

        // SECURITY FIX C-3: Require caller funds the ETH being forwarded
        if (msg.value < value) revert InsufficientValue();

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
     * @dev If a real IProofVerifier is set via `setDecryptionVerifier`, the proof
     *   is forwarded to it for on-chain ZK verification. Otherwise falls back to
     *   a hash-based commitment check (suitable for testing only).
     */
    function _verifyDecryptionProof(
        bytes32 calldataCommitment,
        bytes calldata decryptedCalldata,
        bytes calldata zkProof
    ) internal view returns (bool) {
        // SECURITY FIX C-4: Always require a real ZK verifier — no hash bypass
        if (decryptionVerifier == address(0)) {
            revert DecryptionVerificationFailed();
        }

        // Pack public inputs: [calldataCommitment, keccak256(decryptedCalldata)]
        uint256[] memory publicInputs = new uint256[](2);
        publicInputs[0] = uint256(calldataCommitment);
        publicInputs[1] = uint256(keccak256(decryptedCalldata));

        try
            IProofVerifier(decryptionVerifier).verify(zkProof, publicInputs)
        returns (bool valid) {
            return valid;
        } catch {
            return false;
        }
    }

    /// @notice Set the ZK decryption proof verifier
    /// @param _verifier The IProofVerifier address (address(0) to disable)
    function setDecryptionVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        address oldVerifier = decryptionVerifier;
        decryptionVerifier = _verifier;
        emit DecryptionVerifierUpdated(oldVerifier, _verifier);
    }
}
