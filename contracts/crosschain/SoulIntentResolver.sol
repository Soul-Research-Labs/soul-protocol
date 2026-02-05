// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title SoulIntentResolver
/// @author Soul Protocol
/// @notice Privacy-preserving cross-chain intent resolution per ERC-7683
/// @dev Aligns with Ethereum's "The Surge" roadmap for cross-L2 interoperability
///
/// ERC-7683 INTEGRATION (per Vitalik's Possible Futures Part 2):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Soul Private Intent Flow                              │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                          │
/// │   User creates                Filler resolves              Settlement   │
/// │   private intent              cross-chain                  + proof      │
/// │   ────────────────────────────────────────────────────────────────────   │
/// │        │                           │                              │      │
/// │        ▼                           ▼                              ▼      │
/// │   ┌─────────────┐           ┌───────────────┐           ┌───────────┐   │
/// │   │ Encrypted   │           │ Filler decrypts│          │ ZK proof  │   │
/// │   │ Intent +    │──────────▶│ fills on dest  │─────────▶│ settlement│   │
/// │   │ Commitment  │           │ chain          │          │ on source │   │
/// │   └─────────────┘           └───────────────┘           └───────────┘   │
/// │         │                                                      │         │
/// │         └──────────────────────────────────────────────────────┘         │
/// │                      Nullifier prevents replay                           │
/// │                                                                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// References:
/// - https://eips.ethereum.org/EIPS/eip-7683
/// - https://vitalik.eth.limo/general/2024/10/17/futures2.html
contract SoulIntentResolver is ReentrancyGuard, AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant FILLER_ROLE = keccak256("FILLER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Intent status
    enum IntentStatus {
        PENDING, // Awaiting fill
        FILLED, // Filled on destination
        SETTLED, // Settled with proof
        CANCELLED, // Cancelled by user
        EXPIRED // Timed out
    }

    /// @notice Private intent structure (ERC-7683 compatible)
    struct PrivateIntent {
        bytes32 intentId; // Unique intent identifier
        bytes32 intentHash; // Hash of intent parameters
        bytes32 nullifier; // Prevents double-execution
        bytes32 commitment; // Soul commitment for privacy
        bytes encryptedPayload; // Encrypted swap/transfer details
        uint256[] destinationChains; // Allowed destination chains
        address initiator; // Intent creator
        uint64 deadline; // Expiration timestamp
        uint256 minOutput; // Minimum output amount (encrypted for privacy)
        IntentStatus status;
    }

    /// @notice Intent fill proof
    struct FillProof {
        bytes32 intentId;
        uint256 filledChainId;
        bytes32 fillTxHash;
        bytes32 outputCommitment; // Commitment to actual output
        bytes zkProof; // ZK proof of correct fill
        address filler;
        uint64 filledAt;
    }

    /// @notice Cross-chain order (ERC-7683 CrossChainOrder)
    struct CrossChainOrder {
        address settlementContract;
        address swapper;
        uint256 nonce;
        uint32 originChainId;
        uint32 initiateDeadline;
        uint32 fillDeadline;
        bytes orderData; // Encoded PrivateIntent
    }

    /// @notice Resolved cross-chain order
    struct ResolvedCrossChainOrder {
        address settlementContract;
        address swapper;
        uint256 nonce;
        uint32 originChainId;
        uint32 initiateDeadline;
        uint32 fillDeadline;
        bytes32[] swapperInputs; // Commitment hashes
        bytes32[] swapperOutputs; // Expected output commitments
        bytes32[] fillerOutputs; // What filler provides
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Intents by ID
    mapping(bytes32 => PrivateIntent) public intents;

    /// @notice Fill proofs by intent ID
    mapping(bytes32 => FillProof) public fillProofs;

    /// @notice Used nullifiers (prevents replay)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Registered fillers and their bonds
    mapping(address => uint256) public fillerBonds;

    /// @notice Minimum filler bond
    uint256 public minFillerBond = 0.1 ether;

    /// @notice Default intent deadline (1 hour)
    uint64 public defaultDeadline = 3600;

    /// @notice Verifier for fill proofs
    address public fillProofVerifier;

    /// @notice Total intents created
    uint256 public totalIntents;

    /// @notice Total intents filled
    uint256 public totalFilled;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PrivateIntentCreated(
        bytes32 indexed intentId,
        address indexed initiator,
        uint256[] destinationChains,
        uint64 deadline
    );

    event IntentFilled(
        bytes32 indexed intentId,
        address indexed filler,
        uint256 indexed chainId,
        bytes32 fillTxHash
    );

    event IntentSettled(
        bytes32 indexed intentId,
        bytes32 indexed nullifier,
        address indexed filler
    );

    event IntentCancelled(bytes32 indexed intentId, address indexed initiator);

    event IntentExpired(bytes32 indexed intentId);

    event FillerRegistered(address indexed filler, uint256 bond);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error IntentNotFound();
    error IntentAlreadyExists();
    error NullifierAlreadyUsed();
    error IntentExpiredError();
    error InvalidFillProof();
    error InsufficientBond();
    error UnauthorizedFiller();
    error InvalidDestinationChain();
    error NotIntentInitiator();
    error IntentAlreadyFilled();
    error SettlementFailed();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                            INTENT CREATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a private cross-chain intent
    /// @param intentHash Hash of the intent parameters
    /// @param nullifier Unique nullifier for this intent
    /// @param commitment Soul commitment for privacy
    /// @param encryptedPayload Encrypted intent details
    /// @param destinationChains Allowed destination chains
    /// @param deadline Intent expiration
    /// @return intentId Unique intent identifier
    function submitPrivateIntent(
        bytes32 intentHash,
        bytes32 nullifier,
        bytes32 commitment,
        bytes calldata encryptedPayload,
        uint256[] calldata destinationChains,
        uint64 deadline
    ) external nonReentrant returns (bytes32 intentId) {
        return
            _submitPrivateIntentInternal(
                intentHash,
                nullifier,
                commitment,
                encryptedPayload,
                destinationChains,
                deadline
            );
    }

    /// @notice Internal implementation of intent submission
    function _submitPrivateIntentInternal(
        bytes32 intentHash,
        bytes32 nullifier,
        bytes32 commitment,
        bytes memory encryptedPayload,
        uint256[] memory destinationChains,
        uint64 deadline
    ) internal returns (bytes32 intentId) {
        if (usedNullifiers[nullifier]) revert NullifierAlreadyUsed();
        if (destinationChains.length == 0) revert InvalidDestinationChain();

        if (deadline == 0) {
            deadline = uint64(block.timestamp) + defaultDeadline;
        }

        if (deadline <= block.timestamp) revert IntentExpiredError();

        intentId = keccak256(
            abi.encode(
                intentHash,
                nullifier,
                msg.sender,
                block.timestamp,
                block.chainid
            )
        );

        if (intents[intentId].intentHash != bytes32(0)) {
            revert IntentAlreadyExists();
        }

        intents[intentId] = PrivateIntent({
            intentId: intentId,
            intentHash: intentHash,
            nullifier: nullifier,
            commitment: commitment,
            encryptedPayload: encryptedPayload,
            destinationChains: destinationChains,
            initiator: msg.sender,
            deadline: deadline,
            minOutput: 0, // Encoded in encrypted payload
            status: IntentStatus.PENDING
        });

        totalIntents++;

        emit PrivateIntentCreated(
            intentId,
            msg.sender,
            destinationChains,
            deadline
        );
    }

    /// @notice ERC-7683 compatible: Open a cross-chain order
    /// @param order The cross-chain order to open
    /// @return resolvedOrder The resolved order details
    function open(
        CrossChainOrder calldata order
    ) external returns (ResolvedCrossChainOrder memory resolvedOrder) {
        // Decode private intent from order data
        (
            bytes32 intentHash,
            bytes32 nullifier,
            bytes32 commitment,
            bytes memory encryptedPayload,
            uint256[] memory destinationChains
        ) = abi.decode(
                order.orderData,
                (bytes32, bytes32, bytes32, bytes, uint256[])
            );

        bytes32 intentId = _submitPrivateIntentInternal(
            intentHash,
            nullifier,
            commitment,
            encryptedPayload,
            destinationChains,
            uint64(order.fillDeadline)
        );

        // Return resolved order
        bytes32[] memory swapperInputs = new bytes32[](1);
        swapperInputs[0] = commitment;

        resolvedOrder = ResolvedCrossChainOrder({
            settlementContract: order.settlementContract,
            swapper: order.swapper,
            nonce: order.nonce,
            originChainId: order.originChainId,
            initiateDeadline: order.initiateDeadline,
            fillDeadline: order.fillDeadline,
            swapperInputs: swapperInputs,
            swapperOutputs: new bytes32[](0),
            fillerOutputs: new bytes32[](0)
        });
    }

    /*//////////////////////////////////////////////////////////////
                             INTENT FILLING
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit proof that intent was filled on destination chain
    /// @param intentId The intent that was filled
    /// @param filledChainId Chain where it was filled
    /// @param fillTxHash Transaction hash of the fill
    /// @param outputCommitment Commitment to the output
    /// @param zkProof ZK proof of correct fill
    function submitFillProof(
        bytes32 intentId,
        uint256 filledChainId,
        bytes32 fillTxHash,
        bytes32 outputCommitment,
        bytes calldata zkProof
    ) external nonReentrant {
        if (fillerBonds[msg.sender] < minFillerBond) revert InsufficientBond();

        PrivateIntent storage intent = intents[intentId];
        if (intent.intentHash == bytes32(0)) revert IntentNotFound();
        if (intent.status != IntentStatus.PENDING) revert IntentAlreadyFilled();
        if (block.timestamp > intent.deadline) revert IntentExpiredError();

        // Verify destination chain is allowed
        bool validChain = false;
        for (uint i = 0; i < intent.destinationChains.length; i++) {
            if (intent.destinationChains[i] == filledChainId) {
                validChain = true;
                break;
            }
        }
        if (!validChain) revert InvalidDestinationChain();

        // Verify ZK proof (in production, call verifier)
        if (!_verifyFillProof(intentId, outputCommitment, zkProof)) {
            revert InvalidFillProof();
        }

        fillProofs[intentId] = FillProof({
            intentId: intentId,
            filledChainId: filledChainId,
            fillTxHash: fillTxHash,
            outputCommitment: outputCommitment,
            zkProof: zkProof,
            filler: msg.sender,
            filledAt: uint64(block.timestamp)
        });

        intent.status = IntentStatus.FILLED;
        totalFilled++;

        emit IntentFilled(intentId, msg.sender, filledChainId, fillTxHash);
    }

    /// @notice Settle an intent after fill is verified
    /// @param intentId The intent to settle
    function settle(bytes32 intentId) external nonReentrant {
        PrivateIntent storage intent = intents[intentId];
        FillProof storage proof = fillProofs[intentId];

        if (intent.intentHash == bytes32(0)) revert IntentNotFound();
        if (intent.status != IntentStatus.FILLED) revert IntentAlreadyFilled();

        // Mark nullifier as used
        usedNullifiers[intent.nullifier] = true;

        intent.status = IntentStatus.SETTLED;

        emit IntentSettled(intentId, intent.nullifier, proof.filler);
    }

    /// @notice Cancel a pending intent
    /// @param intentId The intent to cancel
    function cancelIntent(bytes32 intentId) external nonReentrant {
        PrivateIntent storage intent = intents[intentId];

        if (intent.intentHash == bytes32(0)) revert IntentNotFound();
        if (msg.sender != intent.initiator) revert NotIntentInitiator();
        if (intent.status != IntentStatus.PENDING) revert IntentAlreadyFilled();

        intent.status = IntentStatus.CANCELLED;

        emit IntentCancelled(intentId, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           FILLER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register as a filler with bond
    function registerFiller() external payable {
        if (msg.value < minFillerBond) revert InsufficientBond();
        fillerBonds[msg.sender] += msg.value;
        _grantRole(FILLER_ROLE, msg.sender);

        emit FillerRegistered(msg.sender, fillerBonds[msg.sender]);
    }

    /// @notice Withdraw filler bond
    function withdrawBond(uint256 amount) external nonReentrant {
        if (fillerBonds[msg.sender] < amount) revert InsufficientBond();
        fillerBonds[msg.sender] -= amount;

        if (fillerBonds[msg.sender] < minFillerBond) {
            _revokeRole(FILLER_ROLE, msg.sender);
        }

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdraw failed");
    }

    /*//////////////////////////////////////////////////////////////
                               HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get intent details
    function getIntent(
        bytes32 intentId
    ) external view returns (PrivateIntent memory) {
        return intents[intentId];
    }

    /// @notice Get fill proof for intent
    function getFillProof(
        bytes32 intentId
    ) external view returns (FillProof memory) {
        return fillProofs[intentId];
    }

    /// @notice Check if nullifier is used
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _verifyFillProof(
        bytes32 intentId,
        bytes32 outputCommitment,
        bytes calldata zkProof
    ) internal view returns (bool) {
        // In production: call fillProofVerifier
        // For now: verify proof has minimum length
        if (zkProof.length < 128) return false;

        // Verify proof matches intent
        // (Would verify using Noir/Groth16 verifier)
        return true;
    }

    /// @notice Set the fill proof verifier
    function setFillProofVerifier(
        address verifier
    ) external onlyRole(OPERATOR_ROLE) {
        fillProofVerifier = verifier;
    }
}
