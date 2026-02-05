// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title SoulPreconfirmationHandler
/// @author Soul Protocol
/// @notice Handles L1 proposer preconfirmations for privacy operations
/// @dev Aligns with Ethereum's "The Merge" roadmap for SSF and faster confirmations
///
/// PRECONFIRMATION ARCHITECTURE (per Vitalik's Possible Futures Part 1):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Soul Preconfirmation Flow                             │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                          │
/// │   User submits                 Proposer accepts               Included   │
/// │   privacy tx                   with preconf                   in block   │
/// │   ────────────────────────────────────────────────────────────────────   │
/// │        │                           │                              │      │
/// │        ▼                           ▼                              ▼      │
/// │   ┌─────────┐    0.5s       ┌───────────┐    12s          ┌─────────┐   │
/// │   │ Submit  │─────────────▶│  Preconf  │───────────────▶│ Final   │   │
/// │   │ to Pool │              │  Received │                 │ in Block│   │
/// │   └─────────┘              └───────────┘                 └─────────┘   │
/// │                                                                          │
/// │   With SSF: Finality at slot end (12s total vs 15min today)             │
/// │                                                                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// References:
/// - https://vitalik.eth.limo/general/2024/10/14/futures1.html
/// - https://ethresear.ch/t/based-preconfirmations/17353
contract SoulPreconfirmationHandler is ReentrancyGuard, AccessControl {
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Preconfirmation status
    enum PreconfStatus {
        PENDING, // Awaiting proposer acceptance
        PRECONFIRMED, // Proposer has committed
        INCLUDED, // Included in block
        EXPIRED, // Timed out
        SLASHED // Proposer violated commitment
    }

    /// @notice Preconfirmation request for a privacy operation
    struct PreconfRequest {
        bytes32 txHash; // Hash of the privacy transaction
        bytes32 commitmentHash; // Soul commitment being used
        bytes32 nullifier; // Nullifier (for double-spend protection)
        address submitter; // Who submitted the request
        uint64 requestedSlot; // Slot requested for inclusion
        uint64 submittedAt; // Timestamp of submission
        uint256 tip; // Priority fee offered
        PreconfStatus status;
    }

    /// @notice Proposer preconfirmation commitment
    struct ProposerCommitment {
        bytes32 preconfId; // ID of the preconfirmation
        address proposer; // Proposer address
        uint64 slot; // Committed slot
        bytes signature; // Proposer's signature
        uint64 committedAt; // When commitment was made
        bool honored; // Was the commitment honored?
    }

    /// @notice Orbit SSF committee attestation
    struct OrbitAttestation {
        bytes32 stateRoot; // State root being attested
        uint256[] committee; // Committee member indices
        bytes aggregatedSig; // Aggregated BLS signature
        uint64 slot; // Slot number
        uint256 participationBits; // Bitmap of who signed
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Preconfirmation requests by ID
    mapping(bytes32 => PreconfRequest) public preconfRequests;

    /// @notice Proposer commitments by preconf ID
    mapping(bytes32 => ProposerCommitment) public commitments;

    /// @notice Pending preconf IDs by slot
    mapping(uint64 => bytes32[]) public slotPreconfs;

    /// @notice Registered proposers and their stakes
    mapping(address => uint256) public proposerStakes;

    /// @notice Minimum stake required to be a proposer
    uint256 public minProposerStake = 1 ether;

    /// @notice Preconfirmation validity period (slots)
    uint64 public preconfValidityPeriod = 32;

    /// @notice Slot duration in seconds (12s for Ethereum)
    uint64 public constant SLOT_DURATION = 12;

    /// @notice SSF finality enabled
    bool public ssfEnabled = false;

    /// @notice Challenge period with SSF (much shorter than 15min)
    uint64 public ssfChallengePeriod = 12; // 1 slot

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event PreconfRequested(
        bytes32 indexed preconfId,
        bytes32 indexed txHash,
        address indexed submitter,
        uint64 requestedSlot,
        uint256 tip
    );

    event PreconfAccepted(
        bytes32 indexed preconfId,
        address indexed proposer,
        uint64 slot
    );

    event PreconfIncluded(
        bytes32 indexed preconfId,
        bytes32 indexed txHash,
        uint64 slot
    );

    event PreconfExpired(bytes32 indexed preconfId);

    event ProposerSlashed(
        address indexed proposer,
        bytes32 indexed preconfId,
        uint256 slashAmount
    );

    event OrbitAttestationVerified(
        bytes32 indexed stateRoot,
        uint64 slot,
        uint256 participantCount
    );

    event SSFEnabled(bool enabled, uint64 challengePeriod);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidProposer();
    error InsufficientStake();
    error PreconfNotFound();
    error PreconfAlreadyExists();
    error InvalidSlot();
    error InvalidSignature();
    error PreconfExpiredError();
    error AlreadyPreconfirmed();
    error UnauthorizedCaller();
    error InvalidOrbitAttestation();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         PRECONFIRMATION FLOW
    //////////////////////////////////////////////////////////////*/

    /// @notice Request a preconfirmation for a privacy transaction
    /// @param txHash Hash of the privacy transaction
    /// @param commitmentHash Soul commitment being used
    /// @param nullifier Nullifier for double-spend protection
    /// @param requestedSlot Desired inclusion slot
    /// @return preconfId Unique preconfirmation ID
    function requestPreconfirmation(
        bytes32 txHash,
        bytes32 commitmentHash,
        bytes32 nullifier,
        uint64 requestedSlot
    ) external payable nonReentrant returns (bytes32 preconfId) {
        uint64 currentSlot = _getCurrentSlot();

        if (requestedSlot <= currentSlot) revert InvalidSlot();
        if (requestedSlot > currentSlot + preconfValidityPeriod)
            revert InvalidSlot();

        preconfId = keccak256(
            abi.encode(
                txHash,
                commitmentHash,
                nullifier,
                msg.sender,
                requestedSlot,
                block.timestamp
            )
        );

        if (preconfRequests[preconfId].txHash != bytes32(0)) {
            revert PreconfAlreadyExists();
        }

        preconfRequests[preconfId] = PreconfRequest({
            txHash: txHash,
            commitmentHash: commitmentHash,
            nullifier: nullifier,
            submitter: msg.sender,
            requestedSlot: requestedSlot,
            submittedAt: uint64(block.timestamp),
            tip: msg.value,
            status: PreconfStatus.PENDING
        });

        slotPreconfs[requestedSlot].push(preconfId);

        emit PreconfRequested(
            preconfId,
            txHash,
            msg.sender,
            requestedSlot,
            msg.value
        );
    }

    /// @notice Proposer accepts a preconfirmation request
    /// @param preconfId The preconfirmation to accept
    /// @param slot The slot for inclusion
    /// @param signature Proposer's signature committing to include
    function acceptPreconfirmation(
        bytes32 preconfId,
        uint64 slot,
        bytes calldata signature
    ) external nonReentrant {
        if (proposerStakes[msg.sender] < minProposerStake) {
            revert InsufficientStake();
        }

        PreconfRequest storage request = preconfRequests[preconfId];
        if (request.txHash == bytes32(0)) revert PreconfNotFound();
        if (request.status != PreconfStatus.PENDING)
            revert AlreadyPreconfirmed();

        // Verify signature
        bytes32 commitmentMessage = keccak256(
            abi.encode(preconfId, slot, msg.sender)
        );

        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(
            commitmentMessage
        );
        if (ECDSA.recover(ethSignedHash, signature) != msg.sender) {
            revert InvalidSignature();
        }

        request.status = PreconfStatus.PRECONFIRMED;

        commitments[preconfId] = ProposerCommitment({
            preconfId: preconfId,
            proposer: msg.sender,
            slot: slot,
            signature: signature,
            committedAt: uint64(block.timestamp),
            honored: false
        });

        emit PreconfAccepted(preconfId, msg.sender, slot);
    }

    /// @notice Confirm that a preconfirmed transaction was included
    /// @param preconfId The preconfirmation ID
    /// @param inclusionProof Proof of inclusion in the block
    function confirmInclusion(
        bytes32 preconfId,
        bytes calldata inclusionProof
    ) external nonReentrant {
        PreconfRequest storage request = preconfRequests[preconfId];
        if (request.txHash == bytes32(0)) revert PreconfNotFound();

        ProposerCommitment storage commitment = commitments[preconfId];

        // Verify inclusion (simplified - in production would verify merkle proof)
        // For now, trusted operator confirms
        if (!hasRole(OPERATOR_ROLE, msg.sender)) revert UnauthorizedCaller();

        request.status = PreconfStatus.INCLUDED;
        commitment.honored = true;

        // Pay tip to proposer
        if (request.tip > 0) {
            (bool success, ) = payable(commitment.proposer).call{
                value: request.tip
            }("");
            require(success, "Transfer failed");
        }

        emit PreconfIncluded(preconfId, request.txHash, commitment.slot);
    }

    /// @notice Slash a proposer who didn't honor their commitment
    /// @param preconfId The violated preconfirmation
    function slashProposer(bytes32 preconfId) external nonReentrant {
        ProposerCommitment storage commitment = commitments[preconfId];
        PreconfRequest storage request = preconfRequests[preconfId];

        if (commitment.proposer == address(0)) revert PreconfNotFound();
        if (commitment.honored) revert UnauthorizedCaller();

        // Check if slot has passed
        uint64 currentSlot = _getCurrentSlot();
        if (currentSlot <= commitment.slot + 1) revert InvalidSlot();

        // Slash
        uint256 slashAmount = proposerStakes[commitment.proposer] / 10; // 10% slash
        proposerStakes[commitment.proposer] -= slashAmount;

        // Refund tip to submitter
        if (request.tip > 0) {
            (bool tipSuccess, ) = payable(request.submitter).call{
                value: request.tip
            }("");
            require(tipSuccess, "Tip refund failed");
        }

        // Reward slasher
        (bool slashSuccess, ) = payable(msg.sender).call{
            value: slashAmount / 2
        }("");
        require(slashSuccess, "Slasher reward failed");

        request.status = PreconfStatus.SLASHED;

        emit ProposerSlashed(commitment.proposer, preconfId, slashAmount);
    }

    /*//////////////////////////////////////////////////////////////
                           ORBIT SSF SUPPORT
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify an Orbit SSF committee attestation
    /// @dev Implements lighter finality checks per "The Merge" roadmap
    /// @param attestation The Orbit committee attestation
    /// @return valid Whether the attestation is valid
    function verifyOrbitCommittee(
        OrbitAttestation calldata attestation
    ) external view returns (bool valid) {
        // Verify participation threshold (e.g., 2/3 of committee)
        uint256 participantCount = _countBits(attestation.participationBits);
        uint256 committeeSize = attestation.committee.length;

        if (participantCount * 3 < committeeSize * 2) {
            return false;
        }

        // In production: verify BLS aggregate signature
        // For now, simplified check
        if (attestation.aggregatedSig.length < 96) {
            return false;
        }

        return true;
    }

    /// @notice Process an Orbit attestation for faster finality
    /// @param attestation The Orbit committee attestation
    function processOrbitAttestation(
        OrbitAttestation calldata attestation
    ) external nonReentrant {
        if (!this.verifyOrbitCommittee(attestation)) {
            revert InvalidOrbitAttestation();
        }

        uint256 participantCount = _countBits(attestation.participationBits);

        emit OrbitAttestationVerified(
            attestation.stateRoot,
            attestation.slot,
            participantCount
        );
    }

    /// @notice Enable/disable SSF mode with adjusted challenge period
    /// @param enabled Whether SSF is enabled
    /// @param challengePeriod New challenge period in seconds
    function setSSFMode(
        bool enabled,
        uint64 challengePeriod
    ) external onlyRole(OPERATOR_ROLE) {
        ssfEnabled = enabled;
        ssfChallengePeriod = challengePeriod;

        emit SSFEnabled(enabled, challengePeriod);
    }

    /// @notice Get the effective challenge period (SSF-aware)
    /// @return period Challenge period in seconds
    function getEffectiveChallengePeriod()
        external
        view
        returns (uint64 period)
    {
        if (ssfEnabled) {
            return ssfChallengePeriod; // 12s with SSF
        }
        return 3600; // 1 hour without SSF (current default)
    }

    /*//////////////////////////////////////////////////////////////
                           PROPOSER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Register as a proposer with stake
    function registerProposer() external payable {
        if (msg.value < minProposerStake) revert InsufficientStake();
        proposerStakes[msg.sender] += msg.value;
        _grantRole(PROPOSER_ROLE, msg.sender);
    }

    /// @notice Withdraw proposer stake (after unbonding period)
    function withdrawStake(uint256 amount) external nonReentrant {
        if (proposerStakes[msg.sender] < amount) revert InsufficientStake();
        proposerStakes[msg.sender] -= amount;

        if (proposerStakes[msg.sender] < minProposerStake) {
            _revokeRole(PROPOSER_ROLE, msg.sender);
        }

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdraw failed");
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _getCurrentSlot() internal view returns (uint64) {
        // Simplified: slots since genesis
        // In production: use actual beacon chain slot
        return uint64(block.timestamp / SLOT_DURATION);
    }

    function _countBits(uint256 bits) internal pure returns (uint256 count) {
        while (bits != 0) {
            count += bits & 1;
            bits >>= 1;
        }
    }
}
