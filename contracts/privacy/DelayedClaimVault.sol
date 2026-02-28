// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

/**
 * @title DelayedClaimVault
 * @author ZASEON
 * @notice Breaks destination timing correlation via delayed claims
 * @dev Phase 5 of Metadata Resistance - decouples receive from claim
 *
 * ATTACK VECTOR:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    DESTINATION TIMING CORRELATION                        │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  DIRECT RECEIVE (Vulnerable):                                           │
 * │  ┌─────────────┐                        ┌─────────────────────────────┐ │
 * │  │ Sender tx   │ ──── 30 seconds ────►  │ Receiver balance increase   │ │
 * │  │ 10:00:00    │                        │ 10:00:30                    │ │
 * │  └─────────────┘                        └─────────────────────────────┘ │
 * │                                                                          │
 * │  ➤ Observer sees: "tx at 10:00 → deposit at 10:00:30 = linked"          │
 * │                                                                          │
 * │  DELAYED CLAIM (Protected):                                             │
 * │  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────────────┐│
 * │  │ Sender tx   │ ──► │ Vault holds │ ──► │ Receiver claims later       ││
 * │  │ 10:00:00    │     │ commitment  │     │ 2024-01-02 14:37:22         ││
 * │  └─────────────┘     └─────────────┘     └─────────────────────────────┘│
 * │                                                                          │
 * │  ➤ 24-72 hour delay + VRF scheduling = no timing correlation           │
 * │                                                                          │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract DelayedClaimVault is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable
{
    // =========================================================================
    // ROLES
    // =========================================================================

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    /// @notice Minimum delay before claim is allowed
    uint256 public constant MIN_DELAY = 24 hours;

    /// @notice Maximum delay before claim is allowed
    uint256 public constant MAX_DELAY = 72 hours;

    /// @notice Default claim window duration
    uint256 public constant DEFAULT_CLAIM_WINDOW = 7 days;

    /// @notice Minimum deposit for anonymous deposits
    uint256 public constant MIN_DEPOSIT = 0.01 ether;

    /// @notice Fixed denomination tiers for amount hiding
    uint256 public constant TIER_1 = 0.1 ether;
    uint256 public constant TIER_2 = 1 ether;
    uint256 public constant TIER_3 = 10 ether;
    uint256 public constant TIER_4 = 100 ether;

    // =========================================================================
    // ENUMS
    // =========================================================================

    enum ClaimStatus {
        PENDING, // Deposited, waiting for delay
        CLAIMABLE, // Delay passed, can be claimed
        CLAIMED, // Successfully claimed
        EXPIRED, // Claim window passed
        REFUNDED // Returned to depositor
    }

    // =========================================================================
    // STRUCTS
    // =========================================================================

    /**
     * @notice Pending claim record
     */
    struct PendingClaim {
        bytes32 claimId;
        bytes32 commitment; // H(recipient, secret)
        bytes32 nullifierHash; // For double-claim prevention
        uint256 amount;
        uint256 depositedAt;
        uint256 claimableAt; // When claim becomes available
        uint256 expiresAt; // When claim expires
        ClaimStatus status;
        address token; // address(0) for ETH
        uint256 denomination; // Fixed tier for amount hiding
    }

    /**
     * @notice Claim proof for verification
     */
    struct ClaimProof {
        bytes32 nullifier; // Revealed nullifier
        bytes32 secret; // Secret for commitment
        bytes merkleProof; // If using merkle tree accumulator
        bytes zkProof; // ZK proof of knowledge
    }

    // =========================================================================
    // STATE
    // =========================================================================

    /// @notice All pending claims: claimId => claim
    mapping(bytes32 => PendingClaim) public claims;

    /// @notice Commitment to claimId mapping
    mapping(bytes32 => bytes32) public commitmentToClaimId;

    /// @notice Used nullifiers (double-claim prevention)
    mapping(bytes32 => bool) public usedNullifiers;

    /// @notice Total pending claims per denomination tier
    mapping(uint256 => uint256) public pendingPerTier;

    /// @notice Total deposited per token
    mapping(address => uint256) public totalDeposited;

    /// @notice Total claimed per token
    mapping(address => uint256) public totalClaimed;

    /// @notice VRF seed for delay randomization
    bytes32 public vrfSeed;

    /// @notice Claim nonce
    uint256 public claimNonce;

    /// @notice Claim window duration
    uint256 public claimWindowDuration;

    // =========================================================================
    // EVENTS
    // =========================================================================

    event DepositMade(
        bytes32 indexed claimId,
        bytes32 indexed commitment,
        uint256 denomination,
        uint256 claimableAt,
        uint256 expiresAt
    );

    event ClaimExecuted(
        bytes32 indexed claimId,
        bytes32 indexed nullifierHash,
        uint256 amount,
        uint256 timestamp
    );

    event ClaimExpired(bytes32 indexed claimId, uint256 amount);

    event ClaimRefunded(
        bytes32 indexed claimId,
        address indexed depositor,
        uint256 amount
    );

    // =========================================================================
    // ERRORS
    // =========================================================================

    error InvalidCommitment();
    error InvalidAmount();
    error InvalidDenomination();
    error ClaimNotFound();
    error ClaimNotReady();
    error ClaimAlreadyUsed();
    error ClaimExpiredError();
    error InvalidProof();
    error NullifierAlreadyUsed();
    error TransferFailed();
    error ZeroAddress();

    // =========================================================================
    // INITIALIZER
    // =========================================================================

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

        /**
     * @notice Initializes the operation
     * @param admin The admin bound
     */
function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(OPERATOR_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);

        claimWindowDuration = DEFAULT_CLAIM_WINDOW;
        vrfSeed = keccak256(
            abi.encodePacked(block.timestamp, block.prevrandao, admin)
        );
    }

    // =========================================================================
    // DEPOSITS
    // =========================================================================

    /**
     * @notice Make an anonymous deposit with commitment
     * @param commitment Hash of (recipient, secret) - recipient proves knowledge to claim
     * @param denomination Fixed tier amount (must match msg.value exactly)
     * @return claimId Unique identifier for the claim
     */
    function deposit(
        bytes32 commitment,
        uint256 denomination
    ) external payable nonReentrant whenNotPaused returns (bytes32 claimId) {
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (!_isValidDenomination(denomination)) revert InvalidDenomination();
        if (msg.value != denomination) revert InvalidAmount();

        // Generate claim ID
        claimId = keccak256(
            abi.encodePacked(
                commitment,
                block.timestamp,
                claimNonce++,
                msg.sender
            )
        );

        // Calculate random delay using VRF-like mechanism
        uint256 delay = _calculateRandomDelay(claimId);
        uint256 claimableAt = block.timestamp + delay;
        uint256 expiresAt = claimableAt + claimWindowDuration;

        // Store claim
        claims[claimId] = PendingClaim({
            claimId: claimId,
            commitment: commitment,
            nullifierHash: bytes32(0), // Set on claim
            amount: denomination,
            depositedAt: block.timestamp,
            claimableAt: claimableAt,
            expiresAt: expiresAt,
            status: ClaimStatus.PENDING,
            token: address(0),
            denomination: denomination
        });

        commitmentToClaimId[commitment] = claimId;
        pendingPerTier[denomination]++;
        totalDeposited[address(0)] += denomination;

        emit DepositMade(
            claimId,
            commitment,
            denomination,
            claimableAt,
            expiresAt
        );
    }

    /**
     * @notice Deposit with custom delay (for testing/specific use cases)
     * @param commitment Hash of (recipient, secret)
     * @param denomination Fixed tier amount
     * @param minDelay Minimum delay in seconds
     * @param maxDelay Maximum delay in seconds
          * @return claimId The claim id
     */
    function depositWithCustomDelay(
        bytes32 commitment,
        uint256 denomination,
        uint256 minDelay,
        uint256 maxDelay
    ) external payable nonReentrant whenNotPaused returns (bytes32 claimId) {
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (!_isValidDenomination(denomination)) revert InvalidDenomination();
        if (msg.value != denomination) revert InvalidAmount();
        require(minDelay >= 1 hours, "Delay too short");
        require(maxDelay <= 30 days, "Delay too long");
        require(minDelay <= maxDelay, "Invalid delay range");

        claimId = keccak256(
            abi.encodePacked(
                commitment,
                block.timestamp,
                claimNonce++,
                msg.sender
            )
        );

        uint256 delay = _calculateRandomDelayInRange(
            claimId,
            minDelay,
            maxDelay
        );
        uint256 claimableAt = block.timestamp + delay;
        uint256 expiresAt = claimableAt + claimWindowDuration;

        claims[claimId] = PendingClaim({
            claimId: claimId,
            commitment: commitment,
            nullifierHash: bytes32(0),
            amount: denomination,
            depositedAt: block.timestamp,
            claimableAt: claimableAt,
            expiresAt: expiresAt,
            status: ClaimStatus.PENDING,
            token: address(0),
            denomination: denomination
        });

        commitmentToClaimId[commitment] = claimId;
        pendingPerTier[denomination]++;
        totalDeposited[address(0)] += denomination;

        emit DepositMade(
            claimId,
            commitment,
            denomination,
            claimableAt,
            expiresAt
        );
    }

    // =========================================================================
    // CLAIMS
    // =========================================================================

    /**
     * @notice Claim deposited funds with proof
     * @param claimId Claim identifier
     * @param recipient Address to receive funds
     * @param proof Claim proof (nullifier, secret, zkProof)
     */
    function claim(
        bytes32 claimId,
        address recipient,
        ClaimProof calldata proof
    ) external nonReentrant whenNotPaused {
        if (recipient == address(0)) revert ZeroAddress();

        PendingClaim storage pendingClaim = claims[claimId];
        if (pendingClaim.depositedAt == 0) revert ClaimNotFound();
        if (pendingClaim.status != ClaimStatus.PENDING)
            revert ClaimAlreadyUsed();
        if (block.timestamp < pendingClaim.claimableAt) revert ClaimNotReady();
        if (block.timestamp > pendingClaim.expiresAt)
            revert ClaimExpiredError();

        // Verify nullifier hasn't been used
        if (usedNullifiers[proof.nullifier]) revert NullifierAlreadyUsed();

        // Verify proof
        bool isValid = _verifyClaimProof(
            pendingClaim.commitment,
            recipient,
            proof
        );
        if (!isValid) revert InvalidProof();

        // Mark nullifier as used
        usedNullifiers[proof.nullifier] = true;
        pendingClaim.nullifierHash = proof.nullifier;
        pendingClaim.status = ClaimStatus.CLAIMED;

        // Update state
        pendingPerTier[pendingClaim.denomination]--;
        totalClaimed[address(0)] += pendingClaim.amount;

        // Transfer funds
        (bool success, ) = recipient.call{value: pendingClaim.amount}("");
        if (!success) revert TransferFailed();

        emit ClaimExecuted(
            claimId,
            proof.nullifier,
            pendingClaim.amount,
            block.timestamp
        );
    }

    /**
     * @notice Claim using commitment directly (alternative lookup)
          * @param commitment The cryptographic commitment
     * @param recipient The recipient address
     * @param proof The ZK proof data
     */
    function claimByCommitment(
        bytes32 commitment,
        address recipient,
        ClaimProof calldata proof
    ) external nonReentrant whenNotPaused {
        bytes32 claimId = commitmentToClaimId[commitment];
        if (claimId == bytes32(0)) revert ClaimNotFound();

        PendingClaim storage pendingClaim = claims[claimId];
        if (pendingClaim.status != ClaimStatus.PENDING)
            revert ClaimAlreadyUsed();
        if (block.timestamp < pendingClaim.claimableAt) revert ClaimNotReady();
        if (block.timestamp > pendingClaim.expiresAt)
            revert ClaimExpiredError();

        if (usedNullifiers[proof.nullifier]) revert NullifierAlreadyUsed();

        bool isValid = _verifyClaimProof(commitment, recipient, proof);
        if (!isValid) revert InvalidProof();

        usedNullifiers[proof.nullifier] = true;
        pendingClaim.nullifierHash = proof.nullifier;
        pendingClaim.status = ClaimStatus.CLAIMED;

        pendingPerTier[pendingClaim.denomination]--;
        totalClaimed[address(0)] += pendingClaim.amount;

        (bool success, ) = recipient.call{value: pendingClaim.amount}("");
        if (!success) revert TransferFailed();

        emit ClaimExecuted(
            claimId,
            proof.nullifier,
            pendingClaim.amount,
            block.timestamp
        );
    }

    // =========================================================================
    // EXPIRY & REFUNDS
    // =========================================================================

    /**
     * @notice Mark expired claims (anyone can call)
     * @param claimIds Array of claim IDs to check for expiry
     */
    function markExpired(bytes32[] calldata claimIds) external {
        for (uint256 i = 0; i < claimIds.length; ) {
            PendingClaim storage pendingClaim = claims[claimIds[i]];

            if (
                pendingClaim.status == ClaimStatus.PENDING &&
                block.timestamp > pendingClaim.expiresAt
            ) {
                pendingClaim.status = ClaimStatus.EXPIRED;
                pendingPerTier[pendingClaim.denomination]--;

                emit ClaimExpired(claimIds[i], pendingClaim.amount);
            }

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Refund expired claim to treasury (admin only)
     * @param claimId Claim to refund
     * @param treasury Treasury address
     */
    function refundExpired(
        bytes32 claimId,
        address treasury
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        if (treasury == address(0)) revert ZeroAddress();

        PendingClaim storage pendingClaim = claims[claimId];
        if (pendingClaim.status != ClaimStatus.EXPIRED) revert ClaimNotFound();

        pendingClaim.status = ClaimStatus.REFUNDED;

        (bool success, ) = treasury.call{value: pendingClaim.amount}("");
        if (!success) revert TransferFailed();

        emit ClaimRefunded(claimId, treasury, pendingClaim.amount);
    }

    // =========================================================================
    // DELAY CALCULATION
    // =========================================================================

    /**
     * @dev Calculate random delay using VRF-like mechanism
     */
    function _calculateRandomDelay(
        bytes32 claimId
    ) internal view returns (uint256) {
        bytes32 randomness = keccak256(
            abi.encodePacked(
                vrfSeed,
                claimId,
                block.timestamp,
                block.prevrandao
            )
        );

        // Random delay between MIN_DELAY and MAX_DELAY
        uint256 range = MAX_DELAY - MIN_DELAY;
        uint256 randomOffset = uint256(randomness) % range;

        return MIN_DELAY + randomOffset;
    }

    /**
     * @dev Calculate random delay within custom range
     */
    function _calculateRandomDelayInRange(
        bytes32 claimId,
        uint256 minDelay,
        uint256 maxDelay
    ) internal view returns (uint256) {
        bytes32 randomness = keccak256(
            abi.encodePacked(
                vrfSeed,
                claimId,
                block.timestamp,
                block.prevrandao
            )
        );

        uint256 range = maxDelay - minDelay;
        uint256 randomOffset = uint256(randomness) % range;

        return minDelay + randomOffset;
    }

    // =========================================================================
    // PROOF VERIFICATION
    // =========================================================================

    /**
     * @dev Verify claim proof
     * In production, this verifies a ZK proof that:
     * 1. Claimer knows the secret
     * 2. H(recipient, secret) == commitment
     * 3. Nullifier is correctly derived
     */
    function _verifyClaimProof(
        bytes32 commitment,
        address recipient,
        ClaimProof memory proof
    ) internal pure returns (bool) {
        // Simplified verification for development
        // Real implementation would verify ZK-SNARK proof

        // Check proof components exist
        if (proof.secret == bytes32(0)) return false;
        if (proof.nullifier == bytes32(0)) return false;

        // Verify commitment = H(recipient, secret)
        bytes32 expectedCommitment = keccak256(
            abi.encodePacked(recipient, proof.secret)
        );
        if (expectedCommitment != commitment) return false;

        // Verify nullifier derivation
        bytes32 expectedNullifier = keccak256(
            abi.encodePacked(proof.secret, "nullifier")
        );
        if (expectedNullifier != proof.nullifier) return false;

        // In production: verify zkProof with ZK verifier contract
        // return zkVerifier.verify(proof.zkProof, publicInputs);

        return true;
    }

    // =========================================================================
    // DENOMINATION VALIDATION
    // =========================================================================

    function _isValidDenomination(uint256 amount) internal pure returns (bool) {
        return
            amount == TIER_1 ||
            amount == TIER_2 ||
            amount == TIER_3 ||
            amount == TIER_4;
    }

    // =========================================================================
    // VIEW FUNCTIONS
    // =========================================================================

    /**
     * @notice Get claim details
          * @param claimId The claimId identifier
     * @return The result value
     */
    function getClaim(
        bytes32 claimId
    ) external view returns (PendingClaim memory) {
        return claims[claimId];
    }

    /**
     * @notice Check if claim is ready
          * @param claimId The claimId identifier
     * @return ready The ready
     * @return timeRemaining The time remaining
     */
    function isClaimReady(
        bytes32 claimId
    ) external view returns (bool ready, uint256 timeRemaining) {
        PendingClaim storage pendingClaim = claims[claimId];

        if (pendingClaim.status != ClaimStatus.PENDING) {
            return (false, 0);
        }

        if (block.timestamp >= pendingClaim.claimableAt) {
            if (block.timestamp <= pendingClaim.expiresAt) {
                return (true, 0);
            }
            return (false, 0); // Expired
        }

        return (false, pendingClaim.claimableAt - block.timestamp);
    }

    /**
     * @notice Get anonymity set size for a denomination
          * @param denomination The denomination bound
     * @return The result value
     */
    function getAnonymitySetSize(
        uint256 denomination
    ) external view returns (uint256) {
        return pendingPerTier[denomination];
    }

    /**
     * @notice Get all denomination tiers
          * @return tiers The tiers
     */
    function getDenominationTiers()
        external
        pure
        returns (uint256[] memory tiers)
    {
        tiers = new uint256[](4);
        tiers[0] = TIER_1;
        tiers[1] = TIER_2;
        tiers[2] = TIER_3;
        tiers[3] = TIER_4;
    }

    /**
     * @notice Calculate time until claim is ready
          * @param claimId The claimId identifier
     * @return The result value
     */
    function timeUntilClaimable(
        bytes32 claimId
    ) external view returns (uint256) {
        PendingClaim storage pendingClaim = claims[claimId];
        if (block.timestamp >= pendingClaim.claimableAt) return 0;
        return pendingClaim.claimableAt - block.timestamp;
    }

    // =========================================================================
    // ADMIN FUNCTIONS
    // =========================================================================

        /**
     * @notice Sets the claim window duration
     * @param duration The duration in seconds
     */
function setClaimWindowDuration(
        uint256 duration
    ) external onlyRole(OPERATOR_ROLE) {
        require(duration >= 1 days && duration <= 30 days, "Invalid duration");
        claimWindowDuration = duration;
    }

        /**
     * @notice Pauses the operation
     */
function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

        /**
     * @notice Unpauses the operation
     */
function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    // =========================================================================
    // UPGRADE AUTHORIZATION
    // =========================================================================

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(UPGRADER_ROLE) {}

    // =========================================================================
    // RECEIVE
    // =========================================================================

    receive() external payable {
        revert("Use deposit()");
    }
}
