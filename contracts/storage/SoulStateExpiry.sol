// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/// @title SoulStateExpiry
/// @author Soul Protocol
/// @notice State expiry and resurrection proofs for Soul Protocol
/// @dev Aligns with Ethereum's "The Purge" roadmap for state management
///
/// STATE EXPIRY INTEGRATION (per Vitalik's Possible Futures Part 5):
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                    Soul State Expiry Architecture                        │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                          │
/// │   EIP-7736 State Expiry:                                                │
/// │   ┌─────────────────────────────────────────────────────────────────┐   │
/// │   │                                                                  │   │
/// │   │   Active Period (1 year)     │    Expired (cold storage)       │   │
/// │   │   ┌─────────────────────┐    │    ┌─────────────────────┐      │   │
/// │   │   │ Full state access  │    │    │ Archived state     │      │   │
/// │   │   │ Normal operations  │────┼────│ Needs resurrection │      │   │
/// │   │   │ In-tree storage    │    │    │ proof to access    │      │   │
/// │   │   └─────────────────────┘    │    └─────────────────────┘      │   │
/// │   │                              │                                  │   │
/// │   └─────────────────────────────────────────────────────────────────┘   │
/// │                                                                          │
/// │   Soul Privacy Considerations:                                          │
/// │   • Expired commitments need resurrection proofs                        │
/// │   • Nullifier history must persist (or use ZK proof)                   │
/// │   • Stealth addresses may need periodic "keep-alive"                   │
/// │                                                                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// References:
/// - https://vitalik.eth.limo/general/2024/10/26/futures5.html
/// - EIP-7736: Leaf-level state expiry in Verkle trees
/// - EIP-4444: Bound historical data
contract SoulStateExpiry is ReentrancyGuard, AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant ARCHIVIST_ROLE = keccak256("ARCHIVIST_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice State entry with expiry tracking
    struct ExpiringState {
        bytes32 stateHash; // Hash of the state data
        uint64 createdAt; // When state was created
        uint64 lastAccessed; // Last access time
        uint64 expiryEpoch; // Epoch when it expires
        bool isActive; // Currently in active tree
        bool isResurrected; // Was previously expired and resurrected
    }

    /// @notice Resurrection proof for expired state
    struct ResurrectionProof {
        bytes32 stateHash; // State being resurrected
        bytes32 archiveRoot; // Root of archive tree
        bytes32[] merkleProof; // Proof of inclusion in archive
        bytes32 leafValue; // The archived value
        uint256 archiveEpoch; // When it was archived
    }

    /// @notice Soul commitment with expiry
    struct ExpiringCommitment {
        bytes32 commitment; // Soul commitment
        bytes32 nullifierHash; // Hash of expected nullifier
        uint64 createdEpoch; // Creation epoch
        uint64 expiryEpoch; // Expiry epoch
        bool isSpent; // Whether nullified
        bool isExpired; // Whether expired
    }

    /// @notice Keep-alive transaction for stealth addresses
    struct KeepAlive {
        address stealthAddress;
        bytes32 viewingKeyHash;
        uint64 lastKeepAlive;
        uint64 nextRequired;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Expiring states by key
    mapping(bytes32 => ExpiringState) public expiringStates;

    /// @notice Expiring Soul commitments
    mapping(bytes32 => ExpiringCommitment) public expiringCommitments;

    /// @notice Archive roots by epoch
    mapping(uint256 => bytes32) public archiveRoots;

    /// @notice Stealth address keep-alives
    mapping(address => KeepAlive) public keepAlives;

    /// @notice Current epoch
    uint256 public currentEpoch;

    /// @notice Epoch duration in seconds (default: 1 year)
    uint256 public epochDuration = 365 days;

    /// @notice Grace period for resurrection (before permanent deletion)
    uint256 public gracePeriodEpochs = 2;

    /// @notice Keep-alive interval for stealth addresses
    uint256 public keepAliveInterval = 180 days;

    /// @notice Genesis timestamp for epoch calculation
    uint256 public genesisTimestamp;

    /// @notice Total active states
    uint256 public totalActiveStates;

    /// @notice Total expired states
    uint256 public totalExpiredStates;

    /// @notice Total resurrected states
    uint256 public totalResurrectedStates;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event StateCreated(
        bytes32 indexed stateKey,
        bytes32 stateHash,
        uint64 expiryEpoch
    );

    event StateAccessed(bytes32 indexed stateKey, uint64 newExpiry);

    event StateExpired(bytes32 indexed stateKey, uint256 epoch);

    event StateResurrected(
        bytes32 indexed stateKey,
        bytes32 archiveRoot,
        uint256 newExpiryEpoch
    );

    event ArchiveRootUpdated(uint256 indexed epoch, bytes32 archiveRoot);

    event CommitmentCreated(bytes32 indexed commitment, uint64 expiryEpoch);

    event CommitmentResurrected(bytes32 indexed commitment);

    event KeepAliveSubmitted(
        address indexed stealthAddress,
        uint64 nextRequired
    );

    event EpochAdvanced(uint256 oldEpoch, uint256 newEpoch);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error StateNotFound();
    error StateNotExpired();
    error StateAlreadyActive();
    error InvalidResurrectionProof();
    error StatePermantlyDeleted();
    error KeepAliveNotRequired();
    error InvalidArchiveRoot();
    error CommitmentAlreadySpent();
    error CommitmentExpired();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        genesisTimestamp = block.timestamp;
        currentEpoch = 0;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(ARCHIVIST_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                         STATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a new expiring state entry
    /// @param stateKey Unique key for the state
    /// @param stateHash Hash of the state data
    /// @return expiryEpoch When the state will expire
    function createState(
        bytes32 stateKey,
        bytes32 stateHash
    ) external nonReentrant returns (uint64 expiryEpoch) {
        expiryEpoch = uint64(currentEpoch + 1);

        expiringStates[stateKey] = ExpiringState({
            stateHash: stateHash,
            createdAt: uint64(block.timestamp),
            lastAccessed: uint64(block.timestamp),
            expiryEpoch: expiryEpoch,
            isActive: true,
            isResurrected: false
        });

        totalActiveStates++;

        emit StateCreated(stateKey, stateHash, expiryEpoch);
    }

    /// @notice Access state and extend expiry
    /// @param stateKey The state key
    /// @return stateHash The state hash
    function accessState(
        bytes32 stateKey
    ) external nonReentrant returns (bytes32 stateHash) {
        ExpiringState storage state = expiringStates[stateKey];

        if (state.stateHash == bytes32(0)) revert StateNotFound();
        if (!state.isActive) revert StateNotFound();

        // Update last accessed and extend expiry
        state.lastAccessed = uint64(block.timestamp);
        state.expiryEpoch = uint64(currentEpoch + 1);

        emit StateAccessed(stateKey, state.expiryEpoch);

        return state.stateHash;
    }

    /// @notice Resurrect expired state with proof
    /// @param stateKey The state key to resurrect
    /// @param proof Resurrection proof from archive
    function resurrectState(
        bytes32 stateKey,
        ResurrectionProof calldata proof
    ) external payable nonReentrant {
        ExpiringState storage state = expiringStates[stateKey];

        if (state.isActive) revert StateAlreadyActive();

        // Verify within grace period
        if (currentEpoch > state.expiryEpoch + gracePeriodEpochs) {
            revert StatePermantlyDeleted();
        }

        // Verify archive root
        if (archiveRoots[proof.archiveEpoch] != proof.archiveRoot) {
            revert InvalidArchiveRoot();
        }

        // Verify merkle proof
        if (
            !_verifyMerkleProof(
                proof.merkleProof,
                proof.archiveRoot,
                proof.stateHash,
                proof.leafValue
            )
        ) {
            revert InvalidResurrectionProof();
        }

        // Resurrect state
        state.isActive = true;
        state.isResurrected = true;
        state.lastAccessed = uint64(block.timestamp);
        state.expiryEpoch = uint64(currentEpoch + 1);

        totalActiveStates++;
        totalResurrectedStates++;

        emit StateResurrected(stateKey, proof.archiveRoot, state.expiryEpoch);
    }

    /*//////////////////////////////////////////////////////////////
                     SOUL COMMITMENT EXPIRY
    //////////////////////////////////////////////////////////////*/

    /// @notice Create an expiring Soul commitment
    /// @param commitment The Soul commitment
    /// @param nullifierHash Hash of expected nullifier
    /// @return expiryEpoch When it expires
    function createExpiringCommitment(
        bytes32 commitment,
        bytes32 nullifierHash
    ) external nonReentrant returns (uint64 expiryEpoch) {
        expiryEpoch = uint64(currentEpoch + 1);

        expiringCommitments[commitment] = ExpiringCommitment({
            commitment: commitment,
            nullifierHash: nullifierHash,
            createdEpoch: uint64(currentEpoch),
            expiryEpoch: expiryEpoch,
            isSpent: false,
            isExpired: false
        });

        emit CommitmentCreated(commitment, expiryEpoch);
    }

    /// @notice Spend a commitment (reveal nullifier)
    /// @param commitment The commitment to spend
    /// @param nullifier The nullifier
    function spendCommitment(
        bytes32 commitment,
        bytes32 nullifier
    ) external nonReentrant {
        ExpiringCommitment storage c = expiringCommitments[commitment];

        if (c.commitment == bytes32(0)) revert StateNotFound();
        if (c.isSpent) revert CommitmentAlreadySpent();
        if (c.isExpired) revert CommitmentExpired();
        if (currentEpoch > c.expiryEpoch) revert CommitmentExpired();

        // Verify nullifier matches
        require(
            keccak256(abi.encode(nullifier)) == c.nullifierHash ||
                nullifier == c.nullifierHash,
            "Invalid nullifier"
        );

        c.isSpent = true;
    }

    /// @notice Resurrect an expired commitment
    /// @param commitment The commitment
    /// @param proof Resurrection proof
    function resurrectCommitment(
        bytes32 commitment,
        ResurrectionProof calldata proof
    ) external payable nonReentrant {
        ExpiringCommitment storage c = expiringCommitments[commitment];

        if (c.commitment == bytes32(0)) revert StateNotFound();
        if (!c.isExpired && currentEpoch <= c.expiryEpoch) {
            revert StateAlreadyActive();
        }

        // Verify proof (same as state resurrection)
        if (
            !_verifyMerkleProof(
                proof.merkleProof,
                proof.archiveRoot,
                proof.stateHash,
                proof.leafValue
            )
        ) {
            revert InvalidResurrectionProof();
        }

        c.isExpired = false;
        c.expiryEpoch = uint64(currentEpoch + 1);

        emit CommitmentResurrected(commitment);
    }

    /*//////////////////////////////////////////////////////////////
                     STEALTH ADDRESS KEEP-ALIVE
    //////////////////////////////////////////////////////////////*/

    /// @notice Submit keep-alive for stealth address
    /// @param stealthAddress The stealth address
    /// @param viewingKeyHash Hash of viewing key (for verification)
    function submitKeepAlive(
        address stealthAddress,
        bytes32 viewingKeyHash
    ) external nonReentrant {
        KeepAlive storage ka = keepAlives[stealthAddress];

        ka.stealthAddress = stealthAddress;
        ka.viewingKeyHash = viewingKeyHash;
        ka.lastKeepAlive = uint64(block.timestamp);
        ka.nextRequired = uint64(block.timestamp + keepAliveInterval);

        emit KeepAliveSubmitted(stealthAddress, ka.nextRequired);
    }

    /// @notice Check if stealth address is active
    /// @param stealthAddress The address to check
    /// @return isActive Whether the address is active
    function isStealthAddressActive(
        address stealthAddress
    ) external view returns (bool isActive) {
        KeepAlive storage ka = keepAlives[stealthAddress];

        if (ka.stealthAddress == address(0)) return true; // Not registered = active
        return block.timestamp < ka.nextRequired;
    }

    /*//////////////////////////////////////////////////////////////
                          EPOCH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Advance to next epoch
    function advanceEpoch() external {
        uint256 expectedEpoch = (block.timestamp - genesisTimestamp) /
            epochDuration;

        if (expectedEpoch > currentEpoch) {
            uint256 oldEpoch = currentEpoch;
            currentEpoch = expectedEpoch;

            emit EpochAdvanced(oldEpoch, currentEpoch);
        }
    }

    /// @notice Get current epoch
    function getCurrentEpoch() external view returns (uint256) {
        return (block.timestamp - genesisTimestamp) / epochDuration;
    }

    /// @notice Set archive root for an epoch
    function setArchiveRoot(
        uint256 epoch,
        bytes32 root
    ) external onlyRole(ARCHIVIST_ROLE) {
        archiveRoots[epoch] = root;
        emit ArchiveRootUpdated(epoch, root);
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-4444 SUPPORT
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if historical data is available
    /// @param blockNumber Block to check
    /// @return available Whether data is available
    function isHistoricalDataAvailable(
        uint256 blockNumber
    ) external view returns (bool available) {
        // EIP-4444: ~1 year of history
        uint256 cutoff = block.number - (365 days / 12); // ~2.6M blocks
        return blockNumber > cutoff;
    }

    /// @notice Get archive location for old data
    /// @param blockNumber The block number
    /// @return archiveURI Portal network URI for archived data
    function getArchiveLocation(
        uint256 blockNumber
    ) external pure returns (string memory archiveURI) {
        // Return Portal Network URI format
        return
            string(
                abi.encodePacked("portal://eth/block/", _uint2str(blockNumber))
            );
    }

    /*//////////////////////////////////////////////////////////////
                              INTERNALS
    //////////////////////////////////////////////////////////////*/

    function _verifyMerkleProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        bytes32 /* value */
    ) internal pure returns (bool) {
        bytes32 computed = leaf;

        for (uint i = 0; i < proof.length; i++) {
            if (computed <= proof[i]) {
                computed = keccak256(abi.encode(computed, proof[i]));
            } else {
                computed = keccak256(abi.encode(proof[i], computed));
            }
        }

        return computed == root;
    }

    function _uint2str(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";

        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + (value % 10)));
            value /= 10;
        }

        return string(buffer);
    }

    /**
     * @notice Emergency withdrawal of ETH
     * @param to Recipient address
     * @param amount Amount to withdraw
     */
    function emergencyWithdrawETH(
        address payable to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        require(to != address(0), "Invalid recipient");
        require(amount <= address(this).balance, "Insufficient balance");
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }
}
