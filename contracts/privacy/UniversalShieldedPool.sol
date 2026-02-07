// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IUniversalChainAdapter} from "../interfaces/IUniversalChainAdapter.sol";
import {UniversalChainRegistry} from "../libraries/UniversalChainRegistry.sol";
import {PoseidonYul} from "../libraries/PoseidonYul.sol";

/**
 * @title UniversalShieldedPool
 * @author Soul Protocol
 * @notice Multi-asset shielded pool with cross-chain ZK deposits and withdrawals
 * @dev Implements the canonical deposit→commitment, withdraw→nullifier+proof pattern
 *      that works across ALL blockchain ecosystems via the Universal Adapter Layer.
 *
 * ARCHITECTURE:
 *
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                      UniversalShieldedPool                          │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │                                                                      │
 *   │  ┌──────────────────┐  ┌───────────────────┐  ┌──────────────────┐  │
 *   │  │ Commitment Tree  │  │ Nullifier Registry │  │  Asset Registry  │  │
 *   │  │ (Incremental     │  │ (Cross-chain       │  │  (ERC20, ETH,    │  │
 *   │  │  Merkle, depth   │  │  double-spend      │  │   cross-chain    │  │
 *   │  │  32, ~4B leaves) │  │  prevention)       │  │   bridged)       │  │
 *   │  └──────────────────┘  └───────────────────┘  └──────────────────┘  │
 *   │                                                                      │
 *   │  DEPOSIT: User sends asset ─► pool hashes commitment ─► insert      │
 *   │           into Merkle tree ─► emit DepositNote event                 │
 *   │                                                                      │
 *   │  WITHDRAW: User submits ZK proof ─► verify(root, nullifier,         │
 *   │            recipient, amount) ─► mark nullifier ─► transfer asset    │
 *   │                                                                      │
 *   │  CROSS-CHAIN: User deposits on chain A ─► relayer bridges           │
 *   │               commitment to chain B ─► user withdraws on chain B    │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * PRIVACY MODEL:
 * - Deposits create Pedersen commitments: C = H(asset || amount || secret || nullifier_preimage)
 * - Withdrawals prove knowledge of (secret, nullifier_preimage) for a commitment in the tree
 * - Nullifier = H(nullifier_preimage || leafIndex) prevents double-spend
 * - Cross-chain: commitment trees are synced; nullifier sets are unified via CDNA
 *
 * @custom:security-contact security@soul.network
 */
contract UniversalShieldedPool is AccessControl, ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("RELAYER_ROLE") — syncs cross-chain commitments
    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev keccak256("COMPLIANCE_ROLE")
    bytes32 public constant COMPLIANCE_ROLE =
        0x364d3d7565c7a8982189c6ab03c2167d1f2cc9c82a4c902413ce8d68cfbe88c3;

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Merkle tree depth (supports ~4 billion deposits)
    uint256 public constant TREE_DEPTH = 32;

    /// @notice Maximum supported field element (BN254 scalar field order)
    uint256 public constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Zero value used for empty Merkle leaf
    bytes32 public constant ZERO_VALUE =
        0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c;

    /// @notice Maximum deposit amount per tx (anti-whale)
    uint256 public constant MAX_DEPOSIT = 10_000 ether;

    /// @notice Minimum deposit amount (dust prevention)
    uint256 public constant MIN_DEPOSIT = 0.001 ether;

    /// @notice Number of historical roots tracked
    uint256 public constant ROOT_HISTORY_SIZE = 100;

    /// @notice Native ETH asset identifier
    bytes32 public constant NATIVE_ASSET = keccak256("ETH");

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice A deposit note (public data emitted on-chain)
    struct DepositNote {
        bytes32 commitment; // Pedersen commitment
        bytes32 assetId; // Asset identifier
        uint256 leafIndex; // Position in Merkle tree
        uint256 timestamp; // Block timestamp
        bytes32 sourceChainId; // Chain where deposit occurred
    }

    /// @notice A withdrawal proof submission
    struct WithdrawalProof {
        bytes proof; // ZK proof data
        bytes32 merkleRoot; // Root the proof references
        bytes32 nullifier; // Nullifier to consume
        address recipient; // Withdrawal recipient
        address relayerAddress; // Relayer (for fee payment)
        uint256 amount; // Withdrawal amount
        uint256 relayerFee; // Fee paid to relayer
        bytes32 assetId; // Asset being withdrawn
        bytes32 destChainId; // Destination chain (for cross-chain)
    }

    /// @notice Cross-chain commitment batch from a remote chain
    struct CrossChainCommitmentBatch {
        bytes32 sourceChainId; // Origin chain
        bytes32[] commitments; // Commitments to insert
        bytes32[] assetIds; // Asset IDs per commitment
        bytes32 batchRoot; // Merkle root of the batch (for verification)
        bytes proof; // Proof of batch validity
        uint256 sourceTreeSize; // Tree size on source chain at batch time
    }

    /// @notice Registered asset in the pool
    struct AssetConfig {
        address tokenAddress; // ERC20 address (address(0) for native ETH)
        bytes32 assetId; // Universal asset identifier
        uint256 totalDeposited; // Total amount deposited
        uint256 totalWithdrawn; // Total amount withdrawn
        bool active; // Whether deposits are accepted
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    // ─── Merkle Tree ────────────────────────────────────────────
    /// @notice Current Merkle root
    bytes32 public currentRoot;

    /// @notice Next leaf index
    uint256 public nextLeafIndex;

    /// @notice Filled subtree hashes (for incremental insertion)
    bytes32[TREE_DEPTH] public filledSubtrees;

    /// @notice Historical root ring buffer
    bytes32[ROOT_HISTORY_SIZE] public rootHistory;

    /// @notice Current root history index
    uint256 public currentRootIndex;

    // ─── Nullifiers ─────────────────────────────────────────────
    /// @notice Nullifier registry (nullifier => spent)
    mapping(bytes32 => bool) public nullifiers;

    // ─── Assets ─────────────────────────────────────────────────
    /// @notice Registered assets (assetId => config)
    mapping(bytes32 => AssetConfig) public assets;

    /// @notice Token address to asset ID mapping
    mapping(address => bytes32) public tokenToAssetId;

    /// @notice All registered asset IDs
    bytes32[] public assetIds;

    // ─── Deposits ───────────────────────────────────────────────
    /// @notice All deposit commitments (leafIndex => commitment)
    mapping(uint256 => bytes32) public commitments;

    /// @notice Commitment existence check
    mapping(bytes32 => bool) public commitmentExists;

    // ─── Verifier ───────────────────────────────────────────────
    /// @notice ZK verifier for withdrawal proofs
    address public withdrawalVerifier;

    /// @notice Test mode flag — allows proof bypass for testing only
    /// @dev MUST be false in production. Cannot be re-enabled once disabled.
    bool public testMode;

    /// @notice ZK verifier for cross-chain batch proofs
    address public batchVerifier;

    // ─── Cross-Chain ────────────────────────────────────────────
    /// @notice This chain's universal ID
    bytes32 public immutable universalChainId;

    /// @notice Processed cross-chain batches
    mapping(bytes32 => bool) public processedBatches;

    // ─── Compliance ─────────────────────────────────────────────
    /// @notice Optional sanctions screening oracle
    address public sanctionsOracle;

    // ─── Stats ──────────────────────────────────────────────────
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalCrossChainDeposits;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event Deposit(
        bytes32 indexed commitment,
        bytes32 indexed assetId,
        uint256 leafIndex,
        uint256 amount,
        uint256 timestamp
    );

    event Withdrawal(
        bytes32 indexed nullifier,
        bytes32 indexed assetId,
        address indexed recipient,
        uint256 amount,
        uint256 relayerFee
    );

    event CrossChainCommitmentsInserted(
        bytes32 indexed sourceChainId,
        uint256 count,
        bytes32 newRoot
    );

    event AssetRegistered(
        bytes32 indexed assetId,
        address indexed tokenAddress
    );

    event VerifierUpdated(address indexed newVerifier, string verifierType);

    event SanctionsOracleUpdated(address indexed newOracle);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidCommitment();
    error NullifierAlreadySpent(bytes32 nullifier);
    error InvalidMerkleRoot(bytes32 root);
    error WithdrawalProofFailed();
    error InvalidAmount();
    error AssetNotRegistered(bytes32 assetId);
    error AssetNotActive(bytes32 assetId);
    error AssetAlreadyRegistered(bytes32 assetId);
    error MerkleTreeFull();
    error InvalidRecipient();
    error InsufficientRelayerFee();
    error BatchAlreadyProcessed(bytes32 batchRoot);
    error BatchProofFailed();
    error SanctionedAddress(address addr);
    error ZeroAddress();
    error DepositTooLarge();
    error DepositTooSmall();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, address _withdrawalVerifier, bool _testMode) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        testMode = _testMode;

        universalChainId = UniversalChainRegistry.computeEVMChainId(
            block.chainid
        );

        // Initialize Merkle tree with zero values
        bytes32 currentZero = ZERO_VALUE;
        for (uint256 i = 0; i < TREE_DEPTH; ) {
            filledSubtrees[i] = currentZero;
            currentZero = _hashPair(currentZero, currentZero);
            unchecked {
                ++i;
            }
        }
        currentRoot = currentZero;
        rootHistory[0] = currentRoot;

        // Register native ETH as first asset
        bytes32 ethAssetId = NATIVE_ASSET;
        assets[ethAssetId] = AssetConfig({
            tokenAddress: address(0),
            assetId: ethAssetId,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });
        assetIds.push(ethAssetId);
        emit AssetRegistered(ethAssetId, address(0));

        // Set verifier
        if (_withdrawalVerifier != address(0)) {
            withdrawalVerifier = _withdrawalVerifier;
            emit VerifierUpdated(_withdrawalVerifier, "withdrawal");
        }
    }

    /*//////////////////////////////////////////////////////////////
                             DEPOSIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit native ETH into the shielded pool
    /// @param commitment The Pedersen commitment: H(assetId || amount || secret || nullifierPreimage)
    function depositETH(
        bytes32 commitment
    ) external payable nonReentrant whenNotPaused {
        if (commitment == bytes32(0) || uint256(commitment) >= FIELD_SIZE) {
            revert InvalidCommitment();
        }
        if (msg.value < MIN_DEPOSIT) revert DepositTooSmall();
        if (msg.value > MAX_DEPOSIT) revert DepositTooLarge();
        _checkSanctions(msg.sender);

        _insertCommitment(commitment, NATIVE_ASSET, msg.value);
    }

    /// @notice Deposit ERC20 tokens into the shielded pool
    /// @param assetId The universal asset identifier
    /// @param amount The deposit amount
    /// @param commitment The Pedersen commitment
    function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external nonReentrant whenNotPaused {
        if (commitment == bytes32(0) || uint256(commitment) >= FIELD_SIZE) {
            revert InvalidCommitment();
        }
        if (amount < MIN_DEPOSIT) revert DepositTooSmall();
        if (amount > MAX_DEPOSIT) revert DepositTooLarge();

        AssetConfig storage asset = assets[assetId];
        if (!asset.active) revert AssetNotActive(assetId);
        if (asset.tokenAddress == address(0))
            revert AssetNotRegistered(assetId);

        _checkSanctions(msg.sender);

        // Transfer tokens to pool
        IERC20(asset.tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );

        _insertCommitment(commitment, assetId, amount);
    }

    /*//////////////////////////////////////////////////////////////
                            WITHDRAW
    //////////////////////////////////////////////////////////////*/

    /// @notice Withdraw from the shielded pool using a ZK proof
    /// @param wp The withdrawal proof data
    function withdraw(
        WithdrawalProof calldata wp
    ) external nonReentrant whenNotPaused {
        // Validate inputs
        if (wp.recipient == address(0)) revert InvalidRecipient();
        if (wp.amount == 0) revert InvalidAmount();
        if (nullifiers[wp.nullifier])
            revert NullifierAlreadySpent(wp.nullifier);
        if (!_isKnownRoot(wp.merkleRoot))
            revert InvalidMerkleRoot(wp.merkleRoot);

        AssetConfig storage asset = assets[wp.assetId];
        if (asset.assetId == bytes32(0)) revert AssetNotRegistered(wp.assetId);

        _checkSanctions(wp.recipient);
        if (wp.relayerAddress != address(0)) {
            _checkSanctions(wp.relayerAddress);
        }

        // Verify the ZK proof
        // Public inputs: [merkleRoot, nullifier, recipient, amount, assetId, relayerAddress, relayerFee]
        bool valid = _verifyWithdrawalProof(wp);
        if (!valid) revert WithdrawalProofFailed();

        // Mark nullifier as spent
        nullifiers[wp.nullifier] = true;

        // Update stats
        uint256 netAmount = wp.amount - wp.relayerFee;
        asset.totalWithdrawn += wp.amount;
        unchecked {
            ++totalWithdrawals;
        }

        // Transfer assets
        if (asset.tokenAddress == address(0)) {
            // Native ETH
            _safeTransferETH(wp.recipient, netAmount);
            if (wp.relayerFee > 0 && wp.relayerAddress != address(0)) {
                _safeTransferETH(wp.relayerAddress, wp.relayerFee);
            }
        } else {
            // ERC20
            IERC20(asset.tokenAddress).safeTransfer(wp.recipient, netAmount);
            if (wp.relayerFee > 0 && wp.relayerAddress != address(0)) {
                IERC20(asset.tokenAddress).safeTransfer(
                    wp.relayerAddress,
                    wp.relayerFee
                );
            }
        }

        emit Withdrawal(
            wp.nullifier,
            wp.assetId,
            wp.recipient,
            wp.amount,
            wp.relayerFee
        );
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN COMMITMENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Insert commitments from a remote chain (bridged by relayer)
    /// @param batch The cross-chain commitment batch
    function insertCrossChainCommitments(
        CrossChainCommitmentBatch calldata batch
    ) external nonReentrant whenNotPaused onlyRole(RELAYER_ROLE) {
        if (processedBatches[batch.batchRoot]) {
            revert BatchAlreadyProcessed(batch.batchRoot);
        }

        // Verify the batch proof (attests the commitments are valid on the source chain)
        if (batchVerifier != address(0)) {
            bool validBatch = _verifyBatchProof(batch);
            if (!validBatch) revert BatchProofFailed();
        }

        // Insert each commitment into the local tree
        uint256 count = batch.commitments.length;
        for (uint256 i = 0; i < count; ) {
            bytes32 commitment = batch.commitments[i];
            if (
                commitment != bytes32(0) &&
                uint256(commitment) < FIELD_SIZE &&
                !commitmentExists[commitment]
            ) {
                uint256 leafIndex = nextLeafIndex;
                _insertLeaf(commitment);
                commitments[leafIndex] = commitment;
                commitmentExists[commitment] = true;
            }
            unchecked {
                ++i;
            }
        }

        processedBatches[batch.batchRoot] = true;
        unchecked {
            totalCrossChainDeposits += count;
        }

        emit CrossChainCommitmentsInserted(
            batch.sourceChainId,
            count,
            currentRoot
        );
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a new ERC20 asset
    function registerAsset(
        bytes32 assetId,
        address tokenAddress
    ) external onlyRole(OPERATOR_ROLE) {
        if (tokenAddress == address(0)) revert ZeroAddress();
        if (assets[assetId].active) revert AssetAlreadyRegistered(assetId);

        assets[assetId] = AssetConfig({
            tokenAddress: tokenAddress,
            assetId: assetId,
            totalDeposited: 0,
            totalWithdrawn: 0,
            active: true
        });
        tokenToAssetId[tokenAddress] = assetId;
        assetIds.push(assetId);

        emit AssetRegistered(assetId, tokenAddress);
    }

    /// @notice Set the withdrawal proof verifier
    function setWithdrawalVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        withdrawalVerifier = _verifier;
        emit VerifierUpdated(_verifier, "withdrawal");
    }

    /// @notice Permanently disable test mode (one-way, irreversible)
    /// @dev Once disabled, withdrawals require a real verifier contract
    function disableTestMode() external onlyRole(DEFAULT_ADMIN_ROLE) {
        testMode = false;
    }

    /// @notice Set the cross-chain batch verifier
    function setBatchVerifier(
        address _verifier
    ) external onlyRole(OPERATOR_ROLE) {
        if (_verifier == address(0)) revert ZeroAddress();
        batchVerifier = _verifier;
        emit VerifierUpdated(_verifier, "batch");
    }

    /// @notice Set the sanctions screening oracle
    function setSanctionsOracle(
        address _oracle
    ) external onlyRole(COMPLIANCE_ROLE) {
        sanctionsOracle = _oracle;
        emit SanctionsOracleUpdated(_oracle);
    }

    /// @notice Deactivate an asset (no new deposits)
    function deactivateAsset(bytes32 assetId) external onlyRole(OPERATOR_ROLE) {
        assets[assetId].active = false;
    }

    /// @notice Emergency pause
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get the current Merkle root
    function getLastRoot() external view returns (bytes32) {
        return currentRoot;
    }

    /// @notice Check if a Merkle root is in the history
    function isKnownRoot(bytes32 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

    /// @notice Check if a nullifier has been spent
    function isSpent(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }

    /// @notice Get pool statistics
    function getPoolStats()
        external
        view
        returns (
            uint256 deposits,
            uint256 withdrawalsCount,
            uint256 crossChainDeposits,
            uint256 treeSize,
            bytes32 root
        )
    {
        return (
            totalDeposits,
            totalWithdrawals,
            totalCrossChainDeposits,
            nextLeafIndex,
            currentRoot
        );
    }

    /// @notice Get all registered asset IDs
    function getRegisteredAssets() external view returns (bytes32[] memory) {
        return assetIds;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Insert a commitment into the tree
    function _insertCommitment(
        bytes32 commitment,
        bytes32 assetId,
        uint256 amount
    ) internal {
        if (commitmentExists[commitment]) revert InvalidCommitment();

        uint256 leafIndex = nextLeafIndex;
        _insertLeaf(commitment);

        commitments[leafIndex] = commitment;
        commitmentExists[commitment] = true;
        assets[assetId].totalDeposited += amount;

        unchecked {
            ++totalDeposits;
        }

        emit Deposit(commitment, assetId, leafIndex, amount, block.timestamp);
    }

    /// @notice Insert a leaf into the incremental Merkle tree
    function _insertLeaf(bytes32 leaf) internal {
        uint256 index = nextLeafIndex;
        if (index >= 2 ** TREE_DEPTH) revert MerkleTreeFull();

        bytes32 currentHash = leaf;

        for (uint256 i = 0; i < TREE_DEPTH; ) {
            if (index & 1 == 0) {
                // Left child: store current hash and pair with zero
                filledSubtrees[i] = currentHash;
                currentHash = _hashPair(currentHash, _zeros(i));
            } else {
                // Right child: pair with stored left sibling
                currentHash = _hashPair(filledSubtrees[i], currentHash);
            }
            index >>= 1;
            unchecked {
                ++i;
            }
        }

        uint256 newRootIndex;
        unchecked {
            newRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        }
        currentRootIndex = newRootIndex;
        rootHistory[newRootIndex] = currentHash;
        currentRoot = currentHash;

        unchecked {
            ++nextLeafIndex;
        }
    }

    /// @notice Check if a root exists in history
    function _isKnownRoot(bytes32 root) internal view returns (bool) {
        if (root == bytes32(0)) return false;
        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ) {
            if (rootHistory[i] == root) return true;
            unchecked {
                ++i;
            }
        }
        return false;
    }

    /// @notice Get the zero value for a given tree level
    function _zeros(uint256 level) internal pure returns (bytes32) {
        // Precomputed zero hashes for each level
        // Level 0 = ZERO_VALUE
        // Level n = hash(zeros(n-1), zeros(n-1))
        if (level == 0) return ZERO_VALUE;

        // For higher levels, compute dynamically
        bytes32 z = ZERO_VALUE;
        for (uint256 i = 0; i < level; ) {
            z = _hashPair(z, z);
            unchecked {
                ++i;
            }
        }
        return z;
    }

    /// @notice Hash a pair of nodes using Poseidon (BN254, T=3)
    /// @dev Uses PoseidonYul for ZK-compatible Merkle tree hashing
    function _hashPair(
        bytes32 left,
        bytes32 right
    ) internal pure returns (bytes32) {
        return bytes32(PoseidonYul.hash2(uint256(left), uint256(right)));
    }

    /// @notice Verify a withdrawal ZK proof
    function _verifyWithdrawalProof(
        WithdrawalProof calldata wp
    ) internal view returns (bool) {
        if (withdrawalVerifier == address(0)) {
            // No verifier set — only accept in explicit test mode
            require(testMode, "No verifier configured");
            return wp.proof.length >= 64;
        }

        // Encode public inputs for the verifier
        bytes memory publicInputs = abi.encode(
            wp.merkleRoot,
            wp.nullifier,
            wp.recipient,
            wp.amount,
            wp.assetId,
            wp.relayerAddress,
            wp.relayerFee
        );

        (bool success, bytes memory result) = withdrawalVerifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes)",
                wp.proof,
                publicInputs
            )
        );

        return success && result.length >= 32 && abi.decode(result, (bool));
    }

    /// @notice Verify a cross-chain batch proof
    function _verifyBatchProof(
        CrossChainCommitmentBatch calldata batch
    ) internal view returns (bool) {
        bytes memory publicInputs = abi.encode(
            batch.sourceChainId,
            batch.batchRoot,
            batch.sourceTreeSize,
            keccak256(abi.encodePacked(batch.commitments))
        );

        (bool success, bytes memory result) = batchVerifier.staticcall(
            abi.encodeWithSignature(
                "verify(bytes,bytes)",
                batch.proof,
                publicInputs
            )
        );

        return success && result.length >= 32 && abi.decode(result, (bool));
    }

    /// @notice Check sanctions screening
    function _checkSanctions(address addr) internal view {
        if (sanctionsOracle != address(0)) {
            (bool success, bytes memory result) = sanctionsOracle.staticcall(
                abi.encodeWithSignature("isSanctioned(address)", addr)
            );
            if (success && result.length >= 32 && abi.decode(result, (bool))) {
                revert SanctionedAddress(addr);
            }
        }
    }

    /// @notice Safe ETH transfer
    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
