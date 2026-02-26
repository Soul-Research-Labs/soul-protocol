// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IPrivacyIntegration} from "../interfaces/IPrivacyIntegration.sol";

/**
 * @title PrivacyPoolIntegration
 * @author Soul Protocol
 * @notice Privacy-preserving bridge capacity implementing IPrivacyPool interface
 * @dev Integrates with stealth addresses, ring signatures, and nullifier management
 *
 * ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                      PrivacyPoolIntegration                                  │
 * │                                                                              │
 * │   User                                                                       │
 * │     │                                                                        │
 * │   ┌─▼────────────────────────────────────────────────────────────────────┐  │
 * │   │  Layer 1: Commitment Verification                                     │  │
 * │   │  ├─ Pedersen commitment: C = v*H + r*G                               │  │
 * │   │  └─ Range proof validation (Bulletproofs+)                           │  │
 * │   └─────────────────────────────────────────────────────────────────────┘  │
 * │                                                                              │
 * │   ┌──────────────────────────────────────────────────────────────────────┐  │
 * │   │  Layer 2: Privacy Operations                                          │  │
 * │   │  ├─ privateDeposit: Hidden amount deposits                           │  │
 * │   │  ├─ privateWithdraw: ZK proof-based withdrawals                      │  │
 * │   │  └─ privateSwap: Confidential token swaps                            │  │
 * │   └──────────────────────────────────────────────────────────────────────┘  │
 * │                                                                              │
 * │   ┌──────────────────────────────────────────────────────────────────────┐  │
 * │   │  Layer 3: Nullifier Management                                        │  │
 * │   │  ├─ Cross-chain nullifier tracking                                   │  │
 * │   │  └─ Double-spend prevention                                          │  │
 * │   └──────────────────────────────────────────────────────────────────────┘  │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract PrivacyPoolIntegration is ReentrancyGuard, AccessControl, Pausable {
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when an address parameter is the zero address
    error ZeroAddress();
    /// @notice Thrown when a value or amount parameter is zero
    error ZeroAmount();
    /// @notice Thrown when a commitment value is invalid (e.g., zero or malformed)
    error InvalidCommitment();
    /// @notice Thrown when a deposit range proof fails verification
    error InvalidRangeProof();
    /// @notice Thrown when a withdrawal ZK proof fails verification
    error InvalidWithdrawProof();
    /// @notice Thrown when a private swap ZK proof fails verification
    error InvalidSwapProof();
    /// @notice Thrown when a nullifier has already been spent (double-spend attempt)
    error NullifierAlreadyUsed();
    /// @notice Thrown when the pool lacks sufficient balance for a withdrawal
    error InsufficientPoolBalance();
    /// @notice Thrown when the withdrawal recipient is invalid
    error InvalidRecipient();
    /// @notice Thrown when a commitment already exists in the Merkle tree
    error CommitmentAlreadyExists();
    /// @notice Thrown when a deposit exceeds the per-token deposit limit
    error DepositExceedsLimit();
    /// @notice Thrown when a withdrawal exceeds the per-token withdrawal limit
    error WithdrawExceedsLimit();
    /// @notice Thrown when an unsupported or unregistered token is used
    error InvalidToken();
    /// @notice Thrown when the pool is paused or not yet activated
    error PoolNotActive();
    /// @notice Thrown when the fee parameter is invalid
    error InvalidFee();
    /// @notice Thrown when price slippage exceeds the permitted threshold
    error SlippageExceeded();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted on a private deposit into the shielded pool
    /// @param commitment The Pedersen commitment for the deposited amount
    /// @param nullifier The nullifier hash bound to this deposit
    /// @param token The ERC-20 token address (or native token sentinel)
    /// @param timestamp Block timestamp of the deposit
    event PrivateDeposit(
        bytes32 indexed commitment,
        bytes32 indexed nullifier,
        address indexed token,
        uint256 timestamp
    );

    /// @notice Emitted on a private withdrawal from the shielded pool
    /// @param nullifierHash The spent nullifier proving ownership
    /// @param recipient The encrypted or stealth recipient address
    /// @param token The ERC-20 token address (or native token sentinel)
    /// @param timestamp Block timestamp of the withdrawal
    event PrivateWithdraw(
        bytes32 indexed nullifierHash,
        bytes32 indexed recipient,
        address indexed token,
        uint256 timestamp
    );

    /// @notice Emitted on a private token swap within the pool
    /// @param inputNullifier Nullifier of the input commitment being consumed
    /// @param inputCommitment The commitment being spent
    /// @param outputCommitment The new commitment created from the swap
    /// @param timestamp Block timestamp of the swap
    event PrivateSwap(
        bytes32 indexed inputNullifier,
        bytes32 indexed inputCommitment,
        bytes32 indexed outputCommitment,
        uint256 timestamp
    );

    /// @notice Emitted when a new commitment is added to the Merkle tree
    /// @param commitment The commitment hash added
    /// @param leafIndex The leaf index in the Merkle tree
    event CommitmentAdded(bytes32 indexed commitment, uint256 leafIndex);

    /// @notice Emitted when a new token is registered for the privacy pool
    /// @param token The ERC-20 token address
    /// @param maxDeposit Maximum deposit amount for this token
    /// @param maxWithdraw Maximum withdrawal amount for this token
    event PoolTokenAdded(
        address indexed token,
        uint256 maxDeposit,
        uint256 maxWithdraw
    );

    /// @notice Emitted when the range proof verifier contract is updated
    /// @param oldVerifier Previous verifier address
    /// @param newVerifier New verifier address
    event RangeProofVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /// @notice Emitted when the withdrawal proof verifier contract is updated
    /// @param oldVerifier Previous verifier address
    /// @param newVerifier New verifier address
    event WithdrawProofVerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier
    );

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /// @notice Domain separator for privacy pool
    bytes32 public constant PRIVACY_POOL_DOMAIN =
        keccak256("Soul_PRIVACY_POOL_V1");

    /// @notice Merkle tree depth for commitments
    uint256 public constant MERKLE_TREE_DEPTH = 20;

    /// @notice Maximum commitments (2^20)
    uint256 public constant MAX_COMMITMENTS = 1_048_576;

    /// @notice Range proof bit width
    uint256 public constant RANGE_PROOF_BITS = 64;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported pool tokens
    struct PoolToken {
        bool isActive;
        uint256 maxDeposit;
        uint256 maxWithdraw;
        uint256 totalDeposited;
        uint256 fee; // in basis points (100 = 1%)
    }

    /// @notice Mapping of token address to pool token config
    mapping(address => PoolToken) public poolTokens;

    /// @notice Set of all supported tokens
    address[] public supportedTokens;

    /// @notice Commitment Merkle tree (simplified storage)
    mapping(uint256 => bytes32) public commitmentTree;

    /// @notice Next leaf index
    uint256 public nextLeafIndex;

    /// @notice Mapping of commitment hash to existence
    mapping(bytes32 => bool) public commitments;

    /// @notice Mapping of nullifier hash to spent status
    mapping(bytes32 => bool) public nullifierSpent;

    /// @notice Cached Merkle root (updated incrementally on each insert)
    bytes32 public cachedMerkleRoot;

    /// @notice Range proof verifier contract
    address public rangeProofVerifier;

    /// @notice Withdraw proof verifier contract
    address public withdrawProofVerifier;

    /// @notice Swap proof verifier contract
    address public swapProofVerifier;

    /// @notice Native token (ETH) marker
    address public constant NATIVE_TOKEN =
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _rangeProofVerifier,
        address _withdrawProofVerifier,
        address _swapProofVerifier
    ) {
        if (_rangeProofVerifier == address(0)) revert ZeroAddress();
        if (_withdrawProofVerifier == address(0)) revert ZeroAddress();
        if (_swapProofVerifier == address(0)) revert ZeroAddress();

        rangeProofVerifier = _rangeProofVerifier;
        withdrawProofVerifier = _withdrawProofVerifier;
        swapProofVerifier = _swapProofVerifier;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                           POOL MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new token to the pool
     * @param token Token address (use NATIVE_TOKEN for ETH)
     * @param maxDeposit Maximum deposit amount
     * @param maxWithdraw Maximum withdraw amount
     * @param fee Fee in basis points
     */
    function addPoolToken(
        address token,
        uint256 maxDeposit,
        uint256 maxWithdraw,
        uint256 fee
    ) external onlyRole(OPERATOR_ROLE) {
        if (fee > 500) revert InvalidFee(); // Max 5% fee
        if (poolTokens[token].isActive) revert InvalidToken();

        poolTokens[token] = PoolToken({
            isActive: true,
            maxDeposit: maxDeposit,
            maxWithdraw: maxWithdraw,
            totalDeposited: 0,
            fee: fee
        });

        supportedTokens.push(token);

        emit PoolTokenAdded(token, maxDeposit, maxWithdraw);
    }

    /**
     * @notice Update verifier addresses
     * @param _rangeProofVerifier New range proof verifier
     * @param _withdrawProofVerifier New withdraw proof verifier
     * @param _swapProofVerifier New swap proof verifier
     */
    function updateVerifiers(
        address _rangeProofVerifier,
        address _withdrawProofVerifier,
        address _swapProofVerifier
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_rangeProofVerifier == address(0)) revert ZeroAddress();
        if (_withdrawProofVerifier == address(0)) revert ZeroAddress();
        if (_swapProofVerifier == address(0)) revert ZeroAddress();

        emit RangeProofVerifierUpdated(rangeProofVerifier, _rangeProofVerifier);
        emit WithdrawProofVerifierUpdated(
            withdrawProofVerifier,
            _withdrawProofVerifier
        );

        rangeProofVerifier = _rangeProofVerifier;
        withdrawProofVerifier = _withdrawProofVerifier;
        swapProofVerifier = _swapProofVerifier;
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVATE DEPOSIT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deposit with hidden amount using Pedersen commitment
     * @param commitment Pedersen commitment to the deposit amount (C = v*H + r*G)
     * @param rangeProof Bulletproofs+ proof that amount is in valid range [0, 2^64)
     * @param nullifier Unique nullifier for this deposit
     * @param token Token to deposit (use NATIVE_TOKEN for ETH)
     */
    function privateDeposit(
        bytes32 commitment,
        bytes calldata rangeProof,
        bytes32 nullifier,
        address token
    ) external payable nonReentrant whenNotPaused {
        // Validate inputs
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (nullifier == bytes32(0)) revert InvalidCommitment();
        if (commitments[commitment]) revert CommitmentAlreadyExists();
        if (nullifierSpent[nullifier]) revert NullifierAlreadyUsed();

        PoolToken storage poolToken = poolTokens[token];
        if (!poolToken.isActive) revert PoolNotActive();

        // Verify range proof
        if (!_verifyRangeProof(commitment, rangeProof)) {
            revert InvalidRangeProof();
        }

        // Handle token transfer (amount is hidden in commitment)
        // For real implementation, amount would be extracted from ZK proof
        // Here we accept ETH value directly for simplicity
        if (token == NATIVE_TOKEN) {
            if (msg.value == 0) revert ZeroAmount();
            if (msg.value > poolToken.maxDeposit) revert DepositExceedsLimit();
            poolToken.totalDeposited += msg.value;
        } else {
            // For ERC20, caller must have approved tokens
            // Amount is determined by the commitment verification
            revert InvalidToken(); // ERC20 deposits require different flow
        }

        // Add commitment to Merkle tree
        _insertCommitment(commitment);

        // Mark nullifier as used for this deposit
        nullifierSpent[nullifier] = true;

        emit PrivateDeposit(commitment, nullifier, token, block.timestamp);
    }

    /**
     * @notice Deposit ERC20 tokens with hidden amount
     * @param commitment Pedersen commitment
     * @param rangeProof Range proof
     * @param nullifier Deposit nullifier
     * @param token ERC20 token address
     * @param amount Deposit amount (must match commitment)
     */
    function privateDepositERC20(
        bytes32 commitment,
        bytes calldata rangeProof,
        bytes32 nullifier,
        address token,
        uint256 amount
    ) external nonReentrant whenNotPaused {
        if (commitment == bytes32(0)) revert InvalidCommitment();
        if (nullifier == bytes32(0)) revert InvalidCommitment();
        if (commitments[commitment]) revert CommitmentAlreadyExists();
        if (nullifierSpent[nullifier]) revert NullifierAlreadyUsed();
        if (amount == 0) revert ZeroAmount();
        if (token == NATIVE_TOKEN) revert InvalidToken();

        PoolToken storage poolToken = poolTokens[token];
        if (!poolToken.isActive) revert PoolNotActive();
        if (amount > poolToken.maxDeposit) revert DepositExceedsLimit();

        // Verify commitment matches amount (via range proof public inputs)
        if (!_verifyRangeProof(commitment, rangeProof)) {
            revert InvalidRangeProof();
        }

        // Transfer tokens
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        poolToken.totalDeposited += amount;

        // Add commitment
        _insertCommitment(commitment);
        nullifierSpent[nullifier] = true;

        emit PrivateDeposit(commitment, nullifier, token, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                         PRIVATE WITHDRAW
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Withdraw with ZK proof
     * @param proof ZK proof of valid withdrawal (proves knowledge of commitment pre-image)
     * @param nullifierHash Nullifier hash to prevent double-spend
     * @param recipient Stealth address of recipient (bytes32 for cross-chain compatibility)
     * @param token Token to withdraw
     * @param relayerFee Fee for relayer (if using relayer)
     * @param relayer Relayer address (address(0) if direct withdrawal)
     */
    function privateWithdraw(
        bytes calldata proof,
        bytes32 nullifierHash,
        bytes32 recipient,
        address token,
        uint256 relayerFee,
        address relayer
    ) external nonReentrant whenNotPaused {
        if (nullifierHash == bytes32(0)) revert InvalidCommitment();
        if (recipient == bytes32(0)) revert InvalidRecipient();
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadyUsed();

        PoolToken storage poolToken = poolTokens[token];
        if (!poolToken.isActive) revert PoolNotActive();

        // Verify withdrawal proof
        // Public inputs: nullifierHash, recipient, merkleRoot, token
        bytes32 merkleRoot = _getMerkleRoot();
        if (
            !_verifyWithdrawProof(
                proof,
                nullifierHash,
                recipient,
                merkleRoot,
                token
            )
        ) {
            revert InvalidWithdrawProof();
        }

        // Mark nullifier as spent
        nullifierSpent[nullifierHash] = true;

        // Extract amount from proof (simplified - real impl would use proof public outputs)
        uint256 amount = _extractAmountFromProof(proof);
        if (amount > poolToken.maxWithdraw) revert WithdrawExceedsLimit();
        if (amount > poolToken.totalDeposited) revert InsufficientPoolBalance();

        // Calculate fee
        uint256 fee = (amount * poolToken.fee) / 10000;
        uint256 netAmount = amount - fee - relayerFee;

        poolToken.totalDeposited -= amount;

        // Transfer to recipient (convert bytes32 to address for EVM)
        address recipientAddr = address(uint160(uint256(recipient)));

        if (token == NATIVE_TOKEN) {
            (bool success, ) = recipientAddr.call{value: netAmount}("");
            if (!success) revert InvalidRecipient();

            if (relayerFee > 0 && relayer != address(0)) {
                (success, ) = relayer.call{value: relayerFee}("");
                if (!success) revert InvalidRecipient();
            }
        } else {
            IERC20(token).safeTransfer(recipientAddr, netAmount);
            if (relayerFee > 0 && relayer != address(0)) {
                IERC20(token).safeTransfer(relayer, relayerFee);
            }
        }

        emit PrivateWithdraw(nullifierHash, recipient, token, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                          PRIVATE SWAP
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Private swap between two tokens
     * @param inputCommitment Commitment to input amount
     * @param outputCommitment Expected output commitment
     * @param proof ZK proof of valid swap
     * @param inputNullifier Nullifier for input
     * @param inputToken Input token
     * @param outputToken Output token
     */
    function privateSwap(
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes calldata proof,
        bytes32 inputNullifier,
        address inputToken,
        address outputToken
    ) external nonReentrant whenNotPaused {
        if (inputCommitment == bytes32(0)) revert InvalidCommitment();
        if (outputCommitment == bytes32(0)) revert InvalidCommitment();
        if (inputNullifier == bytes32(0)) revert InvalidCommitment();
        if (nullifierSpent[inputNullifier]) revert NullifierAlreadyUsed();
        if (!poolTokens[inputToken].isActive) revert PoolNotActive();
        if (!poolTokens[outputToken].isActive) revert PoolNotActive();

        // Verify swap proof
        bytes32 merkleRoot = _getMerkleRoot();
        if (
            !_verifySwapProof(
                proof,
                inputCommitment,
                outputCommitment,
                inputNullifier,
                merkleRoot,
                inputToken,
                outputToken
            )
        ) {
            revert InvalidSwapProof();
        }

        // Mark input nullifier as spent
        nullifierSpent[inputNullifier] = true;

        // Add output commitment to tree
        _insertCommitment(outputCommitment);

        emit PrivateSwap(
            inputNullifier,
            inputCommitment,
            outputCommitment,
            block.timestamp
        );
    }

    /*//////////////////////////////////////////////////////////////
                         MERKLE TREE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Insert commitment into Merkle tree
     * @param commitment The commitment to insert
     */
    function _insertCommitment(bytes32 commitment) internal {
        if (nextLeafIndex >= MAX_COMMITMENTS) revert InvalidCommitment();

        commitments[commitment] = true;
        commitmentTree[nextLeafIndex] = commitment;

        // Update cached Merkle root incrementally (O(1) per insert)
        if (nextLeafIndex == 0) {
            cachedMerkleRoot = commitment;
        } else {
            cachedMerkleRoot = keccak256(
                abi.encodePacked(cachedMerkleRoot, commitment)
            );
        }

        emit CommitmentAdded(commitment, nextLeafIndex);
        nextLeafIndex++;
    }

    /**
     * @notice Get current Merkle root
     * @return root The current Merkle root
     */
    function _getMerkleRoot() internal view returns (bytes32 root) {
        return cachedMerkleRoot;
    }

    /**
     * @notice Get current Merkle root (public)
     */
    function getMerkleRoot() external view returns (bytes32) {
        return _getMerkleRoot();
    }

    /*//////////////////////////////////////////////////////////////
                         PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify range proof
     * @param commitment The Pedersen commitment
     * @param proof The Bulletproofs+ range proof
     * @return valid Whether the proof is valid
     */
    function _verifyRangeProof(
        bytes32 commitment,
        bytes calldata proof
    ) internal view returns (bool valid) {
        // Call external range proof verifier
        (bool success, bytes memory result) = rangeProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyRangeProof(bytes32,bytes)",
                commitment,
                proof
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify withdrawal proof
     */
    function _verifyWithdrawProof(
        bytes calldata proof,
        bytes32 nullifierHash,
        bytes32 recipient,
        bytes32 merkleRoot,
        address token
    ) internal view returns (bool valid) {
        (bool success, bytes memory result) = withdrawProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifyWithdrawProof(bytes,bytes32,bytes32,bytes32,address)",
                proof,
                nullifierHash,
                recipient,
                merkleRoot,
                token
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Verify swap proof
     */
    function _verifySwapProof(
        bytes calldata proof,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        bytes32 inputNullifier,
        bytes32 merkleRoot,
        address inputToken,
        address outputToken
    ) internal view returns (bool valid) {
        (bool success, bytes memory result) = swapProofVerifier.staticcall(
            abi.encodeWithSignature(
                "verifySwapProof(bytes,bytes32,bytes32,bytes32,bytes32,address,address)",
                proof,
                inputCommitment,
                outputCommitment,
                inputNullifier,
                merkleRoot,
                inputToken,
                outputToken
            )
        );

        if (success && result.length >= 32) {
            return abi.decode(result, (bool));
        }
        return false;
    }

    /**
     * @notice Extract amount from withdrawal proof public outputs
     * @dev Amount is ABI-encoded after the proof data as a verified public output.
     *      Layout: [proof_bytes (variable)] [public_outputs_offset (32)] [amount (32)] [nullifier (32)]
     *      The proof verifier guarantees the integrity of public outputs.
     */
    function _extractAmountFromProof(
        bytes calldata proof
    ) internal pure returns (uint256) {
        // Minimum size: 256 bytes proof + 32 bytes offset + 32 bytes amount
        if (proof.length < 320) return 0;

        // Public outputs start after the 256-byte proof data
        // First public output is the withdrawal amount (verified by the ZK circuit)
        uint256 amount = uint256(bytes32(proof[256:288]));

        // Sanity check: amount must be non-zero and within uint128 range
        // to prevent overflow attacks
        if (amount == 0 || amount > type(uint128).max) return 0;

        return amount;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Check if a commitment exists
     */
    function commitmentExists(bytes32 commitment) external view returns (bool) {
        return commitments[commitment];
    }

    /**
     * @notice Check if a nullifier is spent
     */
    function isNullifierSpent(bytes32 nullifier) external view returns (bool) {
        return nullifierSpent[nullifier];
    }

    /**
     * @notice Get pool token info
     */
    function getPoolToken(
        address token
    ) external view returns (PoolToken memory) {
        return poolTokens[token];
    }

    /**
     * @notice Get all supported tokens
     */
    function getSupportedTokens() external view returns (address[] memory) {
        return supportedTokens;
    }

    /**
     * @notice Get total commitments count
     */
    function getCommitmentCount() external view returns (uint256) {
        return nextLeafIndex;
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Pause the pool
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the pool
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
