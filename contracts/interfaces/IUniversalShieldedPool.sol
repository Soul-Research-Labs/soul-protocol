// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IUniversalShieldedPool
 * @author Soul Protocol
 * @notice Interface for the multi-asset shielded pool with cross-chain ZK deposits/withdrawals
 */
interface IUniversalShieldedPool {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct DepositNote {
        bytes32 commitment;
        bytes32 assetId;
        uint256 leafIndex;
        uint256 timestamp;
        bytes32 sourceChainId;
    }

    struct WithdrawalProof {
        bytes proof;
        bytes32 merkleRoot;
        bytes32 nullifier;
        address recipient;
        address relayerAddress;
        uint256 amount;
        uint256 relayerFee;
        bytes32 assetId;
        bytes32 destChainId;
    }

    struct CrossChainCommitmentBatch {
        bytes32 sourceChainId;
        bytes32[] commitments;
        bytes32[] assetIds;
        bytes32 batchRoot;
        bytes proof;
        uint256 sourceTreeSize;
    }

    struct AssetConfig {
        address tokenAddress;
        bytes32 assetId;
        uint256 totalDeposited;
        uint256 totalWithdrawn;
        bool active;
    }

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
                        DEPOSIT FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function depositETH(bytes32 commitment) external payable;

    function depositERC20(
        bytes32 assetId,
        uint256 amount,
        bytes32 commitment
    ) external;

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function withdraw(WithdrawalProof calldata wp) external;

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function insertCrossChainCommitments(
        CrossChainCommitmentBatch calldata batch
    ) external;

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerAsset(bytes32 assetId, address tokenAddress) external;

    function setWithdrawalVerifier(address _verifier) external;

    function disableTestMode() external;

    function setBatchVerifier(address _verifier) external;

    function setSanctionsOracle(address _oracle) external;

    function deactivateAsset(bytes32 assetId) external;

    function pause() external;

    function unpause() external;

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getLastRoot() external view returns (bytes32);

    function isKnownRoot(bytes32 root) external view returns (bool);

    function isSpent(bytes32 nullifier) external view returns (bool);

    function getPoolStats()
        external
        view
        returns (
            uint256 deposits,
            uint256 withdrawalsCount,
            uint256 crossChainDeposits,
            uint256 treeSize,
            bytes32 root
        );

    function getRegisteredAssets() external view returns (bytes32[] memory);
}
