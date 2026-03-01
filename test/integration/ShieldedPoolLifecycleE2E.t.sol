// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {UniversalShieldedPool} from "../../contracts/privacy/UniversalShieldedPool.sol";
import {IUniversalShieldedPool} from "../../contracts/interfaces/IUniversalShieldedPool.sol";

/// @dev Mock verifier that accepts all proofs (for integration test flow)
contract MockShieldedPoolVerifier {
    bool public result = true;

    function setResult(bool _result) external {
        result = _result;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }
}

/// @dev Mock batch verifier for cross-chain commitment testing
contract MockShieldedPoolBatchVerifier {
    bool public result = true;

    function setResult(bool _result) external {
        result = _result;
    }

    function verify(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }
}

/**
 * @title ShieldedPoolLifecycleE2E
 * @notice Full lifecycle E2E test for the UniversalShieldedPool:
 *         deposit → verify state → withdraw with proof → verify finality
 *         + multi-deposit, cross-chain commitment insertion, relayer fee flow
 * @dev Tests the complete happy path and edge cases of the privacy pool
 */
contract ShieldedPoolLifecycleE2E is Test {
    UniversalShieldedPool public pool;
    MockShieldedPoolVerifier public verifier;
    MockShieldedPoolBatchVerifier public batchVerifier;

    address public admin = makeAddr("admin");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public relayer = makeAddr("relayer");
    address public recipient = makeAddr("recipient");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    uint256 internal constant FIELD_SIZE =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 public NATIVE_ASSET;

    function _validCommitment(
        bytes memory seed
    ) internal pure returns (bytes32) {
        return bytes32((uint256(keccak256(seed)) % (FIELD_SIZE - 1)) + 1);
    }

    function setUp() public {
        vm.startPrank(admin);
        verifier = new MockShieldedPoolVerifier();
        batchVerifier = new MockShieldedPoolBatchVerifier();
        pool = new UniversalShieldedPool(admin, address(verifier), false);
        pool.grantRole(RELAYER_ROLE, relayer);
        pool.setBatchVerifier(address(batchVerifier));
        NATIVE_ASSET = pool.NATIVE_ASSET();
        vm.stopPrank();

        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Full deposit → withdraw lifecycle (ETH)
    // ═════════════════════════════════════════════════════════════

    function test_E2E_FullETHDepositWithdrawLifecycle() public {
        uint256 depositAmount = 1 ether;
        bytes32 commitment = _validCommitment(
            abi.encodePacked("secret1", depositAmount)
        );
        bytes32 nullifier = keccak256(abi.encodePacked("nullifier1"));

        // --- Phase 1: Deposit ---
        vm.prank(user1);
        pool.depositETH{value: depositAmount}(commitment);

        // Verify deposit state
        assertEq(pool.nextLeafIndex(), 1, "Leaf index should be 1");
        assertEq(pool.totalDeposits(), 1, "Deposit count should be 1");
        assertTrue(
            pool.commitmentExists(commitment),
            "Commitment should exist"
        );
        assertEq(address(pool).balance, depositAmount, "Pool should hold ETH");

        // Capture Merkle root after deposit
        bytes32 merkleRoot = pool.currentRoot();
        assertTrue(pool.isKnownRoot(merkleRoot), "Root should be known");

        // --- Phase 2: Withdraw with ZK proof ---
        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"deadbeef",
                merkleRoot: merkleRoot,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: depositAmount,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: 0
            });

        pool.withdraw(wp);

        // --- Phase 3: Verify withdrawal finality ---
        assertTrue(pool.isSpent(nullifier), "Nullifier should be spent");
        assertEq(
            recipient.balance,
            depositAmount,
            "Recipient should receive ETH"
        );
        assertEq(address(pool).balance, 0, "Pool should be drained");
        assertEq(pool.totalWithdrawals(), 1, "Withdrawal count should be 1");

        // --- Phase 4: Double-spend prevention ---
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalShieldedPool.NullifierAlreadySpent.selector,
                nullifier
            )
        );
        pool.withdraw(wp);
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Multi-deposit + selective withdrawal
    // ═════════════════════════════════════════════════════════════

    function test_E2E_MultiDepositSelectiveWithdraw() public {
        uint256 amount1 = 1 ether;
        uint256 amount2 = 2 ether;
        uint256 amount3 = 0.5 ether;

        bytes32 commit1 = _validCommitment(
            abi.encodePacked("secret-a", amount1)
        );
        bytes32 commit2 = _validCommitment(
            abi.encodePacked("secret-b", amount2)
        );
        bytes32 commit3 = _validCommitment(
            abi.encodePacked("secret-c", amount3)
        );

        // Deposit 3 notes
        vm.startPrank(user1);
        pool.depositETH{value: amount1}(commit1);
        pool.depositETH{value: amount2}(commit2);
        pool.depositETH{value: amount3}(commit3);
        vm.stopPrank();

        assertEq(pool.nextLeafIndex(), 3, "Leaf index should be 3");
        assertEq(pool.totalDeposits(), 3, "Should have 3 deposits");
        assertEq(
            address(pool).balance,
            amount1 + amount2 + amount3,
            "Pool balance"
        );

        bytes32 root = pool.currentRoot();

        // Withdraw only note 2 (2 ETH)
        bytes32 nullifier2 = keccak256(abi.encodePacked("null-b"));
        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"cafe",
                merkleRoot: root,
                nullifier: nullifier2,
                recipient: recipient,
                relayerAddress: address(0),
                amount: amount2,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: 0
            });

        pool.withdraw(wp);

        // Only note 2 withdrawn; notes 1 and 3 remain
        assertEq(recipient.balance, amount2);
        assertEq(address(pool).balance, amount1 + amount3);
        assertTrue(pool.isSpent(nullifier2));
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Withdrawal with relayer fee
    // ═════════════════════════════════════════════════════════════

    function test_E2E_WithdrawWithRelayerFee() public {
        uint256 depositAmount = 5 ether;
        uint256 relayerFee = 0.1 ether;
        bytes32 commitment = _validCommitment(abi.encodePacked("relayer-test"));
        bytes32 nullifier = keccak256("relayer-null");

        // Deposit
        vm.prank(user1);
        pool.depositETH{value: depositAmount}(commitment);

        bytes32 root = pool.currentRoot();

        // Withdraw with relayer fee
        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"beef",
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: relayer,
                amount: depositAmount,
                relayerFee: relayerFee,
                assetId: NATIVE_ASSET,
                destChainId: 0
            });

        pool.withdraw(wp);

        // Recipient gets amount minus fee, relayer gets fee
        assertEq(
            recipient.balance,
            depositAmount - relayerFee,
            "Recipient net amount"
        );
        assertEq(relayer.balance, relayerFee, "Relayer fee");
        assertEq(address(pool).balance, 0, "Pool fully drained");
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Invalid proof rejection
    // ═════════════════════════════════════════════════════════════

    function test_E2E_InvalidProofRejected() public {
        bytes32 commitment = _validCommitment(abi.encodePacked("reject-test"));

        vm.prank(user1);
        pool.depositETH{value: 1 ether}(commitment);

        bytes32 root = pool.currentRoot();

        // Make verifier reject proofs
        verifier.setResult(false);

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"baad",
                merkleRoot: root,
                nullifier: keccak256("reject-null"),
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: 0
            });

        vm.expectRevert(IUniversalShieldedPool.WithdrawalProofFailed.selector);
        pool.withdraw(wp);

        // Pool funds untouched
        assertEq(address(pool).balance, 1 ether);
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Cross-chain commitment batch insertion
    // ═════════════════════════════════════════════════════════════

    function test_E2E_CrossChainCommitmentBatch() public {
        // Create commitments "deposited on another chain"
        bytes32 commit1 = _validCommitment(abi.encodePacked("remote-1"));
        bytes32 commit2 = _validCommitment(abi.encodePacked("remote-2"));

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = commit1;
        commitments[1] = commit2;

        bytes32 batchRoot = keccak256(abi.encodePacked(commit1, commit2));

        bytes32[] memory assetIds = new bytes32[](2);
        assetIds[0] = NATIVE_ASSET;
        assetIds[1] = NATIVE_ASSET;

        IUniversalShieldedPool.CrossChainCommitmentBatch memory batch = IUniversalShieldedPool
            .CrossChainCommitmentBatch({
                sourceChainId: bytes32(uint256(42161)), // Arbitrum
                commitments: commitments,
                assetIds: assetIds,
                batchRoot: batchRoot,
                proof: hex"ba7c400f",
                sourceTreeSize: 100
            });

        // Only relayer can insert cross-chain commitments
        vm.prank(relayer);
        pool.insertCrossChainCommitments(batch);

        // Commitments are now in the local tree
        assertTrue(
            pool.commitmentExists(commit1),
            "Remote commit 1 should exist"
        );
        assertTrue(
            pool.commitmentExists(commit2),
            "Remote commit 2 should exist"
        );
        assertEq(pool.nextLeafIndex(), 2, "Two leaves inserted");

        // Can now withdraw against these commitments locally
        bytes32 root = pool.currentRoot();
        bytes32 nullifier = keccak256("remote-null-1");

        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"00c4a10e",
                merkleRoot: root,
                nullifier: nullifier,
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: 0
            });

        // Fund pool to cover the cross-chain withdrawal
        vm.deal(address(pool), 1 ether);
        pool.withdraw(wp);

        assertEq(
            recipient.balance,
            1 ether,
            "Cross-chain withdrawal succeeded"
        );
        assertTrue(pool.isSpent(nullifier));
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Merkle root history validation
    // ═════════════════════════════════════════════════════════════

    function test_E2E_MerkleRootHistoryPreserved() public {
        // Deposit 1 → capture root
        bytes32 commit1 = _validCommitment(abi.encodePacked("root-test-1"));
        vm.prank(user1);
        pool.depositETH{value: 1 ether}(commit1);
        bytes32 root1 = pool.currentRoot();

        // Deposit 2 → root changes
        bytes32 commit2 = _validCommitment(abi.encodePacked("root-test-2"));
        vm.prank(user1);
        pool.depositETH{value: 1 ether}(commit2);
        bytes32 root2 = pool.currentRoot();

        assertTrue(root1 != root2, "Roots should differ after deposits");

        // Both roots should be known (within history window)
        assertTrue(pool.isKnownRoot(root1), "Root1 should still be valid");
        assertTrue(pool.isKnownRoot(root2), "Root2 should be valid");

        // Can withdraw against old root
        IUniversalShieldedPool.WithdrawalProof
            memory wp = IUniversalShieldedPool.WithdrawalProof({
                proof: hex"01d200fe",
                merkleRoot: root1,
                nullifier: keccak256("root-null-1"),
                recipient: recipient,
                relayerAddress: address(0),
                amount: 1 ether,
                relayerFee: 0,
                assetId: NATIVE_ASSET,
                destChainId: 0
            });

        pool.withdraw(wp);
        assertEq(
            recipient.balance,
            1 ether,
            "Withdrawal against old root succeeded"
        );
    }
}
