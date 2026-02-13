// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/EthereumL1Bridge.sol";

/// @dev Expose internal/virtual helper for testing blob hash (EIP-4844)
contract TestableEthereumL1Bridge is EthereumL1Bridge {
    bytes32 public mockBlobHash;

    function setMockBlobHash(bytes32 h) external {
        mockBlobHash = h;
    }

    function _getBlobHash(uint256) internal view override returns (bytes32) {
        return mockBlobHash;
    }
}

/// @title EthereumL1Bridge Extended Fuzz Tests
/// @notice Covers commitment lifecycle, challenge/finalization, deposits,
///         withdrawals + Merkle proof, proof relay, rate limiting, pausing, EIP-4844.
contract EthereumL1BridgeExtendedFuzz is Test {
    TestableEthereumL1Bridge public bridge;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public operator = address(0xC);
    address public guardian = address(0xD);
    address public user1 = address(0xF1);
    address public user2 = address(0xF2);

    bytes32 internal RELAYER_ROLE;
    bytes32 internal OPERATOR_ROLE;
    bytes32 internal GUARDIAN_ROLE;

    function setUp() public {
        vm.prank(admin);
        bridge = new TestableEthereumL1Bridge();

        RELAYER_ROLE = bridge.RELAYER_ROLE();
        OPERATOR_ROLE = bridge.OPERATOR_ROLE();
        GUARDIAN_ROLE = bridge.GUARDIAN_ROLE();

        vm.startPrank(admin);
        bridge.grantRole(RELAYER_ROLE, relayer);
        bridge.grantRole(OPERATOR_ROLE, operator);
        bridge.grantRole(GUARDIAN_ROLE, guardian);
        vm.stopPrank();

        vm.deal(relayer, 100 ether);
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(guardian, 10 ether);
    }

    // =====================================================================
    // Section 1 — L2 Chain Configuration
    // =====================================================================

    function test_constructorConfigures7Chains() public view {
        uint256[] memory chains = bridge.getSupportedChainIds();
        assertGe(chains.length, 7, "should configure >= 7 L2s");
        EthereumL1Bridge.L2Config memory arb = bridge.getL2Config(42161);
        assertEq(arb.chainId, 42161);
        assertTrue(arb.enabled);
    }

    function testFuzz_configureL2Chain(uint256 chainId) public {
        chainId = bound(chainId, 1_000_000, 9_999_999);
        EthereumL1Bridge.L2Config memory cfg = _makeL2Config(chainId);
        vm.prank(operator);
        bridge.configureL2Chain(cfg);
        EthereumL1Bridge.L2Config memory stored = bridge.getL2Config(chainId);
        assertEq(stored.chainId, chainId);
        assertTrue(stored.enabled);
    }

    function testFuzz_configureL2Chain_operatorOnly(address caller) public {
        vm.assume(caller != operator && caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        bridge.configureL2Chain(_makeL2Config(999_999));
    }

    function testFuzz_setCanonicalBridge(address newBridge) public {
        vm.assume(newBridge != address(0));
        vm.prank(operator);
        bridge.setCanonicalBridge(42161, newBridge);
        assertEq(bridge.getL2Config(42161).canonicalBridge, newBridge);
    }

    function test_setCanonicalBridgeZeroReverts() public {
        vm.prank(operator);
        vm.expectRevert(EthereumL1Bridge.ZeroAddress.selector);
        bridge.setCanonicalBridge(42161, address(0));
    }

    function test_setChainEnabledUnsupportedReverts() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotSupported.selector,
                12345
            )
        );
        bridge.setChainEnabled(12345, true);
    }

    // =====================================================================
    // Section 2 — State Commitment Submission
    // =====================================================================

    function testFuzz_submitStateCommitment_optimistic(
        bytes32 stateRoot,
        bytes32 proofRoot,
        uint256 blockNum
    ) public {
        vm.assume(stateRoot != bytes32(0) && proofRoot != bytes32(0));
        blockNum = bound(blockNum, 1, 1e12);

        uint256 prev = bridge.totalCommitments();
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            stateRoot,
            proofRoot,
            blockNum
        );
        assertEq(bridge.totalCommitments(), prev + 1);
    }

    function testFuzz_submitStateCommitment_insufficientBond(
        uint256 bondAmt
    ) public {
        uint256 minBond = bridge.minSubmissionBond();
        bondAmt = bound(bondAmt, 0, minBond - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.InsufficientBond.selector,
                bondAmt,
                minBond
            )
        );
        vm.prank(relayer);
        bridge.submitStateCommitment{value: bondAmt}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
    }

    function test_submitStateCommitment_unsupportedChainReverts() public {
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotSupported.selector,
                12345
            )
        );
        bridge.submitStateCommitment{value: 0.1 ether}(
            12345,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
    }

    function test_submitStateCommitment_noRelayerReverts() public {
        vm.prank(user1);
        vm.expectRevert();
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
    }

    function test_submitStateCommitment_disabledChainReverts() public {
        vm.prank(operator);
        bridge.setChainEnabled(42161, false);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotEnabled.selector,
                42161
            )
        );
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
    }

    function test_submitStateCommitment_duplicateReverts() public {
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
    }

    function test_submitStateCommitment_zkRollupInstantFinality() public {
        bytes32 stateRoot = bytes32(uint256(42));
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            324,
            stateRoot,
            bytes32(uint256(2)),
            100
        );
        assertEq(bridge.getLatestStateRoot(324), stateRoot);
    }

    // =====================================================================
    // Section 3 — EIP-4844 Blob Commitments
    // =====================================================================

    function testFuzz_submitStateCommitmentWithBlob(
        bytes32 blobHash,
        bytes32 stateRoot,
        bytes32 proofRoot
    ) public {
        vm.assume(
            blobHash != bytes32(0) &&
                stateRoot != bytes32(0) &&
                proofRoot != bytes32(0)
        );
        bridge.setMockBlobHash(blobHash);
        vm.prank(relayer);
        bridge.submitStateCommitmentWithBlob{value: 0.1 ether}(
            42161,
            stateRoot,
            proofRoot,
            100,
            0
        );
    }

    function test_submitStateCommitmentWithBlobZeroBlobReverts() public {
        bridge.setMockBlobHash(bytes32(0));
        vm.prank(relayer);
        vm.expectRevert(EthereumL1Bridge.InvalidBlobIndex.selector);
        bridge.submitStateCommitmentWithBlob{value: 0.1 ether}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100,
            0
        );
    }

    // =====================================================================
    // Section 4 — Challenge Lifecycle
    // =====================================================================

    function test_challengeCommitment_happyPath() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));

        vm.prank(user1);
        bridge.challengeCommitment{value: 0.05 ether}(cId, bytes32("fraud"));
    }

    function test_challengeCommitment_insufficientBondReverts() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.InsufficientChallengeBond.selector,
                0.01 ether,
                0.05 ether
            )
        );
        bridge.challengeCommitment{value: 0.01 ether}(cId, bytes32("fraud"));
    }

    function test_challengeCommitment_afterDeadlineReverts() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(user1);
        vm.expectRevert();
        bridge.challengeCommitment{value: 0.05 ether}(cId, bytes32("fraud"));
    }

    function test_resolveChallenge_reject() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));
        vm.prank(user1);
        bridge.challengeCommitment{value: 0.05 ether}(cId, bytes32("fraud"));

        uint256 balBefore = user1.balance;
        vm.prank(guardian);
        bridge.resolveChallenge(cId, true);
        assertGt(user1.balance, balBefore, "challenger should receive bonds");
    }

    function test_resolveChallenge_uphold() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));
        vm.prank(user1);
        bridge.challengeCommitment{value: 0.05 ether}(cId, bytes32("fraud"));

        uint256 submitterBal = relayer.balance;
        vm.prank(guardian);
        bridge.resolveChallenge(cId, false);
        assertGt(
            relayer.balance,
            submitterBal,
            "submitter should receive challenger bond"
        );
    }

    function test_resolveChallenge_nonGuardianReverts() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));
        vm.prank(user1);
        bridge.challengeCommitment{value: 0.05 ether}(cId, bytes32("fraud"));

        vm.prank(user2);
        vm.expectRevert();
        bridge.resolveChallenge(cId, true);
    }

    function test_resolveChallenge_notChallengedReverts() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(1)));
        vm.prank(guardian);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.CommitmentNotChallenged.selector,
                cId
            )
        );
        bridge.resolveChallenge(cId, true);
    }

    // =====================================================================
    // Section 5 — Commitment Finalization
    // =====================================================================

    function test_finalizeCommitment_afterChallengePeriod() public {
        bytes32 stateRoot = bytes32(uint256(7));
        bytes32 cId = _submitOptimistic(42161, stateRoot);

        vm.warp(block.timestamp + 7 days + 1);
        uint256 relayerBal = relayer.balance;
        bridge.finalizeCommitment(cId);

        assertEq(bridge.getLatestStateRoot(42161), stateRoot);
        assertGt(relayer.balance, relayerBal, "bond returned");
    }

    function test_finalizeCommitment_beforeDeadlineReverts() public {
        bytes32 cId = _submitOptimistic(42161, bytes32(uint256(7)));
        vm.expectRevert();
        bridge.finalizeCommitment(cId);
    }

    // =====================================================================
    // Section 6 — Deposits (L1 → L2)
    // =====================================================================

    function testFuzz_depositETH(uint256 amount) public {
        amount = bound(amount, 1, 10 ether);
        uint256 prev = bridge.totalDeposits();
        vm.prank(user1);
        bridge.depositETH{value: amount}(42161, bytes32(uint256(1)));
        assertEq(bridge.totalDeposits(), prev + 1);
    }

    function test_depositETH_zeroValueReverts() public {
        vm.prank(user1);
        vm.expectRevert(EthereumL1Bridge.ZeroAmount.selector);
        bridge.depositETH{value: 0}(42161, bytes32(uint256(1)));
    }

    function test_depositETH_zeroCommitmentReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.InvalidCommitment.selector,
                bytes32(0)
            )
        );
        vm.prank(user1);
        bridge.depositETH{value: 1 ether}(42161, bytes32(0));
    }

    function test_depositETH_unsupportedChainReverts() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotSupported.selector,
                99999
            )
        );
        bridge.depositETH{value: 1 ether}(99999, bytes32(uint256(1)));
    }

    function test_depositETH_disabledChainReverts() public {
        vm.prank(operator);
        bridge.setChainEnabled(42161, false);
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.ChainNotEnabled.selector,
                42161
            )
        );
        bridge.depositETH{value: 1 ether}(42161, bytes32(uint256(1)));
    }

    function test_depositETH_pausedReverts() public {
        vm.prank(guardian);
        bridge.pause();
        vm.prank(user1);
        vm.expectRevert();
        bridge.depositETH{value: 1 ether}(42161, bytes32(uint256(1)));
    }

    // =====================================================================
    // Section 7 — Withdrawals with Merkle Proof
    // =====================================================================

    function testFuzz_initiateWithdrawal_validProof(
        bytes32 nullifier,
        uint256 amount
    ) public {
        vm.assume(nullifier != bytes32(0));
        amount = bound(amount, 1, 50 ether);

        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        bytes32 sibling = keccak256("sibling");
        bytes32 root = _hashPair(leaf, sibling);

        _finalizeStateRoot(42161, root);
        vm.deal(address(bridge), amount + 5 ether);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;

        vm.prank(user1);
        bridge.initiateWithdrawal(42161, amount, nullifier, proof);
        assertTrue(bridge.isNullifierUsed(nullifier));
    }

    function test_initiateWithdrawal_duplicateNullifierReverts() public {
        bytes32 nullifier = bytes32(uint256(0xDEAD));
        uint256 amount = 1 ether;
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        bytes32 sibling = keccak256("sibling");
        bytes32 root = _hashPair(leaf, sibling);
        _finalizeStateRoot(42161, root);
        vm.deal(address(bridge), 10 ether);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        vm.prank(user1);
        bridge.initiateWithdrawal(42161, amount, nullifier, proof);

        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.initiateWithdrawal(42161, amount, nullifier, proof);
    }

    function test_initiateWithdrawal_invalidProofReverts() public {
        _finalizeStateRoot(42161, bytes32(uint256(42)));
        bytes32[] memory bad = new bytes32[](1);
        bad[0] = bytes32(uint256(0x999));
        vm.prank(user1);
        vm.expectRevert(EthereumL1Bridge.InvalidProof.selector);
        bridge.initiateWithdrawal(42161, 1 ether, bytes32(uint256(1)), bad);
    }

    function test_initiateWithdrawal_zeroAmountReverts() public {
        _finalizeStateRoot(42161, bytes32(uint256(42)));
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = bytes32(uint256(1));
        vm.prank(user1);
        vm.expectRevert(EthereumL1Bridge.ZeroAmount.selector);
        bridge.initiateWithdrawal(42161, 0, bytes32(uint256(1)), proof);
    }

    function test_initiateWithdrawal_emptyProofReverts() public {
        _finalizeStateRoot(42161, bytes32(uint256(42)));
        bytes32[] memory empty = new bytes32[](0);
        vm.prank(user1);
        vm.expectRevert(EthereumL1Bridge.InvalidProof.selector);
        bridge.initiateWithdrawal(42161, 1 ether, bytes32(uint256(1)), empty);
    }

    // =====================================================================
    // Section 8 — Withdrawal Finalization & Claiming
    // =====================================================================

    function test_finalizeAndClaim_optimistic() public {
        (bytes32 wId, ) = _setupWithdrawal(42161, 1 ether);

        // Before challenge period — cannot finalize
        vm.expectRevert();
        bridge.finalizeWithdrawal(wId);

        EthereumL1Bridge.L2Config memory cfg = bridge.getL2Config(42161);
        vm.warp(block.timestamp + cfg.challengePeriod + 1);
        bridge.finalizeWithdrawal(wId);

        uint256 balBefore = user1.balance;
        bridge.claimWithdrawal(wId);
        assertEq(user1.balance, balBefore + 1 ether);
    }

    function test_claimWithdrawal_notFinalizedReverts() public {
        (bytes32 wId, ) = _setupWithdrawal(42161, 1 ether);
        vm.expectRevert(
            abi.encodeWithSelector(
                EthereumL1Bridge.WithdrawalNotFinalized.selector,
                wId
            )
        );
        bridge.claimWithdrawal(wId);
    }

    function test_claimWithdrawal_doubleClaimReverts() public {
        (bytes32 wId, ) = _setupWithdrawal(42161, 1 ether);
        EthereumL1Bridge.L2Config memory cfg = bridge.getL2Config(42161);
        vm.warp(block.timestamp + cfg.challengePeriod + 1);
        bridge.finalizeWithdrawal(wId);
        bridge.claimWithdrawal(wId);

        vm.expectRevert(EthereumL1Bridge.AlreadyClaimed.selector);
        bridge.claimWithdrawal(wId);
    }

    function test_finalizeAndClaim_zkRollupInstant() public {
        (bytes32 wId, ) = _setupWithdrawal(324, 1 ether);
        // ZK rollup → already finalized
        uint256 bal = user1.balance;
        bridge.claimWithdrawal(wId);
        assertEq(user1.balance, bal + 1 ether);
    }

    // =====================================================================
    // Section 9 — Proof Relay
    // =====================================================================

    function testFuzz_relayProof(bytes32 proofHash) public {
        vm.assume(proofHash != bytes32(0));
        bytes32 sr = bytes32(uint256(42));
        _finalizeStateRoot(42161, sr);
        vm.prank(relayer);
        bridge.relayProof(42161, proofHash, sr, "");
        assertTrue(bridge.relayedProofs(proofHash));
    }

    function test_relayProof_duplicateReverts() public {
        bytes32 sr = bytes32(uint256(42));
        _finalizeStateRoot(42161, sr);
        bytes32 ph = keccak256("p1");
        vm.prank(relayer);
        bridge.relayProof(42161, ph, sr, "");
        vm.prank(relayer);
        vm.expectRevert();
        bridge.relayProof(42161, ph, sr, "");
    }

    function test_relayProof_mismatchedRootReverts() public {
        _finalizeStateRoot(42161, bytes32(uint256(42)));
        vm.prank(relayer);
        vm.expectRevert();
        bridge.relayProof(42161, keccak256("p1"), bytes32(uint256(99)), "");
    }

    function test_relayProof_nonRelayerReverts() public {
        _finalizeStateRoot(42161, bytes32(uint256(42)));
        vm.prank(user1);
        vm.expectRevert();
        bridge.relayProof(42161, keccak256("p1"), bytes32(uint256(42)), "");
    }

    // =====================================================================
    // Section 10 — Rate Limiting
    // =====================================================================

    function test_rateLimit_exceedsMaxReverts() public {
        vm.prank(operator);
        bridge.setMaxCommitmentsPerHour(3);

        for (uint256 i = 1; i <= 3; i++) {
            vm.prank(relayer);
            bridge.submitStateCommitment{value: 0.1 ether}(
                42161,
                bytes32(i),
                bytes32(i + 100),
                i
            );
        }

        vm.prank(relayer);
        vm.expectRevert(EthereumL1Bridge.RateLimitExceeded.selector);
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(4)),
            bytes32(uint256(104)),
            4
        );
    }

    function test_rateLimit_resetsAfterOneHour() public {
        vm.prank(operator);
        bridge.setMaxCommitmentsPerHour(2);

        for (uint256 i = 1; i <= 2; i++) {
            vm.prank(relayer);
            bridge.submitStateCommitment{value: 0.1 ether}(
                42161,
                bytes32(i),
                bytes32(i + 100),
                i
            );
        }

        vm.warp(block.timestamp + 1 hours);
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(10)),
            bytes32(uint256(110)),
            10
        );
    }

    // =====================================================================
    // Section 11 — Admin Functions
    // =====================================================================

    function testFuzz_setMinSubmissionBond(uint256 newBond) public {
        vm.prank(operator);
        bridge.setMinSubmissionBond(newBond);
        assertEq(bridge.minSubmissionBond(), newBond);
    }

    function testFuzz_setMaxCommitmentsPerHour(uint256 max) public {
        vm.prank(operator);
        bridge.setMaxCommitmentsPerHour(max);
        assertEq(bridge.maxCommitmentsPerHour(), max);
    }

    function test_pauseUnpause() public {
        vm.prank(guardian);
        bridge.pause();
        assertTrue(bridge.paused());
        vm.prank(operator);
        bridge.unpause();
        assertFalse(bridge.paused());
    }

    function test_pauseBlocksCommitments() public {
        vm.prank(guardian);
        bridge.pause();
        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitStateCommitment{value: 0.1 ether}(
            42161,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            100
        );
    }

    function test_receiveETH() public {
        vm.prank(user1);
        (bool ok, ) = address(bridge).call{value: 1 ether}("");
        assertTrue(ok, "bridge accepts raw ETH");
    }

    // =====================================================================
    // Section 12 — Multi-depth Merkle proof fuzz
    // =====================================================================

    function testFuzz_merkleProof_depth2(
        bytes32 nullifier,
        uint256 amount
    ) public {
        vm.assume(nullifier != bytes32(0));
        amount = bound(amount, 1, 10 ether);

        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        bytes32 s0 = keccak256("s0");
        bytes32 level1 = _hashPair(leaf, s0);
        bytes32 s1 = keccak256("s1");
        bytes32 root = _hashPair(level1, s1);

        _finalizeStateRoot(42161, root);
        vm.deal(address(bridge), amount + 5 ether);

        bytes32[] memory proof = new bytes32[](2);
        proof[0] = s0;
        proof[1] = s1;

        vm.prank(user1);
        bridge.initiateWithdrawal(42161, amount, nullifier, proof);
        assertTrue(bridge.isNullifierUsed(nullifier));
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    function _makeL2Config(
        uint256 chainId
    ) internal pure returns (EthereumL1Bridge.L2Config memory) {
        return
            EthereumL1Bridge.L2Config({
                chainId: chainId,
                name: "TestL2",
                rollupType: EthereumL1Bridge.RollupType.OPTIMISTIC,
                canonicalBridge: address(0x1),
                messenger: address(0x2),
                stateCommitmentChain: address(0x3),
                challengePeriod: 7 days,
                confirmationBlocks: 10,
                enabled: true,
                gasLimit: 200000,
                lastSyncedBlock: 0
            });
    }

    function _submitOptimistic(
        uint256 chainId,
        bytes32 stateRoot
    ) internal returns (bytes32) {
        bytes32 proofRoot = keccak256(abi.encodePacked(stateRoot, "proof"));
        uint256 blockNum = 100;
        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            chainId,
            stateRoot,
            proofRoot,
            blockNum
        );
        return
            keccak256(
                abi.encodePacked(
                    chainId,
                    stateRoot,
                    proofRoot,
                    blockNum,
                    block.timestamp,
                    bytes32(0)
                )
            );
    }

    function _finalizeStateRoot(uint256 chainId, bytes32 stateRoot) internal {
        bytes32 proofRoot = keccak256(abi.encodePacked(stateRoot, "finalize"));
        uint256 blockNum = 50;
        EthereumL1Bridge.L2Config memory cfg = bridge.getL2Config(chainId);

        vm.prank(relayer);
        bridge.submitStateCommitment{value: 0.1 ether}(
            chainId,
            stateRoot,
            proofRoot,
            blockNum
        );

        if (cfg.rollupType != EthereumL1Bridge.RollupType.ZK_ROLLUP) {
            bytes32 cId = keccak256(
                abi.encodePacked(
                    chainId,
                    stateRoot,
                    proofRoot,
                    blockNum,
                    block.timestamp,
                    bytes32(0)
                )
            );
            vm.warp(block.timestamp + cfg.challengePeriod + 1);
            bridge.finalizeCommitment(cId);
        }
    }

    function _setupWithdrawal(
        uint256 chainId,
        uint256 amount
    ) internal returns (bytes32, bytes32) {
        bytes32 nullifier = keccak256(
            abi.encodePacked("null", chainId, amount)
        );
        bytes32 leaf = keccak256(abi.encodePacked(nullifier, amount));
        bytes32 sibling = keccak256("sibling");
        bytes32 root = _hashPair(leaf, sibling);

        _finalizeStateRoot(chainId, root);
        vm.deal(address(bridge), amount + 5 ether);

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        vm.prank(user1);
        bridge.initiateWithdrawal(chainId, amount, nullifier, proof);

        bytes32 wId = keccak256(
            abi.encodePacked(user1, chainId, amount, nullifier, block.timestamp)
        );
        return (wId, nullifier);
    }

    function _hashPair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return
            a < b
                ? keccak256(abi.encodePacked(a, b))
                : keccak256(abi.encodePacked(b, a));
    }
}
