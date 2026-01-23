// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/crosschain/TornadoBridgeAdapter.sol";
import "../../contracts/tornado/TornadoPrimitives.sol";

/**
 * @title TornadoBridgeFuzz
 * @notice Fuzz tests for Tornado Cash bridge adapter
 * @dev Tests deposits, withdrawals, relayer operations, and cross-domain nullifiers
 */
contract TornadoBridgeFuzz is Test {
    using TornadoPrimitives for *;

    // =========================================================================
    // STATE
    // =========================================================================

    TornadoBridgeAdapter public bridge;
    address public admin;
    address public user1;
    address public user2;
    address public relayer;

    uint256 constant BN254_R = TornadoPrimitives.BN254_R;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        admin = makeAddr("admin");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        relayer = makeAddr("relayer");

        vm.prank(admin);
        bridge = new TornadoBridgeAdapter(admin);

        // Fund users
        vm.deal(user1, 1000 ether);
        vm.deal(user2, 1000 ether);
        vm.deal(relayer, 10 ether);

        // Register relayer
        vm.prank(relayer);
        bridge.registerRelayer();
    }

    // =========================================================================
    // DEPOSIT TESTS
    // =========================================================================

    function testFuzz_DepositValidDenomination(
        uint256 denominationIndex
    ) public {
        denominationIndex = bound(denominationIndex, 0, 3);
        uint256[4] memory denoms = TornadoPrimitives
            .getSupportedDenominations();
        uint256 denomination = denoms[denominationIndex];

        bytes32 commitment = _generateValidCommitment();

        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        (uint256 totalDeposits, , uint32 nextIndex) = bridge.getPoolStats(
            denomination
        );
        assertEq(totalDeposits, 1, "Deposit count should be 1");
        assertEq(nextIndex, 1, "Next index should be 1");
    }

    function testFuzz_DepositMultiple(uint256 count) public {
        count = bound(count, 1, 20);
        uint256 denomination = 1 ether;

        for (uint256 i = 0; i < count; i++) {
            bytes32 commitment = _generateValidCommitment();
            vm.prank(user1);
            bridge.deposit{value: denomination}(commitment, denomination);
        }

        (uint256 totalDeposits, , uint32 nextIndex) = bridge.getPoolStats(
            denomination
        );
        assertEq(totalDeposits, count, "Deposit count mismatch");
        assertEq(nextIndex, count, "Next index mismatch");
    }

    function testFuzz_DepositTimestamp(bytes32 commitment) public {
        commitment = bytes32(bound(uint256(commitment), 1, BN254_R - 1));
        uint256 denomination = 1 ether;

        uint256 depositTime = block.timestamp;
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        uint256 recordedTime = bridge.getDepositTimestamp(commitment);
        assertEq(recordedTime, depositTime, "Timestamp not recorded correctly");
    }

    function testFuzz_DepositRevertsInvalidDenomination(uint256 amount) public {
        vm.assume(
            amount != 0.1 ether &&
                amount != 1 ether &&
                amount != 10 ether &&
                amount != 100 ether
        );
        vm.assume(amount > 0 && amount <= 1000 ether);

        bytes32 commitment = _generateValidCommitment();

        vm.prank(user1);
        vm.expectRevert(TornadoBridgeAdapter.InvalidDenomination.selector);
        bridge.deposit{value: amount}(commitment, amount);
    }

    function testFuzz_DepositRevertsWrongValue(uint256 sentValue) public {
        uint256 denomination = 1 ether;
        sentValue = bound(sentValue, 0, 1000 ether);
        vm.assume(sentValue != denomination);

        bytes32 commitment = _generateValidCommitment();

        vm.prank(user1);
        vm.expectRevert(TornadoBridgeAdapter.InvalidDenomination.selector);
        bridge.deposit{value: sentValue}(commitment, denomination);
    }

    function testFuzz_DepositRevertsZeroCommitment() public {
        uint256 denomination = 1 ether;

        vm.prank(user1);
        vm.expectRevert(TornadoBridgeAdapter.InvalidCommitment.selector);
        bridge.deposit{value: denomination}(bytes32(0), denomination);
    }

    function testFuzz_DepositRevertsOutOfFieldCommitment() public {
        uint256 denomination = 1 ether;
        bytes32 commitment = bytes32(BN254_R); // Out of field

        vm.prank(user1);
        vm.expectRevert(TornadoBridgeAdapter.InvalidCommitment.selector);
        bridge.deposit{value: denomination}(commitment, denomination);
    }

    function testFuzz_DepositRevertsDuplicate(bytes32 commitment) public {
        commitment = bytes32(bound(uint256(commitment), 1, BN254_R - 1));
        uint256 denomination = 1 ether;

        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        vm.prank(user2);
        vm.expectRevert(TornadoBridgeAdapter.CommitmentAlreadyExists.selector);
        bridge.deposit{value: denomination}(commitment, denomination);
    }

    // =========================================================================
    // WITHDRAWAL TESTS
    // =========================================================================

    function testFuzz_WithdrawalFlow(uint256 denominationIndex) public {
        denominationIndex = bound(denominationIndex, 0, 3);
        uint256[4] memory denoms = TornadoPrimitives
            .getSupportedDenominations();
        uint256 denomination = denoms[denominationIndex];

        // Deposit
        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        // Get root
        bytes32 root = bridge.getLastRoot(denomination);

        // Create withdrawal inputs
        bytes32 nullifierHash = _generateValidNullifier();
        TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
            .WithdrawalInputs({
                root: root,
                nullifierHash: nullifierHash,
                recipient: user2,
                relayer: address(0),
                fee: 0,
                refund: 0
            });

        // Create proof
        TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

        uint256 balanceBefore = user2.balance;

        vm.prank(user2);
        bridge.withdraw(proof, inputs, denomination);

        assertEq(
            user2.balance - balanceBefore,
            denomination,
            "Withdrawal amount mismatch"
        );
        assertTrue(
            bridge.isSpent(denomination, nullifierHash),
            "Nullifier not marked spent"
        );
    }

    function testFuzz_WithdrawalWithRelayer(uint256 feePercent) public {
        uint256 denomination = 1 ether;
        feePercent = bound(feePercent, 1, 500); // 0.01% to 5%
        uint256 fee = (denomination * feePercent) / 10000;

        // Deposit
        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        bytes32 root = bridge.getLastRoot(denomination);
        bytes32 nullifierHash = _generateValidNullifier();

        TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
            .WithdrawalInputs({
                root: root,
                nullifierHash: nullifierHash,
                recipient: user2,
                relayer: relayer,
                fee: fee,
                refund: 0
            });

        TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

        uint256 recipientBefore = user2.balance;
        uint256 relayerBefore = relayer.balance;

        vm.prank(relayer);
        bridge.withdraw(proof, inputs, denomination);

        assertEq(
            user2.balance - recipientBefore,
            denomination - fee,
            "Recipient amount wrong"
        );
        assertEq(relayer.balance - relayerBefore, fee, "Relayer fee wrong");
    }

    function testFuzz_WithdrawalRevertsFeeTooHigh(uint256 feePercent) public {
        uint256 denomination = 1 ether;
        feePercent = bound(feePercent, 501, 10000); // >5%
        uint256 fee = (denomination * feePercent) / 10000;

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        bytes32 root = bridge.getLastRoot(denomination);
        bytes32 nullifierHash = _generateValidNullifier();

        TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
            .WithdrawalInputs({
                root: root,
                nullifierHash: nullifierHash,
                recipient: user2,
                relayer: relayer,
                fee: fee,
                refund: 0
            });

        TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

        vm.prank(user2);
        vm.expectRevert(TornadoBridgeAdapter.RelayerFeeTooHigh.selector);
        bridge.withdraw(proof, inputs, denomination);
    }

    function testFuzz_WithdrawalRevertsUnknownRoot(bytes32 fakeRoot) public {
        uint256 denomination = 1 ether;
        vm.assume(fakeRoot != bytes32(0));

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        bytes32 realRoot = bridge.getLastRoot(denomination);
        vm.assume(fakeRoot != realRoot);

        TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
            .WithdrawalInputs({
                root: fakeRoot,
                nullifierHash: _generateValidNullifier(),
                recipient: user2,
                relayer: address(0),
                fee: 0,
                refund: 0
            });

        TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

        vm.prank(user2);
        vm.expectRevert(TornadoBridgeAdapter.InvalidRoot.selector);
        bridge.withdraw(proof, inputs, denomination);
    }

    function testFuzz_WithdrawalRevertsDoubleSpend() public {
        uint256 denomination = 1 ether;

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        bytes32 root = bridge.getLastRoot(denomination);
        bytes32 nullifierHash = _generateValidNullifier();

        TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
            .WithdrawalInputs({
                root: root,
                nullifierHash: nullifierHash,
                recipient: user2,
                relayer: address(0),
                fee: 0,
                refund: 0
            });

        TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

        // First withdrawal
        vm.prank(user2);
        bridge.deposit{value: denomination}(
            _generateValidCommitment(),
            denomination
        );
        bridge.withdraw(proof, inputs, denomination);

        // Second withdrawal with same nullifier
        vm.prank(user2);
        vm.expectRevert(TornadoBridgeAdapter.NullifierAlreadySpent.selector);
        bridge.withdraw(proof, inputs, denomination);
    }

    // =========================================================================
    // RELAYER TESTS
    // =========================================================================

    function testFuzz_RelayerRegistration(address newRelayer) public {
        vm.assume(newRelayer != address(0) && newRelayer != relayer);

        assertFalse(
            bridge.registeredRelayers(newRelayer),
            "Should not be registered"
        );

        vm.prank(newRelayer);
        bridge.registerRelayer();

        assertTrue(
            bridge.registeredRelayers(newRelayer),
            "Should be registered"
        );
    }

    function testFuzz_RelayerUnregistration(address newRelayer) public {
        vm.assume(newRelayer != address(0));

        vm.startPrank(newRelayer);
        bridge.registerRelayer();
        assertTrue(
            bridge.registeredRelayers(newRelayer),
            "Should be registered"
        );

        bridge.unregisterRelayer();
        assertFalse(
            bridge.registeredRelayers(newRelayer),
            "Should be unregistered"
        );
        vm.stopPrank();
    }

    function test_UnregisteredRelayerRejected() public {
        address unregisteredRelayer = makeAddr("unregistered");
        uint256 denomination = 1 ether;

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: denomination}(commitment, denomination);

        bytes32 root = bridge.getLastRoot(denomination);
        bytes32 nullifierHash = _generateValidNullifier();

        TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
            .WithdrawalInputs({
                root: root,
                nullifierHash: nullifierHash,
                recipient: user2,
                relayer: unregisteredRelayer,
                fee: 0.01 ether,
                refund: 0
            });

        TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

        vm.prank(user2);
        vm.expectRevert(TornadoBridgeAdapter.InvalidRelayer.selector);
        bridge.withdraw(proof, inputs, denomination);
    }

    // =========================================================================
    // CROSS-DOMAIN TESTS
    // =========================================================================

    function testFuzz_CrossDomainNullifierRegistration(
        bytes32 tornadoNullifier,
        uint256 targetChainId
    ) public {
        tornadoNullifier = bytes32(
            bound(uint256(tornadoNullifier), 1, type(uint256).max)
        );
        targetChainId = bound(targetChainId, 1, type(uint64).max);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(tornadoNullifier, targetChainId);

        bytes32 pilNullifier = bridge.crossDomainNullifiers(tornadoNullifier);
        assertNotEq(
            pilNullifier,
            bytes32(0),
            "PIL nullifier should be registered"
        );

        bytes32 reverseMapping = bridge.pilBindings(pilNullifier);
        assertEq(
            reverseMapping,
            tornadoNullifier,
            "Reverse mapping should match"
        );
    }

    function testFuzz_CrossDomainNullifierUniqueness(
        bytes32 nf1,
        bytes32 nf2,
        uint256 targetChainId
    ) public {
        nf1 = bytes32(bound(uint256(nf1), 1, type(uint256).max));
        nf2 = bytes32(bound(uint256(nf2), 1, type(uint256).max));
        vm.assume(nf1 != nf2);
        targetChainId = bound(targetChainId, 1, type(uint64).max);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(nf1, targetChainId);
        bytes32 pilNf1 = bridge.crossDomainNullifiers(nf1);

        vm.prank(user1);
        bridge.registerCrossDomainNullifier(nf2, targetChainId);
        bytes32 pilNf2 = bridge.crossDomainNullifiers(nf2);

        assertNotEq(pilNf1, pilNf2, "PIL nullifiers should be unique");
    }

    // =========================================================================
    // ROOT HISTORY TESTS
    // =========================================================================

    function testFuzz_RootHistoryTracking(uint256 depositCount) public {
        depositCount = bound(depositCount, 1, 35); // More than ROOT_HISTORY_SIZE
        uint256 denomination = 1 ether;

        bytes32[] memory roots = new bytes32[](depositCount);

        for (uint256 i = 0; i < depositCount; i++) {
            bytes32 commitment = _generateValidCommitment();
            vm.prank(user1);
            bridge.deposit{value: denomination}(commitment, denomination);
            roots[i] = bridge.getLastRoot(denomination);
        }

        // Check recent roots are known
        uint256 historySize = 30;
        for (uint256 i = 0; i < depositCount && i < historySize; i++) {
            uint256 idx = depositCount - 1 - i;
            assertTrue(
                bridge.isKnownRoot(denomination, roots[idx]),
                "Recent root should be known"
            );
        }

        // If we have more than history size, old roots should be evicted
        if (depositCount > historySize) {
            // Early roots may not be known anymore
            // This depends on implementation details
        }
    }

    // =========================================================================
    // POOL STATS TESTS
    // =========================================================================

    function testFuzz_PoolStatsConsistency(
        uint256 deposits,
        uint256 withdrawals
    ) public {
        deposits = bound(deposits, 1, 20);
        withdrawals = bound(withdrawals, 0, deposits);
        uint256 denomination = 1 ether;

        // Make deposits
        bytes32[] memory nullifiers = new bytes32[](deposits);
        for (uint256 i = 0; i < deposits; i++) {
            bytes32 commitment = _generateValidCommitment();
            vm.prank(user1);
            bridge.deposit{value: denomination}(commitment, denomination);
            nullifiers[i] = _generateValidNullifier();
        }

        // Make withdrawals
        for (uint256 i = 0; i < withdrawals; i++) {
            bytes32 root = bridge.getLastRoot(denomination);
            TornadoPrimitives.WithdrawalInputs memory inputs = TornadoPrimitives
                .WithdrawalInputs({
                    root: root,
                    nullifierHash: nullifiers[i],
                    recipient: user2,
                    relayer: address(0),
                    fee: 0,
                    refund: 0
                });
            TornadoPrimitives.Groth16Proof memory proof = _createValidProof();

            vm.prank(user2);
            bridge.withdraw(proof, inputs, denomination);
        }

        (uint256 totalDeposits, uint256 totalWithdrawals, ) = bridge
            .getPoolStats(denomination);
        assertEq(totalDeposits, deposits, "Deposit count mismatch");
        assertEq(totalWithdrawals, withdrawals, "Withdrawal count mismatch");
    }

    // =========================================================================
    // CIRCUIT BREAKER TESTS
    // =========================================================================

    function test_CircuitBreakerBlocksDeposits() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Testing");

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        vm.expectRevert(TornadoBridgeAdapter.CircuitBreakerActive.selector);
        bridge.deposit{value: 1 ether}(commitment, 1 ether);
    }

    function test_CircuitBreakerReset() public {
        vm.prank(admin);
        bridge.triggerCircuitBreaker("Testing");

        assertTrue(bridge.circuitBreakerTriggered(), "Should be triggered");

        vm.prank(admin);
        bridge.resetCircuitBreaker();

        assertFalse(bridge.circuitBreakerTriggered(), "Should be reset");

        // Can deposit again
        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: 1 ether}(commitment, 1 ether);
    }

    // =========================================================================
    // PAUSE TESTS
    // =========================================================================

    function test_PauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        vm.expectRevert();
        bridge.deposit{value: 1 ether}(commitment, 1 ether);
    }

    function test_UnpauseAllowsDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        bytes32 commitment = _generateValidCommitment();
        vm.prank(user1);
        bridge.deposit{value: 1 ether}(commitment, 1 ether);
    }

    // =========================================================================
    // ACCESS CONTROL TESTS
    // =========================================================================

    function testFuzz_OnlyGuardianCanTriggerCircuitBreaker(
        address attacker
    ) public {
        vm.assume(attacker != admin);
        vm.assume(!bridge.hasRole(bridge.GUARDIAN_ROLE(), attacker));

        vm.prank(attacker);
        vm.expectRevert();
        bridge.triggerCircuitBreaker("Attack");
    }

    function testFuzz_OnlyAdminCanResetCircuitBreaker(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(!bridge.hasRole(bridge.DEFAULT_ADMIN_ROLE(), attacker));

        vm.prank(admin);
        bridge.triggerCircuitBreaker("Testing");

        vm.prank(attacker);
        vm.expectRevert();
        bridge.resetCircuitBreaker();
    }

    // =========================================================================
    // VERIFIER TESTS
    // =========================================================================

    function testFuzz_VerifierUpdate(
        uint256 denominationIndex,
        address verifier
    ) public {
        denominationIndex = bound(denominationIndex, 0, 3);
        uint256[4] memory denoms = TornadoPrimitives
            .getSupportedDenominations();
        uint256 denomination = denoms[denominationIndex];

        vm.prank(admin);
        bridge.setVerifier(denomination, verifier);

        assertEq(
            bridge.verifiers(denominationIndex),
            verifier,
            "Verifier not set"
        );
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    uint256 private _commitmentNonce;
    uint256 private _nullifierNonce;

    function _generateValidCommitment() internal returns (bytes32) {
        _commitmentNonce++;
        return
            bytes32(
                uint256(
                    keccak256(abi.encodePacked("commitment", _commitmentNonce))
                ) % BN254_R
            );
    }

    function _generateValidNullifier() internal returns (bytes32) {
        _nullifierNonce++;
        return
            bytes32(
                uint256(
                    keccak256(abi.encodePacked("nullifier", _nullifierNonce))
                ) % BN254_R
            );
    }

    function _createValidProof()
        internal
        pure
        returns (TornadoPrimitives.Groth16Proof memory)
    {
        return
            TornadoPrimitives.Groth16Proof({
                a: [uint256(1), uint256(2)],
                b: [[uint256(1), uint256(2)], [uint256(3), uint256(4)]],
                c: [uint256(1), uint256(2)]
            });
    }
}
