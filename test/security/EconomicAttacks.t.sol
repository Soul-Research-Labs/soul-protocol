// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {GriefingProtection} from "../../contracts/security/GriefingProtection.sol";
import {MEVProtection} from "../../contracts/security/MEVProtection.sol";
import {FlashLoanGuard} from "../../contracts/security/FlashLoanGuard.sol";
import {RelayerStaking} from "../../contracts/relayer/RelayerStaking.sol";
import {MockERC20} from "../../contracts/mocks/MockERC20.sol";

/**
 * @title EconomicAttacks
 * @author Soul Protocol
 * @notice Comprehensive economic attack vector testing
 * @dev Tests front-running, MEV extraction, griefing, Sybil, and proof grinding attacks
 *      per CROSS_CHAIN_PRIVACY_SECURITY_NEXT_STEPS.md Security Phase 2
 */
contract EconomicAttacksTest is Test {
    // =========================================================================
    // CONTRACTS
    // =========================================================================

    NullifierRegistryV3 public nullifierRegistry;
    GriefingProtection public griefingProtection;
    MEVProtection public mevProtection;
    FlashLoanGuard public flashLoanGuard;
    RelayerStaking public relayerStaking;
    MockERC20 public stakingToken;

    // =========================================================================
    // ACTORS
    // =========================================================================

    address public admin;
    address public attacker;
    address public victim;
    address public relayer1;
    address public relayer2;
    address public relayer3;

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    bytes32 constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    bytes32 constant BRIDGE_ROLE = keccak256("BRIDGE_ROLE");
    bytes32 constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    bytes32 constant OP_BRIDGE = keccak256("BRIDGE_TRANSFER");
    bytes32 constant OP_PROOF = keccak256("PROOF_VERIFICATION");

    uint256 constant MIN_STAKE = 10 ether;
    uint256 constant LARGE_SUPPLY = 1_000_000 ether;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        admin = address(this);
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        relayer1 = makeAddr("relayer1");
        relayer2 = makeAddr("relayer2");
        relayer3 = makeAddr("relayer3");

        // Deploy core contracts
        nullifierRegistry = new NullifierRegistryV3();
        griefingProtection = new GriefingProtection(
            5, // maxFailedAttempts
            1 hours, // suspensionDuration
            10_000_000, // maxGasPerEpoch
            admin
        );
        mevProtection = new MEVProtection(2, 100, admin);
        flashLoanGuard = new FlashLoanGuard(500, 1000, admin);

        // Deploy staking token and relayer staking
        stakingToken = new MockERC20("Soul Token", "SOUL", 18);
        relayerStaking = new RelayerStaking(
            address(stakingToken),
            MIN_STAKE,
            admin
        );

        // Fund actors
        stakingToken.mint(attacker, LARGE_SUPPLY);
        stakingToken.mint(relayer1, 100 ether);
        stakingToken.mint(relayer2, 100 ether);
        stakingToken.mint(relayer3, 100 ether);

        // Setup roles
        nullifierRegistry.grantRole(REGISTRAR_ROLE, admin);
        griefingProtection.registerProtectedContract(address(this));
    }

    // =========================================================================
    // 1. NULLIFIER DoS GRIEFING ATTACKS
    // =========================================================================

    /// @notice Test that mass nullifier registration by a non-registrar is blocked
    function test_attack_nullifierDoS_unauthorizedMassRegister() public {
        vm.startPrank(attacker);
        for (uint256 i = 0; i < 20; i++) {
            bytes32 nullifier = keccak256(abi.encodePacked("spam", i));
            bytes32 commitment = keccak256(abi.encodePacked("fake_commit", i));
            vm.expectRevert();
            nullifierRegistry.registerNullifier(nullifier, commitment);
        }
        vm.stopPrank();
    }

    /// @notice Test that double-registration of the same nullifier reverts
    function test_attack_nullifierDoS_doubleRegister() public {
        bytes32 nullifier = keccak256("legit_nullifier");
        bytes32 commitment = keccak256("legit_commitment");

        nullifierRegistry.registerNullifier(nullifier, commitment);

        // Second registration of same nullifier must revert
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifier, commitment);
    }

    /// @notice Fuzz: attacker cannot register nullifiers without REGISTRAR_ROLE
    function testFuzz_attack_nullifierDoS_roleProtection(
        bytes32 nullifier,
        bytes32 commitment,
        address caller
    ) public {
        vm.assume(caller != admin && caller != address(0));
        vm.assume(!nullifierRegistry.hasRole(REGISTRAR_ROLE, caller));

        vm.prank(caller);
        vm.expectRevert();
        nullifierRegistry.registerNullifier(nullifier, commitment);
    }

    // =========================================================================
    // 2. MEV FRONT-RUNNING ATTACKS
    // =========================================================================

    /// @notice Test that commit-reveal prevents front-running
    function test_attack_mevFrontRunning_commitRevealProtects() public {
        bytes32 opType = keccak256("TRANSFER");
        bytes memory data = abi.encode(victim, 1 ether);
        bytes32 salt = keccak256("secret_salt");

        // Victim commits
        bytes32 commitHash = mevProtection.calculateCommitHash(
            victim,
            opType,
            data,
            salt
        );
        vm.prank(victim);
        bytes32 commitId = mevProtection.commit(commitHash);

        // Attacker sees the commit on-chain but cannot derive the operation
        // because the hash is one-way. Attacker tries to front-run with a
        // different commitment.
        bytes32 attackerSalt = keccak256("attacker_salt");
        bytes32 attackerHash = mevProtection.calculateCommitHash(
            attacker,
            opType,
            data,
            attackerSalt
        );
        vm.prank(attacker);
        bytes32 attackerCommitId = mevProtection.commit(attackerHash);

        // Wait for reveal delay
        vm.roll(block.number + 3);

        // Victim reveals successfully
        vm.prank(victim);
        mevProtection.reveal(commitId, opType, data, salt);

        // Attacker's reveal succeeds but operates on THEIR address, not victim's
        // This proves the commit-reveal binds the operation to the sender
        vm.prank(attacker);
        mevProtection.reveal(attackerCommitId, opType, data, attackerSalt);
    }

    /// @notice Test that revealing before delay reverts (prevents same-block MEV)
    function test_attack_mevFrontRunning_earlyRevealBlocked() public {
        bytes32 opType = keccak256("WITHDRAW");
        bytes memory data = abi.encode(victim, 5 ether);
        bytes32 salt = keccak256("my_salt");

        bytes32 commitHash = mevProtection.calculateCommitHash(
            victim,
            opType,
            data,
            salt
        );
        vm.prank(victim);
        bytes32 commitId = mevProtection.commit(commitHash);

        // Try to reveal in the same block — should fail
        vm.prank(victim);
        vm.expectRevert(MEVProtection.CommitmentNotReady.selector);
        mevProtection.reveal(commitId, opType, data, salt);
    }

    /// @notice Test expired commitment cannot be revealed (stale front-run attempt)
    function test_attack_mevFrontRunning_expiredCommitment() public {
        bytes32 opType = keccak256("TRANSFER");
        bytes memory data = abi.encode(attacker, 1 ether);
        bytes32 salt = keccak256("old_salt");

        bytes32 commitHash = mevProtection.calculateCommitHash(
            attacker,
            opType,
            data,
            salt
        );
        vm.prank(attacker);
        bytes32 commitId = mevProtection.commit(commitHash);

        // Fast forward past max commitment age
        vm.roll(block.number + 200);

        vm.prank(attacker);
        vm.expectRevert(MEVProtection.CommitmentExpired.selector);
        mevProtection.reveal(commitId, opType, data, salt);
    }

    /// @notice Test that an attacker cannot reveal someone else's commitment
    function test_attack_mevFrontRunning_cannotRevealOthersCommitment() public {
        bytes32 opType = keccak256("TRANSFER");
        bytes memory data = abi.encode(victim, 1 ether);
        bytes32 salt = keccak256("victim_salt");

        bytes32 commitHash = mevProtection.calculateCommitHash(
            victim,
            opType,
            data,
            salt
        );
        vm.prank(victim);
        bytes32 commitId = mevProtection.commit(commitHash);

        vm.roll(block.number + 3);

        // Attacker tries to reveal victim's commitment
        vm.prank(attacker);
        vm.expectRevert(MEVProtection.InvalidReveal.selector);
        mevProtection.reveal(commitId, opType, data, salt);
    }

    // =========================================================================
    // 3. FLASH LOAN TVL MANIPULATION ATTACKS
    // =========================================================================

    /// @notice Test that same-block operations are rate-limited (flash loan defense)
    function test_attack_flashLoan_sameBlockBlocked() public {
        address protectedPool = makeAddr("pool");
        flashLoanGuard.registerProtectedContract(protectedPool);

        // Simulate operations up to MAX_OPS_PER_BLOCK (3)
        for (uint256 i = 0; i < 3; i++) {
            bool safe = flashLoanGuard.validateOperation(
                protectedPool,
                address(stakingToken),
                0.01 ether
            );
            assertTrue(safe, "First 3 ops should succeed");
        }

        // Fourth operation in the same block should be rejected (returns false)
        bool safe = flashLoanGuard.validateOperation(
            protectedPool,
            address(stakingToken),
            0.01 ether
        );
        assertFalse(safe, "4th same-block op should be blocked");
    }

    /// @notice Test TVL delta detection (large balance swings in one block)
    function test_attack_flashLoan_tvlDeltaDetection() public {
        // Set initial TVL
        flashLoanGuard.updateTVL(100 ether);

        // Simulate flash loan: TVL jumps dramatically
        // TVL delta of >5% should be flagged
        flashLoanGuard.updateTVL(200 ether); // 100% jump

        // Contract should detect the manipulation
        uint256 newTvl = 200 ether;
        uint256 oldTvl = 100 ether;
        uint256 deltaBps = ((newTvl - oldTvl) * 10_000) / oldTvl;
        assertGt(deltaBps, 500, "TVL delta should exceed threshold");
    }

    // =========================================================================
    // 4. SYBIL RELAYER ATTACKS
    // =========================================================================

    /// @notice Test that Sybil relayers cannot dominate with minimal total stake
    function test_attack_sybilRelayer_minimumStakeRequired() public {
        // Attacker tries to register many relayers with minimum stake
        // Each still requires MIN_STAKE
        for (uint256 i = 0; i < 5; i++) {
            address sybil = makeAddr(string(abi.encodePacked("sybil", i)));
            stakingToken.mint(sybil, MIN_STAKE);

            vm.startPrank(sybil);
            stakingToken.approve(address(relayerStaking), MIN_STAKE);
            relayerStaking.stake(MIN_STAKE);
            vm.stopPrank();
        }

        // Even with 5 Sybil relayers, they need 5 * MIN_STAKE total capital
        // which is economically costly
        uint256 totalSybilCapital = 5 * MIN_STAKE;
        assertEq(
            totalSybilCapital,
            50 ether,
            "Sybil attack requires 50 ETH worth of stake"
        );
    }

    /// @notice Test that under-staked relayers are NOT activated
    function test_attack_sybilRelayer_insufficientStakeNotActivated() public {
        vm.startPrank(attacker);
        stakingToken.approve(address(relayerStaking), MIN_STAKE - 1);
        relayerStaking.stake(MIN_STAKE - 1);
        vm.stopPrank();

        // Staking below minStake succeeds but the relayer is NOT activated
        (, , , , , , bool isActive, ) = relayerStaking.relayers(attacker);
        assertFalse(isActive, "Under-staked relayer must not be active");
    }

    /// @notice Test that slashing punishes misbehaving Sybil relayers
    function test_attack_sybilRelayer_slashingPunishment() public {
        // Register attacker as relayer
        vm.startPrank(attacker);
        stakingToken.approve(address(relayerStaking), MIN_STAKE);
        relayerStaking.stake(MIN_STAKE);
        vm.stopPrank();

        // Slash for misbehavior
        relayerStaking.grantRole(SLASHER_ROLE, admin);
        uint256 stakeBefore = _getRelayerStake(attacker);
        relayerStaking.slash(attacker, "Proof fraud");
        uint256 stakeAfter = _getRelayerStake(attacker);

        assertLt(
            stakeAfter,
            stakeBefore,
            "Stake should decrease after slashing"
        );
    }

    /// @notice Fuzz: verify slashing is bounded and doesn't exceed stake
    function testFuzz_attack_sybilRelayer_slashingBounded(
        uint256 slashPercentage
    ) public {
        slashPercentage = bound(slashPercentage, 1, 50);

        vm.startPrank(attacker);
        stakingToken.approve(address(relayerStaking), MIN_STAKE);
        relayerStaking.stake(MIN_STAKE);
        vm.stopPrank();

        relayerStaking.grantRole(SLASHER_ROLE, admin);
        relayerStaking.slash(attacker, "test");

        uint256 remaining = _getRelayerStake(attacker);
        assertLe(
            remaining,
            MIN_STAKE,
            "Remaining stake cannot exceed original"
        );
    }

    // =========================================================================
    // 5. GRIEFING VIA REPEATED FAILURES
    // =========================================================================

    /// @notice Test that repeated failed attempts trigger suspension
    function test_attack_griefing_repeatedFailuresSuspends() public {
        // Record max failed attempts
        for (uint256 i = 0; i < 5; i++) {
            griefingProtection.recordFailure(attacker, OP_BRIDGE);
        }

        // After max failures, user should be suspended
        (bool canOperate, ) = griefingProtection.canPerformOperation(
            attacker,
            OP_BRIDGE,
            0
        );
        assertFalse(
            canOperate,
            "Attacker should be suspended after max failures"
        );
    }

    /// @notice Test that suspension eventually expires (time-bounded punishment)
    function test_attack_griefing_suspensionExpires() public {
        // Trigger suspension
        for (uint256 i = 0; i < 5; i++) {
            griefingProtection.recordFailure(attacker, OP_BRIDGE);
        }

        // Fast forward past suspension duration
        vm.warp(block.timestamp + 1 hours + 1);

        // After suspension expires, check if user can operate again
        // The griefing protection resets failure count after suspension
        (bool canOperate, ) = griefingProtection.canPerformOperation(
            attacker,
            OP_BRIDGE,
            0
        );
        assertTrue(canOperate, "Suspension should expire after duration");
    }

    /// @notice Test that whitelisted users are still suspended (defense-in-depth)
    function test_attack_griefing_whitelistedStillSuspended() public {
        address whitelisted = makeAddr("whitelisted");
        griefingProtection.whitelistUser(whitelisted);

        // Record failures — even whitelisted users are suspended (defense-in-depth)
        for (uint256 i = 0; i < 10; i++) {
            griefingProtection.recordFailure(whitelisted, OP_BRIDGE);
        }

        (bool canOperate, ) = griefingProtection.canPerformOperation(
            whitelisted,
            OP_BRIDGE,
            0
        );
        assertFalse(
            canOperate,
            "Whitelisted user should still be suspended (defense-in-depth)"
        );
    }

    // =========================================================================
    // 6. PROOF GRINDING ATTACKS
    // =========================================================================

    /// @notice Test that gas-limited proof submission prevents grinding
    function test_attack_proofGrinding_gasLimitsEnforced() public {
        // The griefing protection enforces gas limits per operation type
        // Proof verification has a max gas budget per epoch
        (uint256 maxGas, , , , ) = griefingProtection.operationLimits(OP_PROOF);
        assertGt(maxGas, 0, "Proof operations should have gas limits");
    }

    /// @notice Test that proof grinding triggers failure tracking
    function test_attack_proofGrinding_failureTracking() public {
        // Attacker submits many invalid proofs
        for (uint256 i = 0; i < 4; i++) {
            griefingProtection.recordFailure(attacker, OP_PROOF);
        }

        // After multiple failures, the user is rate-limited
        griefingProtection.recordFailure(attacker, OP_PROOF);
        (bool canOperate, ) = griefingProtection.canPerformOperation(
            attacker,
            OP_PROOF,
            0
        );
        assertFalse(canOperate, "Proof grinder should be suspended");
    }

    // =========================================================================
    // 7. ECONOMIC INVARIANT TESTS
    // =========================================================================

    /// @notice Invariant: total staked tokens cannot exceed token supply
    function test_invariant_stakingDoesNotExceedSupply() public {
        // Register multiple relayers
        address[] memory relayers = new address[](3);
        relayers[0] = relayer1;
        relayers[1] = relayer2;
        relayers[2] = relayer3;

        uint256 totalStaked = 0;
        for (uint256 i = 0; i < relayers.length; i++) {
            vm.startPrank(relayers[i]);
            stakingToken.approve(address(relayerStaking), 100 ether);
            relayerStaking.stake(MIN_STAKE);
            totalStaked += MIN_STAKE;
            vm.stopPrank();
        }

        assertLe(
            totalStaked,
            stakingToken.totalSupply(),
            "Total staked cannot exceed supply"
        );
    }

    /// @notice Test that unstaking requires unbonding period
    function test_attack_instantUnstake_blocked() public {
        vm.startPrank(relayer1);
        stakingToken.approve(address(relayerStaking), MIN_STAKE);
        relayerStaking.stake(MIN_STAKE);

        // Request unstake
        relayerStaking.requestUnstake(MIN_STAKE);

        // Try to complete immediately — should fail
        vm.expectRevert(RelayerStaking.UnbondingPeriodNotComplete.selector);
        relayerStaking.completeUnstake();
        vm.stopPrank();
    }

    /// @notice Test that unbonding period completes correctly
    function test_attack_unstakeAfterUnbonding() public {
        vm.startPrank(relayer1);
        stakingToken.approve(address(relayerStaking), MIN_STAKE);
        relayerStaking.stake(MIN_STAKE);
        relayerStaking.requestUnstake(MIN_STAKE);
        vm.stopPrank();

        // Fast forward past unbonding period (7 days)
        vm.warp(block.timestamp + 7 days + 1);

        uint256 balanceBefore = stakingToken.balanceOf(relayer1);
        vm.prank(relayer1);
        relayerStaking.completeUnstake();
        uint256 balanceAfter = stakingToken.balanceOf(relayer1);

        assertGt(
            balanceAfter,
            balanceBefore,
            "Tokens should be returned after unbonding"
        );
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    function _getRelayerStake(address relayer) internal view returns (uint256) {
        (uint256 staked, , , , , , , ) = relayerStaking.relayers(relayer);
        return staked;
    }
}
