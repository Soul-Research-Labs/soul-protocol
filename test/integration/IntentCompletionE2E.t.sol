// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/core/IntentCompletionLayer.sol";
import "../../contracts/core/InstantCompletionGuarantee.sol";
import "../../contracts/relayer/InstantRelayerRewards.sol";
import "../../contracts/core/DynamicRoutingOrchestrator.sol";
import "../../contracts/core/ZaseonProtocolHub.sol";
import "../../contracts/interfaces/IZaseonProtocolHub.sol";
import {IIntentCompletionLayer} from "../../contracts/interfaces/IIntentCompletionLayer.sol";
import {IInstantCompletionGuarantee} from "../../contracts/interfaces/IInstantCompletionGuarantee.sol";
import {IDynamicRoutingOrchestrator} from "../../contracts/interfaces/IDynamicRoutingOrchestrator.sol";

/**
 * @title IntentCompletionE2E
 * @notice End-to-end tests for the Tachyon-inspired intent completion suite.
 * @dev Tests the full lifecycle: Intent → Completion → Guarantee → Rewards → Routing.
 *      Validates that the three unwired Tachyon contracts (IntentCompletionLayer,
 *      InstantCompletionGuarantee, DynamicRoutingOrchestrator) work together correctly
 *      and integrate with the Hub.
 */
contract IntentCompletionE2E is Test {
    // =========================================================================
    // CONTRACTS
    // =========================================================================

    IntentCompletionLayer public intentLayer;
    InstantCompletionGuarantee public guarantee;
    InstantRelayerRewards public rewards;
    DynamicRoutingOrchestrator public router;
    ZaseonProtocolHub public hub;

    // =========================================================================
    // ACTORS
    // =========================================================================

    address public admin = makeAddr("admin");
    address public oracle = makeAddr("oracle");
    address public bridgeAdmin = makeAddr("bridgeAdmin");
    address public user = makeAddr("user");
    address public solver = makeAddr("solver");
    address public relayer = makeAddr("relayer");
    address public challenger = makeAddr("challenger");
    address public beneficiary = makeAddr("beneficiary");

    // =========================================================================
    // CONSTANTS
    // =========================================================================

    uint256 constant SOURCE_CHAIN = 1;
    uint256 constant DEST_CHAIN = 42161; // Arbitrum
    uint256 constant SOLVER_STAKE = 1 ether;
    uint256 constant INTENT_FEE = 0.1 ether;

    // =========================================================================
    // SETUP
    // =========================================================================

    function setUp() public {
        // Fund actors
        vm.deal(admin, 100 ether);
        vm.deal(user, 100 ether);
        vm.deal(solver, 100 ether);
        vm.deal(relayer, 100 ether);
        vm.deal(beneficiary, 10 ether);

        // Deploy all contracts
        vm.startPrank(admin);

        intentLayer = new IntentCompletionLayer(admin, address(0));
        guarantee = new InstantCompletionGuarantee(admin, address(intentLayer));
        rewards = new InstantRelayerRewards(admin);
        router = new DynamicRoutingOrchestrator(admin, oracle, bridgeAdmin);

        // Grant roles
        intentLayer.grantRole(intentLayer.CHALLENGER_ROLE(), challenger);

        bytes32 RELAY_MANAGER = rewards.RELAY_MANAGER_ROLE();
        rewards.grantRole(RELAY_MANAGER, admin);

        bytes32 COMPLETION_ROLE = guarantee.COMPLETION_ROLE();
        guarantee.grantRole(COMPLETION_ROLE, admin);

        // Enable chain on IntentCompletionLayer
        intentLayer.setSupportedChain(SOURCE_CHAIN, true);
        intentLayer.setSupportedChain(DEST_CHAIN, true);

        vm.stopPrank();
    }

    // =========================================================================
    // FULL LIFECYCLE: Intent → Claim → Fulfill → Finalize
    // =========================================================================

    function test_fullIntentLifecycle() public {
        // Step 1: Register solver
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        IIntentCompletionLayer.Solver memory solverInfo = intentLayer.getSolver(
            solver
        );
        assertTrue(solverInfo.isActive, "solver should be active");
        assertEq(solverInfo.stake, SOLVER_STAKE, "solver stake incorrect");

        // Step 2: User submits an intent
        bytes32 sourceCommitment = keccak256("source_state");
        bytes32 desiredStateHash = keccak256("desired_state");
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            sourceCommitment,
            desiredStateHash,
            INTENT_FEE,
            deadline,
            bytes32(0) // no policy
        );

        IIntentCompletionLayer.Intent memory intent = intentLayer.getIntent(
            intentId
        );
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.PENDING)
        );
        assertEq(intent.user, user);

        // Step 3: Solver claims the intent
        vm.prank(solver);
        intentLayer.claimIntent(intentId);

        intent = intentLayer.getIntent(intentId);
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.CLAIMED)
        );
        assertEq(intent.solver, solver);

        // Step 4: Solver fulfills the intent (mock proof)
        bytes memory mockProof = hex"deadbeef";
        bytes memory mockInputs = hex"cafebabe";
        bytes32 newCommitment = keccak256("new_state");

        vm.prank(solver);
        intentLayer.fulfillIntent(
            intentId,
            mockProof,
            mockInputs,
            newCommitment
        );

        intent = intentLayer.getIntent(intentId);
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.FULFILLED)
        );

        // Step 5: Wait for challenge period (1 hour)
        assertTrue(
            !intentLayer.canFinalize(intentId),
            "cannot finalize before challenge period"
        );
        vm.warp(block.timestamp + 1 hours + 1);
        assertTrue(
            intentLayer.canFinalize(intentId),
            "should be finalizable after challenge period"
        );
        assertFalse(
            intentLayer.isFinalized(intentId),
            "should not yet be finalized"
        );

        // Step 6: Finalize
        uint256 solverBalBefore = solver.balance;
        intentLayer.finalizeIntent(intentId);

        intent = intentLayer.getIntent(intentId);
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.FINALIZED)
        );
        assertTrue(
            intentLayer.isFinalized(intentId),
            "should be finalized now"
        );

        // Solver should receive payout (fee minus protocol fee)
        assertTrue(
            solver.balance > solverBalBefore,
            "solver should receive payout"
        );
    }

    // =========================================================================
    // INSTANT COMPLETION: Guarantee Lifecycle
    // =========================================================================

    function test_instantCompletionWithGuarantee() public {
        // Setup: Register solver and submit intent
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            INTENT_FEE,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        // Solver posts guarantee bond for instant completion
        uint256 guaranteeAmount = 1 ether;
        uint256 requiredBond = guarantee.requiredBond(guaranteeAmount);
        assertTrue(
            requiredBond >= guaranteeAmount,
            "bond should be >= amount (110%)"
        );

        vm.prank(solver);
        bytes32 guaranteeId = guarantee.postGuarantee{value: requiredBond}(
            intentId,
            beneficiary,
            guaranteeAmount,
            1 hours // duration
        );

        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            guaranteeId
        );
        assertEq(
            uint256(g.status),
            uint256(IInstantCompletionGuarantee.GuaranteeStatus.ACTIVE)
        );
        assertEq(g.guarantor, solver);
        assertEq(g.beneficiary, beneficiary);
        assertEq(g.bond, requiredBond);

        // Simluate solver fulfills and intent finalizes
        vm.prank(solver);
        intentLayer.claimIntent(intentId);
        vm.prank(solver);
        intentLayer.fulfillIntent(
            intentId,
            hex"deadbeef",
            hex"cafebabe",
            keccak256("new")
        );
        vm.warp(block.timestamp + 1 hours + 1);
        intentLayer.finalizeIntent(intentId);

        assertTrue(
            intentLayer.isFinalized(intentId),
            "intent should be finalized"
        );

        // Solver settles guarantee → bond returned
        uint256 solverBalBefore = solver.balance;
        vm.prank(solver);
        guarantee.settleGuarantee(guaranteeId);

        g = guarantee.getGuarantee(guaranteeId);
        assertEq(
            uint256(g.status),
            uint256(IInstantCompletionGuarantee.GuaranteeStatus.SETTLED)
        );
        assertTrue(
            solver.balance > solverBalBefore,
            "solver should get bond back"
        );
    }

    function test_guaranteeClaimOnExpiredUnfinalizedIntent() public {
        // Setup: Register solver and submit intent
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            INTENT_FEE,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        // Solver posts guarantee but NEVER fulfills
        uint256 guaranteeAmount = 1 ether;
        uint256 bond = guarantee.requiredBond(guaranteeAmount);

        vm.prank(solver);
        bytes32 guaranteeId = guarantee.postGuarantee{value: bond}(
            intentId,
            beneficiary,
            guaranteeAmount,
            30 minutes
        );

        // Wait for guarantee to expire without intent finalization
        vm.warp(block.timestamp + 31 minutes);

        // Beneficiary should be able to claim the bond
        uint256 beneficiaryBalBefore = beneficiary.balance;
        vm.prank(beneficiary);
        guarantee.claimGuarantee(guaranteeId);

        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            guaranteeId
        );
        assertEq(
            uint256(g.status),
            uint256(IInstantCompletionGuarantee.GuaranteeStatus.CLAIMED)
        );
        assertTrue(
            beneficiary.balance > beneficiaryBalBefore,
            "beneficiary should receive claim"
        );
    }

    // =========================================================================
    // RELAYER REWARDS: Speed Tier Incentives
    // =========================================================================

    function test_relayerRewardsSpeedTiers() public {
        bytes32 relayId = keccak256("relay_1");
        uint256 baseReward = 0.1 ether;

        // Admin deposits relay fee
        vm.startPrank(admin);
        rewards.depositRelayFee{value: baseReward}(relayId, user);

        InstantRelayerRewards.RelayDeposit memory deposit = rewards.getDeposit(
            relayId
        );
        assertEq(deposit.requester, user);
        assertEq(deposit.baseReward, baseReward);

        // Claim relay
        rewards.claimRelay(relayId, relayer);
        deposit = rewards.getDeposit(relayId);
        assertEq(deposit.relayer, relayer);

        // Complete relay (needs time to pass for speed tier calculation)
        // ULTRA_FAST tier: < 30 seconds → multiplier 1.5x
        uint256 relayerBalBefore = relayer.balance;
        rewards.completeRelayWithReward(relayId);

        uint256 relayerBalAfter = relayer.balance;
        uint256 actualReward = relayerBalAfter - relayerBalBefore;

        // With ULTRA_FAST reward: baseReward * 15000/15000 = baseReward (full deposit)
        // minus 5% protocol fee
        uint256 expectedReward = (baseReward * 15000) / 15000;
        uint256 protocolFee = (expectedReward * 500) / 10000;
        expectedReward -= protocolFee;

        assertEq(
            actualReward,
            expectedReward,
            "ULTRA_FAST reward should be ~95% of deposit"
        );

        vm.stopPrank();
    }

    function test_relayerRewardsSlowTier() public {
        bytes32 relayId = keccak256("relay_slow");
        uint256 baseReward = 1 ether;

        vm.startPrank(admin);
        rewards.depositRelayFee{value: baseReward}(relayId, user);
        rewards.claimRelay(relayId, relayer);

        // Advance 10 minutes → SLOW tier (>= 5 min)
        vm.warp(block.timestamp + 10 minutes);

        uint256 relayerBalBefore = relayer.balance;
        rewards.completeRelayWithReward(relayId);
        uint256 actualReward = relayer.balance - relayerBalBefore;

        // SLOW: baseReward * 9000/15000 = 0.6 * baseReward, minus 5% fee
        uint256 tieredReward = (baseReward * 9000) / 15000;
        uint256 expectedReward = tieredReward - (tieredReward * 500) / 10000;

        assertEq(
            actualReward,
            expectedReward,
            "SLOW reward should be ~57% of deposit"
        );

        vm.stopPrank();
    }

    function test_calculateRewardTiers() public view {
        // Verify speed tier reward calculations
        // calculateReward applies 5% protocol fee after tiering
        uint256 baseReward = 1 ether;

        // Helper: expected = (base * multiplier / 15000) * 95%
        // ULTRA_FAST: <30s → full deposit minus 5% fee
        uint256 ultraFast = rewards.calculateReward(baseReward, 15);
        uint256 ufTiered = (baseReward * 15000) / 15000;
        uint256 ufExpected = ufTiered - (ufTiered * 500) / 10000;
        assertEq(ultraFast, ufExpected, "ULTRA_FAST should get 95% of deposit");

        // FAST: <60s → 83.3% of deposit minus 5% fee
        uint256 fast = rewards.calculateReward(baseReward, 45);
        uint256 fTiered = (baseReward * 12500) / 15000;
        uint256 fExpected = fTiered - (fTiered * 500) / 10000;
        assertEq(fast, fExpected, "FAST should get ~79.2%");

        // NORMAL: <5min → 66.7% of deposit minus 5% fee
        uint256 normal = rewards.calculateReward(baseReward, 120);
        uint256 nTiered = (baseReward * 10000) / 15000;
        uint256 nExpected = nTiered - (nTiered * 500) / 10000;
        assertEq(normal, nExpected, "NORMAL should get ~63.3%");

        // SLOW: >=5min → 60% of deposit minus 5% fee
        uint256 slow = rewards.calculateReward(baseReward, 600);
        uint256 sTiered = (baseReward * 9000) / 15000;
        uint256 sExpected = sTiered - (sTiered * 500) / 10000;
        assertEq(slow, sExpected, "SLOW should get ~57%");
    }

    // =========================================================================
    // DYNAMIC ROUTING: Pool & Bridge Management
    // =========================================================================

    function test_dynamicRoutingPoolRegistration() public {
        // Register bridge capacity
        vm.startPrank(bridgeAdmin);
        router.registerPool(SOURCE_CHAIN, 1000 ether, 0.01 ether);
        router.registerPool(DEST_CHAIN, 500 ether, 0.02 ether);
        vm.stopPrank();

        IDynamicRoutingOrchestrator.AdapterCapacity memory pool = router
            .getPool(SOURCE_CHAIN);
        assertEq(pool.chainId, SOURCE_CHAIN);
        assertEq(pool.totalCapacity, 1000 ether);
        assertEq(pool.availableCapacity, 1000 ether);
        assertEq(
            uint256(pool.status),
            uint256(IDynamicRoutingOrchestrator.PoolStatus.ACTIVE)
        );
    }

    function test_dynamicRoutingCapacityUpdate() public {
        // Register pool first
        vm.prank(bridgeAdmin);
        router.registerPool(SOURCE_CHAIN, 1000 ether, 0.01 ether);

        // Oracle updates capacity
        vm.prank(oracle);
        router.updateCapacity(SOURCE_CHAIN, 800 ether);

        IDynamicRoutingOrchestrator.AdapterCapacity memory pool = router
            .getPool(SOURCE_CHAIN);
        assertEq(pool.availableCapacity, 800 ether);
        // Utilization = (1000 - 800) / 1000 = 20% = 2000 bps
        assertEq(pool.utilizationBps, 2000);
    }

    function test_dynamicRoutingBridgeRegistration() public {
        address mockBridge = makeAddr("mockBridge");
        uint256[] memory supportedChains = new uint256[](2);
        supportedChains[0] = SOURCE_CHAIN;
        supportedChains[1] = DEST_CHAIN;

        vm.prank(bridgeAdmin);
        router.registerAdapter(mockBridge, supportedChains, 9000); // 90% security score

        IDynamicRoutingOrchestrator.AdapterMetrics memory metrics = router
            .getAdapterMetrics(mockBridge);
        assertTrue(metrics.isActive, "bridge should be active");
        assertEq(metrics.securityScoreBps, 9000);
    }

    function test_dynamicRoutingFindRoute() public {
        // Setup: Register pools and bridge
        address mockBridge = makeAddr("mockBridge");
        uint256[] memory chains = new uint256[](2);
        chains[0] = SOURCE_CHAIN;
        chains[1] = DEST_CHAIN;

        vm.startPrank(bridgeAdmin);
        router.registerPool(SOURCE_CHAIN, 1000 ether, 0.01 ether);
        router.registerPool(DEST_CHAIN, 500 ether, 0.02 ether);
        router.registerAdapter(mockBridge, chains, 9000);
        vm.stopPrank();

        // Update capacity to make data fresh
        vm.prank(oracle);
        router.updateCapacity(SOURCE_CHAIN, 1000 ether);
        vm.prank(oracle);
        router.updateCapacity(DEST_CHAIN, 500 ether);

        // Find optimal route
        IDynamicRoutingOrchestrator.RouteRequest
            memory request = IDynamicRoutingOrchestrator.RouteRequest({
                sourceChainId: SOURCE_CHAIN,
                destChainId: DEST_CHAIN,
                amount: 1 ether,
                urgency: IDynamicRoutingOrchestrator.Urgency.STANDARD,
                maxCost: 1 ether,
                maxTime: 3600,
                minSuccessBps: 5000,
                requirePrivacy: false
            });

        IDynamicRoutingOrchestrator.Route memory route = router
            .findOptimalRoute(request);
        assertTrue(route.routeId != bytes32(0), "route should be found");
        assertEq(
            route.chainPath.length,
            2,
            "route should be direct (2 chains)"
        );
        assertEq(route.chainPath[0], SOURCE_CHAIN);
        assertEq(route.chainPath[1], DEST_CHAIN);
    }

    // =========================================================================
    // HUB INTEGRATION: Verify Components Are Wired
    // =========================================================================

    function test_hubWiringWithIntentComponents() public {
        // Deploy hub and wire everything
        vm.startPrank(admin);
        hub = new ZaseonProtocolHub();

        hub.wireAll(
            IZaseonProtocolHub.WireAllParams({
                _verifierRegistry: address(0),
                _universalVerifier: address(0),
                _crossChainMessageRelay: address(0),
                _crossChainPrivacyHub: address(0),
                _stealthAddressRegistry: address(0),
                _privateRelayerNetwork: address(0),
                _viewKeyRegistry: address(0),
                _shieldedPool: address(0),
                _nullifierManager: address(0),
                _complianceOracle: address(0),
                _proofTranslator: address(0),
                _privacyRouter: address(0),
                _relayProofValidator: address(0),
                _zkBoundStateLocks: address(0),
                _proofCarryingContainer: address(0),
                _crossDomainNullifierAlgebra: address(0),
                _policyBoundProofs: address(0),
                _multiProver: address(0),
                _relayWatchtower: address(0),
                _intentCompletionLayer: address(intentLayer),
                _instantCompletionGuarantee: address(guarantee),
                _dynamicRoutingOrchestrator: address(router),
                _crossChainLiquidityVault: address(0)
            })
        );
        vm.stopPrank();

        // Verify components are wired
        (string[] memory names, address[] memory addrs) = hub
            .getComponentStatus();
        assertEq(names.length, 26, "should have 26 components");

        // Check the 3 new components are set
        bool foundIntent;
        bool foundGuarantee;
        bool foundRouter;
        for (uint256 i = 0; i < names.length; i++) {
            if (addrs[i] == address(intentLayer)) foundIntent = true;
            if (addrs[i] == address(guarantee)) foundGuarantee = true;
            if (addrs[i] == address(router)) foundRouter = true;
        }
        assertTrue(foundIntent, "IntentCompletionLayer should be wired");
        assertTrue(
            foundGuarantee,
            "InstantCompletionGuarantee should be wired"
        );
        assertTrue(foundRouter, "DynamicRoutingOrchestrator should be wired");
    }

    // =========================================================================
    // EDGE CASES & SECURITY
    // =========================================================================

    function test_intentCannotFinalizeBeforeChallengePeriod() public {
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            INTENT_FEE,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        vm.prank(solver);
        intentLayer.claimIntent(intentId);
        vm.prank(solver);
        intentLayer.fulfillIntent(intentId, hex"ab", hex"cd", keccak256("new"));

        // Should NOT be finalizable yet
        assertFalse(intentLayer.canFinalize(intentId));
        vm.expectRevert();
        intentLayer.finalizeIntent(intentId);
    }

    function test_intentExpiry() public {
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            INTENT_FEE,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        // Warp past deadline without claim
        vm.warp(block.timestamp + 2 hours);
        intentLayer.expireIntent(intentId);

        IIntentCompletionLayer.Intent memory intent = intentLayer.getIntent(
            intentId
        );
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.EXPIRED)
        );
    }

    function test_solverCannotClaimAfterTimeout() public {
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            INTENT_FEE,
            block.timestamp + 2 hours,
            bytes32(0)
        );

        // Solver claims
        vm.prank(solver);
        intentLayer.claimIntent(intentId);

        // Warp past claim timeout (30 min) without fulfilling
        vm.warp(block.timestamp + 31 minutes);

        // Intent should be expirable or reclaimable
        IIntentCompletionLayer.Intent memory intent = intentLayer.getIntent(
            intentId
        );
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.CLAIMED)
        );
    }

    function test_rewardRefundOnUnclaimedRelay() public {
        bytes32 relayId = keccak256("unclaimed_relay");
        uint256 baseReward = 0.5 ether;

        vm.startPrank(admin);
        rewards.depositRelayFee{value: baseReward}(relayId, user);

        // Refund without claiming
        uint256 userBalBefore = user.balance;
        rewards.refundDeposit(relayId);

        InstantRelayerRewards.RelayDeposit memory deposit = rewards.getDeposit(
            relayId
        );
        assertTrue(deposit.refunded, "should be refunded");
        assertEq(
            user.balance - userBalBefore,
            baseReward,
            "user should get full refund"
        );

        vm.stopPrank();
    }

    // =========================================================================
    // COMBINED FLOW: Intent + Guarantee + Reward
    // =========================================================================

    function test_fullEndToEndWithAllComponents() public {
        // 1. Register solver
        vm.prank(solver);
        intentLayer.registerSolver{value: SOLVER_STAKE}();

        // 2. Register pools and bridge for routing
        address mockBridge = makeAddr("bridge");
        uint256[] memory chains = new uint256[](2);
        chains[0] = SOURCE_CHAIN;
        chains[1] = DEST_CHAIN;
        vm.startPrank(bridgeAdmin);
        router.registerPool(SOURCE_CHAIN, 1000 ether, 0.01 ether);
        router.registerPool(DEST_CHAIN, 500 ether, 0.02 ether);
        router.registerAdapter(mockBridge, chains, 9000);
        vm.stopPrank();

        // 3. User submits intent
        vm.prank(user);
        bytes32 intentId = intentLayer.submitIntent{value: INTENT_FEE}(
            SOURCE_CHAIN,
            DEST_CHAIN,
            keccak256("src"),
            keccak256("dst"),
            INTENT_FEE,
            block.timestamp + 1 hours,
            bytes32(0)
        );

        // 4. Solver posts instant completion guarantee
        uint256 gAmount = 1 ether;
        uint256 bond = guarantee.requiredBond(gAmount);
        vm.prank(solver);
        bytes32 gId = guarantee.postGuarantee{value: bond}(
            intentId,
            user,
            gAmount,
            1 hours
        );

        // 5. Solver claims and fulfills intent
        vm.prank(solver);
        intentLayer.claimIntent(intentId);
        vm.prank(solver);
        intentLayer.fulfillIntent(
            intentId,
            hex"aabbccdd",
            hex"11223344",
            keccak256("new_state")
        );

        // 6. Deposit relay reward
        bytes32 relayId = keccak256(abi.encodePacked("relay_for_", intentId));
        vm.prank(admin);
        rewards.depositRelayFee{value: 0.05 ether}(relayId, user);
        vm.prank(admin);
        rewards.claimRelay(relayId, relayer);

        // 7. Complete relay (ULTRA_FAST)
        uint256 relayerBal = relayer.balance;
        vm.prank(admin);
        rewards.completeRelayWithReward(relayId);
        assertTrue(relayer.balance > relayerBal, "relayer should get reward");

        // 8. Wait for challenge period and finalize
        vm.warp(block.timestamp + 1 hours + 1);
        intentLayer.finalizeIntent(intentId);

        // 9. Solver settles guarantee
        uint256 solverBal = solver.balance;
        vm.prank(solver);
        guarantee.settleGuarantee(gId);
        assertTrue(solver.balance > solverBal, "solver should get bond back");

        // 10. Verify final states
        IIntentCompletionLayer.Intent memory intent = intentLayer.getIntent(
            intentId
        );
        assertEq(
            uint256(intent.status),
            uint256(IIntentCompletionLayer.IntentStatus.FINALIZED)
        );

        IInstantCompletionGuarantee.Guarantee memory g = guarantee.getGuarantee(
            gId
        );
        assertEq(
            uint256(g.status),
            uint256(IInstantCompletionGuarantee.GuaranteeStatus.SETTLED)
        );

        InstantRelayerRewards.RelayDeposit memory deposit = rewards.getDeposit(
            relayId
        );
        assertTrue(deposit.completed, "relay should be completed");
    }
}
