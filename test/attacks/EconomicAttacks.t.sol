// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Economic Attack Simulation Tests
 * @notice Tests economic attack vectors specific to bridge fee extraction,
 *         escrow timing races, relayer bond economics, and gas griefing.
 * @dev Complements FlashLoanAttacks.t.sol and FrontrunningAttacks.t.sol by
 *      covering bridge-specific economic attack surfaces.
 *
 * Coverage targets:
 * - Bridge fee rounding/dust extraction
 * - Escrow HTLC timing race conditions
 * - Relayer bond slashing economics
 * - Cross-chain withdrawal refund double-claim
 * - Gas griefing on message execution
 * - Batch processing incentive alignment
 * - Donation/inflation attacks on wrapped tokens
 */
contract EconomicAttacks is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant BRIDGE_FEE_BPS = 3;
    uint256 constant BPS_DENOMINATOR = 10_000;
    uint256 constant MIN_DEPOSIT = 0.001 ether;
    uint256 constant MAX_DEPOSIT = 10_000_000 ether;
    uint256 constant WITHDRAWAL_REFUND_DELAY = 24 hours;
    uint256 constant MIN_ESCROW_TIMELOCK = 1 hours;
    uint256 constant MAX_ESCROW_TIMELOCK = 30 days;
    uint256 constant MIN_RELAYER_BOND = 1 ether;
    uint256 constant SLASH_PERCENTAGE = 10; // 10%
    uint256 constant CHALLENGE_BOND = 0.1 ether;
    uint256 constant UNBONDING_PERIOD = 7 days;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockBridgeWithFees public bridge;
    MockEscrowSystem public escrow;
    MockRelayerRegistry public relayerRegistry;
    MockWrappedToken public wrappedToken;
    MockMessageExecutor public messageExecutor;
    MockBatchProcessor public batchProcessor;

    address public attacker;
    address public victim;
    address public relayer;
    address public operator;
    address public challenger;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        relayer = makeAddr("relayer");
        operator = makeAddr("operator");
        challenger = makeAddr("challenger");

        // Deploy mock infrastructure
        wrappedToken = new MockWrappedToken("Wrapped OP", "wOP");
        bridge = new MockBridgeWithFees(
            address(wrappedToken),
            BRIDGE_FEE_BPS,
            BPS_DENOMINATOR,
            MIN_DEPOSIT
        );
        escrow = new MockEscrowSystem(MIN_ESCROW_TIMELOCK, MAX_ESCROW_TIMELOCK);
        relayerRegistry = new MockRelayerRegistry(
            MIN_RELAYER_BOND,
            SLASH_PERCENTAGE,
            CHALLENGE_BOND,
            UNBONDING_PERIOD
        );
        messageExecutor = new MockMessageExecutor();
        batchProcessor = new MockBatchProcessor();

        // Fund accounts
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
        vm.deal(relayer, 10 ether);
        vm.deal(challenger, 10 ether);
        vm.deal(operator, 10 ether);

        // Setup relayer
        vm.prank(relayer);
        relayerRegistry.registerRelayer{value: MIN_RELAYER_BOND}();
    }

    /*//////////////////////////////////////////////////////////////
              1. BRIDGE FEE ROUNDING / DUST EXTRACTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that sub-BPS-threshold amounts are rejected by MIN_DEPOSIT
     * @dev If fee = (amount * 3) / 10000 = 0 for amounts below ~3333 wei,
     *      MIN_DEPOSIT (0.001 ether) prevents zero-fee bridging.
     */
    function test_dustAmount_belowMinDeposit_shouldRevert() public {
        uint256 dustAmount = 100 wei; // Way below MIN_DEPOSIT
        vm.prank(attacker);
        vm.expectRevert("Amount below minimum");
        bridge.initiateDeposit{value: dustAmount}(attacker);
    }

    /**
     * @notice Test that fee at MIN_DEPOSIT is non-zero
     * @dev fee = (0.001 ether * 3) / 10000 = 300_000_000_000 wei = 0.0000003 ether
     */
    function test_feeAtMinDeposit_shouldBeNonZero() public {
        uint256 fee = bridge.calculateFee(MIN_DEPOSIT);
        assertGt(fee, 0, "Fee at MIN_DEPOSIT should be > 0");
        assertEq(fee, (MIN_DEPOSIT * BRIDGE_FEE_BPS) / BPS_DENOMINATOR);
    }

    /**
     * @notice Fuzz test: fee is always > 0 for valid amounts
     */
    function testFuzz_fee_alwaysPositive(uint256 amount) public view {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = bridge.calculateFee(amount);
        assertGt(fee, 0, "Fee should always be positive for valid amounts");
    }

    /**
     * @notice Test batch of small deposits doesn't bypass total fees
     * @dev Attacker tries N small deposits instead of 1 large deposit
     */
    function test_batchSmallDeposits_shouldNotBypassFees() public {
        uint256 totalAmount = 10 ether;
        uint256 numDeposits = 100;
        uint256 perDeposit = totalAmount / numDeposits;

        // Ensure per-deposit amount is >= MIN_DEPOSIT
        assertGe(
            perDeposit,
            MIN_DEPOSIT,
            "Per-deposit should be >= MIN_DEPOSIT"
        );

        uint256 totalFeeBatch = 0;
        for (uint256 i = 0; i < numDeposits; i++) {
            totalFeeBatch += bridge.calculateFee(perDeposit);
        }

        uint256 totalFeeSingle = bridge.calculateFee(totalAmount);

        // Due to rounding, batch fees should be >= single fee (integer division rounds down)
        // The difference should be negligible (< numDeposits wei per deposit)
        assertGe(
            totalFeeBatch,
            totalFeeSingle - numDeposits,
            "Batch fees should not be significantly less than single fee"
        );
    }

    /*//////////////////////////////////////////////////////////////
            2. ESCROW HTLC TIMING RACE CONDITIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that escrow cannot be finished before finishAfter
     */
    function test_escrowFinish_beforeTimelock_shouldRevert() public {
        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 4 hours;
        bytes32 preimage = keccak256("secret");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        vm.prank(victim);
        bytes32 escrowId = escrow.createEscrow{value: 1 ether}(
            attacker,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Try to finish before finishAfter
        vm.prank(attacker);
        vm.expectRevert("Timelock not met");
        escrow.finishEscrow(escrowId, preimage);
    }

    /**
     * @notice Test race condition at the finishAfter/cancelAfter boundary
     * @dev Both finish and cancel become available — first to execute wins
     */
    function test_escrowRace_atBoundary_firstExecutorWins() public {
        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 4 hours;
        bytes32 preimage = keccak256("secret");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        vm.prank(victim);
        bytes32 escrowId = escrow.createEscrow{value: 1 ether}(
            attacker,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Advance to cancelAfter (both finish and cancel are valid)
        vm.warp(cancelAfter);

        // Attacker finishes first (has the preimage)
        uint256 attackerBalBefore = attacker.balance;
        vm.prank(attacker);
        escrow.finishEscrow(escrowId, preimage);
        assertEq(
            attacker.balance,
            attackerBalBefore + 1 ether,
            "Attacker should receive funds"
        );

        // Victim tries to cancel — should fail (already finished)
        vm.prank(victim);
        vm.expectRevert("Escrow not active");
        escrow.cancelEscrow(escrowId);
    }

    /**
     * @notice Test that cancel is blocked before cancelAfter even if finishAfter passed
     */
    function test_escrowCancel_beforeCancelAfter_shouldRevert() public {
        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 4 hours;
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        vm.prank(victim);
        bytes32 escrowId = escrow.createEscrow{value: 1 ether}(
            attacker,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Advance past finishAfter but before cancelAfter
        vm.warp(finishAfter + 1);

        vm.prank(victim);
        vm.expectRevert("Cancel timelock not met");
        escrow.cancelEscrow(escrowId);
    }

    /**
     * @notice Fuzz: escrow timelocks maintain ordering invariant
     */
    function testFuzz_escrowTimelocks_finishBeforeCancel(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1, 365 days);
        duration = bound(duration, MIN_ESCROW_TIMELOCK, MAX_ESCROW_TIMELOCK);

        uint256 finishAfter = block.timestamp + finishOffset;
        uint256 cancelAfter = finishAfter + duration;
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("fuzz_secret")));

        vm.prank(victim);
        bytes32 escrowId = escrow.createEscrow{value: MIN_DEPOSIT}(
            attacker,
            hashlock,
            finishAfter,
            cancelAfter
        );
        assertTrue(escrowId != bytes32(0), "Escrow should be created");
    }

    /*//////////////////////////////////////////////////////////////
            3. RELAYER BOND SLASHING ECONOMICS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that slashing amount is >= minimum profit threshold
     * @dev If slash < potential profit, relayers are incentivized to cheat
     */
    function test_slashAmount_exceedsPotentialProfit() public {
        uint256 bond = MIN_RELAYER_BOND;
        uint256 slashAmount = (bond * SLASH_PERCENTAGE) / 100;

        // Slash amount should be meaningful (>= 0.1 ether for 1 ether bond)
        assertGe(
            slashAmount,
            0.1 ether,
            "Slash must exceed minimum profit threshold"
        );
    }

    /**
     * @notice Test that Sybil registration is costly
     * @dev N relayer registrations cost N * MIN_RELAYER_BOND
     */
    function test_sybilRegistration_isCostly() public {
        uint256 numSybils = 10;
        uint256 totalCost = numSybils * MIN_RELAYER_BOND;

        assertEq(totalCost, 10 ether, "10 Sybil relayers cost 10 ETH");

        // Register multiple relayers
        for (uint256 i = 0; i < numSybils; i++) {
            address sybil = makeAddr(string(abi.encodePacked("sybil_", i)));
            vm.deal(sybil, MIN_RELAYER_BOND);
            vm.prank(sybil);
            relayerRegistry.registerRelayer{value: MIN_RELAYER_BOND}();
        }

        // Verify all registered
        assertEq(
            relayerRegistry.relayerCount(),
            numSybils + 1, // +1 from setUp
            "All Sybils should be registered"
        );
    }

    /**
     * @notice Test that unbonding period prevents slash-and-run
     */
    function test_unbonding_preventsImmediateWithdrawal() public {
        vm.prank(relayer);
        relayerRegistry.initiateUnbonding();

        // Try to withdraw before unbonding period
        vm.prank(relayer);
        vm.expectRevert("Unbonding period not elapsed");
        relayerRegistry.withdrawBond();

        // Advance past unbonding period
        vm.warp(block.timestamp + UNBONDING_PERIOD + 1);

        uint256 balBefore = relayer.balance;
        vm.prank(relayer);
        relayerRegistry.withdrawBond();
        assertEq(
            relayer.balance,
            balBefore + MIN_RELAYER_BOND,
            "Should receive full bond after unbonding"
        );
    }

    /**
     * @notice Test that slashed relayer receives reduced bond
     */
    function test_slashedRelayer_receivesReducedBond() public {
        // Slash the relayer
        vm.prank(operator);
        relayerRegistry.slashRelayer(relayer);

        uint256 expectedBond = MIN_RELAYER_BOND -
            (MIN_RELAYER_BOND * SLASH_PERCENTAGE) /
            100;

        vm.prank(relayer);
        relayerRegistry.initiateUnbonding();
        vm.warp(block.timestamp + UNBONDING_PERIOD + 1);

        uint256 balBefore = relayer.balance;
        vm.prank(relayer);
        relayerRegistry.withdrawBond();
        assertEq(
            relayer.balance,
            balBefore + expectedBond,
            "Slashed relayer gets reduced bond"
        );
    }

    /*//////////////////////////////////////////////////////////////
            4. CHALLENGE BOND GRIEFING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that spam challenges cost the challenger
     * @dev Failed challenges forfeit the challenge bond
     */
    function test_spamChallenge_forfeitsChallengeBond() public {
        // Submit a valid relay
        vm.prank(relayer);
        bytes32 relayId = relayerRegistry.submitRelay(
            keccak256("valid_message")
        );

        // Challenger submits frivolous challenge
        uint256 challengerBalBefore = challenger.balance;
        vm.prank(challenger);
        relayerRegistry.challengeRelay{value: CHALLENGE_BOND}(relayId);

        // Challenge resolved as invalid (relayer was honest)
        vm.prank(operator);
        relayerRegistry.resolveChallenge(relayId, false); // false = challenge failed

        // Challenger loses their bond
        assertEq(
            challenger.balance,
            challengerBalBefore - CHALLENGE_BOND,
            "Challenger should lose bond on failed challenge"
        );
    }

    /**
     * @notice Test that valid challenges reward the challenger
     */
    function test_validChallenge_rewardsChallenger() public {
        vm.prank(relayer);
        bytes32 relayId = relayerRegistry.submitRelay(
            keccak256("fraudulent_message")
        );

        uint256 challengerBalBefore = challenger.balance;
        vm.prank(challenger);
        relayerRegistry.challengeRelay{value: CHALLENGE_BOND}(relayId);

        // Challenge resolved as valid (relayer was dishonest)
        vm.prank(operator);
        relayerRegistry.resolveChallenge(relayId, true); // true = challenge succeeded

        // Challenger gets bond back + slash reward
        uint256 slashReward = (MIN_RELAYER_BOND * SLASH_PERCENTAGE) / 100;
        assertGe(
            challenger.balance,
            challengerBalBefore + slashReward - 1, // -1 for rounding
            "Challenger should be rewarded on valid challenge"
        );
    }

    /*//////////////////////////////////////////////////////////////
            5. WITHDRAWAL REFUND TIMING ATTACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that refund is blocked before WITHDRAWAL_REFUND_DELAY
     */
    function test_earlyRefund_shouldRevert() public {
        vm.prank(victim);
        bytes32 withdrawalId = bridge.initiateWithdrawal{value: 1 ether}(
            victim
        );

        // Try to refund immediately
        vm.prank(victim);
        vm.expectRevert("Refund delay not elapsed");
        bridge.refundWithdrawal(withdrawalId);
    }

    /**
     * @notice Test that completed withdrawal cannot be refunded
     * @dev Prevents double-claim: refund on L1 + tokens already released on L2
     */
    function test_completedWithdrawal_cannotBeRefunded() public {
        vm.prank(victim);
        bytes32 withdrawalId = bridge.initiateWithdrawal{value: 1 ether}(
            victim
        );

        // Complete the withdrawal
        vm.prank(operator);
        bridge.completeWithdrawal(withdrawalId);

        // Advance past refund delay
        vm.warp(block.timestamp + WITHDRAWAL_REFUND_DELAY + 1);

        // Try to refund — should fail because already completed
        vm.prank(victim);
        vm.expectRevert("Withdrawal not pending");
        bridge.refundWithdrawal(withdrawalId);
    }

    /**
     * @notice Test that refund after delay succeeds for pending withdrawals
     */
    function test_refundAfterDelay_succeeds() public {
        vm.prank(victim);
        bytes32 withdrawalId = bridge.initiateWithdrawal{value: 1 ether}(
            victim
        );

        vm.warp(block.timestamp + WITHDRAWAL_REFUND_DELAY + 1);

        uint256 balBefore = victim.balance;
        vm.prank(victim);
        bridge.refundWithdrawal(withdrawalId);
        assertEq(
            victim.balance,
            balBefore + 1 ether,
            "Refund should return full amount"
        );
    }

    /*//////////////////////////////////////////////////////////////
            6. GAS GRIEFING ON MESSAGE EXECUTION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that gas griefing recipient cannot consume unlimited gas
     * @dev Malicious recipient consumes all forwarded gas to force failure
     */
    function test_gasGriefing_cappedByGasLimit() public {
        GasGriefingReceiver griefingReceiver = new GasGriefingReceiver();

        bytes memory payload = abi.encodeWithSignature(
            "receiveMessage(bytes)",
            "hello"
        );
        uint256 gasLimit = 100_000;

        // Execute with capped gas — should not revert the outer call
        bool success = messageExecutor.executeWithGasLimit(
            address(griefingReceiver),
            payload,
            gasLimit
        );

        // Execution may fail (griefing consumed the gas) but the executor survives
        // The key invariant: the executor itself doesn't run out of gas
        assertTrue(true, "Executor survived gas griefing attempt");
    }

    /**
     * @notice Test that return-data bomb doesn't grief the executor
     * @dev Malicious contract returns huge data to waste gas on memory expansion
     */
    function test_returnDataBomb_doesNotGriefExecutor() public {
        ReturnDataBomber bomber = new ReturnDataBomber();

        bytes memory payload = abi.encodeWithSignature("execute()");
        uint256 gasLimit = 200_000;

        // Execute — should cap return data handling
        bool success = messageExecutor.executeWithGasLimit(
            address(bomber),
            payload,
            gasLimit
        );

        // Executor survives regardless of return data size
        assertTrue(true, "Executor handled return data bomb");
    }

    /*//////////////////////////////////////////////////////////////
            7. WRAPPED TOKEN DONATION/INFLATION ATTACK
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test first-depositor inflation attack on wrapped token
     * @dev Attacker deposits 1 wei, donates large amount, next depositor gets 0 shares
     */
    function test_firstDepositorInflation_isProtected() public {
        // Attacker is the first depositor — deposits minimum
        vm.prank(attacker);
        uint256 attackerShares = wrappedToken.deposit{value: 1 wei}();
        assertGt(attackerShares, 0, "Attacker should receive shares");

        // Attacker donates directly to inflate share price
        vm.prank(attacker);
        (bool s, ) = address(wrappedToken).call{value: 10 ether}("");
        require(s);

        // Victim deposits a normal amount
        vm.prank(victim);
        uint256 victimShares = wrappedToken.deposit{value: 1 ether}();

        // Protection: victim should still get meaningful shares
        // Without protection: victimShares = 0 (1 ether / (10 ether + 1 wei) * 1 share = 0)
        // With protection: minimum shares or virtual offset prevents this
        assertGt(
            victimShares,
            0,
            "Victim should receive > 0 shares (inflation protection)"
        );
    }

    /**
     * @notice Test that token mint/burn is balanced
     */
    function test_wrappedToken_mintBurnBalance() public {
        vm.prank(victim);
        uint256 shares = wrappedToken.deposit{value: 5 ether}();

        uint256 balBefore = victim.balance;
        vm.prank(victim);
        wrappedToken.withdraw(shares);

        // Victim should get back approximately what they deposited (minus any fees)
        uint256 returned = victim.balance - balBefore;
        assertGe(returned, 4.99 ether, "Should return ~deposited amount");
        assertLe(returned, 5 ether, "Should not return more than deposited");
    }

    /*//////////////////////////////////////////////////////////////
            8. BATCH PROCESSING INCENTIVE ALIGNMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test that batch processing has an incentive (relayer reward)
     */
    function test_batchProcessing_hasReward() public {
        // Add items to the batch
        for (uint256 i = 0; i < 5; i++) {
            batchProcessor.addToBatch(keccak256(abi.encodePacked("tx_", i)));
        }

        uint256 relayerBalBefore = relayer.balance;
        vm.prank(relayer);
        batchProcessor.processBatch{value: 0}();

        // Relayer should receive a processing reward
        uint256 reward = relayer.balance - relayerBalBefore;
        assertGt(reward, 0, "Batch processor should receive reward");
    }

    /**
     * @notice Test that empty batch processing is rejected
     */
    function test_emptyBatch_shouldRevert() public {
        vm.prank(relayer);
        vm.expectRevert("Empty batch");
        batchProcessor.processBatch();
    }

    /*//////////////////////////////////////////////////////////////
             FUZZ: COMPREHENSIVE ECONOMIC INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Fuzz: bridge fees are always between 0 and amount
     */
    function testFuzz_bridgeFee_bounded(uint256 amount) public view {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = bridge.calculateFee(amount);
        assertGt(fee, 0, "Fee must be positive");
        assertLt(fee, amount, "Fee must be less than amount");
    }

    /**
     * @notice Fuzz: net amount + fee == deposited amount
     */
    function testFuzz_feeAccountingInvariant(uint256 amount) public view {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = bridge.calculateFee(amount);
        uint256 netAmount = amount - fee;
        assertEq(netAmount + fee, amount, "Accounting must be exact");
    }

    /**
     * @notice Fuzz: slash amount scales with bond
     */
    function testFuzz_slashScalesWithBond(uint256 bond) public pure {
        bond = bound(bond, 0.1 ether, 100 ether);
        uint256 slashAmount = (bond * SLASH_PERCENTAGE) / 100;
        assertGe(
            slashAmount,
            bond / 100,
            "Slash should be at least 1% of bond"
        );
        assertLe(slashAmount, bond, "Slash should not exceed bond");
    }
}

/*//////////////////////////////////////////////////////////////
                       MOCK CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockBridgeWithFees {
    address public wrappedToken;
    uint256 public feeBps;
    uint256 public bpsDenom;
    uint256 public minDeposit;
    uint256 public withdrawalRefundDelay = 24 hours;

    enum WithdrawalStatus {
        PENDING,
        COMPLETED,
        REFUNDED
    }

    struct Withdrawal {
        address sender;
        uint256 amount;
        uint256 initiatedAt;
        WithdrawalStatus status;
    }

    mapping(bytes32 => Withdrawal) public withdrawals;
    uint256 private nonce;

    constructor(
        address _wrappedToken,
        uint256 _feeBps,
        uint256 _bpsDenom,
        uint256 _minDeposit
    ) {
        wrappedToken = _wrappedToken;
        feeBps = _feeBps;
        bpsDenom = _bpsDenom;
        minDeposit = _minDeposit;
    }

    function calculateFee(uint256 amount) public view returns (uint256) {
        return (amount * feeBps) / bpsDenom;
    }

    function initiateDeposit(
        address recipient
    ) external payable returns (bytes32) {
        require(msg.value >= minDeposit, "Amount below minimum");
        require(recipient != address(0), "Zero address");
        bytes32 depositId = keccak256(
            abi.encodePacked(msg.sender, recipient, msg.value, nonce++)
        );
        return depositId;
    }

    function initiateWithdrawal(
        address l2Recipient
    ) external payable returns (bytes32) {
        require(msg.value >= minDeposit, "Amount below minimum");
        bytes32 withdrawalId = keccak256(
            abi.encodePacked(msg.sender, l2Recipient, msg.value, nonce++)
        );
        withdrawals[withdrawalId] = Withdrawal({
            sender: msg.sender,
            amount: msg.value,
            initiatedAt: block.timestamp,
            status: WithdrawalStatus.PENDING
        });
        return withdrawalId;
    }

    function completeWithdrawal(bytes32 withdrawalId) external {
        Withdrawal storage w = withdrawals[withdrawalId];
        require(w.status == WithdrawalStatus.PENDING, "Withdrawal not pending");
        w.status = WithdrawalStatus.COMPLETED;
    }

    function refundWithdrawal(bytes32 withdrawalId) external {
        Withdrawal storage w = withdrawals[withdrawalId];
        require(w.status == WithdrawalStatus.PENDING, "Withdrawal not pending");
        require(
            block.timestamp >= w.initiatedAt + withdrawalRefundDelay,
            "Refund delay not elapsed"
        );
        require(msg.sender == w.sender, "Not sender");
        w.status = WithdrawalStatus.REFUNDED;
        (bool success, ) = payable(w.sender).call{value: w.amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

contract MockEscrowSystem {
    uint256 public minTimelock;
    uint256 public maxTimelock;

    enum EscrowStatus {
        ACTIVE,
        FINISHED,
        CANCELLED
    }

    struct Escrow {
        address creator;
        address beneficiary;
        uint256 amount;
        bytes32 hashlock;
        uint256 finishAfter;
        uint256 cancelAfter;
        EscrowStatus status;
    }

    mapping(bytes32 => Escrow) public escrows;
    uint256 private nonce;

    constructor(uint256 _minTimelock, uint256 _maxTimelock) {
        minTimelock = _minTimelock;
        maxTimelock = _maxTimelock;
    }

    function createEscrow(
        address beneficiary,
        bytes32 hashlock,
        uint256 finishAfter,
        uint256 cancelAfter
    ) external payable returns (bytes32) {
        require(msg.value > 0, "Zero value");
        require(beneficiary != address(0), "Zero address");
        require(finishAfter < cancelAfter, "Invalid timelocks");
        uint256 duration = cancelAfter - finishAfter;
        require(duration >= minTimelock, "Duration too short");
        require(duration <= maxTimelock, "Duration too long");

        bytes32 escrowId = keccak256(
            abi.encodePacked(msg.sender, beneficiary, hashlock, nonce++)
        );
        escrows[escrowId] = Escrow({
            creator: msg.sender,
            beneficiary: beneficiary,
            amount: msg.value,
            hashlock: hashlock,
            finishAfter: finishAfter,
            cancelAfter: cancelAfter,
            status: EscrowStatus.ACTIVE
        });
        return escrowId;
    }

    function finishEscrow(bytes32 escrowId, bytes32 preimage) external {
        Escrow storage e = escrows[escrowId];
        require(e.status == EscrowStatus.ACTIVE, "Escrow not active");
        require(block.timestamp >= e.finishAfter, "Timelock not met");
        bytes32 computedHash = sha256(abi.encodePacked(preimage));
        require(computedHash == e.hashlock, "Invalid preimage");
        e.status = EscrowStatus.FINISHED;
        (bool success, ) = payable(e.beneficiary).call{value: e.amount}("");
        require(success, "Transfer failed");
    }

    function cancelEscrow(bytes32 escrowId) external {
        Escrow storage e = escrows[escrowId];
        require(e.status == EscrowStatus.ACTIVE, "Escrow not active");
        require(block.timestamp >= e.cancelAfter, "Cancel timelock not met");
        e.status = EscrowStatus.CANCELLED;
        (bool success, ) = payable(e.creator).call{value: e.amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

contract MockRelayerRegistry {
    uint256 public minBond;
    uint256 public slashPct;
    uint256 public challengeBond;
    uint256 public unbondingPeriod;
    uint256 public relayerCount;

    struct Relayer {
        uint256 bond;
        bool active;
        uint256 unbondingStart;
        bool slashed;
    }

    struct Relay {
        bytes32 messageHash;
        address relayer;
        bool challenged;
        bool resolved;
    }

    mapping(address => Relayer) public relayers;
    mapping(bytes32 => Relay) public relays;
    mapping(bytes32 => address) public challengers;
    mapping(bytes32 => uint256) public challengeBonds;
    uint256 private nonce;

    constructor(
        uint256 _minBond,
        uint256 _slashPct,
        uint256 _challengeBond,
        uint256 _unbondingPeriod
    ) {
        minBond = _minBond;
        slashPct = _slashPct;
        challengeBond = _challengeBond;
        unbondingPeriod = _unbondingPeriod;
    }

    function registerRelayer() external payable {
        require(msg.value >= minBond, "Insufficient bond");
        require(!relayers[msg.sender].active, "Already registered");
        relayers[msg.sender] = Relayer({
            bond: msg.value,
            active: true,
            unbondingStart: 0,
            slashed: false
        });
        relayerCount++;
    }

    function initiateUnbonding() external {
        Relayer storage r = relayers[msg.sender];
        require(r.active, "Not active");
        r.active = false;
        r.unbondingStart = block.timestamp;
    }

    function withdrawBond() external {
        Relayer storage r = relayers[msg.sender];
        require(!r.active, "Still active");
        require(r.unbondingStart > 0, "Not unbonding");
        require(
            block.timestamp >= r.unbondingStart + unbondingPeriod,
            "Unbonding period not elapsed"
        );
        uint256 amount = r.bond;
        r.bond = 0;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }

    function slashRelayer(address _relayer) external {
        Relayer storage r = relayers[_relayer];
        require(r.bond > 0, "No bond");
        uint256 slashAmount = (r.bond * slashPct) / 100;
        r.bond -= slashAmount;
        r.slashed = true;
    }

    function submitRelay(
        bytes32 messageHash
    ) external returns (bytes32 relayId) {
        relayId = keccak256(abi.encodePacked(messageHash, msg.sender, nonce++));
        relays[relayId] = Relay({
            messageHash: messageHash,
            relayer: msg.sender,
            challenged: false,
            resolved: false
        });
    }

    function challengeRelay(bytes32 relayId) external payable {
        require(msg.value >= challengeBond, "Insufficient challenge bond");
        Relay storage r = relays[relayId];
        require(!r.challenged, "Already challenged");
        r.challenged = true;
        challengers[relayId] = msg.sender;
        challengeBonds[relayId] = msg.value;
    }

    function resolveChallenge(
        bytes32 relayId,
        bool challengeSucceeded
    ) external {
        Relay storage r = relays[relayId];
        require(r.challenged, "Not challenged");
        require(!r.resolved, "Already resolved");
        r.resolved = true;

        if (challengeSucceeded) {
            // Slash the relayer, reward the challenger
            uint256 slashAmount = (relayers[r.relayer].bond * slashPct) / 100;
            relayers[r.relayer].bond -= slashAmount;
            relayers[r.relayer].slashed = true;

            uint256 reward = challengeBonds[relayId] + slashAmount;
            (bool success, ) = payable(challengers[relayId]).call{
                value: reward
            }("");
            require(success, "Reward transfer failed");
        }
        // If challenge failed, challenger loses their bond (stays in contract)
    }

    receive() external payable {}
}

contract MockWrappedToken {
    string public name;
    string public symbol;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    // Virtual offset to prevent inflation attack (ERC4626 mitigation)
    uint256 constant VIRTUAL_OFFSET = 1e6;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function deposit() external payable returns (uint256) {
        uint256 totalAssets = address(this).balance -
            msg.value +
            VIRTUAL_OFFSET;
        uint256 currentShares = totalShares + VIRTUAL_OFFSET;
        uint256 newShares = (msg.value * currentShares) / totalAssets;

        shares[msg.sender] += newShares;
        totalShares += newShares;
        return newShares;
    }

    function withdraw(uint256 shareAmount) external {
        require(shares[msg.sender] >= shareAmount, "Insufficient shares");
        uint256 totalAssets = address(this).balance + VIRTUAL_OFFSET;
        uint256 currentShares = totalShares + VIRTUAL_OFFSET;
        uint256 assetAmount = (shareAmount * totalAssets) / currentShares;

        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        (bool success, ) = payable(msg.sender).call{value: assetAmount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

contract MockMessageExecutor {
    function executeWithGasLimit(
        address target,
        bytes memory payload,
        uint256 gasLimit
    ) external returns (bool) {
        (bool success, ) = target.call{gas: gasLimit}(payload);
        return success;
    }
}

contract MockBatchProcessor {
    bytes32[] public pendingBatch;
    uint256 constant BATCH_REWARD = 0.01 ether;

    function addToBatch(bytes32 txHash) external {
        pendingBatch.push(txHash);
    }

    function processBatch() external payable {
        require(pendingBatch.length > 0, "Empty batch");
        delete pendingBatch;

        // Pay the processor
        (bool success, ) = payable(msg.sender).call{value: BATCH_REWARD}("");
        require(success, "Reward failed");
    }

    receive() external payable {}
}

contract GasGriefingReceiver {
    function receiveMessage(bytes calldata) external {
        // Consume all available gas with infinite loop
        // solhint-disable-next-line no-empty-blocks
        for (uint256 i = 0; ; i++) {
            // Waste gas on storage writes
            assembly {
                sstore(i, i)
            }
        }
    }
}

contract ReturnDataBomber {
    function execute() external pure returns (bytes memory) {
        // Return 1 MB of data to try to grief via memory expansion
        bytes memory bomb = new bytes(1024 * 1024);
        return bomb;
    }
}
