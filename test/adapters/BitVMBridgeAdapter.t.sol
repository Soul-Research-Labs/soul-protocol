// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/adapters/BitVMBridgeAdapter.sol";

/**
 * @title MockBitcoinRelay
 * @notice Configurable mock for IBitcoinRelay
 */
contract MockBitcoinRelay is IBitcoinRelay {
    bool public shouldVerify = true;
    uint256 public bestHeight = 900000;

    function setVerifyResult(bool _v) external {
        shouldVerify = _v;
    }

    function setBestHeight(uint256 h) external {
        bestHeight = h;
    }

    function verifyTx(
        bytes32,
        bytes32,
        uint256,
        bytes calldata,
        uint256
    ) external view override returns (bool valid) {
        return shouldVerify;
    }

    function getBestKnownHeight() external view override returns (uint256) {
        return bestHeight;
    }
}

/**
 * @title MockWrappedBTC
 * @notice Minimal mock ERC-20 for IWrappedBTC with mint/burn tracking
 */
contract MockWrappedBTC is IWrappedBTC {
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;
    uint256 public override totalSupply;

    uint256 public mintCallCount;
    uint256 public burnCallCount;

    function mint(address to, uint256 amount) external override {
        balanceOf[to] += amount;
        totalSupply += amount;
        mintCallCount++;
    }

    function burn(address from, uint256 amount) external override {
        require(balanceOf[from] >= amount, "Insufficient balance");
        balanceOf[from] -= amount;
        totalSupply -= amount;
        burnCallCount++;
    }

    function transfer(
        address to,
        uint256 amount
    ) external override returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(
        address spender,
        uint256 amount
    ) external override returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external override returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract BitVMBridgeAdapterTest is Test {
    BitVMBridgeAdapter adapter;
    MockBitcoinRelay relay;
    MockWrappedBTC wbtc;

    address admin = makeAddr("admin");
    address operator = makeAddr("operator");
    address challenger = makeAddr("challenger");
    address user = makeAddr("user");
    address guardian = makeAddr("guardian");

    function setUp() public {
        relay = new MockBitcoinRelay();
        wbtc = new MockWrappedBTC();

        vm.prank(admin);
        adapter = new BitVMBridgeAdapter(
            admin,
            0,
            address(relay),
            address(wbtc)
        );
    }

    // ── Constructor & Roles ──

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.GUARDIAN_ROLE(), admin));
    }

    function test_constructor_defaultChallengePeriod() public view {
        assertEq(adapter.challengePeriod(), 7 days);
    }

    function test_constructor_customChallengePeriod() public {
        vm.prank(admin);
        BitVMBridgeAdapter custom = new BitVMBridgeAdapter(
            admin,
            3 days,
            address(relay),
            address(wbtc)
        );
        assertEq(custom.challengePeriod(), 3 days);
    }

    function test_constants() public view {
        assertEq(adapter.BITCOIN_CHAIN_ID(), 0);
        assertEq(adapter.MIN_OPERATOR_BOND(), 10 ether);
        assertEq(adapter.MIN_CHALLENGE_BOND(), 1 ether);
        assertEq(adapter.BTC_CONFIRMATIONS(), 6);
    }

    // ── bridgeMessage reverts NotImplemented ──

    function test_bridgeMessage_reverts() public {
        vm.expectRevert(BitVMBridgeAdapter.NotImplemented.selector);
        adapter.bridgeMessage{value: 0.1 ether}(
            address(0xBEEF),
            hex"01",
            address(0)
        );
    }

    // ── estimateFee ──

    function test_estimateFee_returnsFixedFee() public view {
        uint256 fee = adapter.estimateFee(address(0), hex"01");
        assertEq(fee, 0.01 ether);
    }

    // ── registerOperator ──

    function test_registerOperator_success() public {
        vm.deal(operator, 20 ether);
        vm.prank(operator);
        adapter.registerOperator{value: 10 ether}();

        BitVMBridgeAdapter.Operator memory op = adapter.getOperator(operator);
        assertEq(op.bond, 10 ether);
        assertTrue(op.active);
        assertFalse(op.slashed);
    }

    function test_registerOperator_insufficientBond() public {
        vm.deal(operator, 5 ether);
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMBridgeAdapter.InsufficientBond.selector,
                5 ether,
                10 ether
            )
        );
        adapter.registerOperator{value: 5 ether}();
    }

    // ── submitDepositClaim ──

    function _registerAndGrantOperator() internal {
        vm.deal(operator, 20 ether);
        vm.prank(operator);
        adapter.registerOperator{value: 10 ether}();
        vm.prank(admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), operator);
    }

    function test_submitDepositClaim_success() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );
        assertTrue(claimId != bytes32(0));

        BitVMBridgeAdapter.DepositClaim memory claim = adapter.getDepositClaim(
            claimId
        );
        assertEq(claim.evmRecipient, user);
        assertEq(claim.amountSats, 1_00000000);
        assertEq(
            uint8(claim.status),
            uint8(BitVMBridgeAdapter.DepositStatus.PENDING)
        );
    }

    function test_submitDepositClaim_nonOperator_reverts() public {
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(user);
        vm.expectRevert();
        adapter.submitDepositClaim(keccak256("btcTx"), user, 1_00000000, proof);
    }

    // ── challengeDeposit ──

    function test_challengeDeposit_success() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );

        // Grant challenger role and challenge
        vm.prank(admin);
        adapter.grantRole(adapter.CHALLENGER_ROLE(), challenger);

        vm.deal(challenger, 2 ether);
        vm.prank(challenger);
        adapter.challengeDeposit{value: 1 ether}(claimId);

        BitVMBridgeAdapter.DepositClaim memory claim = adapter.getDepositClaim(
            claimId
        );
        assertEq(
            uint8(claim.status),
            uint8(BitVMBridgeAdapter.DepositStatus.CHALLENGED)
        );
    }

    // ── finalizeDeposit ──

    function test_finalizeDeposit_beforeChallengePeriod_reverts() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );

        // Try to finalize immediately — should fail
        vm.expectRevert();
        adapter.finalizeDeposit(claimId);
    }

    function test_finalizeDeposit_afterChallengePeriod() public {
        _registerAndGrantOperator();
        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        bytes32 claimId = adapter.submitDepositClaim(
            keccak256("btcTx"),
            user,
            1_00000000,
            proof
        );

        // Warp past challenge period
        vm.warp(block.timestamp + 7 days + 1);
        adapter.finalizeDeposit(claimId);

        assertTrue(adapter.isDepositFinalized(claimId));
    }

    // ── requestWithdrawal ──

    function test_requestWithdrawal() public {
        // Give user wBTC balance so burn succeeds
        wbtc.mint(user, 50000000);
        vm.prank(user);
        bytes32 reqId = adapter.requestWithdrawal(hex"0014aabbccdd", 50000000);
        assertTrue(reqId != bytes32(0));

        BitVMBridgeAdapter.WithdrawalRequest memory req = adapter
            .getWithdrawalRequest(reqId);
        assertEq(req.evmSender, user);
        assertEq(req.amountSats, 50000000);
        assertEq(
            uint8(req.status),
            uint8(BitVMBridgeAdapter.WithdrawalStatus.PENDING)
        );
    }

    // ── Pause / Unpause ──

    function test_pause_byGuardian() public {
        vm.prank(admin);
        adapter.pause();
        assertTrue(adapter.paused());
    }

    function test_unpause_byGuardian() public {
        vm.prank(admin);
        adapter.pause();
        vm.prank(admin);
        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function test_pause_byNonGuardian_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.pause();
    }

    function test_submitDepositClaim_whenPaused_reverts() public {
        _registerAndGrantOperator();
        vm.prank(admin);
        adapter.pause();

        BitVMBridgeAdapter.BitcoinSPVProof memory proof = BitVMBridgeAdapter
            .BitcoinSPVProof({
                txHash: keccak256("btcTx"),
                blockHash: keccak256("block"),
                blockHeight: 800000,
                merkleProof: hex"aabb",
                txIndex: 0
            });

        vm.prank(operator);
        vm.expectRevert();
        adapter.submitDepositClaim(keccak256("btcTx"), user, 1_00000000, proof);
    }

    // ── setChallengePeriod ──

    function test_setChallengePeriod_byAdmin() public {
        vm.prank(admin);
        adapter.setChallengePeriod(14 days);
        assertEq(adapter.challengePeriod(), 14 days);
    }

    function test_setChallengePeriod_byNonAdmin_reverts() public {
        vm.prank(user);
        vm.expectRevert();
        adapter.setChallengePeriod(14 days);
    }

    // ── receive() accepts ETH ──

    function test_receiveETH() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(ok);
        assertEq(address(adapter).balance, 1 ether);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // fulfillWithdrawal tests
    // ═══════════════════════════════════════════════════════════════════════

    function _requestWithdrawal() internal returns (bytes32 requestId) {
        // Give user wBTC balance so burn succeeds
        wbtc.mint(user, 50000000);
        vm.prank(user);
        requestId = adapter.requestWithdrawal(hex"0014aabbccdd", 50000000);
    }

    function test_fulfillWithdrawal_success() public {
        _registerAndGrantOperator();
        bytes32 reqId = _requestWithdrawal();

        relay.setVerifyResult(true);

        vm.prank(operator);
        adapter.fulfillWithdrawal(
            reqId,
            keccak256("btcReleaseTx"),
            keccak256("block123"),
            800100,
            hex"aabbccdd",
            0
        );

        BitVMBridgeAdapter.WithdrawalRequest memory req = adapter
            .getWithdrawalRequest(reqId);
        assertEq(
            uint8(req.status),
            uint8(BitVMBridgeAdapter.WithdrawalStatus.COMPLETED)
        );
        assertEq(req.btcTxHash, keccak256("btcReleaseTx"));

        // Operator stats should be updated
        BitVMBridgeAdapter.Operator memory op = adapter.getOperator(operator);
        assertEq(op.totalWithdrawalsProcessed, 1);
    }

    function test_fulfillWithdrawal_invalidSPV_reverts() public {
        _registerAndGrantOperator();
        bytes32 reqId = _requestWithdrawal();

        relay.setVerifyResult(false);

        vm.prank(operator);
        vm.expectRevert(BitVMBridgeAdapter.InvalidSPVProof.selector);
        adapter.fulfillWithdrawal(
            reqId,
            keccak256("badTx"),
            keccak256("block"),
            800100,
            hex"aa",
            0
        );
    }

    function test_fulfillWithdrawal_notPending_reverts() public {
        _registerAndGrantOperator();
        bytes32 reqId = _requestWithdrawal();

        // Fulfill once
        relay.setVerifyResult(true);
        vm.prank(operator);
        adapter.fulfillWithdrawal(
            reqId,
            keccak256("tx"),
            keccak256("b"),
            800100,
            hex"aa",
            0
        );

        // Try again — should revert
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMBridgeAdapter.WithdrawalNotPending.selector,
                reqId
            )
        );
        adapter.fulfillWithdrawal(
            reqId,
            keccak256("tx2"),
            keccak256("b2"),
            800200,
            hex"bb",
            0
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // forceExitWithdrawal tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_forceExitWithdrawal_success() public {
        bytes32 reqId = _requestWithdrawal();

        // Warp past challenge period
        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(user);
        adapter.forceExitWithdrawal(reqId);

        BitVMBridgeAdapter.WithdrawalRequest memory req = adapter
            .getWithdrawalRequest(reqId);
        assertEq(
            uint8(req.status),
            uint8(BitVMBridgeAdapter.WithdrawalStatus.FORCE_EXIT)
        );

        // wBTC should be re-minted
        assertEq(wbtc.balanceOf(user), 50000000);
    }

    function test_forceExitWithdrawal_beforeChallengePeriod_reverts() public {
        bytes32 reqId = _requestWithdrawal();

        vm.prank(user);
        vm.expectRevert();
        adapter.forceExitWithdrawal(reqId);
    }

    function test_forceExitWithdrawal_nonRequester_reverts() public {
        bytes32 reqId = _requestWithdrawal();

        vm.warp(block.timestamp + 7 days + 1);

        vm.prank(operator); // Not the requester
        vm.expectRevert("Not withdrawal requester");
        adapter.forceExitWithdrawal(reqId);
    }

    function test_forceExitWithdrawal_alreadyCompleted_reverts() public {
        _registerAndGrantOperator();
        bytes32 reqId = _requestWithdrawal();

        // Fulfill first
        relay.setVerifyResult(true);
        vm.prank(operator);
        adapter.fulfillWithdrawal(
            reqId,
            keccak256("tx"),
            keccak256("b"),
            800100,
            hex"aa",
            0
        );

        // Cannot force-exit a completed withdrawal
        vm.warp(block.timestamp + 7 days + 1);
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                BitVMBridgeAdapter.WithdrawalNotPending.selector,
                reqId
            )
        );
        adapter.forceExitWithdrawal(reqId);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // deregisterOperator tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_deregisterOperator_success() public {
        _registerAndGrantOperator();

        vm.prank(operator);
        adapter.deregisterOperator();

        BitVMBridgeAdapter.Operator memory op = adapter.getOperator(operator);
        assertFalse(op.active);
        assertEq(op.bond, 10 ether); // Bond still held
    }

    function test_deregisterOperator_notActive_reverts() public {
        vm.prank(operator);
        vm.expectRevert("Not active operator");
        adapter.deregisterOperator();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // withdrawOperatorBond tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_withdrawOperatorBond_success() public {
        _registerAndGrantOperator();

        vm.prank(operator);
        adapter.deregisterOperator();

        uint256 balBefore = operator.balance;

        vm.prank(operator);
        adapter.withdrawOperatorBond();

        assertEq(operator.balance, balBefore + 10 ether);

        BitVMBridgeAdapter.Operator memory op = adapter.getOperator(operator);
        assertEq(op.bond, 0);
    }

    function test_withdrawOperatorBond_stillActive_reverts() public {
        _registerAndGrantOperator();

        vm.prank(operator);
        vm.expectRevert("Still active");
        adapter.withdrawOperatorBond();
    }

    function test_withdrawOperatorBond_slashed_reverts() public {
        _registerAndGrantOperator();

        // Slash operator first
        vm.prank(admin);
        adapter.slashOperator(operator);

        vm.prank(operator);
        vm.expectRevert("Operator slashed");
        adapter.withdrawOperatorBond();
    }

    function test_withdrawOperatorBond_noBond_reverts() public {
        _registerAndGrantOperator();

        vm.prank(operator);
        adapter.deregisterOperator();

        // Withdraw once
        vm.prank(operator);
        adapter.withdrawOperatorBond();

        // Try again
        vm.prank(operator);
        vm.expectRevert("No bond to withdraw");
        adapter.withdrawOperatorBond();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // slashOperator tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_slashOperator_success() public {
        _registerAndGrantOperator();

        uint256 guardianBalBefore = admin.balance;

        vm.prank(admin); // admin has GUARDIAN_ROLE
        adapter.slashOperator(operator);

        BitVMBridgeAdapter.Operator memory op = adapter.getOperator(operator);
        assertTrue(op.slashed);
        assertFalse(op.active);
        assertEq(op.bond, 0);

        // Guardian receives slashed bond
        assertEq(admin.balance, guardianBalBefore + 10 ether);
    }

    function test_slashOperator_doubleSlash_reverts() public {
        _registerAndGrantOperator();

        vm.prank(admin);
        adapter.slashOperator(operator);

        vm.prank(admin);
        vm.expectRevert("Already slashed");
        adapter.slashOperator(operator);
    }

    function test_slashOperator_nonGuardian_reverts() public {
        _registerAndGrantOperator();

        vm.prank(user);
        vm.expectRevert();
        adapter.slashOperator(operator);
    }

    function test_slashOperator_nothingToSlash_reverts() public {
        vm.prank(admin);
        vm.expectRevert("Nothing to slash");
        adapter.slashOperator(makeAddr("nobody"));
    }
}
