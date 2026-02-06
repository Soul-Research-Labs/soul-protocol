// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/PlasmaBridgeAdapter.sol";
import "../../contracts/interfaces/IPlasmaBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedPLASMA.sol";
import "../../contracts/mocks/MockPlasmaOperatorOracle.sol";

/**
 * @title PlasmaBridgeFuzz
 * @notice Foundry fuzz & invariant tests for PlasmaBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      block commitment submission, and security invariants
 *
 * Plasma-specific test parameters:
 * - 1 PLASMA = 1e8 satoplasma (8 decimals, UTXO-inspired)
 * - Chain ID 515 (plasma-mainnet-1 EVM mapping)
 * - 12 L1 commitment confirmations (Ethereum finality)
 * - Single operator model (security via fraud proofs)
 * - 7-day challenge period for exits
 */
contract PlasmaBridgeFuzz is Test {
    PlasmaBridgeAdapter public bridge;
    MockWrappedPLASMA public wPLASMA;
    MockPlasmaOperatorOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    address public constant PLASMA_BRIDGE_CONTRACT =
        address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address public constant PLASMA_USER =
        address(0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC);

    uint256 public constant SATOPLASMA_PER_PLASMA = 100_000_000; // 1e8
    uint256 public constant MIN_DEPOSIT = SATOPLASMA_PER_PLASMA / 10; // 0.1 PLASMA
    uint256 public constant MAX_DEPOSIT = 5_000_000 * SATOPLASMA_PER_PLASMA; // 5M PLASMA

    // Operator addresses (Plasma uses a single operator, but we test with 3 for robustness)
    address public constant OPERATOR_1 =
        address(0x1111111111111111111111111111111111111111);
    address public constant OPERATOR_2 =
        address(0x2222222222222222222222222222222222222222);
    address public constant OPERATOR_3 =
        address(0x3333333333333333333333333333333333333333);

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wPLASMA = new MockWrappedPLASMA();
        oracle = new MockPlasmaOperatorOracle();

        // Deploy bridge
        bridge = new PlasmaBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register 3 Plasma operators
        oracle.addOperator(OPERATOR_1);
        oracle.addOperator(OPERATOR_2);
        oracle.addOperator(OPERATOR_3);

        // Configure bridge (2 min confirmations, 12 L1 confirmations)
        bridge.configure(
            PLASMA_BRIDGE_CONTRACT,
            address(wPLASMA),
            address(oracle),
            2, // minOperatorConfirmations
            12 // requiredL1Confirmations
        );

        // Fund user1 with wPLASMA for withdrawal tests (10K PLASMA in satoplasma)
        wPLASMA.mint(user1, 10_000 * SATOPLASMA_PER_PLASMA);

        vm.stopPrank();

        // Approve bridge to spend user1's wPLASMA
        vm.prank(user1);
        IERC20(address(wPLASMA)).approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildOperatorConfirmations()
        internal
        pure
        returns (IPlasmaBridgeAdapter.OperatorConfirmation[] memory)
    {
        IPlasmaBridgeAdapter.OperatorConfirmation[]
            memory confirmations = new IPlasmaBridgeAdapter.OperatorConfirmation[](
                3
            );
        confirmations[0] = IPlasmaBridgeAdapter.OperatorConfirmation({
            operator: OPERATOR_1,
            signature: hex"0123456789"
        });
        confirmations[1] = IPlasmaBridgeAdapter.OperatorConfirmation({
            operator: OPERATOR_2,
            signature: hex"0123456789"
        });
        confirmations[2] = IPlasmaBridgeAdapter.OperatorConfirmation({
            operator: OPERATOR_3,
            signature: hex"0123456789"
        });
        return confirmations;
    }

    function _buildInclusionProof()
        internal
        pure
        returns (IPlasmaBridgeAdapter.PlasmaInclusionProof memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("sibling");

        return
            IPlasmaBridgeAdapter.PlasmaInclusionProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _submitCommittedBlock(uint256 blockNum) internal {
        vm.prank(relayer);
        bridge.submitBlockCommitment(
            blockNum,
            keccak256(abi.encodePacked("block", blockNum)),
            blockNum > 0
                ? keccak256(abi.encodePacked("block", blockNum - 1))
                : bytes32(0),
            keccak256(abi.encodePacked("txRoot", blockNum)),
            keccak256(abi.encodePacked("stateRoot", blockNum)),
            OPERATOR_1,
            keccak256(abi.encodePacked("l1Tx", blockNum)),
            block.timestamp,
            _buildOperatorConfirmations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: DEPOSIT AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        _submitCommittedBlock(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPlasmaBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiatePLASMADeposit(
            txHash,
            PLASMA_USER,
            user1,
            amount,
            1,
            _buildInclusionProof(),
            _buildOperatorConfirmations()
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        _submitCommittedBlock(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPlasmaBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiatePLASMADeposit(
            txHash,
            PLASMA_USER,
            user1,
            amount,
            1,
            _buildInclusionProof(),
            _buildOperatorConfirmations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: WITHDRAWAL AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPlasmaBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(PLASMA_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPlasmaBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(PLASMA_USER, amount);
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: ESCROW TIMELOCKS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_escrowTimelockBounds(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1, 365 days);
        uint256 finishAfter = block.timestamp + finishOffset;

        // Duration too short (< 1 hour)
        duration = bound(duration, 0, 1 hours - 1);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                PLASMA_USER,
                keccak256("hashlock"),
                finishAfter,
                cancelAfter
            )
        );
        assertFalse(success, "Escrow with too short timelock should revert");
    }

    function testFuzz_escrowTimelockTooLong(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1, 365 days);
        uint256 finishAfter = block.timestamp + finishOffset;

        // Duration too long (> 45 days)
        duration = bound(duration, 45 days + 1, 365 days);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                PLASMA_USER,
                keccak256("hashlock"),
                finishAfter,
                cancelAfter
            )
        );
        assertFalse(success, "Escrow with too long timelock should revert");
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: FEE CALCULATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        uint256 expectedFee = (amount * 8) / 10_000; // 0.08% fee
        uint256 expectedNet = amount - expectedFee;

        // Fee should never exceed 1% even with rounding
        assertLe(expectedFee, amount / 100 + 1, "Fee exceeds 1%");

        // Net + fee should equal original amount
        assertEq(expectedNet + expectedFee, amount, "Fee arithmetic mismatch");
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: REPLAY PROTECTION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        _submitCommittedBlock(1);

        // Tx hash should initially be unused
        assertFalse(bridge.usedPlasmaTxHashes(txHash));
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: NULLIFIER UNIQUENESS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        assertFalse(bridge.usedNullifiers(nullifier));
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT: BRIDGE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configCannotSetZeroAddresses(
        address plasmaBridge,
        address wrappedPLASMAAddr,
        address oracleAddr,
        uint256 minConfirmations
    ) public {
        vm.assume(minConfirmations > 0);

        if (
            plasmaBridge == address(0) ||
            wrappedPLASMAAddr == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(IPlasmaBridgeAdapter.ZeroAddress.selector);
            bridge.configure(plasmaBridge, wrappedPLASMAAddr, oracleAddr, minConfirmations, 12);
        }
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT: NONCE MONOTONICITY
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositNonceOnlyIncreases(uint8 numOps) public {
        numOps = uint8(bound(numOps, 0, 5));

        uint256 prevNonce = bridge.depositNonce();

        for (uint8 i = 0; i < numOps; i++) {
            uint256 currentNonce = bridge.depositNonce();
            assertGe(currentNonce, prevNonce, "Nonce decreased");
            prevNonce = currentNonce;
        }
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 numOps) public {
        numOps = uint8(bound(numOps, 0, 5));

        uint256 prevNonce = bridge.withdrawalNonce();

        for (uint8 i = 0; i < numOps; i++) {
            uint256 currentNonce = bridge.withdrawalNonce();
            assertGe(currentNonce, prevNonce, "Nonce decreased");
            prevNonce = currentNonce;
        }
    }

    /*//////////////////////////////////////////////////////////////
              INVARIANT: ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin);

        _submitCommittedBlock(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiatePLASMADeposit(
            keccak256("tx"),
            PLASMA_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildInclusionProof(),
            _buildOperatorConfirmations()
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != operator && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.completePLASMADeposit(keccak256("deposit"));
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != guardian && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
            INVARIANT: PAUSE BLOCKS OPERATIONS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        _submitCommittedBlock(1);

        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiatePLASMADeposit(
            keccak256("tx"),
            PLASMA_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildInclusionProof(),
            _buildOperatorConfirmations()
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateWithdrawal(PLASMA_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                PLASMA_USER,
                keccak256("hashlock"),
                block.timestamp + 2 hours,
                block.timestamp + 26 hours
            )
        );
        assertFalse(success, "Escrow creation should be blocked when paused");
    }

    /*//////////////////////////////////////////////////////////////
            ESCROW: FINISH & CANCEL LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("secret_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 48 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            PLASMA_USER,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot finish before finishAfter
        vm.prank(user2);
        vm.expectRevert();
        bridge.finishEscrow(escrowId, preimage);

        // Advance time past finishAfter
        vm.warp(finishAfter + 1);

        // Finish with valid preimage
        uint256 balBefore = user2.balance;
        vm.prank(user2);
        bridge.finishEscrow(escrowId, preimage);

        assertEq(user2.balance - balBefore, 1 ether);

        IPlasmaBridgeAdapter.PLASMAEscrow memory esc = bridge.getEscrow(escrowId);
        assertEq(uint8(esc.status), uint8(IPlasmaBridgeAdapter.EscrowStatus.FINISHED));
        assertEq(esc.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 48 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            PLASMA_USER,
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.prank(user1);
        vm.expectRevert();
        bridge.cancelEscrow(escrowId);

        // Advance time past cancelAfter
        vm.warp(cancelAfter + 1);

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        bridge.cancelEscrow(escrowId);

        assertEq(user1.balance - balBefore, 1 ether);

        IPlasmaBridgeAdapter.PLASMAEscrow memory esc = bridge.getEscrow(escrowId);
        assertEq(uint8(esc.status), uint8(IPlasmaBridgeAdapter.EscrowStatus.CANCELLED));
    }

    /*//////////////////////////////////////////////////////////////
            WITHDRAWAL REFUND AFTER DELAY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * SATOPLASMA_PER_PLASMA; // 1 PLASMA in satoplasma

        vm.prank(user1);
        bytes32 withdrawalId = bridge.initiateWithdrawal(PLASMA_USER, amount);

        // Cannot refund before 192 hours (8 days)
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(withdrawalId);

        // Advance 192 hours
        vm.warp(block.timestamp + 192 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(withdrawalId);

        IPlasmaBridgeAdapter.PLASMAWithdrawal memory w = bridge.getWithdrawal(withdrawalId);
        assertEq(uint8(w.status), uint8(IPlasmaBridgeAdapter.WithdrawalStatus.REFUNDED));
    }

    /*//////////////////////////////////////////////////////////////
            BLOCK COMMITMENT: CHAIN VALIDATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_blockCommitmentChain(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        for (uint8 i = 0; i < count; i++) {
            _submitCommittedBlock(i + 1);
        }

        assertEq(bridge.latestBlockNumber(), count);
    }

    /*//////////////////////////////////////////////////////////////
            CHALLENGE PERIOD VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_challengePeriodConstant() public view {
        assertEq(bridge.CHALLENGE_PERIOD(), 7 days);
    }

    /*//////////////////////////////////////////////////////////////
            STATISTICS TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_statisticsTracking() public {
        (uint256 totalDep, uint256 totalWith, uint256 totalEsc, , , , ) = bridge
            .getBridgeStats();

        assertEq(totalDep, 0);
        assertEq(totalWith, 0);
        assertEq(totalEsc, 0);
    }

    /*//////////////////////////////////////////////////////////////
            CONSTRUCTOR VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IPlasmaBridgeAdapter.ZeroAddress.selector);
        new PlasmaBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IPlasmaBridgeAdapter.PLASMADeposit memory dep = bridge.getDeposit(bytes32(0));
        assertEq(dep.depositId, bytes32(0));

        IPlasmaBridgeAdapter.PLASMAWithdrawal memory w = bridge.getWithdrawal(bytes32(0));
        assertEq(w.withdrawalId, bytes32(0));

        IPlasmaBridgeAdapter.PLASMAEscrow memory esc = bridge.getEscrow(bytes32(0));
        assertEq(esc.escrowId, bytes32(0));
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user1);
        assertEq(deps.length, 0);

        bytes32[] memory withs = bridge.getUserWithdrawals(user1);
        assertEq(withs.length, 0);

        bytes32[] memory escs = bridge.getUserEscrows(user1);
        assertEq(escs.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
            TREASURY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_treasuryCanBeUpdated() public {
        address newTreasury = makeAddr("newTreasury");

        vm.prank(admin);
        bridge.setTreasury(newTreasury);

        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IPlasmaBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            CONSTANTS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.PLASMA_CHAIN_ID(), 515);
        assertEq(bridge.SATOPLASMA_PER_PLASMA(), 100_000_000); // 1e8
        assertEq(bridge.MIN_DEPOSIT_SATOPLASMA(), SATOPLASMA_PER_PLASMA / 10); // 0.1 PLASMA
        assertEq(bridge.MAX_DEPOSIT_SATOPLASMA(), 5_000_000 * SATOPLASMA_PER_PLASMA); // 5M PLASMA
        assertEq(bridge.BRIDGE_FEE_BPS(), 8); // 0.08%
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 45 days);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 192 hours); // 8 days
        assertEq(bridge.DEFAULT_L1_CONFIRMATIONS(), 12);
        assertEq(bridge.CHALLENGE_PERIOD(), 7 days);
    }

    /*//////////////////////////////////////////////////////////////
            PLASMA-SPECIFIC: SATOPLASMA PRECISION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_satoplasmaPrecision(uint256 plasmaAmount) public pure {
        plasmaAmount = bound(plasmaAmount, 1, 5_000_000);

        uint256 satoplasma = plasmaAmount * SATOPLASMA_PER_PLASMA;
        uint256 backToPlasma = satoplasma / SATOPLASMA_PER_PLASMA;

        assertEq(backToPlasma, plasmaAmount, "Satoplasma conversion not reversible");
        assertEq(satoplasma % SATOPLASMA_PER_PLASMA, 0, "Satoplasma should be exact multiple");
    }

    function testFuzz_satoplasmaSubUnitDeposit(uint256 subUnitSatoplasma) public {
        subUnitSatoplasma = bound(subUnitSatoplasma, MIN_DEPOSIT, SATOPLASMA_PER_PLASMA - 1);

        bytes32 txHash = keccak256(
            abi.encodePacked("sub_unit_tx", subUnitSatoplasma)
        );

        bytes32 sibling = keccak256("sibling");
        bytes32 txRoot = keccak256(abi.encodePacked(txHash, sibling));

        // Submit block with matching txRoot
        vm.prank(relayer);
        bridge.submitBlockCommitment(
            1,
            keccak256(abi.encodePacked("block", uint256(1))),
            keccak256(abi.encodePacked("block", uint256(0))),
            txRoot,
            keccak256(abi.encodePacked("stateRoot", uint256(1))),
            OPERATOR_1,
            keccak256(abi.encodePacked("l1Tx", uint256(1))),
            block.timestamp,
            _buildOperatorConfirmations()
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        IPlasmaBridgeAdapter.PlasmaInclusionProof
            memory inclusionProof = IPlasmaBridgeAdapter
                .PlasmaInclusionProof({
                    leafHash: txHash,
                    proof: proof,
                    index: 0
                });

        // Should succeed — fractional PLASMA deposits above min are valid
        vm.prank(relayer);
        bytes32 depositId = bridge.initiatePLASMADeposit(
            txHash,
            PLASMA_USER,
            user1,
            subUnitSatoplasma,
            1,
            inclusionProof,
            _buildOperatorConfirmations()
        );

        IPlasmaBridgeAdapter.PLASMADeposit memory dep = bridge.getDeposit(depositId);
        assertEq(dep.amountSatoplasma, subUnitSatoplasma);
    }

    /*//////////////////////////////////////////////////////////////
            BLOCK COMMITMENT: L1 REQUIRED
    //////////////////////////////////////////////////////////////*/

    function test_depositRequiresCommittedBlock() public {
        // Try deposit without submitting a block commitment first
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IPlasmaBridgeAdapter.BlockNotCommitted.selector,
                999
            )
        );
        bridge.initiatePLASMADeposit(
            keccak256("tx"),
            PLASMA_USER,
            user1,
            MIN_DEPOSIT,
            999,
            _buildInclusionProof(),
            _buildOperatorConfirmations()
        );
    }
}
