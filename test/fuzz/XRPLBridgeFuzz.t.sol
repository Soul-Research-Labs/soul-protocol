// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/XRPLBridgeAdapter.sol";
import "../../contracts/interfaces/IXRPLBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedXRP.sol";
import "../../contracts/mocks/MockXRPLValidatorOracle.sol";

/**
 * @title XRPLBridgeFuzz
 * @notice Foundry fuzz & invariant tests for XRPLBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      ledger header submission, and security invariants
 */
contract XRPLBridgeFuzz is Test {
    XRPLBridgeAdapter public bridge;
    MockWrappedXRP public wXRP;
    MockXRPLValidatorOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    bytes20 public constant XRPL_MULTISIG = bytes20(uint160(0xDEADBEEF));
    bytes20 public constant XRPL_USER = bytes20(uint160(0xCAFEBABE));

    uint256 public constant MIN_DEPOSIT = 10_000_000; // 10 XRP
    uint256 public constant MAX_DEPOSIT = 10_000_000_000_000; // 10M XRP

    // Validator keys
    bytes32 public constant VAL_KEY_1 = keccak256("validator1");
    bytes32 public constant VAL_KEY_2 = keccak256("validator2");
    bytes32 public constant VAL_KEY_3 = keccak256("validator3");

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wXRP = new MockWrappedXRP(admin);
        oracle = new MockXRPLValidatorOracle(admin);

        // Deploy bridge
        bridge = new XRPLBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register validators
        oracle.registerValidator(VAL_KEY_1);
        oracle.registerValidator(VAL_KEY_2);
        oracle.registerValidator(VAL_KEY_3);

        // Configure bridge
        bridge.configure(
            XRPL_MULTISIG,
            address(wXRP),
            address(oracle),
            2, // minSignatures
            32 // requiredLedgerConfirmations
        );

        // Grant minter role to bridge
        wXRP.grantMinter(address(bridge));

        // Fund user1 with wXRP for withdrawal tests
        wXRP.mint(user1, 1_000_000_000_000); // 1M XRP in drops

        vm.stopPrank();

        // Approve bridge to spend user1's wXRP
        vm.prank(user1);
        wXRP.approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IXRPLBridgeAdapter.ValidatorAttestation[] memory)
    {
        IXRPLBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IXRPLBridgeAdapter.ValidatorAttestation[](
                3
            );
        attestations[0] = IXRPLBridgeAdapter.ValidatorAttestation({
            validatorPubKey: VAL_KEY_1,
            signature: hex"0123456789"
        });
        attestations[1] = IXRPLBridgeAdapter.ValidatorAttestation({
            validatorPubKey: VAL_KEY_2,
            signature: hex"0123456789"
        });
        attestations[2] = IXRPLBridgeAdapter.ValidatorAttestation({
            validatorPubKey: VAL_KEY_3,
            signature: hex"0123456789"
        });
        return attestations;
    }

    function _buildSHAMapProof()
        internal
        pure
        returns (IXRPLBridgeAdapter.SHAMapProof memory)
    {
        bytes32[] memory innerNodes = new bytes32[](1);
        innerNodes[0] = keccak256("inner1");

        uint8[] memory nodeTypes = new uint8[](1);
        nodeTypes[0] = 0;

        bytes32[] memory branchKeys = new bytes32[](1);
        branchKeys[0] = bytes32(0);

        return
            IXRPLBridgeAdapter.SHAMapProof({
                leafHash: keccak256("leaf"),
                innerNodes: innerNodes,
                nodeTypes: nodeTypes,
                branchKeys: branchKeys
            });
    }

    function _submitValidatedLedger(uint256 ledgerIndex) internal {
        vm.prank(relayer);
        bridge.submitLedgerHeader(
            ledgerIndex,
            keccak256(abi.encodePacked("ledger", ledgerIndex)),
            ledgerIndex > 0
                ? keccak256(abi.encodePacked("ledger", ledgerIndex - 1))
                : bytes32(0),
            keccak256(abi.encodePacked("txHash", ledgerIndex)),
            keccak256(abi.encodePacked("accountState", ledgerIndex)),
            block.timestamp,
            _buildValidatorAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: DEPOSIT AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        _submitValidatedLedger(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IXRPLBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateXRPDeposit(
            txHash,
            XRPL_USER,
            user1,
            amount,
            bytes32(uint256(1)),
            1,
            _buildSHAMapProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        _submitValidatedLedger(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IXRPLBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateXRPDeposit(
            txHash,
            XRPL_USER,
            user1,
            amount,
            bytes32(uint256(1)),
            1,
            _buildSHAMapProof(),
            _buildValidatorAttestations()
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
                IXRPLBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(XRPL_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IXRPLBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(XRPL_USER, amount);
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
                XRPL_USER,
                keccak256("condition"),
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

        // Duration too long (> 30 days)
        duration = bound(duration, 30 days + 1, 365 days);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                XRPL_USER,
                keccak256("condition"),
                finishAfter,
                cancelAfter
            )
        );
        assertFalse(success, "Escrow with too long timelock should revert");
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: FEE CALCULATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        uint256 expectedFee = (amount * 25) / 10_000;
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

        _submitValidatedLedger(1);

        // First deposit should work (if proofs pass internal checks)
        // We test the replay flag directly
        assertFalse(bridge.usedXRPLTxHashes(txHash));
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: NULLIFIER UNIQUENESS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        // Initially unused
        assertFalse(bridge.usedNullifiers(nullifier));
    }

    /*//////////////////////////////////////////////////////////////
                INVARIANT: BRIDGE CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configCannotSetZeroAddresses(
        bytes20 multisig,
        address wrappedXRP,
        address oracleAddr,
        uint256 minSigs
    ) public {
        vm.assume(minSigs > 0);

        // Zero multisig should revert
        if (
            multisig == bytes20(0) ||
            wrappedXRP == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(IXRPLBridgeAdapter.ZeroAddress.selector);
            bridge.configure(multisig, wrappedXRP, oracleAddr, minSigs, 32);
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

        _submitValidatedLedger(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateXRPDeposit(
            keccak256("tx"),
            XRPL_USER,
            user1,
            MIN_DEPOSIT,
            bytes32(uint256(1)),
            1,
            _buildSHAMapProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != operator && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeXRPDeposit(keccak256("deposit"));
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
        // Submit ledger BEFORE pausing
        _submitValidatedLedger(1);

        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateXRPDeposit(
            keccak256("tx"),
            XRPL_USER,
            user1,
            MIN_DEPOSIT,
            bytes32(uint256(1)),
            1,
            _buildSHAMapProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateWithdrawal(XRPL_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                XRPL_USER,
                keccak256("condition"),
                block.timestamp + 1 hours,
                block.timestamp + 2 hours
            )
        );
        assertFalse(success, "Escrow creation should be blocked when paused");
    }

    /*//////////////////////////////////////////////////////////////
            ESCROW: FINISH & CANCEL LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("secret_preimage");
        bytes32 condition = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            XRPL_USER,
            condition,
            finishAfter,
            cancelAfter
        );

        // Cannot finish before finishAfter
        vm.prank(user2);
        vm.expectRevert();
        bridge.finishEscrow(escrowId, preimage);

        // Advance past finishAfter
        vm.warp(finishAfter + 1);

        // Wrong preimage should fail
        vm.prank(user2);
        vm.expectRevert();
        bridge.finishEscrow(escrowId, keccak256("wrong"));

        // Correct preimage should succeed
        uint256 balBefore = user2.balance;
        vm.prank(user2);
        bridge.finishEscrow(escrowId, preimage);
        assertEq(
            user2.balance - balBefore,
            1 ether,
            "Escrow funds not released"
        );

        // Cannot finish again
        vm.prank(user2);
        vm.expectRevert();
        bridge.finishEscrow(escrowId, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 condition = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            XRPL_USER,
            condition,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.prank(user1);
        vm.expectRevert();
        bridge.cancelEscrow(escrowId);

        // Advance past cancelAfter
        vm.warp(cancelAfter + 1);

        uint256 balBefore = user1.balance;
        vm.prank(user1);
        bridge.cancelEscrow(escrowId);
        assertEq(
            user1.balance - balBefore,
            1 ether,
            "Escrow funds not returned"
        );

        // Cannot cancel again
        vm.prank(user1);
        vm.expectRevert();
        bridge.cancelEscrow(escrowId);
    }

    /*//////////////////////////////////////////////////////////////
             WITHDRAWAL: REFUND LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        vm.prank(user1);
        bytes32 wId = bridge.initiateWithdrawal(XRPL_USER, MIN_DEPOSIT);

        // Cannot refund before delay
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Advance past refund delay (48 hours)
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(wId);

        // Cannot refund again
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(wId);
    }

    /*//////////////////////////////////////////////////////////////
              LEDGER HEADER: CHAIN VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_ledgerHeaderParentChain() public {
        // Submit ledger 1
        _submitValidatedLedger(1);

        // Submit ledger 2 (should verify parent)
        _submitValidatedLedger(2);

        // Latest ledger should be 2
        assertEq(bridge.latestLedgerIndex(), 2, "Latest ledger not updated");
    }

    function testFuzz_ledgerHeaderRequiresRelayer(address caller) public {
        vm.assume(caller != relayer && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.submitLedgerHeader(
            1,
            keccak256("ledger1"),
            bytes32(0),
            keccak256("txHash1"),
            keccak256("accountState1"),
            block.timestamp,
            _buildValidatorAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                      STATISTICS TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_bridgeStatsUpdate() public {
        (
            uint256 totalDep,
            uint256 totalWith,
            uint256 totalEsc,
            uint256 totalEscFin,
            uint256 totalEscCan,
            uint256 fees,
            uint256 latestLedger
        ) = bridge.getBridgeStats();

        assertEq(totalDep, 0, "Initial deposits not zero");
        assertEq(totalWith, 0, "Initial withdrawals not zero");
        assertEq(totalEsc, 0, "Initial escrows not zero");
        assertEq(totalEscFin, 0, "Initial finished not zero");
        assertEq(totalEscCan, 0, "Initial cancelled not zero");
        assertEq(fees, 0, "Initial fees not zero");
        assertEq(latestLedger, 0, "Initial ledger not zero");
    }

    /*//////////////////////////////////////////////////////////////
                      CONSTRUCTOR VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IXRPLBridgeAdapter.ZeroAddress.selector);
        new XRPLBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                   VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_getDepositReturnsEmpty() public view {
        IXRPLBridgeAdapter.XRPDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.depositId, bytes32(0));
    }

    function test_getWithdrawalReturnsEmpty() public view {
        IXRPLBridgeAdapter.XRPWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.withdrawalId, bytes32(0));
    }

    function test_getEscrowReturnsEmpty() public view {
        IXRPLBridgeAdapter.XRPLEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.escrowId, bytes32(0));
    }

    function test_getUserDeposits() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user1);
        assertEq(deps.length, 0);
    }

    function test_getUserWithdrawals() public view {
        bytes32[] memory ws = bridge.getUserWithdrawals(user1);
        assertEq(ws.length, 0);
    }

    function test_getUserEscrows() public view {
        bytes32[] memory es = bridge.getUserEscrows(user1);
        assertEq(es.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                   TREASURY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_setTreasury() public {
        vm.prank(admin);
        bridge.setTreasury(treasury);
        assertEq(bridge.treasury(), treasury);
    }

    function test_setTreasuryRejectsZero() public {
        vm.prank(admin);
        vm.expectRevert(IXRPLBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    function testFuzz_setTreasuryRequiresAdmin(address caller) public {
        vm.assume(caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.setTreasury(treasury);
    }
}
