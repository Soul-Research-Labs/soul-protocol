// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {AptosBridgeAdapter} from "../../contracts/crosschain/AptosBridgeAdapter.sol";
import {IAptosBridgeAdapter} from "../../contracts/interfaces/IAptosBridgeAdapter.sol";
import {MockWrappedAPT} from "../../contracts/mocks/MockWrappedAPT.sol";
import {MockAptosValidatorOracle} from "../../contracts/mocks/MockAptosValidatorOracle.sol";

/**
 * @title AptosBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the AptosBridgeAdapter
 * @dev Tests Octas precision (8 decimals), LedgerInfo verification,
 *      AptosBFT validator attestation, and Aptos-specific bridge parameters.
 */
contract AptosBridgeFuzz is Test {
    AptosBridgeAdapter public bridge;
    MockWrappedAPT public wAPT;
    MockAptosValidatorOracle public oracle;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant OCTAS_PER_APT = 100_000_000; // 1e8
    uint256 constant MIN_DEPOSIT = OCTAS_PER_APT / 10; // 0.1 APT
    uint256 constant MAX_DEPOSIT = 10_000_000 * OCTAS_PER_APT;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new AptosBridgeAdapter(admin);
        wAPT = new MockWrappedAPT();
        oracle = new MockAptosValidatorOracle();

        // Register validators with voting power
        oracle.addValidator(VALIDATOR_1, 100);
        oracle.addValidator(VALIDATOR_2, 100);
        oracle.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // aptosBridgeContract
            address(wAPT),
            address(oracle),
            2, // minValidatorSignatures
            6 // requiredLedgerConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wAPT
        wAPT.mint(address(bridge), 100_000_000 * OCTAS_PER_APT);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IAptosBridgeAdapter.ValidatorAttestation[] memory)
    {
        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IAptosBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IAptosBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IAptosBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IAptosBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedLedger(uint256 version, bytes32 txHash) internal {
        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitLedgerInfo(
            version,
            txHash,
            keccak256(abi.encode("stateRoot", version)),
            keccak256(abi.encode("eventRoot", version)),
            1, // epoch
            version, // round
            block.timestamp,
            10, // numTransactions
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (IAptosBridgeAdapter.AptosStateProof memory)
    {
        bytes32[] memory proof = new bytes32[](2);
        proof[0] = keccak256("proof_node_0");
        proof[1] = keccak256("proof_node_1");

        return
            IAptosBridgeAdapter.AptosStateProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit ledger info first
        _submitVerifiedLedger(1, keccak256("ledger1"));

        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateAPTDeposit(
                txHash,
                keccak256("aptos_sender"),
                user,
                amount,
                1, // ledgerVersion
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.APTOS_CHAIN_ID(), 1);
        assertEq(bridge.OCTAS_PER_APT(), 100_000_000);
        assertEq(bridge.BRIDGE_FEE_BPS(), 4);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_LEDGER_CONFIRMATIONS(), 6);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IAptosBridgeAdapter.ZeroAddress.selector);
        new AptosBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         OCTAS PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_octasPrecision(uint256 aptAmount) public pure {
        aptAmount = bound(aptAmount, 1, 1_000_000);
        uint256 octas = aptAmount * OCTAS_PER_APT;
        assertEq(octas / OCTAS_PER_APT, aptAmount);
        assertEq(octas % OCTAS_PER_APT, 0);
    }

    function testFuzz_octasSubUnitDeposit(uint256 octas) public {
        octas = bound(octas, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("apt_tx_sub", octas));
        bytes32 depositId = _initiateDeposit(octas, txHash);

        IAptosBridgeAdapter.APTDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountOctas, octas);
        assertEq(dep.fee, (octas * 4) / 10_000);
        assertEq(dep.netAmountOctas, octas - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 4) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.04% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                    LEDGER INFO VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ledgerInfoChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("ledger", i));
            _submitVerifiedLedger(i, txHash);

            IAptosBridgeAdapter.AptosLedgerInfo memory li = bridge
                .getLedgerInfo(i);
            assertTrue(li.verified);
            assertEq(li.transactionHash, txHash);
        }

        assertEq(bridge.latestLedgerVersion(), n - 1);
    }

    function test_depositRequiresVerifiedLedger() public {
        // Don't submit any ledger info — deposit should fail
        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.LedgerVersionNotVerified.selector,
                999
            )
        );
        bridge.initiateAPTDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * OCTAS_PER_APT,
            999, // non-existent version
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedLedger(1, keccak256("ledger_low"));

        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateAPTDeposit(
            keccak256(abi.encode("tx_low", amount)),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        _submitVerifiedLedger(1, keccak256("ledger_high"));

        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateAPTDeposit(
            keccak256(abi.encode("tx_high", amount)),
            keccak256("sender"),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 * OCTAS_PER_APT, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit another ledger for second attempt
        _submitVerifiedLedger(2, keccak256("ledger2"));

        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.AptosTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateAPTDeposit(
            txHash,
            keccak256("sender"),
            user,
            1 * OCTAS_PER_APT,
            2,
            proof,
            attestations
        );
    }

    function testFuzz_depositNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("nonce_tx", i));
            _submitVerifiedLedger(
                i + 1,
                keccak256(abi.encode("nonce_ledger", i))
            );

            IAptosBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IAptosBridgeAdapter.AptosStateProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateAPTDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * OCTAS_PER_APT,
                i + 1,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("aptos_recipient"), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("aptos_recipient"), amount);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 * OCTAS_PER_APT;

        // Mint wAPT to user for withdrawals
        vm.prank(admin);
        wAPT.mint(user, amount * n);

        vm.startPrank(user);
        wAPT.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(keccak256("aptos_recipient"), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * OCTAS_PER_APT;

        vm.prank(admin);
        wAPT.mint(user, amount);

        vm.startPrank(user);
        wAPT.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("aptos_recipient"),
            amount
        );
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wAPT.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wAPT.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IAptosBridgeAdapter.APTWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(IAptosBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_aptos");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("aptos_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        IAptosBridgeAdapter.APTEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IAptosBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountOctas, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IAptosBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_aptos")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("aptos_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(IAptosBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.cancelEscrow(escrowId);

        // Warp past cancelAfter
        vm.warp(cancelAfter + 1);
        uint256 balBefore = user.balance;
        bridge.cancelEscrow(escrowId);
        uint256 balAfter = user.balance;

        assertEq(balAfter - balBefore, 0.5 ether);
    }

    function testFuzz_escrowTimelockBounds(
        uint256 finish,
        uint256 duration
    ) public {
        finish = bound(finish, block.timestamp + 1, block.timestamp + 365 days);
        duration = bound(duration, 1 hours, 30 days);
        uint256 cancel = finish + duration;

        bytes32 hashlock = sha256(
            abi.encodePacked(keccak256("timelock_aptos"))
        );

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("aptos_party"),
            hashlock,
            finish,
            cancel
        );

        IAptosBridgeAdapter.APTEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(e.finishAfter, finish);
        assertEq(e.cancelAfter, cancel);
    }

    function testFuzz_escrowTimelockTooLong(
        uint256 finish,
        uint256 excess
    ) public {
        finish = bound(finish, block.timestamp + 1, block.timestamp + 365 days);
        excess = bound(excess, 30 days + 1, 365 days);
        uint256 cancel = finish + excess;

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_aptos")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IAptosBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("aptos_party"),
            hashlock,
            finish,
            cancel
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        _submitVerifiedLedger(1, keccak256("ledger_ac"));

        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateAPTDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * OCTAS_PER_APT,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 * OCTAS_PER_APT,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeAPTDeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        _submitVerifiedLedger(1, keccak256("ledger_pause"));

        IAptosBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IAptosBridgeAdapter.AptosStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateAPTDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * OCTAS_PER_APT,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(
            keccak256("aptos_recipient"),
            1 * OCTAS_PER_APT
        );
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_aptos")));

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("aptos_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    /*//////////////////////////////////////////////////////////////
                       NULLIFIER / PRIVACY TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes32 depositId = _initiateDeposit(
            1 * OCTAS_PER_APT,
            keccak256(abi.encode("null_tx", nullifier))
        );

        bridge.registerPrivateDeposit(
            depositId,
            keccak256("commitment"),
            nullifier,
            hex"00"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IAptosBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.registerPrivateDeposit(
            depositId,
            keccak256("commitment2"),
            nullifier,
            hex"00"
        );
    }

    /*//////////////////////////////////////////////////////////////
                     CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configCannotSetZeroAddresses(
        address a,
        address b,
        address c,
        uint256 sigs
    ) public {
        vm.prank(admin);
        vm.expectRevert(IAptosBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 6);

        vm.prank(admin);
        vm.expectRevert(IAptosBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            6
        );
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0xF1);
        vm.prank(admin);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IAptosBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IAptosBridgeAdapter.APTDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountOctas, 0);

        IAptosBridgeAdapter.APTWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountOctas, 0);

        IAptosBridgeAdapter.APTEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountOctas, 0);

        IAptosBridgeAdapter.AptosLedgerInfo memory li = bridge.getLedgerInfo(0);
        assertFalse(li.verified);
    }

    function test_statisticsTracking() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestVersion
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestVersion, 0);
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user);
        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        bytes32[] memory es = bridge.getUserEscrows(user);

        assertEq(deps.length, 0);
        assertEq(ws.length, 0);
        assertEq(es.length, 0);
    }
}
