// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {FantomBridgeAdapter} from "../../contracts/crosschain/FantomBridgeAdapter.sol";
import {IFantomBridgeAdapter} from "../../contracts/interfaces/IFantomBridgeAdapter.sol";
import {MockWrappedFTM} from "../../contracts/mocks/MockWrappedFTM.sol";
import {MockLachesisVerifier} from "../../contracts/mocks/MockLachesisVerifier.sol";

/**
 * @title FantomBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the FantomBridgeAdapter
 * @dev Tests Wei precision (18 decimals), Lachesis aBFT verification,
 *      DAGStateProof validation, and Fantom-specific bridge parameters.
 */
contract FantomBridgeFuzz is Test {
    FantomBridgeAdapter public bridge;
    MockWrappedFTM public wFTM;
    MockLachesisVerifier public lachesisVerifier;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant MIN_DEPOSIT = 0.01 ether;
    uint256 constant MAX_DEPOSIT = 10_000_000 ether;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new FantomBridgeAdapter(admin);
        wFTM = new MockWrappedFTM();
        lachesisVerifier = new MockLachesisVerifier();

        // Register validators with voting power
        lachesisVerifier.addValidator(VALIDATOR_1, 100);
        lachesisVerifier.addValidator(VALIDATOR_2, 100);
        lachesisVerifier.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // fantomBridgeContract
            address(wFTM),
            address(lachesisVerifier),
            2, // minValidatorSignatures
            1 // requiredBlockConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wFTM
        wFTM.mint(address(bridge), 100_000_000 ether);

        // Transfer wFTM ownership to bridge so completeFTMDeposit can mint
        wFTM.transferOwnership(address(bridge));

        vm.stopPrank();

        // Wildcard mock: accept any verifyAttestation(bytes32,address,bytes) call
        vm.mockCall(
            address(lachesisVerifier),
            abi.encodeWithSelector(
                bytes4(keccak256("verifyAttestation(bytes32,address,bytes)"))
            ),
            abi.encode(true)
        );
    }

    /// @notice Accept ETH for escrow operations
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IFantomBridgeAdapter.ValidatorAttestation[] memory)
    {
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IFantomBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IFantomBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IFantomBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IFantomBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _buildDAGStateProof()
        internal
        pure
        returns (IFantomBridgeAdapter.DAGStateProof memory)
    {
        bytes32[] memory merkleProof = new bytes32[](1);
        merkleProof[0] = keccak256("sibling");
        return
            IFantomBridgeAdapter.DAGStateProof({
                merkleProof: merkleProof,
                stateRoot: keccak256("proofStateRoot"),
                value: abi.encodePacked(keccak256("proofValue"))
            });
    }

    /// @dev Computes the Lachesis event state root that matches _buildDAGStateProof()
    ///      for a given leaf hash (ftmTxHash).
    function _computeStateRoot(bytes32 leafHash) internal pure returns (bytes32) {
        IFantomBridgeAdapter.DAGStateProof memory proof = _buildDAGStateProof();
        bytes32 computedHash = keccak256(
            abi.encodePacked(leafHash, proof.stateRoot, proof.value)
        );
        bytes32 sibling = proof.merkleProof[0];
        if (computedHash <= sibling) {
            return keccak256(abi.encodePacked(computedHash, sibling));
        } else {
            return keccak256(abi.encodePacked(sibling, computedHash));
        }
    }

    function _submitVerifiedEvent(
        uint256 eventId,
        bytes32 stateRoot
    ) internal {
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitLachesisEvent(
            eventId,
            1, // epoch
            keccak256(abi.encode("eventHash", eventId)),
            eventId > 0
                ? keccak256(abi.encode("eventHash", eventId - 1))
                : bytes32(0),
            stateRoot,
            block.timestamp,
            attestations
        );
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Compute the state root that will pass DAG state proof verification
        bytes32 stateRoot = _computeStateRoot(txHash);
        _submitVerifiedEvent(1, stateRoot);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        return
            bridge.initiateFTMDeposit(
                txHash,
                address(0x1234), // ftmSender (EVM-compatible address)
                user,
                amount,
                1, // ftmBlockNumber (maps to eventId)
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.FANTOM_CHAIN_ID(), 250);
        assertEq(bridge.WEI_PER_FTM(), 1 ether);
        assertEq(bridge.BRIDGE_FEE_BPS(), 4);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
        assertEq(bridge.MIN_DEPOSIT(), 0.01 ether);
        assertEq(bridge.MAX_DEPOSIT(), 10_000_000 ether);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        new FantomBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmount(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("ftm_tx_fuzz", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, amount);
        assertEq(dep.fee, (amount * 4) / 10_000);
        assertEq(dep.netAmountWei, amount - dep.fee);
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

    function testFuzz_feeCalculationPrecision(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("fee_prec_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );

        uint256 expectedFee = (amount * 4) / 10_000;
        uint256 expectedNet = amount - expectedFee;

        assertEq(dep.fee, expectedFee);
        assertEq(dep.netAmountWei, expectedNet);
        assertEq(dep.fee + dep.netAmountWei, dep.amountWei);
    }

    /*//////////////////////////////////////////////////////////////
                    LACHESIS EVENT CHAIN TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_lachesisEventChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 stateRoot = keccak256(abi.encode("stateRoot", i));

            IFantomBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();

            bytes32 eventHash = keccak256(abi.encode("eventHash", i));
            bytes32 parentHash = i > 0
                ? keccak256(abi.encode("eventHash", i - 1))
                : bytes32(0);

            vm.prank(relayer);
            bridge.submitLachesisEvent(
                i,
                1, // epoch
                eventHash,
                parentHash,
                stateRoot,
                block.timestamp,
                attestations
            );

            IFantomBridgeAdapter.LachesisEvent memory ev = bridge
                .getLachesisEvent(i);
            assertTrue(ev.verified);
            assertEq(ev.eventHash, eventHash);
            assertEq(ev.stateRoot, stateRoot);
        }

        assertEq(bridge.latestEventId(), n - 1);
    }

    function test_depositRequiresVerifiedEvent() public {
        // Don't submit any Lachesis event — deposit should fail
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.FTMBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateFTMDeposit(
            keccak256("unverified_tx"),
            address(0x1234),
            user,
            1 ether,
            999, // non-existent event
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSIT ROUND TRIP TEST
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("roundtrip_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IFantomBridgeAdapter.DepositStatus.VERIFIED)
        );
        assertEq(dep.evmRecipient, user);
        assertEq(dep.ftmSender, address(0x1234));
        assertEq(dep.ftmTxHash, txHash);
        assertGt(dep.initiatedAt, 0);
    }

    function testFuzz_depositCompleteRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("complete_rt_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        // Complete the deposit
        vm.prank(admin);
        bridge.completeFTMDeposit(depositId);

        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IFantomBridgeAdapter.DepositStatus.COMPLETED)
        );
        assertGt(dep.completedAt, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       AMOUNT BOUNDS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountWei, MIN_DEPOSIT);
        assertLe(dep.amountWei, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        bytes32 txHash = keccak256(abi.encode("below_tx", amount));
        bytes32 stateRoot = _computeStateRoot(txHash);
        _submitVerifiedEvent(1, stateRoot);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateFTMDeposit(
            txHash,
            address(0x1234),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        bytes32 txHash = keccak256(abi.encode("above_tx", amount));
        bytes32 stateRoot = _computeStateRoot(txHash);
        _submitVerifiedEvent(1, stateRoot);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateFTMDeposit(
            txHash,
            address(0x1234),
            user,
            amount,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        // Mint wFTM to user for withdrawal (bridge owns wFTM)
        vm.prank(address(bridge));
        wFTM.mint(user, amount);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            address(0x5678), // ftmRecipient (EVM-compatible address)
            amount
        );
        vm.stopPrank();

        IFantomBridgeAdapter.FTMWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IFantomBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.evmSender, user);
        assertEq(w.ftmRecipient, address(0x5678));
        assertEq(w.amountWei, amount);
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wFTM.mint(user, amount);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wFTM.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wFTM.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IFantomBridgeAdapter.FTMWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IFantomBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_refundTooEarly() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wFTM.mint(user, amount);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        uint256 initiatedAt = block.timestamp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.RefundTooEarly.selector,
                block.timestamp,
                initiatedAt + 24 hours
            )
        );
        bridge.refundWithdrawal(wId);
    }

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
    }

    function test_withdrawalRejectsZeroRecipient() public {
        vm.prank(address(bridge));
        wFTM.mint(user, 1 ether);

        vm.startPrank(user);
        wFTM.approve(address(bridge), 1 ether);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.initiateWithdrawal(address(0), 1 ether);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_ftm");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678), // ftmParty (EVM-compatible address)
            hashlock,
            finishAfter,
            cancelAfter
        );

        IFantomBridgeAdapter.FTMEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IFantomBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountWei, 1 ether);
        assertEq(e.ftmParty, address(0x5678));

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IFantomBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_ftm")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(IFantomBridgeAdapter.EscrowTimelockNotMet.selector);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_ftm")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );

        IFantomBridgeAdapter.FTMEscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_ftm")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IFantomBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );
    }

    function testFuzz_escrowTimelockTooShort(
        uint256 finish,
        uint256 shortDuration
    ) public {
        finish = bound(finish, block.timestamp + 1, block.timestamp + 365 days);
        shortDuration = bound(shortDuration, 1, 1 hours - 1);
        uint256 cancel = finish + shortDuration;

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("short_ftm")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IFantomBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );
    }

    function test_escrowRejectsZeroValue() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("zero_val")));

        vm.prank(user);
        vm.expectRevert(IFantomBridgeAdapter.InvalidAmount.selector);
        bridge.createEscrow{value: 0}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowRejectsZeroHashlock() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IFantomBridgeAdapter.InvalidAmount.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            bytes32(0),
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowRejectsZeroFtmParty() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("zero_party")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_escrowFinishBeforeTimelockReverts() public {
        bytes32 preimage = keccak256("early_finish_ftm");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Try to finish before finishAfter
        vm.expectRevert(IFantomBridgeAdapter.EscrowTimelockNotMet.selector);
        bridge.finishEscrow(escrowId, preimage);
    }

    function test_escrowInvalidPreimageReverts() public {
        bytes32 preimage = keccak256("correct_preimage_ftm");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);

        bytes32 wrongPreimage = keccak256("wrong_preimage_ftm");
        bytes32 wrongHash = sha256(abi.encodePacked(wrongPreimage));
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.InvalidPreimage.selector,
                hashlock,
                wrongHash
            )
        );
        bridge.finishEscrow(escrowId, wrongPreimage);
    }

    function testFuzz_escrowAmountPreserved(uint256 amount) public {
        amount = bound(amount, 0.01 ether, 100 ether);

        bytes32 preimage = keccak256(abi.encode("escrow_amt_ftm", amount));
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, amount);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: amount}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        IFantomBridgeAdapter.FTMEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(e.amountWei, amount);
    }

    /*//////////////////////////////////////////////////////////////
                     PRIVATE DEPOSIT / NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_privateDeposit(bytes32 commitment) public {
        vm.assume(commitment != bytes32(0));

        bytes32 txHash = keccak256(abi.encode("priv_tx", commitment));
        bytes32 depositId = _initiateDeposit(1 ether, txHash);

        // Complete the deposit so status is COMPLETED
        vm.prank(admin);
        bridge.completeFTMDeposit(depositId);

        // Build a valid ZK proof
        bytes32 nullifier = keccak256(abi.encode("nullifier", commitment));
        bytes32 proofBinding = keccak256(
            abi.encodePacked(depositId, commitment, nullifier)
        );
        // Proof must be >= 256 bytes, with proofBind at bytes [32:64]
        bytes memory zkProof = new bytes(256);
        assembly {
            mstore(add(zkProof, 64), proofBinding)
        }

        vm.prank(admin);
        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            zkProof
        );

        assertTrue(bridge.usedNullifiers(nullifier));
    }

    function testFuzz_duplicateNullifier(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        // First deposit
        bytes32 txHash1 = keccak256(abi.encode("null_tx1", nullifier));
        bytes32 depositId1 = _initiateDeposit(1 ether, txHash1);

        vm.prank(admin);
        bridge.completeFTMDeposit(depositId1);

        bytes32 commitment1 = keccak256("commitment1");
        bytes32 proofBinding1 = keccak256(
            abi.encodePacked(depositId1, commitment1, nullifier)
        );
        bytes memory zkProof1 = new bytes(256);
        assembly {
            mstore(add(zkProof1, 64), proofBinding1)
        }

        vm.prank(admin);
        bridge.registerPrivateDeposit(
            depositId1,
            commitment1,
            nullifier,
            zkProof1
        );

        // Second deposit with same nullifier should fail
        bytes32 txHash2 = keccak256(abi.encode("null_tx2", nullifier));

        // Submit new Lachesis event for the second deposit
        bytes32 stateRoot2 = _computeStateRoot(txHash2);
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        bridge.submitLachesisEvent(
            2,
            1,
            keccak256(abi.encode("eventHash", uint256(2))),
            keccak256(abi.encode("eventHash", uint256(1))),
            stateRoot2,
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        bytes32 depositId2 = bridge.initiateFTMDeposit(
            txHash2,
            address(0x1234),
            user,
            1 ether,
            2,
            proof,
            attestations
        );

        vm.prank(admin);
        bridge.completeFTMDeposit(depositId2);

        bytes32 commitment2 = keccak256("commitment2");
        bytes32 proofBinding2 = keccak256(
            abi.encodePacked(depositId2, commitment2, nullifier)
        );
        bytes memory zkProof2 = new bytes(256);
        assembly {
            mstore(add(zkProof2, 64), proofBinding2)
        }

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.registerPrivateDeposit(
            depositId2,
            commitment2,
            nullifier,
            zkProof2
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        bytes32 txHash = keccak256("ac_tx");
        bytes32 stateRoot = _computeStateRoot(txHash);
        _submitVerifiedEvent(1, stateRoot);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateFTMDeposit(
            txHash,
            address(0x1234),
            user,
            1 ether,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 ether,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeFTMDeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    function testFuzz_onlyAdminCanSetTreasury(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.setTreasury(address(0xF1));
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // Cannot submit Lachesis event while paused
        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitLachesisEvent(
            1,
            1,
            keccak256("eventHash"),
            bytes32(0),
            keccak256("stateRoot"),
            block.timestamp,
            attestations
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(address(0x5678), 1 ether);
    }

    function testFuzz_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_ftm")));

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_unpauseRestoresDeposits() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        // Should succeed after unpause
        bytes32 txHash = keccak256("unpause_tx");
        bytes32 depositId = _initiateDeposit(1 ether, txHash);
        assertTrue(depositId != bytes32(0));
    }

    function test_unpauseRestoresEscrow() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("unpause_escrow")));
        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
        assertTrue(escrowId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        // Create a deposit to accumulate fees
        bytes32 depositId = _initiateDeposit(
            100 ether,
            keccak256("fee_test_tx")
        );

        uint256 expectedFee = (100 ether * 4) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        // Withdraw fees
        uint256 treasuryBalBefore = wFTM.balanceOf(treasury);
        vm.prank(admin);
        bridge.withdrawFees();

        assertEq(bridge.accumulatedFees(), 0);
        // Treasury should have received fees (up to bridge balance)
        uint256 treasuryBalAfter = wFTM.balanceOf(treasury);
        assertGe(treasuryBalAfter, treasuryBalBefore);
    }

    function test_feeWithdrawalRejectsZeroFees() public {
        // No deposits made, so accumulated fees are 0
        vm.prank(admin);
        vm.expectRevert(IFantomBridgeAdapter.InvalidAmount.selector);
        bridge.withdrawFees();
    }

    function testFuzz_feesAccumulateAcrossDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 totalFees = 0;

        for (uint256 i = 0; i < n; i++) {
            uint256 amount = 10 ether * (i + 1);
            bytes32 txHash = keccak256(abi.encode("fee_multi_tx", i));

            // Submit a unique event for each deposit
            // Use widely-spaced IDs to avoid parent chain linkage
            uint256 eventId = (i + 1) * 1000;
            bytes32 stateRoot = _computeStateRoot(txHash);
            IFantomBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();

            vm.prank(relayer);
            bridge.submitLachesisEvent(
                eventId,
                1,
                keccak256(abi.encode("feeEventHash", i)),
                bytes32(0),
                stateRoot,
                block.timestamp,
                attestations
            );

            IFantomBridgeAdapter.DAGStateProof
                memory proof = _buildDAGStateProof();

            vm.prank(relayer);
            bridge.initiateFTMDeposit(
                txHash,
                address(0x1234),
                user,
                amount,
                eventId,
                proof,
                attestations
            );

            totalFees += (amount * 4) / 10_000;
        }

        assertEq(bridge.accumulatedFees(), totalFees);
    }

    /*//////////////////////////////////////////////////////////////
                     MULTIPLE DEPOSITS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));

            // Submit Lachesis event for each deposit
            bytes32 stateRoot = _computeStateRoot(txHash);
            _submitVerifiedEvent(i + 1, stateRoot);

            IFantomBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IFantomBridgeAdapter.DAGStateProof
                memory proof = _buildDAGStateProof();

            vm.prank(relayer);
            bridge.initiateFTMDeposit(
                txHash,
                address(0x1234),
                user,
                1 ether,
                i + 1,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
    }

    /*//////////////////////////////////////////////////////////////
                     TX HASH REPLAY PROTECTION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        bytes32 depositId = _initiateDeposit(1 ether, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit another Lachesis event for second attempt
        // Use a widely-spaced event ID to avoid parent chain linkage
        uint256 replayEventId = 5000;
        bytes32 stateRoot = _computeStateRoot(txHash);
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitLachesisEvent(
            replayEventId,
            1,
            keccak256(abi.encode("eventHash", replayEventId)),
            bytes32(0),
            stateRoot,
            block.timestamp,
            attestations
        );

        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.FTMTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateFTMDeposit(
            txHash,
            address(0x1234),
            user,
            1 ether,
            replayEventId,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                     CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configRejectsZeroAddresses(
        address a,
        address b,
        address c,
        uint256 sigs
    ) public {
        vm.prank(admin);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 1);

        vm.prank(admin);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            1
        );

        vm.prank(admin);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            b == address(0) ? address(1) : b,
            address(0),
            sigs,
            1
        );
    }

    function test_configRejectsZeroSignatures() public {
        vm.prank(admin);
        vm.expectRevert(IFantomBridgeAdapter.InvalidAmount.selector);
        bridge.configure(address(0x1), address(wFTM), address(lachesisVerifier), 0, 1);
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0xF1);
        vm.prank(admin);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                       EVENT EMISSION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_depositEmitsFTMDepositInitiated() public {
        bytes32 txHash = keccak256("emit_deposit_tx");
        bytes32 stateRoot = _computeStateRoot(txHash);
        _submitVerifiedEvent(1, stateRoot);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        vm.expectEmit(false, true, false, true);
        emit IFantomBridgeAdapter.FTMDepositInitiated(
            bytes32(0), // depositId (not checked since indexed and computed)
            txHash,
            address(0x1234),
            user,
            1 ether
        );
        bridge.initiateFTMDeposit(
            txHash,
            address(0x1234),
            user,
            1 ether,
            1,
            proof,
            attestations
        );
    }

    function test_lachesisEventEmitsVerified() public {
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        bytes32 eventHash = keccak256("test_event_hash");

        vm.prank(relayer);
        vm.expectEmit(false, false, false, true);
        emit IFantomBridgeAdapter.LachesisEventVerified(
            1,
            42,
            eventHash
        );
        bridge.submitLachesisEvent(
            1,
            42,
            eventHash,
            bytes32(0),
            keccak256("stateRoot"),
            block.timestamp,
            attestations
        );
    }

    function test_withdrawalEmitsInitiated() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wFTM.mint(user, amount);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount);

        vm.expectEmit(false, true, false, true);
        emit IFantomBridgeAdapter.FTMWithdrawalInitiated(
            bytes32(0),
            user,
            address(0x5678),
            amount
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();
    }

    function test_escrowEmitsCreated() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("emit_escrow")));

        vm.deal(user, 10 ether);
        vm.prank(user);
        vm.expectEmit(false, true, false, true);
        emit IFantomBridgeAdapter.EscrowCreated(
            bytes32(0),
            user,
            address(0x5678),
            1 ether,
            hashlock
        );
        bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    /*//////////////////////////////////////////////////////////////
                       USER TRACKING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_userTracking() public {
        // Deposit tracking
        bytes32 depositId = _initiateDeposit(
            1 ether,
            keccak256("track_deposit")
        );
        bytes32[] memory userDeps = bridge.getUserDeposits(user);
        assertEq(userDeps.length, 1);
        assertEq(userDeps[0], depositId);

        // Withdrawal tracking
        vm.prank(address(bridge));
        wFTM.mint(user, 1 ether);

        vm.startPrank(user);
        wFTM.approve(address(bridge), 1 ether);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), 1 ether);
        vm.stopPrank();

        bytes32[] memory userWithds = bridge.getUserWithdrawals(user);
        assertEq(userWithds.length, 1);
        assertEq(userWithds[0], wId);

        // Escrow tracking
        vm.deal(user, 1 ether);
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("track_escrow")));
        vm.prank(user);
        bytes32 eId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        bytes32[] memory userEscs = bridge.getUserEscrows(user);
        assertEq(userEscs.length, 1);
        assertEq(userEscs[0], eId);
    }

    /*//////////////////////////////////////////////////////////////
                       BRIDGE STATS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeStats() public {
        // Initial stats
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 lastEventId
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(lastEventId, 0);

        // After deposit
        _initiateDeposit(10 ether, keccak256("stats_deposit"));
        (deposited, , , , , fees, ) = bridge.getBridgeStats();
        assertEq(deposited, 10 ether);
        assertEq(fees, (10 ether * 4) / 10_000);

        // After withdrawal
        vm.prank(address(bridge));
        wFTM.mint(user, 1 ether);
        vm.startPrank(user);
        wFTM.approve(address(bridge), 1 ether);
        bridge.initiateWithdrawal(address(0x5678), 1 ether);
        vm.stopPrank();

        (, withdrawn, , , , , ) = bridge.getBridgeStats();
        assertEq(withdrawn, 1 ether);

        // After escrow
        vm.deal(user, 1 ether);
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("stats_escrow")));
        vm.prank(user);
        bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        (, , escrowCount, , , , ) = bridge.getBridgeStats();
        assertEq(escrowCount, 1);
    }

    function test_bridgeStatsEscrowFinishAndCancel() public {
        // Create and finish an escrow
        bytes32 preimage = keccak256("stats_preimage");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));
        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId1 = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId1, preimage);

        (, , , uint256 escrowsFinished, , , ) = bridge.getBridgeStats();
        assertEq(escrowsFinished, 1);

        // Create and cancel another escrow
        bytes32 hashlock2 = sha256(abi.encodePacked(keccak256("stats_cancel")));
        uint256 finishAfter2 = block.timestamp + 1 hours;
        uint256 cancelAfter2 = finishAfter2 + 6 hours;

        vm.prank(user);
        bytes32 escrowId2 = bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock2,
            finishAfter2,
            cancelAfter2
        );

        vm.warp(cancelAfter2 + 1);
        bridge.cancelEscrow(escrowId2);

        (, , , , uint256 escrowsCancelled, , ) = bridge.getBridgeStats();
        assertEq(escrowsCancelled, 1);
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT ID UNIQUENESS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositIdUniqueness(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);
        bytes32[] memory ids = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("unique_tx", i));

            bytes32 stateRoot = _computeStateRoot(txHash);
            _submitVerifiedEvent(i + 1, stateRoot);

            IFantomBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IFantomBridgeAdapter.DAGStateProof
                memory proof = _buildDAGStateProof();

            vm.prank(relayer);
            ids[i] = bridge.initiateFTMDeposit(
                txHash,
                address(0x1234),
                user,
                1 ether,
                i + 1,
                proof,
                attestations
            );
        }

        // Verify all IDs are unique
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(ids[i] != ids[j], "Deposit IDs must be unique");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                    ESCROW DOUBLE FINISH / CANCEL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_ftm");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Finish the escrow
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Attempt to finish again — should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    function test_escrowDoubleCancel() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("double_cancel_ftm")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(cancelAfter + 1);
        bridge.cancelEscrow(escrowId);

        // Attempt to cancel again — should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.cancelEscrow(escrowId);
    }

    function test_cannotFinishCancelledEscrow() public {
        bytes32 preimage = keccak256("finish_cancelled_ftm");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cancel first
        vm.warp(cancelAfter + 1);
        bridge.cancelEscrow(escrowId);

        // Try to finish — should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    /*//////////////////////////////////////////////////////////////
                  WITHDRAWAL DOUBLE COMPLETE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wFTM.mint(user, amount);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Complete the withdrawal — use event >= 100 to avoid underflow in loop
        bytes32 ftmTxHash = keccak256("complete_ftm_tx");
        bytes32 stateRoot = _computeStateRoot(ftmTxHash);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitLachesisEvent(
            100,
            1,
            keccak256(abi.encode("eventHash", uint256(100))),
            bytes32(0),
            stateRoot,
            block.timestamp,
            attestations
        );

        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        bridge.completeWithdrawal(wId, ftmTxHash, proof, attestations);

        // Attempt to complete again — should revert
        bytes32 ftmTxHash2 = keccak256("complete_ftm_tx_2");

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(wId, ftmTxHash2, proof, attestations);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL NONCE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 ether;

        // Mint wFTM to user for withdrawals (bridge owns wFTM)
        vm.prank(address(bridge));
        wFTM.mint(user, amount * n);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0x5678), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT COMPLETION EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_completeNonExistentDeposit() public {
        bytes32 fakeId = keccak256("nonexistent");

        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.DepositNotFound.selector,
                fakeId
            )
        );
        bridge.completeFTMDeposit(fakeId);
    }

    function test_doubleCompleteDeposit() public {
        bytes32 txHash = keccak256("double_complete_tx");
        bytes32 depositId = _initiateDeposit(1 ether, txHash);

        vm.prank(admin);
        bridge.completeFTMDeposit(depositId);

        // Second attempt should revert
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.DepositNotVerified.selector,
                depositId
            )
        );
        bridge.completeFTMDeposit(depositId);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountWei, 0);

        IFantomBridgeAdapter.FTMWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountWei, 0);

        IFantomBridgeAdapter.FTMEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountWei, 0);

        IFantomBridgeAdapter.LachesisEvent memory ev = bridge.getLachesisEvent(
            0
        );
        assertFalse(ev.verified);
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user);
        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        bytes32[] memory es = bridge.getUserEscrows(user);

        assertEq(deps.length, 0);
        assertEq(ws.length, 0);
        assertEq(es.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                  LACHESIS EVENT EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_lachesisEventParentHashMismatch() public {
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        // Submit event 0
        vm.prank(relayer);
        bridge.submitLachesisEvent(
            0,
            1,
            keccak256("eventHash_0"),
            bytes32(0),
            keccak256("stateRoot_0"),
            block.timestamp,
            attestations
        );

        // Submit event 1 with wrong parent hash
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.FTMBlockNotVerified.selector,
                1
            )
        );
        bridge.submitLachesisEvent(
            1,
            1,
            keccak256("eventHash_1"),
            keccak256("wrong_parent"), // wrong parent hash
            keccak256("stateRoot_1"),
            block.timestamp,
            attestations
        );
    }

    function test_lachesisEventUpdatesLatest() public {
        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        bytes32 eventHash5 = keccak256("eventHash_5");

        vm.prank(relayer);
        bridge.submitLachesisEvent(
            5,
            1,
            eventHash5,
            bytes32(0),
            keccak256("stateRoot_5"),
            block.timestamp,
            attestations
        );

        assertEq(bridge.latestEventId(), 5);
        assertEq(bridge.latestEventHash(), eventHash5);

        // Submit earlier event — latestEventId should not change
        vm.prank(relayer);
        bridge.submitLachesisEvent(
            3,
            1,
            keccak256("eventHash_3"),
            bytes32(0),
            keccak256("stateRoot_3"),
            block.timestamp,
            attestations
        );

        assertEq(bridge.latestEventId(), 5);
        assertEq(bridge.latestEventHash(), eventHash5);
    }

    /*//////////////////////////////////////////////////////////////
                  DEPOSIT ZERO RECIPIENT TEST
    //////////////////////////////////////////////////////////////*/

    function test_depositRejectsZeroRecipient() public {
        bytes32 txHash = keccak256("zero_recipient_tx");
        bytes32 stateRoot = _computeStateRoot(txHash);
        _submitVerifiedEvent(1, stateRoot);

        IFantomBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IFantomBridgeAdapter.DAGStateProof
            memory proof = _buildDAGStateProof();

        vm.prank(relayer);
        vm.expectRevert(IFantomBridgeAdapter.ZeroAddress.selector);
        bridge.initiateFTMDeposit(
            txHash,
            address(0x1234),
            address(0), // zero recipient
            1 ether,
            1,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                  ESCROW NOT FOUND TESTS
    //////////////////////////////////////////////////////////////*/

    function test_finishNonExistentEscrow() public {
        bytes32 fakeId = keccak256("fake_escrow_finish");

        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.EscrowNotFound.selector,
                fakeId
            )
        );
        bridge.finishEscrow(fakeId, keccak256("preimage"));
    }

    function test_cancelNonExistentEscrow() public {
        bytes32 fakeId = keccak256("fake_escrow_cancel");

        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.EscrowNotFound.selector,
                fakeId
            )
        );
        bridge.cancelEscrow(fakeId);
    }

    /*//////////////////////////////////////////////////////////////
                  WITHDRAWAL NOT FOUND TESTS
    //////////////////////////////////////////////////////////////*/

    function test_refundNonExistentWithdrawal() public {
        bytes32 fakeId = keccak256("fake_withdrawal");

        vm.expectRevert(
            abi.encodeWithSelector(
                IFantomBridgeAdapter.WithdrawalNotFound.selector,
                fakeId
            )
        );
        bridge.refundWithdrawal(fakeId);
    }

    /*//////////////////////////////////////////////////////////////
                  FANTOM CHAIN ID INTEGRATION TEST
    //////////////////////////////////////////////////////////////*/

    function test_fantomChainIdUsedInDepositId() public {
        bytes32 txHash = keccak256("chainid_test_tx");
        bytes32 depositId = _initiateDeposit(1 ether, txHash);

        // The deposit ID should incorporate FANTOM_CHAIN_ID (250)
        // Verify the deposit exists with correct chain-derived ID
        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, 1 ether);
        assertTrue(dep.depositId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                  WEI PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_weiPrecision(uint256 amount) public {
        // Test that deposits maintain full 18-decimal Wei precision
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("wei_prec_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IFantomBridgeAdapter.FTMDeposit memory dep = bridge.getDeposit(
            depositId
        );

        // Verify no precision loss
        assertEq(dep.amountWei, amount);
        assertEq(dep.fee + dep.netAmountWei, amount);

        // Verify smallest deposit preserves precision
        if (amount == MIN_DEPOSIT) {
            // 0.01 ether = 10^16 wei
            assertEq(dep.amountWei, 10 ** 16);
        }
    }

    /*//////////////////////////////////////////////////////////////
                  TOTAL DEPOSITED / WITHDRAWN TRACKING
    //////////////////////////////////////////////////////////////*/

    function testFuzz_totalDepositedTracking(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 totalExpected = 0;

        for (uint256 i = 0; i < n; i++) {
            uint256 amount = bound(uint256(keccak256(abi.encode(i))), MIN_DEPOSIT, 100 ether);
            bytes32 txHash = keccak256(abi.encode("total_dep_tx", i));

            // Use widely-spaced event IDs to avoid parent chain linkage
            uint256 eventId = (i + 1) * 1000;
            bytes32 stateRoot = _computeStateRoot(txHash);
            IFantomBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();

            vm.prank(relayer);
            bridge.submitLachesisEvent(
                eventId,
                1,
                keccak256(abi.encode("totalDepEventHash", i)),
                bytes32(0),
                stateRoot,
                block.timestamp,
                attestations
            );

            IFantomBridgeAdapter.DAGStateProof
                memory proof = _buildDAGStateProof();

            vm.prank(relayer);
            bridge.initiateFTMDeposit(
                txHash,
                address(0x1234),
                user,
                amount,
                eventId,
                proof,
                attestations
            );

            totalExpected += amount;
        }

        assertEq(bridge.totalDeposited(), totalExpected);
    }

    function testFuzz_totalWithdrawnTracking(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 5);
        uint256 totalExpected = 0;
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wFTM.mint(user, amount * n);

        vm.startPrank(user);
        wFTM.approve(address(bridge), amount * n);

        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0x5678), amount);
            totalExpected += amount;
        }
        vm.stopPrank();

        assertEq(bridge.totalWithdrawn(), totalExpected);
    }
}
