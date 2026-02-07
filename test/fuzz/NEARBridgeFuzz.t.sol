// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {NEARBridgeAdapter} from "../../contracts/crosschain/NEARBridgeAdapter.sol";
import {INEARBridgeAdapter} from "../../contracts/interfaces/INEARBridgeAdapter.sol";
import {MockWrappedNEAR} from "../../contracts/mocks/MockWrappedNEAR.sol";
import {MockNEARLightClient} from "../../contracts/mocks/MockNEARLightClient.sol";

/**
 * @title NEARBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the NEARBridgeAdapter
 * @dev Tests Yocto precision (24 decimals), NEARBlockHeader verification,
 *      Doomslug validator attestation, and NEAR-specific bridge parameters.
 */
contract NEARBridgeFuzz is Test {
    NEARBridgeAdapter public bridge;
    MockWrappedNEAR public wNEAR;
    MockNEARLightClient public nearLC;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant YOCTO_PER_NEAR = 10 ** 24; // 1e24
    uint256 constant MIN_DEPOSIT = YOCTO_PER_NEAR / 10; // 0.1 NEAR
    uint256 constant MAX_DEPOSIT = 10_000_000 * YOCTO_PER_NEAR;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new NEARBridgeAdapter(admin);
        wNEAR = new MockWrappedNEAR();
        nearLC = new MockNEARLightClient();

        // Register validators with voting power
        nearLC.addValidator(VALIDATOR_1, 100);
        nearLC.addValidator(VALIDATOR_2, 100);
        nearLC.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // nearBridgeContract
            address(wNEAR),
            address(nearLC),
            2, // minValidatorSignatures
            2 // requiredConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wNEAR (100M NEAR in yocto)
        wNEAR.mint(address(bridge), 100_000_000 * YOCTO_PER_NEAR);

        vm.stopPrank();
    }

    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (INEARBridgeAdapter.ValidatorAttestation[] memory)
    {
        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = new INEARBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = INEARBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = INEARBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = INEARBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedBlock(
        uint256 blockHeight,
        bytes32 blockHash
    ) internal {
        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitNEARBlock(
            blockHeight,
            blockHash,
            keccak256(abi.encode("prevBlock", blockHeight)),
            keccak256(abi.encode("epoch", blockHeight)),
            keccak256(abi.encode("outcomeRoot", blockHeight)),
            keccak256(abi.encode("chunkMask", blockHeight)),
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (INEARBridgeAdapter.NEARStateProof memory)
    {
        bytes32[] memory proofPath = new bytes32[](2);
        proofPath[0] = keccak256("proof_node_0");
        proofPath[1] = keccak256("proof_node_1");

        return
            INEARBridgeAdapter.NEARStateProof({
                proofPath: proofPath,
                outcomeHash: keccak256("outcome"),
                value: hex"deadbeef"
            });
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit a NEAR block first
        _submitVerifiedBlock(1, keccak256("block1"));

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateNEARDeposit(
                txHash,
                keccak256("near_sender"),
                user,
                amount,
                1, // nearBlockHeight
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.NEAR_CHAIN_ID(), 397);
        assertEq(bridge.YOCTO_PER_NEAR(), 10 ** 24);
        assertEq(bridge.BRIDGE_FEE_BPS(), 5);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 2);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(INEARBridgeAdapter.ZeroAddress.selector);
        new NEARBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        YOCTO PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_yoctoPrecision(uint256 nearAmount) public pure {
        nearAmount = bound(nearAmount, 1, 1_000_000);
        uint256 yocto = nearAmount * YOCTO_PER_NEAR;
        assertEq(yocto / YOCTO_PER_NEAR, nearAmount);
        assertEq(yocto % YOCTO_PER_NEAR, 0);
    }

    function testFuzz_yoctoSubUnitDeposit(uint256 yocto) public {
        yocto = bound(yocto, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("near_tx_sub", yocto));
        bytes32 depositId = _initiateDeposit(yocto, txHash);

        INEARBridgeAdapter.NEARDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountYocto, yocto);
        assertEq(dep.fee, (yocto * 5) / 10_000);
        assertEq(dep.netAmountYocto, yocto - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT YOCTO AMOUNTS FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositYoctoAmounts(uint256 yocto) public {
        yocto = bound(yocto, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("yocto_deposit", yocto));
        bytes32 depositId = _initiateDeposit(yocto, txHash);

        INEARBridgeAdapter.NEARDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountYocto, yocto);
        assertTrue(dep.netAmountYocto <= yocto);
        assertTrue(dep.fee + dep.netAmountYocto == yocto);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 5) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.05% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                    BLOCK HEADER CHAIN TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_blockHeaderChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 blockHash = keccak256(abi.encode("block", i));
            _submitVerifiedBlock(i, blockHash);

            INEARBridgeAdapter.NEARBlockHeader memory bh = bridge.getNEARBlock(
                i
            );
            assertTrue(bh.verified);
            assertEq(bh.blockHash, blockHash);
        }

        assertEq(bridge.latestNEARHeight(), n - 1);
    }

    function test_depositRequiresVerifiedBlock() public {
        // Don't submit any block header — deposit should fail
        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.NEARBlockNotVerified.selector,
                999
            )
        );
        bridge.initiateNEARDeposit(
            keccak256("unverified_tx"),
            keccak256("sender"),
            user,
            1 * YOCTO_PER_NEAR,
            999, // non-existent block height
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRoundTrip(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("roundtrip", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        INEARBridgeAdapter.NEARDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(INEARBridgeAdapter.DepositStatus.VERIFIED)
        );

        // Complete the deposit
        vm.prank(admin);
        bridge.completeNEARDeposit(depositId);

        dep = bridge.getDeposit(depositId);
        assertEq(
            uint256(dep.status),
            uint256(INEARBridgeAdapter.DepositStatus.COMPLETED)
        );
        assertGt(dep.completedAt, 0);
    }

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        INEARBridgeAdapter.NEARDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountYocto, MIN_DEPOSIT);
        assertLe(dep.amountYocto, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedBlock(1, keccak256("block_low"));

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateNEARDeposit(
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

        _submitVerifiedBlock(1, keccak256("block_high"));

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateNEARDeposit(
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

        bytes32 depositId = _initiateDeposit(1 * YOCTO_PER_NEAR, txHash);
        assertTrue(depositId != bytes32(0));

        // Submit another block for second attempt
        _submitVerifiedBlock(2, keccak256("block2"));

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.NEARTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateNEARDeposit(
            txHash,
            keccak256("sender"),
            user,
            1 * YOCTO_PER_NEAR,
            2,
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalLifecycle(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        // Mint wNEAR to user for withdrawal
        vm.prank(admin);
        wNEAR.mint(user, amount);

        vm.startPrank(user);
        wNEAR.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("near_recipient"),
            amount
        );
        vm.stopPrank();

        INEARBridgeAdapter.NEARWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(INEARBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.amountYocto, amount);

        // Complete withdrawal as relayer
        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("near_tx_complete"),
            proof,
            attestations
        );

        w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(INEARBridgeAdapter.WithdrawalStatus.COMPLETED)
        );
        assertGt(w.completedAt, 0);
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * YOCTO_PER_NEAR;

        vm.prank(admin);
        wNEAR.mint(user, amount);

        vm.startPrank(user);
        wNEAR.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("near_recipient"),
            amount
        );
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wNEAR.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wNEAR.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        INEARBridgeAdapter.NEARWithdrawal memory w = bridge.getWithdrawal(wId);
        assertEq(
            uint256(w.status),
            uint256(INEARBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_withdrawalRefundTooEarly() public {
        uint256 amount = 1 * YOCTO_PER_NEAR;

        vm.prank(admin);
        wNEAR.mint(user, amount);

        vm.startPrank(user);
        wNEAR.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("near_recipient"),
            amount
        );
        vm.stopPrank();

        // Warp a bit but not past full delay
        vm.warp(block.timestamp + 12 hours);

        vm.expectRevert();
        bridge.refundWithdrawal(wId);
    }

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("near_recipient"), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(keccak256("near_recipient"), amount);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_near");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("near_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        INEARBridgeAdapter.NEAREscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(INEARBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountYocto, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(INEARBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_near")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = finishAfter + 6 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.5 ether}(
            keccak256("near_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        // Cannot cancel before cancelAfter
        vm.expectRevert(INEARBridgeAdapter.EscrowTimelockNotMet.selector);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_near")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("near_party"),
            hashlock,
            finish,
            cancel
        );

        INEARBridgeAdapter.NEAREscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_near")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(INEARBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("near_party"),
            hashlock,
            finish,
            cancel
        );
    }

    function test_escrowDoubleFinish() public {
        bytes32 preimage = keccak256("double_finish_near");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            keccak256("near_party"),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        // Second finish should fail
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.EscrowNotActive.selector,
                escrowId
            )
        );
        bridge.finishEscrow(escrowId, preimage);
    }

    /*//////////////////////////////////////////////////////////////
                       PRIVACY / NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_privateDeposit() public {
        bytes32 depositId = _initiateDeposit(
            1 * YOCTO_PER_NEAR,
            keccak256("private_tx_near")
        );

        bytes32 commitment = keccak256("commitment_near");
        bytes32 nullifier = keccak256("nullifier_near");

        bridge.registerPrivateDeposit(
            depositId,
            commitment,
            nullifier,
            hex"00"
        );

        assertTrue(bridge.isNullifierUsed(nullifier));
    }

    function testFuzz_duplicateNullifier(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes32 depositId = _initiateDeposit(
            1 * YOCTO_PER_NEAR,
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
                INEARBridgeAdapter.NullifierAlreadyUsed.selector,
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
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != relayer && caller != admin && caller != address(0));

        _submitVerifiedBlock(1, keccak256("block_ac"));

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateNEARDeposit(
            keccak256("ac_tx"),
            keccak256("sender"),
            user,
            1 * YOCTO_PER_NEAR,
            1,
            proof,
            attestations
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        bytes32 depositId = _initiateDeposit(
            1 * YOCTO_PER_NEAR,
            keccak256("complete_test")
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeNEARDeposit(depositId);
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

    function test_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        _submitVerifiedBlock(1, keccak256("block_pause"));

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateNEARDeposit(
            keccak256("paused_tx"),
            keccak256("sender"),
            user,
            1 * YOCTO_PER_NEAR,
            1,
            proof,
            attestations
        );
    }

    function test_pauseBlocksWithdrawals() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.initiateWithdrawal(
            keccak256("near_recipient"),
            1 * YOCTO_PER_NEAR
        );
    }

    function test_pauseBlocksEscrow() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_near")));

        vm.prank(admin);
        bridge.pause();

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        bridge.createEscrow{value: 0.1 ether}(
            keccak256("near_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );
    }

    function test_unpauseResumesOperations() public {
        vm.prank(admin);
        bridge.pause();

        vm.prank(admin);
        bridge.unpause();

        // Should be able to deposit again
        bytes32 depositId = _initiateDeposit(
            1 * YOCTO_PER_NEAR,
            keccak256("unpause_tx")
        );
        assertTrue(depositId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                     FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        // Create a deposit to generate fees
        bytes32 depositId = _initiateDeposit(
            100 * YOCTO_PER_NEAR,
            keccak256("fee_test_tx")
        );

        uint256 expectedFee = (100 * YOCTO_PER_NEAR * 5) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        // Complete the deposit
        vm.prank(admin);
        bridge.completeNEARDeposit(depositId);

        // Withdraw fees
        uint256 treasuryBalBefore = wNEAR.balanceOf(treasury);
        vm.prank(admin);
        bridge.withdrawFees();
        uint256 treasuryBalAfter = wNEAR.balanceOf(treasury);

        assertEq(treasuryBalAfter - treasuryBalBefore, expectedFee);
        assertEq(bridge.accumulatedFees(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                    MULTIPLE DEPOSITS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("nonce_tx", i));
            _submitVerifiedBlock(
                i + 1,
                keccak256(abi.encode("nonce_block", i))
            );

            INEARBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateNEARDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * YOCTO_PER_NEAR,
                i + 1,
                proof,
                attestations
            );

            assertGt(bridge.depositNonce(), prevNonce);
            prevNonce = bridge.depositNonce();
        }
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
        vm.expectRevert(INEARBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 2);

        vm.prank(admin);
        vm.expectRevert(INEARBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            2
        );

        vm.prank(admin);
        vm.expectRevert(INEARBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            b == address(0) ? address(1) : b,
            address(0),
            sigs,
            2
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
        vm.expectRevert(INEARBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                     USER TRACKING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_userTrackingDeposits() public {
        bytes32 depositId = _initiateDeposit(
            1 * YOCTO_PER_NEAR,
            keccak256("track_tx")
        );

        bytes32[] memory deps = bridge.getUserDeposits(user);
        assertEq(deps.length, 1);
        assertEq(deps[0], depositId);
    }

    function test_userTrackingWithdrawals() public {
        uint256 amount = 1 * YOCTO_PER_NEAR;

        vm.prank(admin);
        wNEAR.mint(user, amount);

        vm.startPrank(user);
        wNEAR.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("near_recipient"),
            amount
        );
        vm.stopPrank();

        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        assertEq(ws.length, 1);
        assertEq(ws[0], wId);
    }

    function test_userTrackingEscrows() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("track_near")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            keccak256("near_party"),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 5 hours
        );

        bytes32[] memory es = bridge.getUserEscrows(user);
        assertEq(es.length, 1);
        assertEq(es[0], escrowId);
    }

    /*//////////////////////////////////////////////////////////////
                       BRIDGE STATS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_bridgeStatsDefault() public view {
        (
            uint256 deposited,
            uint256 withdrawn,
            uint256 escrowCount,
            ,
            ,
            uint256 fees,
            uint256 latestHeight
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestHeight, 0);
    }

    function test_bridgeStatsAfterDeposit() public {
        uint256 amount = 10 * YOCTO_PER_NEAR;
        _initiateDeposit(amount, keccak256("stats_tx"));

        (uint256 deposited, , , , , uint256 fees, ) = bridge.getBridgeStats();
        assertEq(deposited, amount);
        assertEq(fees, (amount * 5) / 10_000);
    }

    /*//////////////////////////////////////////////////////////////
                   DEPOSIT ID UNIQUENESS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositIdUniqueness(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);
        bytes32[] memory ids = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("unique_tx", i));
            _submitVerifiedBlock(
                i + 1,
                keccak256(abi.encode("unique_block", i))
            );

            INEARBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

            vm.prank(relayer);
            ids[i] = bridge.initiateNEARDeposit(
                txHash,
                keccak256("sender"),
                user,
                1 * YOCTO_PER_NEAR,
                i + 1,
                proof,
                attestations
            );
        }

        // Verify all IDs are unique
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = i + 1; j < n; j++) {
                assertTrue(ids[i] != ids[j]);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                 WITHDRAWAL DOUBLE COMPLETE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalDoubleComplete() public {
        uint256 amount = 1 * YOCTO_PER_NEAR;

        vm.prank(admin);
        wNEAR.mint(user, amount);

        vm.startPrank(user);
        wNEAR.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            keccak256("near_recipient"),
            amount
        );
        vm.stopPrank();

        INEARBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        INEARBridgeAdapter.NEARStateProof memory proof = _buildStateProof();

        // First complete
        vm.prank(relayer);
        bridge.completeWithdrawal(
            wId,
            keccak256("near_tx_1"),
            proof,
            attestations
        );

        // Second complete should fail
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                INEARBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(
            wId,
            keccak256("near_tx_2"),
            proof,
            attestations
        );
    }

    /*//////////////////////////////////////////////////////////////
                     VIEW FUNCTION DEFAULTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        INEARBridgeAdapter.NEARDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountYocto, 0);

        INEARBridgeAdapter.NEARWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountYocto, 0);

        INEARBridgeAdapter.NEAREscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountYocto, 0);

        INEARBridgeAdapter.NEARBlockHeader memory bh = bridge.getNEARBlock(0);
        assertFalse(bh.verified);
    }

    function test_userHistoryEmpty() public view {
        bytes32[] memory deps = bridge.getUserDeposits(user);
        bytes32[] memory ws = bridge.getUserWithdrawals(user);
        bytes32[] memory es = bridge.getUserEscrows(user);

        assertEq(deps.length, 0);
        assertEq(ws.length, 0);
        assertEq(es.length, 0);
    }
}
