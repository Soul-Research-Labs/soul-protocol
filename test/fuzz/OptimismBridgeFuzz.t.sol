// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {OptimismBridgeAdapter} from "../../contracts/crosschain/OptimismBridgeAdapter.sol";
import {IOptimismBridgeAdapter} from "../../contracts/interfaces/IOptimismBridgeAdapter.sol";
import {MockWrappedOP} from "../../contracts/mocks/MockWrappedOP.sol";
import {MockOptimismOutputOracle} from "../../contracts/mocks/MockOptimismOutputOracle.sol";

/**
 * @title OptimismBridgeFuzz
 * @notice Foundry fuzz & invariant tests for the OptimismBridgeAdapter
 * @dev Tests Wei precision (18 decimals), L2OutputProposal verification,
 *      OutputRootProof validation, and Optimism-specific bridge parameters.
 */
contract OptimismBridgeFuzz is Test {
    OptimismBridgeAdapter public bridge;
    MockWrappedOP public wOP;
    MockOptimismOutputOracle public outputOracle;

    address public admin = address(0xA);
    address public relayer = address(0xB);
    address public user = address(0xC);
    address public treasury = address(0xD);

    // Validator addresses
    address constant VALIDATOR_1 = address(0x2001);
    address constant VALIDATOR_2 = address(0x2002);
    address constant VALIDATOR_3 = address(0x2003);

    uint256 constant MIN_DEPOSIT = 0.001 ether;
    uint256 constant MAX_DEPOSIT = 10_000_000 ether;

    function setUp() public {
        vm.startPrank(admin);

        bridge = new OptimismBridgeAdapter(admin);
        wOP = new MockWrappedOP();
        outputOracle = new MockOptimismOutputOracle();

        // Register validators with voting power
        outputOracle.addValidator(VALIDATOR_1, 100);
        outputOracle.addValidator(VALIDATOR_2, 100);
        outputOracle.addValidator(VALIDATOR_3, 100);

        // Configure bridge
        bridge.configure(
            address(0x1), // optimismBridgeContract
            address(wOP),
            address(outputOracle),
            2, // minValidatorSignatures
            1 // requiredConfirmations
        );

        bridge.setTreasury(treasury);
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);

        // Fund the bridge with wOP
        wOP.mint(address(bridge), 100_000_000 ether);

        // Transfer wOP ownership to bridge so completeOPDeposit can mint
        wOP.transferOwnership(address(bridge));

        vm.stopPrank();

        // Mock the oracle's verifyAttestation(bytes32,address,bytes) to return true
        // The bridge calls this signature via staticcall; the mock must respond correctly
        vm.mockCall(
            address(outputOracle),
            abi.encodeWithSignature(
                "verifyAttestation(bytes32,address,bytes)",
                bytes32(0),
                VALIDATOR_1,
                bytes(hex"01")
            ),
            abi.encode(true)
        );
        vm.mockCall(
            address(outputOracle),
            abi.encodeWithSignature(
                "verifyAttestation(bytes32,address,bytes)",
                bytes32(0),
                VALIDATOR_2,
                bytes(hex"02")
            ),
            abi.encode(true)
        );
        vm.mockCall(
            address(outputOracle),
            abi.encodeWithSignature(
                "verifyAttestation(bytes32,address,bytes)",
                bytes32(0),
                VALIDATOR_3,
                bytes(hex"03")
            ),
            abi.encode(true)
        );
        // Wildcard mock: accept any verifyAttestation(bytes32,address,bytes) call
        vm.mockCall(
            address(outputOracle),
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
        returns (IOptimismBridgeAdapter.ValidatorAttestation[] memory)
    {
        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IOptimismBridgeAdapter.ValidatorAttestation[](
                3
            );

        attestations[0] = IOptimismBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"01"
        });
        attestations[1] = IOptimismBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"02"
        });
        attestations[2] = IOptimismBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"03"
        });

        return attestations;
    }

    function _submitVerifiedOutput(
        uint256 l2BlockNumber,
        bytes32 outputRoot
    ) internal {
        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();

        vm.prank(relayer);
        bridge.submitL2Output(
            l2BlockNumber,
            outputRoot,
            keccak256(abi.encode("stateRoot", l2BlockNumber)),
            keccak256(abi.encode("withdrawalStorageRoot", l2BlockNumber)),
            block.timestamp,
            attestations
        );
    }

    function _buildStateProof()
        internal
        pure
        returns (IOptimismBridgeAdapter.OutputRootProof memory)
    {
        return
            IOptimismBridgeAdapter.OutputRootProof({
                version: bytes32(0),
                stateRoot: keccak256("stateRoot"),
                messagePasserStorageRoot: keccak256("mpsRoot"),
                latestBlockhash: keccak256("blockHash")
            });
    }

    /// @dev Computes the output root that matches _buildStateProof()
    function _computeOutputRoot() internal pure returns (bytes32) {
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();
        return
            keccak256(
                abi.encodePacked(
                    proof.version,
                    proof.stateRoot,
                    proof.messagePasserStorageRoot,
                    proof.latestBlockhash
                )
            );
    }

    function _initiateDeposit(
        uint256 amount,
        bytes32 txHash
    ) internal returns (bytes32) {
        // Submit L2 output with the correct output root first
        bytes32 outputRoot = _computeOutputRoot();
        _submitVerifiedOutput(1, outputRoot);

        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        return
            bridge.initiateOPDeposit(
                txHash,
                address(0x1234), // l2Sender (Optimism address)
                user,
                amount,
                1, // l2BlockNumber
                proof,
                attestations
            );
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTANTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.OPTIMISM_CHAIN_ID(), 10);
        assertEq(bridge.DECIMALS(), 18);
        assertEq(bridge.BRIDGE_FEE_BPS(), 3);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 1);
        assertEq(bridge.MIN_DEPOSIT(), 0.001 ether);
        assertEq(bridge.MAX_DEPOSIT(), 10_000_000 ether);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IOptimismBridgeAdapter.ZeroAddress.selector);
        new OptimismBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmount(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("op_tx_fuzz", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IOptimismBridgeAdapter.OPDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountWei, amount);
        assertEq(dep.fee, (amount * 3) / 10_000);
        assertEq(dep.netAmountWei, amount - dep.fee);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 3) / 10_000;
        uint256 net = amount - fee;

        // Fee should never exceed the amount
        assertLe(fee, amount);
        // Net + fee = amount
        assertEq(net + fee, amount);
        // 0.03% fee
        assertLe(fee, amount / 100);
    }

    /*//////////////////////////////////////////////////////////////
                    L2 OUTPUT CHAIN VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_l2OutputChain(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 20);

        for (uint256 i = 0; i < n; i++) {
            bytes32 outputRoot = keccak256(abi.encode("outputRoot", i));
            _submitVerifiedOutput(i + 1, outputRoot);

            IOptimismBridgeAdapter.L2OutputProposal memory output = bridge
                .getL2Output(i + 1);
            assertTrue(output.verified);
            assertEq(output.outputRoot, outputRoot);
        }

        assertEq(bridge.latestL2BlockNumber(), n);
    }

    function test_depositRequiresVerifiedOutput() public {
        // Don't submit any L2 output — deposit should fail
        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOptimismBridgeAdapter.L2BlockNotVerified.selector,
                999
            )
        );
        bridge.initiateOPDeposit(
            keccak256("unverified_tx"),
            address(0x1234),
            user,
            1 ether,
            999, // non-existent block number
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

        IOptimismBridgeAdapter.OPDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(
            uint256(dep.status),
            uint256(IOptimismBridgeAdapter.DepositStatus.VERIFIED)
        );
        assertEq(dep.evmRecipient, user);
        assertEq(dep.l2Sender, address(0x1234));
        assertEq(dep.l2TxHash, txHash);
        assertGt(dep.initiatedAt, 0);
    }

    /*//////////////////////////////////////////////////////////////
                       AMOUNT BOUNDS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositAmountBounds(uint256 amount) public {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);

        bytes32 txHash = keccak256(abi.encode("bounds_tx", amount));
        bytes32 depositId = _initiateDeposit(amount, txHash);

        IOptimismBridgeAdapter.OPDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertGe(dep.amountWei, MIN_DEPOSIT);
        assertLe(dep.amountWei, MAX_DEPOSIT);
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        bytes32 outputRoot = _computeOutputRoot();
        _submitVerifiedOutput(1, outputRoot);

        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOptimismBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateOPDeposit(
            keccak256(abi.encode("tx_low", amount)),
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

        bytes32 outputRoot = _computeOutputRoot();
        _submitVerifiedOutput(1, outputRoot);

        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOptimismBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateOPDeposit(
            keccak256(abi.encode("tx_high", amount)),
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

        // Mint wOP to user for withdrawal (bridge owns wOP)
        vm.prank(address(bridge));
        wOP.mint(user, amount);

        vm.startPrank(user);
        wOP.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(
            address(0x5678), // l2Recipient (Optimism address)
            amount
        );
        vm.stopPrank();

        IOptimismBridgeAdapter.OPWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IOptimismBridgeAdapter.WithdrawalStatus.PENDING)
        );
        assertEq(w.evmSender, user);
        assertEq(w.l2Recipient, address(0x5678));
        assertEq(w.amountWei, amount);
    }

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wOP.mint(user, amount);

        vm.startPrank(user);
        wOP.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Cannot refund before delay
        vm.expectRevert();
        bridge.refundWithdrawal(wId);

        // Warp past refund delay (24 hours)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wOP.balanceOf(user);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wOP.balanceOf(user);

        assertEq(balAfter - balBefore, amount);

        IOptimismBridgeAdapter.OPWithdrawal memory w = bridge.getWithdrawal(
            wId
        );
        assertEq(
            uint256(w.status),
            uint256(IOptimismBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    function test_refundTooEarly() public {
        uint256 amount = 1 ether;

        vm.prank(address(bridge));
        wOP.mint(user, amount);

        vm.startPrank(user);
        wOP.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        uint256 initiatedAt = block.timestamp;

        vm.expectRevert(
            abi.encodeWithSelector(
                IOptimismBridgeAdapter.RefundTooEarly.selector,
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
                IOptimismBridgeAdapter.AmountBelowMinimum.selector,
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
                IOptimismBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(address(0x5678), amount);
    }

    /*//////////////////////////////////////////////////////////////
                        ESCROW LIFECYCLE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        bytes32 preimage = keccak256("test_preimage_op");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = finishAfter + 12 hours;

        vm.deal(user, 10 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            address(0x5678), // l2Party (Optimism address)
            hashlock,
            finishAfter,
            cancelAfter
        );

        IOptimismBridgeAdapter.OPEscrow memory e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IOptimismBridgeAdapter.EscrowStatus.ACTIVE)
        );
        assertEq(e.amountWei, 1 ether);

        // Finish after timelock
        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        e = bridge.getEscrow(escrowId);
        assertEq(
            uint256(e.status),
            uint256(IOptimismBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(e.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("cancel_op")));

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
        vm.expectRevert(IOptimismBridgeAdapter.EscrowTimelockNotMet.selector);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("timelock_op")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        bytes32 escrowId = bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );

        IOptimismBridgeAdapter.OPEscrow memory e = bridge.getEscrow(escrowId);
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

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("long_op")));

        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(IOptimismBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 0.1 ether}(
            address(0x5678),
            hashlock,
            finish,
            cancel
        );
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
        bridge.completeOPDeposit(depositId);

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
        bridge.completeOPDeposit(depositId1);

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
        // Need a new deposit for the second attempt
        bytes32 txHash2 = keccak256(abi.encode("null_tx2", nullifier));

        // Submit new L2 output for the second deposit
        bytes32 outputRoot2 = _computeOutputRoot();
        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        bridge.submitL2Output(
            2,
            outputRoot2,
            keccak256(abi.encode("stateRoot", uint256(2))),
            keccak256(abi.encode("withdrawalStorageRoot", uint256(2))),
            block.timestamp,
            attestations
        );

        vm.prank(relayer);
        bytes32 depositId2 = bridge.initiateOPDeposit(
            txHash2,
            address(0x1234),
            user,
            1 ether,
            2,
            proof,
            attestations
        );

        vm.prank(admin);
        bridge.completeOPDeposit(depositId2);

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
                IOptimismBridgeAdapter.NullifierAlreadyUsed.selector,
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

        bytes32 outputRoot = _computeOutputRoot();
        _submitVerifiedOutput(1, outputRoot);

        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateOPDeposit(
            keccak256("ac_tx"),
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
        bridge.completeOPDeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin && caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        vm.prank(admin);
        bridge.pause();

        bytes32 outputRoot = _computeOutputRoot();

        // Cannot submit L2 output while paused
        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.submitL2Output(
            1,
            outputRoot,
            keccak256("stateRoot"),
            keccak256("withdrawalStorageRoot"),
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
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("paused_op")));

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

    /*//////////////////////////////////////////////////////////////
                       FEE WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_feeWithdrawal() public {
        // Create a deposit to accumulate fees
        bytes32 depositId = _initiateDeposit(
            100 ether,
            keccak256("fee_test_tx")
        );

        uint256 expectedFee = (100 ether * 3) / 10_000;
        assertEq(bridge.accumulatedFees(), expectedFee);

        // Withdraw fees
        uint256 treasuryBalBefore = wOP.balanceOf(treasury);
        vm.prank(admin);
        bridge.withdrawFees();

        assertEq(bridge.accumulatedFees(), 0);
        // Treasury should have received fees (up to bridge balance)
        uint256 treasuryBalAfter = wOP.balanceOf(treasury);
        assertGe(treasuryBalAfter, treasuryBalBefore);
    }

    /*//////////////////////////////////////////////////////////////
                     MULTIPLE DEPOSITS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_multipleDeposits(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 prevNonce = bridge.depositNonce();

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("multi_tx", i));

            // Submit L2 output for each deposit
            bytes32 outputRoot = _computeOutputRoot();
            _submitVerifiedOutput(i + 1, outputRoot);

            IOptimismBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IOptimismBridgeAdapter.OutputRootProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            bridge.initiateOPDeposit(
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

        // Submit another L2 output for second attempt
        bytes32 outputRoot = _computeOutputRoot();
        _submitVerifiedOutput(2, outputRoot);

        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOptimismBridgeAdapter.L2TxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateOPDeposit(
            txHash,
            address(0x1234),
            user,
            1 ether,
            2,
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
        vm.expectRevert(IOptimismBridgeAdapter.ZeroAddress.selector);
        bridge.configure(address(0), b, c, sigs, 1);

        vm.prank(admin);
        vm.expectRevert(IOptimismBridgeAdapter.ZeroAddress.selector);
        bridge.configure(
            a == address(0) ? address(1) : a,
            address(0),
            c,
            sigs,
            1
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
        vm.expectRevert(IOptimismBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
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
        wOP.mint(user, 1 ether);

        vm.startPrank(user);
        wOP.approve(address(bridge), 1 ether);
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
            uint256 latestBlock
        ) = bridge.getBridgeStats();

        assertEq(deposited, 0);
        assertEq(withdrawn, 0);
        assertEq(escrowCount, 0);
        assertEq(fees, 0);
        assertEq(latestBlock, 0);

        // After deposit
        _initiateDeposit(10 ether, keccak256("stats_deposit"));
        (deposited, , , , , fees, ) = bridge.getBridgeStats();
        assertEq(deposited, 10 ether);
        assertEq(fees, (10 ether * 3) / 10_000);

        // After withdrawal
        vm.prank(address(bridge));
        wOP.mint(user, 1 ether);
        vm.startPrank(user);
        wOP.approve(address(bridge), 1 ether);
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

    /*//////////////////////////////////////////////////////////////
                    DEPOSIT ID UNIQUENESS TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositIdUniqueness(uint8 count) public {
        uint256 n = bound(uint256(count), 2, 10);
        bytes32[] memory ids = new bytes32[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 txHash = keccak256(abi.encode("unique_tx", i));

            bytes32 outputRoot = _computeOutputRoot();
            _submitVerifiedOutput(i + 1, outputRoot);

            IOptimismBridgeAdapter.ValidatorAttestation[]
                memory attestations = _buildValidatorAttestations();
            IOptimismBridgeAdapter.OutputRootProof
                memory proof = _buildStateProof();

            vm.prank(relayer);
            ids[i] = bridge.initiateOPDeposit(
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
        bytes32 preimage = keccak256("double_finish_op");
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
                IOptimismBridgeAdapter.EscrowNotActive.selector,
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
        wOP.mint(user, amount);

        vm.startPrank(user);
        wOP.approve(address(bridge), amount);
        bytes32 wId = bridge.initiateWithdrawal(address(0x5678), amount);
        vm.stopPrank();

        // Complete the withdrawal — use block >= 100 to avoid underflow in the contract's loop
        bytes32 outputRoot = _computeOutputRoot();
        _submitVerifiedOutput(100, outputRoot);

        IOptimismBridgeAdapter.ValidatorAttestation[]
            memory attestations = _buildValidatorAttestations();
        IOptimismBridgeAdapter.OutputRootProof
            memory proof = _buildStateProof();

        bytes32 l2TxHash = keccak256("complete_l2_tx");

        vm.prank(relayer);
        bridge.completeWithdrawal(wId, l2TxHash, proof, attestations);

        // Attempt to complete again — should revert
        bytes32 l2TxHash2 = keccak256("complete_l2_tx_2");

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IOptimismBridgeAdapter.WithdrawalNotPending.selector,
                wId
            )
        );
        bridge.completeWithdrawal(wId, l2TxHash2, proof, attestations);
    }

    /*//////////////////////////////////////////////////////////////
                       WITHDRAWAL NONCE TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 n = bound(uint256(count), 1, 10);
        uint256 amount = 1 ether;

        // Mint wOP to user for withdrawals (bridge owns wOP)
        vm.prank(address(bridge));
        wOP.mint(user, amount * n);

        vm.startPrank(user);
        wOP.approve(address(bridge), amount * n);

        uint256 prevNonce = bridge.withdrawalNonce();
        for (uint256 i = 0; i < n; i++) {
            bridge.initiateWithdrawal(address(0x5678), amount);
            assertGt(bridge.withdrawalNonce(), prevNonce);
            prevNonce = bridge.withdrawalNonce();
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IOptimismBridgeAdapter.OPDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.amountWei, 0);

        IOptimismBridgeAdapter.OPWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.amountWei, 0);

        IOptimismBridgeAdapter.OPEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.amountWei, 0);

        IOptimismBridgeAdapter.L2OutputProposal memory output = bridge
            .getL2Output(0);
        assertFalse(output.verified);
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
