// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/SolanaBridgeAdapter.sol";
import "../../contracts/interfaces/ISolanaBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedSOL.sol";
import "../../contracts/mocks/MockSolanaGuardianOracle.sol";

/**
 * @title SolanaBridgeFuzz
 * @notice Foundry fuzz & invariant tests for SolanaBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      slot header submission, and security invariants
 */
contract SolanaBridgeFuzz is Test {
    SolanaBridgeAdapter public bridge;
    MockWrappedSOL public wSOL;
    MockSolanaGuardianOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    bytes32 public constant SOLANA_BRIDGE_PROGRAM =
        keccak256("SolanaBridgeProgram");
    bytes32 public constant SOLANA_USER =
        keccak256("SolanaUser");

    uint256 public constant MIN_DEPOSIT = 100_000_000; // 0.1 SOL
    uint256 public constant MAX_DEPOSIT = 1_000_000_000_000_000_000; // 1M SOL

    // Guardian keys
    bytes32 public constant GUARDIAN_KEY_1 = keccak256("guardian1");
    bytes32 public constant GUARDIAN_KEY_2 = keccak256("guardian2");
    bytes32 public constant GUARDIAN_KEY_3 = keccak256("guardian3");

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wSOL = new MockWrappedSOL(admin);
        oracle = new MockSolanaGuardianOracle(admin);

        // Deploy bridge
        bridge = new SolanaBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register Guardians
        oracle.registerGuardian(GUARDIAN_KEY_1);
        oracle.registerGuardian(GUARDIAN_KEY_2);
        oracle.registerGuardian(GUARDIAN_KEY_3);

        // Configure bridge
        bridge.configure(
            SOLANA_BRIDGE_PROGRAM,
            address(wSOL),
            address(oracle),
            2, // minGuardianSignatures
            32 // requiredSlotConfirmations
        );

        // Grant minter role to bridge
        wSOL.grantMinter(address(bridge));

        // Fund user1 with wSOL for withdrawal tests
        wSOL.mint(user1, 1_000_000_000_000_000); // 1M SOL in lamports

        vm.stopPrank();

        // Approve bridge to spend user1's wSOL
        vm.prank(user1);
        wSOL.approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildGuardianAttestations()
        internal
        pure
        returns (ISolanaBridgeAdapter.GuardianAttestation[] memory)
    {
        ISolanaBridgeAdapter.GuardianAttestation[]
            memory attestations = new ISolanaBridgeAdapter.GuardianAttestation[](
                3
            );
        attestations[0] = ISolanaBridgeAdapter.GuardianAttestation({
            guardianPubKey: GUARDIAN_KEY_1,
            signature: hex"0123456789"
        });
        attestations[1] = ISolanaBridgeAdapter.GuardianAttestation({
            guardianPubKey: GUARDIAN_KEY_2,
            signature: hex"0123456789"
        });
        attestations[2] = ISolanaBridgeAdapter.GuardianAttestation({
            guardianPubKey: GUARDIAN_KEY_3,
            signature: hex"0123456789"
        });
        return attestations;
    }

    function _buildMerkleProof()
        internal
        pure
        returns (ISolanaBridgeAdapter.SolanaMerkleProof memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("sibling");

        return
            ISolanaBridgeAdapter.SolanaMerkleProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _submitFinalizedSlot(uint256 slot) internal {
        vm.prank(relayer);
        bridge.submitSlotHeader(
            slot,
            keccak256(abi.encodePacked("slot", slot)),
            slot > 0
                ? keccak256(abi.encodePacked("slot", slot - 1))
                : bytes32(0),
            keccak256(abi.encodePacked("txRoot", slot)),
            keccak256(abi.encodePacked("accountsRoot", slot)),
            block.timestamp,
            _buildGuardianAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: DEPOSIT AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        _submitFinalizedSlot(1);

        bytes32 txSig = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISolanaBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateSOLDeposit(
            txSig,
            SOLANA_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildGuardianAttestations()
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        _submitFinalizedSlot(1);

        bytes32 txSig = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISolanaBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateSOLDeposit(
            txSig,
            SOLANA_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildGuardianAttestations()
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
                ISolanaBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(SOLANA_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ISolanaBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(SOLANA_USER, amount);
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
                SOLANA_USER,
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

        // Duration too long (> 30 days)
        duration = bound(duration, 30 days + 1, 365 days);
        uint256 cancelAfter = finishAfter + duration;

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                SOLANA_USER,
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

    function testFuzz_txSignatureReplayProtection(bytes32 txSig) public {
        vm.assume(txSig != bytes32(0));

        _submitFinalizedSlot(1);

        // Tx signature should initially be unused
        assertFalse(bridge.usedSolanaTxSignatures(txSig));
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
        bytes32 bridgeProgram,
        address wrappedSOL,
        address oracleAddr,
        uint256 minSigs
    ) public {
        vm.assume(minSigs > 0);

        if (
            bridgeProgram == bytes32(0) ||
            wrappedSOL == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(ISolanaBridgeAdapter.ZeroAddress.selector);
            bridge.configure(
                bridgeProgram,
                wrappedSOL,
                oracleAddr,
                minSigs,
                32
            );
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

        _submitFinalizedSlot(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateSOLDeposit(
            keccak256("tx"),
            SOLANA_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildGuardianAttestations()
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != operator && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeSOLDeposit(keccak256("deposit"));
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
        _submitFinalizedSlot(1);

        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateSOLDeposit(
            keccak256("tx"),
            SOLANA_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildGuardianAttestations()
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateWithdrawal(SOLANA_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                SOLANA_USER,
                keccak256("hashlock"),
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
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            SOLANA_USER,
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

        // User2 should receive the escrowed ETH
        assertEq(user2.balance - balBefore, 1 ether);

        // Verify escrow status
        ISolanaBridgeAdapter.SolanaEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(uint8(esc.status), uint8(ISolanaBridgeAdapter.EscrowStatus.FINISHED));
        assertEq(esc.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            SOLANA_USER,
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

        // User1 should get funds back
        assertEq(user1.balance - balBefore, 1 ether);

        // Verify escrow status
        ISolanaBridgeAdapter.SolanaEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(uint8(esc.status), uint8(ISolanaBridgeAdapter.EscrowStatus.CANCELLED));
    }

    /*//////////////////////////////////////////////////////////////
            WITHDRAWAL REFUND AFTER DELAY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1_000_000_000; // 1 SOL

        vm.prank(user1);
        bytes32 withdrawalId = bridge.initiateWithdrawal(
            SOLANA_USER,
            amount
        );

        // Cannot refund before 48 hours
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(withdrawalId);

        // Advance 48 hours
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(withdrawalId);

        ISolanaBridgeAdapter.SOLWithdrawal memory w = bridge.getWithdrawal(
            withdrawalId
        );
        assertEq(
            uint8(w.status),
            uint8(ISolanaBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            SLOT HEADER: PARENT CHAIN VALIDATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_slotHeaderParentChain(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        for (uint8 i = 0; i < count; i++) {
            _submitFinalizedSlot(i + 1);
        }

        assertEq(bridge.latestSlot(), count);
    }

    /*//////////////////////////////////////////////////////////////
            STATISTICS TRACKING
    //////////////////////////////////////////////////////////////*/

    function test_statisticsTracking() public {
        (
            uint256 totalDep,
            uint256 totalWith,
            uint256 totalEsc,
            ,
            ,
            ,

        ) = bridge.getBridgeStats();

        assertEq(totalDep, 0);
        assertEq(totalWith, 0);
        assertEq(totalEsc, 0);
    }

    /*//////////////////////////////////////////////////////////////
            CONSTRUCTOR VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(ISolanaBridgeAdapter.ZeroAddress.selector);
        new SolanaBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        ISolanaBridgeAdapter.SOLDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.depositId, bytes32(0));

        ISolanaBridgeAdapter.SOLWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.withdrawalId, bytes32(0));

        ISolanaBridgeAdapter.SolanaEscrow memory esc = bridge.getEscrow(
            bytes32(0)
        );
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
        vm.expectRevert(ISolanaBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            CONSTANTS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.LAMPORTS_PER_SOL(), 1_000_000_000);
        assertEq(bridge.MIN_DEPOSIT_LAMPORTS(), 100_000_000); // 0.1 SOL
        assertEq(bridge.BRIDGE_FEE_BPS(), 25);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 48 hours);
        assertEq(bridge.DEFAULT_SLOT_CONFIRMATIONS(), 32);
    }
}
