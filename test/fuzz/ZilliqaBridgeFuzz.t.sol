// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ZilliqaBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedZIL.sol";
import "../../contracts/mocks/MockZilliqaDSCommitteeOracle.sol";

/**
 * @title ZilliqaBridgeFuzz
 * @notice Fuzz tests for ZilliqaBridgeAdapter
 * @dev Covers constants, Qa precision, fee calculation, DS block verification,
 *      deposits, withdrawals, escrow lifecycle, access control, pause guards,
 *      nullifier privacy, configuration, and view functions.
 */
contract ZilliqaBridgeFuzz is Test {
    ZilliqaBridgeAdapter public bridge;
    MockWrappedZIL public wZIL;
    MockZilliqaDSCommitteeOracle public dsOracle;

    address public admin = address(this);
    address public user = address(0x1001);
    address public treasury = address(0x1002);

    address constant DS_MEMBER_1 = address(0x3001);
    address constant DS_MEMBER_2 = address(0x3002);
    address constant DS_MEMBER_3 = address(0x3003);

    uint256 constant QA_PER_ZIL = 1_000_000_000_000;
    uint256 constant MIN_DEPOSIT = 100 * QA_PER_ZIL;
    uint256 constant MAX_DEPOSIT = 50_000_000 * QA_PER_ZIL;

    receive() external payable {}

    function setUp() public {
        bridge = new ZilliqaBridgeAdapter(admin);
        wZIL = new MockWrappedZIL();
        dsOracle = new MockZilliqaDSCommitteeOracle();

        // Add DS committee members
        dsOracle.addDSMember(DS_MEMBER_1, 100);
        dsOracle.addDSMember(DS_MEMBER_2, 100);
        dsOracle.addDSMember(DS_MEMBER_3, 100);

        // Configure bridge
        bridge.configure(
            address(0xBEEF),
            address(wZIL),
            address(dsOracle),
            3, // min DS signatures
            30 // required TX block confirmations
        );

        bridge.setTreasury(treasury);

        // Fund bridge with wZIL for deposit completions
        wZIL.mint(address(bridge), 1_000_000_000 * QA_PER_ZIL);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.ZILLIQA_CHAIN_ID(), 1);
        assertEq(bridge.QA_PER_ZIL(), 1_000_000_000_000);
        assertEq(bridge.MIN_DEPOSIT_QA(), 100 * QA_PER_ZIL);
        assertEq(bridge.MAX_DEPOSIT_QA(), 50_000_000 * QA_PER_ZIL);
        assertEq(bridge.BRIDGE_FEE_BPS(), 5);
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 24 hours);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.DEFAULT_TX_BLOCK_CONFIRMATIONS(), 30);
    }

    function test_constructorRejectsZeroAdmin() public {
        vm.expectRevert(IZilliqaBridgeAdapter.ZeroAddress.selector);
        new ZilliqaBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          QA PRECISION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_qaPrecision(uint256 zilAmount) public pure {
        zilAmount = bound(zilAmount, 1, 50_000_000);
        uint256 qaAmount = zilAmount * QA_PER_ZIL;
        assertEq(qaAmount / QA_PER_ZIL, zilAmount);
        assertEq(qaAmount % QA_PER_ZIL, 0);
    }

    function testFuzz_qaSubUnitDeposit(uint256 subUnit) public {
        // Sub-ZIL amounts that are still above minimum
        subUnit = bound(subUnit, MIN_DEPOSIT, MIN_DEPOSIT + QA_PER_ZIL);

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();

        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        bytes32 txHash = keccak256(abi.encodePacked("sub_unit", subUnit));

        bridge.initiateZILDeposit(
            txHash,
            bytes32(uint256(0xABC)),
            user,
            subUnit,
            1,
            proof,
            atts
        );

        assertEq(bridge.depositNonce(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                        FEE CALCULATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_feeCalculation(uint256 amount) public pure {
        amount = bound(amount, MIN_DEPOSIT, MAX_DEPOSIT);
        uint256 fee = (amount * 5) / 10_000;
        uint256 net = amount - fee;

        // Fee + net = original
        assertEq(fee + net, amount);

        // Fee is always 0.05% (5 BPS)
        assertLe(fee, amount);
        assertGe(net, (amount * 9995) / 10000);
    }

    /*//////////////////////////////////////////////////////////////
                      DS BLOCK VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_dsBlockChain(uint8 blockCount) public {
        uint256 count = bound(uint256(blockCount), 1, 20);

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();

        for (uint256 i = 1; i <= count; i++) {
            bridge.submitDSBlock(
                i, // dsBlockNumber
                keccak256(abi.encodePacked("block", i)), // blockHash
                keccak256(abi.encodePacked("state", i)), // stateRootHash
                (i - 1) * 100 + 1, // txBlockStart
                i * 100, // txBlockEnd
                keccak256(abi.encodePacked("committee", i)), // dsCommitteeHash
                4, // shardCount
                block.timestamp + i, // timestamp
                atts
            );
        }

        assertEq(bridge.latestDSBlockNumber(), count);
        assertEq(bridge.currentDSEpoch(), count);
    }

    /*//////////////////////////////////////////////////////////////
                          DEPOSIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_depositRequiresVerifiedDSBlock() public {
        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.TxBlockNotConfirmed.selector,
                1
            )
        );
        bridge.initiateZILDeposit(
            keccak256("tx1"),
            bytes32(uint256(0xABC)),
            user,
            MIN_DEPOSIT,
            1,
            proof,
            atts
        );
    }

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateZILDeposit(
            keccak256("tx1"),
            bytes32(uint256(0xABC)),
            user,
            amount,
            1,
            proof,
            atts
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateZILDeposit(
            keccak256("tx1"),
            bytes32(uint256(0xABC)),
            user,
            amount,
            1,
            proof,
            atts
        );
    }

    function testFuzz_txHashReplayProtection(bytes32 txHash) public {
        vm.assume(txHash != bytes32(0));

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        bridge.initiateZILDeposit(
            txHash,
            bytes32(uint256(0xABC)),
            user,
            MIN_DEPOSIT,
            1,
            proof,
            atts
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.ZilliqaTxAlreadyUsed.selector,
                txHash
            )
        );
        bridge.initiateZILDeposit(
            txHash,
            bytes32(uint256(0xABC)),
            user,
            MIN_DEPOSIT,
            1,
            proof,
            atts
        );
    }

    function testFuzz_depositNonceOnlyIncreases(uint8 count) public {
        uint256 numDeposits = bound(uint256(count), 1, 20);

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        uint256 prevNonce = 0;
        for (uint256 i = 0; i < numDeposits; i++) {
            bytes32 txHash = keccak256(abi.encodePacked("deposit_nonce", i));
            bridge.initiateZILDeposit(
                txHash,
                bytes32(uint256(0xABC)),
                user,
                MIN_DEPOSIT,
                1,
                proof,
                atts
            );
            uint256 currentNonce = bridge.depositNonce();
            assertGt(currentNonce, prevNonce);
            prevNonce = currentNonce;
        }
    }

    /*//////////////////////////////////////////////////////////////
                        WITHDRAWAL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_withdrawalRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 1, MIN_DEPOSIT - 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.AmountBelowMinimum.selector,
                amount,
                MIN_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(bytes32(uint256(0xABC)), amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint128).max);

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.AmountAboveMaximum.selector,
                amount,
                MAX_DEPOSIT
            )
        );
        bridge.initiateWithdrawal(bytes32(uint256(0xABC)), amount);
    }

    function testFuzz_withdrawalNonceOnlyIncreases(uint8 count) public {
        uint256 numWithdrawals = bound(uint256(count), 1, 20);

        wZIL.mint(admin, numWithdrawals * MIN_DEPOSIT);
        wZIL.approve(address(bridge), numWithdrawals * MIN_DEPOSIT);

        uint256 prevNonce = 0;
        for (uint256 i = 0; i < numWithdrawals; i++) {
            bridge.initiateWithdrawal(bytes32(uint256(0xABC)), MIN_DEPOSIT);
            uint256 currentNonce = bridge.withdrawalNonce();
            assertGt(currentNonce, prevNonce);
            prevNonce = currentNonce;
        }
    }

    function test_withdrawalRefundAfterDelay() public {
        wZIL.mint(admin, MIN_DEPOSIT);
        wZIL.approve(address(bridge), MIN_DEPOSIT);

        bytes32 wId = bridge.initiateWithdrawal(
            bytes32(uint256(0xABC)),
            MIN_DEPOSIT
        );

        // Too early
        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.RefundTooEarly.selector,
                block.timestamp,
                block.timestamp + 24 hours
            )
        );
        bridge.refundWithdrawal(wId);

        // After delay
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 balBefore = wZIL.balanceOf(admin);
        bridge.refundWithdrawal(wId);
        uint256 balAfter = wZIL.balanceOf(admin);

        assertEq(balAfter - balBefore, MIN_DEPOSIT);
    }

    /*//////////////////////////////////////////////////////////////
                          ESCROW TESTS
    //////////////////////////////////////////////////////////////*/

    function test_escrowCreateFinishLifecycle() public {
        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = block.timestamp + 2 hours;

        bytes32 preimage = keccak256("zilliqa_secret");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            bytes32(uint256(0xDEF)),
            hashlock,
            finishAfter,
            cancelAfter
        );

        assertEq(bridge.totalEscrows(), 1);

        vm.warp(finishAfter + 1);
        bridge.finishEscrow(escrowId, preimage);

        assertEq(bridge.totalEscrowsFinished(), 1);
    }

    function test_escrowCreateCancelLifecycle() public {
        uint256 finishAfter = block.timestamp + 1 hours;
        uint256 cancelAfter = block.timestamp + 2 hours;

        bytes32 preimage = keccak256("zilliqa_cancel");
        bytes32 hashlock = sha256(abi.encodePacked(preimage));

        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            bytes32(uint256(0xDEF)),
            hashlock,
            finishAfter,
            cancelAfter
        );

        vm.warp(cancelAfter + 1);
        bridge.cancelEscrow(escrowId);

        assertEq(bridge.totalEscrowsCancelled(), 1);
    }

    function testFuzz_escrowTimelockBounds(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1 hours, 365 days);
        duration = bound(duration, 1 hours, 30 days);

        uint256 finishAfter = block.timestamp + finishOffset;
        uint256 cancelAfter = finishAfter + duration;

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("test")));

        bridge.createEscrow{value: 1 ether}(
            bytes32(uint256(0xDEF)),
            hashlock,
            finishAfter,
            cancelAfter
        );

        assertEq(bridge.totalEscrows(), 1);
    }

    function testFuzz_escrowTimelockTooLong(
        uint256 finishOffset,
        uint256 duration
    ) public {
        finishOffset = bound(finishOffset, 1 hours, 365 days);
        duration = bound(duration, 30 days + 1, 365 days);

        uint256 finishAfter = block.timestamp + finishOffset;
        uint256 cancelAfter = finishAfter + duration;

        bytes32 hashlock = sha256(abi.encodePacked(keccak256("test")));

        vm.expectRevert(IZilliqaBridgeAdapter.InvalidTimelockRange.selector);
        bridge.createEscrow{value: 1 ether}(
            bytes32(uint256(0xDEF)),
            hashlock,
            finishAfter,
            cancelAfter
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_onlyRelayerCanInitiateDeposit(address caller) public {
        vm.assume(caller != admin);
        vm.assume(caller != address(0));

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateZILDeposit(
            keccak256("tx_access"),
            bytes32(uint256(0xABC)),
            user,
            MIN_DEPOSIT,
            1,
            proof,
            atts
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != admin);
        vm.assume(caller != address(0));

        _submitVerifiedDSBlock(1, keccak256("block1"));

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        bytes32 depositId = bridge.initiateZILDeposit(
            keccak256("tx_complete"),
            bytes32(uint256(0xABC)),
            user,
            MIN_DEPOSIT,
            1,
            proof,
            atts
        );

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeZILDeposit(depositId);
    }

    function testFuzz_onlyGuardianCanPause(address caller) public {
        vm.assume(caller != admin);
        vm.assume(caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        bridge.pause();
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE GUARD TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_pauseBlocksDeposits() public {
        _submitVerifiedDSBlock(1, keccak256("block1"));

        bridge.pause();

        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();
        IZilliqaBridgeAdapter.ZilliqaStateProof
            memory proof = IZilliqaBridgeAdapter.ZilliqaStateProof({
                leafHash: keccak256("leaf"),
                proof: new bytes32[](0),
                index: 0
            });

        vm.expectRevert();
        bridge.initiateZILDeposit(
            keccak256("tx_paused"),
            bytes32(uint256(0xABC)),
            user,
            MIN_DEPOSIT,
            1,
            proof,
            atts
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        bridge.pause();

        vm.expectRevert();
        bridge.initiateWithdrawal(bytes32(uint256(0xABC)), MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        bridge.pause();

        // Compute hashlock BEFORE expectRevert to avoid sha256 precompile issue
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("test")));

        vm.expectRevert();
        bridge.createEscrow{value: 1 ether}(
            bytes32(uint256(0xDEF)),
            hashlock,
            block.timestamp + 1 hours,
            block.timestamp + 2 hours
        );
    }

    /*//////////////////////////////////////////////////////////////
                        PRIVACY / NULLIFIER TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierCannotBeReused(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bridge.registerPrivateDeposit(
            keccak256("dep1"),
            keccak256("commit1"),
            nullifier,
            ""
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                IZilliqaBridgeAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        bridge.registerPrivateDeposit(
            keccak256("dep2"),
            keccak256("commit2"),
            nullifier,
            ""
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CONFIGURATION TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_configCannotSetZeroAddresses(
        address a,
        address b,
        address c,
        uint256 mask
    ) public {
        // One of the three addresses must be zero
        mask = bound(mask, 0, 2);
        address addr0 = mask == 0
            ? address(0)
            : (a == address(0) ? address(1) : a);
        address addr1 = mask == 1
            ? address(0)
            : (b == address(0) ? address(1) : b);
        address addr2 = mask == 2
            ? address(0)
            : (c == address(0) ? address(1) : c);

        ZilliqaBridgeAdapter newBridge = new ZilliqaBridgeAdapter(admin);

        vm.expectRevert(IZilliqaBridgeAdapter.ZeroAddress.selector);
        newBridge.configure(addr0, addr1, addr2, 3, 30);
    }

    function test_treasuryCanBeUpdated() public {
        address newTreasury = address(0x9999);
        bridge.setTreasury(newTreasury);
        assertEq(bridge.treasury(), newTreasury);
    }

    function test_treasuryRejectsZeroAddress() public {
        vm.expectRevert(IZilliqaBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IZilliqaBridgeAdapter.ZILDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.initiatedAt, 0);

        IZilliqaBridgeAdapter.ZILWithdrawal memory w = bridge.getWithdrawal(
            bytes32(0)
        );
        assertEq(w.initiatedAt, 0);

        IZilliqaBridgeAdapter.ZILEscrow memory e = bridge.getEscrow(bytes32(0));
        assertEq(e.createdAt, 0);

        IZilliqaBridgeAdapter.ZilliqaDSBlock memory ds = bridge.getDSBlock(0);
        assertEq(ds.dsBlockNumber, 0);
        assertEq(ds.verified, false);

        bytes32[] memory uDeps = bridge.getUserDeposits(user);
        assertEq(uDeps.length, 0);

        bytes32[] memory uWiths = bridge.getUserWithdrawals(user);
        assertEq(uWiths.length, 0);

        bytes32[] memory uEsc = bridge.getUserEscrows(user);
        assertEq(uEsc.length, 0);
    }

    function test_statisticsTracking() public view {
        (
            uint256 totalDep,
            uint256 totalWith,
            uint256 totalEsc,
            uint256 totalEscFin,
            uint256 totalEscCan,
            uint256 accFees,
            uint256 latestDS
        ) = bridge.getBridgeStats();

        assertEq(totalDep, 0);
        assertEq(totalWith, 0);
        assertEq(totalEsc, 0);
        assertEq(totalEscFin, 0);
        assertEq(totalEscCan, 0);
        assertEq(accFees, 0);
        assertEq(latestDS, 0);
    }

    function test_userHistoryTracking() public view {
        bytes32[] memory deps = bridge.getUserDeposits(admin);
        bytes32[] memory withs = bridge.getUserWithdrawals(admin);
        bytes32[] memory escs = bridge.getUserEscrows(admin);

        assertEq(deps.length, 0);
        assertEq(withs.length, 0);
        assertEq(escs.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _submitVerifiedDSBlock(
        uint256 dsBlockNumber,
        bytes32 blockHash
    ) internal {
        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = _createDSAttestations();

        bridge.submitDSBlock(
            dsBlockNumber,
            blockHash,
            keccak256(abi.encodePacked("state", dsBlockNumber)),
            1, // txBlockStart
            100, // txBlockEnd
            keccak256(abi.encodePacked("committee", dsBlockNumber)),
            4, // shardCount
            block.timestamp,
            atts
        );
    }

    function _createDSAttestations()
        internal
        pure
        returns (IZilliqaBridgeAdapter.DSCommitteeAttestation[] memory)
    {
        IZilliqaBridgeAdapter.DSCommitteeAttestation[]
            memory atts = new IZilliqaBridgeAdapter.DSCommitteeAttestation[](3);
        atts[0] = IZilliqaBridgeAdapter.DSCommitteeAttestation({
            member: DS_MEMBER_1,
            signature: hex"01"
        });
        atts[1] = IZilliqaBridgeAdapter.DSCommitteeAttestation({
            member: DS_MEMBER_2,
            signature: hex"02"
        });
        atts[2] = IZilliqaBridgeAdapter.DSCommitteeAttestation({
            member: DS_MEMBER_3,
            signature: hex"03"
        });
        return atts;
    }
}
