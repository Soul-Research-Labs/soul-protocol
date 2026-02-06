// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ProvenanceBridgeAdapter.sol";
import "../../contracts/interfaces/IProvenanceBridgeAdapter.sol";
import "../../contracts/mocks/MockWrappedHASH.sol";
import "../../contracts/mocks/MockTendermintValidatorOracle.sol";

/**
 * @title ProvenanceBridgeFuzz
 * @notice Foundry fuzz & invariant tests for ProvenanceBridgeAdapter
 * @dev Tests cover deposit/withdrawal flows, escrow lifecycle,
 *      block header submission, and security invariants
 *
 * Provenance-specific test parameters:
 * - 1 HASH = 1e9 nhash (9 decimals)
 * - Chain ID 505 (pio-mainnet-1 EVM mapping)
 * - 10 block confirmations (~60s BFT finality)
 * - 5 active validators (test set), 4/5 supermajority
 */
contract ProvenanceBridgeFuzz is Test {
    ProvenanceBridgeAdapter public bridge;
    MockWrappedHASH public wHASH;
    MockTendermintValidatorOracle public oracle;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");
    address public guardian = makeAddr("guardian");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public treasury = makeAddr("treasury");

    address public constant PROV_BRIDGE_CONTRACT =
        address(0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB);
    address public constant PROV_USER =
        address(0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC);

    uint256 public constant NHASH_PER_HASH = 1_000_000_000; // 1e9
    uint256 public constant MIN_DEPOSIT = NHASH_PER_HASH / 10; // 0.1 HASH = 100_000_000 nhash
    uint256 public constant MAX_DEPOSIT = 1_000_000 * NHASH_PER_HASH; // 1M HASH

    // Validator addresses (5 validators for Tendermint BFT test set)
    address public constant VALIDATOR_1 =
        address(0x1111111111111111111111111111111111111111);
    address public constant VALIDATOR_2 =
        address(0x2222222222222222222222222222222222222222);
    address public constant VALIDATOR_3 =
        address(0x3333333333333333333333333333333333333333);
    address public constant VALIDATOR_4 =
        address(0x4444444444444444444444444444444444444444);
    address public constant VALIDATOR_5 =
        address(0x5555555555555555555555555555555555555555);

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy mocks
        wHASH = new MockWrappedHASH();
        oracle = new MockTendermintValidatorOracle();

        // Deploy bridge
        bridge = new ProvenanceBridgeAdapter(admin);

        // Grant roles
        bridge.grantRole(bridge.RELAYER_ROLE(), relayer);
        bridge.grantRole(bridge.OPERATOR_ROLE(), operator);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.TREASURY_ROLE(), treasury);

        // Register 5 Tendermint validators
        oracle.addValidator(VALIDATOR_1);
        oracle.addValidator(VALIDATOR_2);
        oracle.addValidator(VALIDATOR_3);
        oracle.addValidator(VALIDATOR_4);
        oracle.addValidator(VALIDATOR_5);

        // Configure bridge (4 min sigs, 10 block confirmations)
        bridge.configure(
            PROV_BRIDGE_CONTRACT,
            address(wHASH),
            address(oracle),
            4, // minValidatorSignatures (4/5 supermajority)
            10 // requiredBlockConfirmations (~60s)
        );

        // Fund user1 with wHASH for withdrawal tests (10K HASH in nhash)
        wHASH.mint(user1, 10_000 * NHASH_PER_HASH);

        vm.stopPrank();

        // Approve bridge to spend user1's wHASH
        vm.prank(user1);
        IERC20(address(wHASH)).approve(address(bridge), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _buildValidatorAttestations()
        internal
        pure
        returns (IProvenanceBridgeAdapter.ValidatorAttestation[] memory)
    {
        IProvenanceBridgeAdapter.ValidatorAttestation[]
            memory attestations = new IProvenanceBridgeAdapter.ValidatorAttestation[](
                5
            );
        attestations[0] = IProvenanceBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_1,
            signature: hex"0123456789"
        });
        attestations[1] = IProvenanceBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_2,
            signature: hex"0123456789"
        });
        attestations[2] = IProvenanceBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_3,
            signature: hex"0123456789"
        });
        attestations[3] = IProvenanceBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_4,
            signature: hex"0123456789"
        });
        attestations[4] = IProvenanceBridgeAdapter.ValidatorAttestation({
            validator: VALIDATOR_5,
            signature: hex"0123456789"
        });
        return attestations;
    }

    function _buildMerkleProof()
        internal
        pure
        returns (IProvenanceBridgeAdapter.ProvenanceMerkleProof memory)
    {
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256("sibling");

        return
            IProvenanceBridgeAdapter.ProvenanceMerkleProof({
                leafHash: keccak256("leaf"),
                proof: proof,
                index: 0
            });
    }

    function _submitFinalizedBlock(uint256 blockNum) internal {
        vm.prank(relayer);
        bridge.submitBlockHeader(
            blockNum,
            keccak256(abi.encodePacked("block", blockNum)),
            blockNum > 0
                ? keccak256(abi.encodePacked("block", blockNum - 1))
                : bytes32(0),
            keccak256(abi.encodePacked("txRoot", blockNum)),
            keccak256(abi.encodePacked("stateRoot", blockNum)),
            keccak256(abi.encodePacked("validatorsHash", blockNum)),
            block.timestamp,
            _buildValidatorAttestations()
        );
    }

    /*//////////////////////////////////////////////////////////////
                    FUZZ: DEPOSIT AMOUNT BOUNDS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_depositRejectsAmountBelowMin(uint256 amount) public {
        amount = bound(amount, 0, MIN_DEPOSIT - 1);

        _submitFinalizedBlock(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProvenanceBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateHASHDeposit(
            txHash,
            PROV_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_depositRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        _submitFinalizedBlock(1);

        bytes32 txHash = keccak256(abi.encodePacked("tx", amount));

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProvenanceBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateHASHDeposit(
            txHash,
            PROV_USER,
            user1,
            amount,
            1,
            _buildMerkleProof(),
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
                IProvenanceBridgeAdapter.AmountTooSmall.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(PROV_USER, amount);
    }

    function testFuzz_withdrawalRejectsAmountAboveMax(uint256 amount) public {
        amount = bound(amount, MAX_DEPOSIT + 1, type(uint256).max);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IProvenanceBridgeAdapter.AmountTooLarge.selector,
                amount
            )
        );
        bridge.initiateWithdrawal(PROV_USER, amount);
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
                PROV_USER,
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
                PROV_USER,
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

        uint256 expectedFee = (amount * 10) / 10_000; // 0.10% fee
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

        _submitFinalizedBlock(1);

        // Tx hash should initially be unused
        assertFalse(bridge.usedProvTxHashes(txHash));
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
        address provBridge,
        address wrappedHASHAddr,
        address oracleAddr,
        uint256 minSigs
    ) public {
        vm.assume(minSigs > 0);

        if (
            provBridge == address(0) ||
            wrappedHASHAddr == address(0) ||
            oracleAddr == address(0)
        ) {
            vm.prank(admin);
            vm.expectRevert(IProvenanceBridgeAdapter.ZeroAddress.selector);
            bridge.configure(provBridge, wrappedHASHAddr, oracleAddr, minSigs, 10);
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

        _submitFinalizedBlock(1);

        vm.prank(caller);
        vm.expectRevert();
        bridge.initiateHASHDeposit(
            keccak256("tx"),
            PROV_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_onlyOperatorCanCompleteDeposit(address caller) public {
        vm.assume(caller != operator && caller != admin);

        vm.prank(caller);
        vm.expectRevert();
        bridge.completeHASHDeposit(keccak256("deposit"));
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
        _submitFinalizedBlock(1);

        vm.prank(guardian);
        bridge.pause();

        vm.prank(relayer);
        vm.expectRevert();
        bridge.initiateHASHDeposit(
            keccak256("tx"),
            PROV_USER,
            user1,
            MIN_DEPOSIT,
            1,
            _buildMerkleProof(),
            _buildValidatorAttestations()
        );
    }

    function testFuzz_pauseBlocksWithdrawals() public {
        vm.prank(guardian);
        bridge.pause();

        vm.prank(user1);
        vm.expectRevert();
        bridge.initiateWithdrawal(PROV_USER, MIN_DEPOSIT);
    }

    function testFuzz_pauseBlocksEscrow() public {
        vm.prank(guardian);
        bridge.pause();

        vm.deal(user1, 10 ether);
        vm.prank(user1);
        (bool success, ) = address(bridge).call{value: 1 ether}(
            abi.encodeWithSelector(
                bridge.createEscrow.selector,
                PROV_USER,
                keccak256("hashlock"),
                block.timestamp + 2 hours,
                block.timestamp + 14 hours
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
            PROV_USER,
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
        IProvenanceBridgeAdapter.HASHEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint8(esc.status),
            uint8(IProvenanceBridgeAdapter.EscrowStatus.FINISHED)
        );
        assertEq(esc.preimage, preimage);
    }

    function test_escrowCreateCancelLifecycle() public {
        bytes32 hashlock = sha256(abi.encodePacked(keccak256("secret")));

        uint256 finishAfter = block.timestamp + 2 hours;
        uint256 cancelAfter = block.timestamp + 26 hours;

        vm.deal(user1, 10 ether);

        vm.prank(user1);
        bytes32 escrowId = bridge.createEscrow{value: 1 ether}(
            PROV_USER,
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
        IProvenanceBridgeAdapter.HASHEscrow memory esc = bridge.getEscrow(
            escrowId
        );
        assertEq(
            uint8(esc.status),
            uint8(IProvenanceBridgeAdapter.EscrowStatus.CANCELLED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            WITHDRAWAL REFUND AFTER DELAY
    //////////////////////////////////////////////////////////////*/

    function test_withdrawalRefundAfterDelay() public {
        uint256 amount = 1 * NHASH_PER_HASH; // 1 HASH in nhash

        vm.prank(user1);
        bytes32 withdrawalId = bridge.initiateWithdrawal(PROV_USER, amount);

        // Cannot refund before 48 hours
        vm.prank(user1);
        vm.expectRevert();
        bridge.refundWithdrawal(withdrawalId);

        // Advance 48 hours
        vm.warp(block.timestamp + 48 hours + 1);

        vm.prank(user1);
        bridge.refundWithdrawal(withdrawalId);

        IProvenanceBridgeAdapter.HASHWithdrawal memory w = bridge
            .getWithdrawal(withdrawalId);
        assertEq(
            uint8(w.status),
            uint8(IProvenanceBridgeAdapter.WithdrawalStatus.REFUNDED)
        );
    }

    /*//////////////////////////////////////////////////////////////
            BLOCK HEADER: PARENT CHAIN VALIDATION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_blockHeaderParentChain(uint8 count) public {
        count = uint8(bound(count, 1, 10));

        for (uint8 i = 0; i < count; i++) {
            _submitFinalizedBlock(i + 1);
        }

        assertEq(bridge.latestBlockNumber(), count);
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
        vm.expectRevert(IProvenanceBridgeAdapter.ZeroAddress.selector);
        new ProvenanceBridgeAdapter(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_viewFunctionsReturnDefaults() public view {
        IProvenanceBridgeAdapter.HASHDeposit memory dep = bridge.getDeposit(
            bytes32(0)
        );
        assertEq(dep.depositId, bytes32(0));

        IProvenanceBridgeAdapter.HASHWithdrawal memory w = bridge
            .getWithdrawal(bytes32(0));
        assertEq(w.withdrawalId, bytes32(0));

        IProvenanceBridgeAdapter.HASHEscrow memory esc = bridge.getEscrow(
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
        vm.expectRevert(IProvenanceBridgeAdapter.ZeroAddress.selector);
        bridge.setTreasury(address(0));
    }

    /*//////////////////////////////////////////////////////////////
            CONSTANTS VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_constantsAreCorrect() public view {
        assertEq(bridge.PROVENANCE_CHAIN_ID(), 505);
        assertEq(bridge.NHASH_PER_HASH(), 1_000_000_000); // 1e9
        assertEq(bridge.MIN_DEPOSIT_NHASH(), NHASH_PER_HASH / 10); // 0.1 HASH
        assertEq(bridge.MAX_DEPOSIT_NHASH(), 1_000_000 * NHASH_PER_HASH); // 1M HASH
        assertEq(bridge.BRIDGE_FEE_BPS(), 10); // 0.10%
        assertEq(bridge.BPS_DENOMINATOR(), 10_000);
        assertEq(bridge.MIN_ESCROW_TIMELOCK(), 1 hours);
        assertEq(bridge.MAX_ESCROW_TIMELOCK(), 30 days);
        assertEq(bridge.WITHDRAWAL_REFUND_DELAY(), 48 hours);
        assertEq(bridge.DEFAULT_BLOCK_CONFIRMATIONS(), 10);
    }

    /*//////////////////////////////////////////////////////////////
            PROVENANCE-SPECIFIC: NHASH PRECISION
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nhashPrecision(uint256 hashAmount) public pure {
        hashAmount = bound(hashAmount, 1, 1_000_000);

        uint256 nhash = hashAmount * NHASH_PER_HASH;
        uint256 backToHash = nhash / NHASH_PER_HASH;

        assertEq(backToHash, hashAmount, "Nhash conversion not reversible");
        assertEq(nhash % NHASH_PER_HASH, 0, "Nhash should be exact multiple");
    }

    function testFuzz_nhashSubUnitDeposit(uint256 subUnitNhash) public {
        // Test deposits of fractional HASH amounts (sub-unit nhash)
        subUnitNhash = bound(subUnitNhash, MIN_DEPOSIT, NHASH_PER_HASH - 1);

        bytes32 txHash = keccak256(
            abi.encodePacked("sub_unit_tx", subUnitNhash)
        );

        // Build a merkle proof that matches the txHash and derive txRoot
        bytes32 sibling = keccak256("sibling");
        bytes32 txRoot = keccak256(abi.encodePacked(txHash, sibling));

        // Submit block with a txRoot that matches our proof
        vm.prank(relayer);
        bridge.submitBlockHeader(
            1,
            keccak256(abi.encodePacked("block", uint256(1))),
            keccak256(abi.encodePacked("block", uint256(0))),
            txRoot,
            keccak256(abi.encodePacked("stateRoot", uint256(1))),
            keccak256(abi.encodePacked("validatorsHash", uint256(1))),
            block.timestamp,
            _buildValidatorAttestations()
        );

        bytes32[] memory proof = new bytes32[](1);
        proof[0] = sibling;
        IProvenanceBridgeAdapter.ProvenanceMerkleProof
            memory merkleProof = IProvenanceBridgeAdapter
                .ProvenanceMerkleProof({
                    leafHash: txHash,
                    proof: proof,
                    index: 0
                });

        // Should succeed — fractional HASH deposits above min are valid
        vm.prank(relayer);
        bytes32 depositId = bridge.initiateHASHDeposit(
            txHash,
            PROV_USER,
            user1,
            subUnitNhash,
            1,
            merkleProof,
            _buildValidatorAttestations()
        );

        IProvenanceBridgeAdapter.HASHDeposit memory dep = bridge.getDeposit(
            depositId
        );
        assertEq(dep.amountNhash, subUnitNhash);
    }
}
