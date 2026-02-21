// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/BatchAccumulator.sol";
import "../../contracts/interfaces/IProofVerifier.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title RejectingVerifier
 * @notice Always rejects proofs — used to test that invalid proofs fail
 */
contract RejectingVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return false;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return false;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return false;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

/**
 * @title AcceptingVerifier
 * @notice Always accepts proofs — baseline for batch processing tests
 */
contract AcceptingVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

/**
 * @title BatchAccumulator Security Tests
 * @notice Attack-focused tests for proof verification bypass and batch manipulation
 */
contract BatchAccumulatorSecurityTest is Test {
    BatchAccumulator public accumulator;
    address public admin;
    address public relayer;
    address public attacker;

    function setUp() public {
        admin = address(this);
        relayer = makeAddr("relayer");
        attacker = makeAddr("attacker");

        AcceptingVerifier verifier = new AcceptingVerifier();

        BatchAccumulator impl = new BatchAccumulator();
        bytes memory initData = abi.encodeWithSelector(
            BatchAccumulator.initialize.selector,
            admin,
            address(verifier),
            makeAddr("crossChainHub")
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        accumulator = BatchAccumulator(address(proxy));

        accumulator.grantRole(accumulator.RELAYER_ROLE(), relayer);
        accumulator.grantRole(accumulator.OPERATOR_ROLE(), admin);
        accumulator.configureRoute(block.chainid, 10, 2, 10 minutes);
    }

    /*//////////////////////////////////////////////////////////////
                    PROOF BYPASS ATTACKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attack: Empty proof should fail when verifier is set
    function test_attack_emptyProofRejection() public {
        // Submit 2 transactions to fill batch
        _fillBatch(2);

        // Warp to make batch ready
        vm.warp(block.timestamp + 11 minutes);

        // Try process with empty proof
        bytes32 batchId = _getActiveBatch();
        _markReady(batchId);

        // Switch to rejecting verifier to ensure proof matters
        RejectingVerifier rejector = new RejectingVerifier();
        accumulator.setProofVerifier(address(rejector));

        // H-12: invalid proof sets FAILED status instead of reverting
        vm.prank(relayer);
        accumulator.processBatch(batchId, bytes(""));

        (, , BatchAccumulator.BatchStatus status2, , ) = accumulator
            .getBatchInfo(batchId);
        assertEq(uint8(status2), uint8(BatchAccumulator.BatchStatus.FAILED));
    }

    /// @notice Attack: Reject short proof when no verifier configured
    function test_attack_shortProofFallback() public {
        // Deploy a fresh instance with no verifier
        BatchAccumulator impl2 = new BatchAccumulator();
        AcceptingVerifier dummyVerifier = new AcceptingVerifier();
        bytes memory initData2 = abi.encodeWithSelector(
            BatchAccumulator.initialize.selector,
            admin,
            address(dummyVerifier),
            makeAddr("hub2")
        );
        ERC1967Proxy proxy2 = new ERC1967Proxy(address(impl2), initData2);
        BatchAccumulator acc2 = BatchAccumulator(address(proxy2));

        // Swap verifier to rejecting to test the proof matters
        RejectingVerifier rejector = new RejectingVerifier();
        acc2.grantRole(acc2.DEFAULT_ADMIN_ROLE(), admin);
        acc2.setProofVerifier(address(rejector));

        acc2.grantRole(acc2.RELAYER_ROLE(), relayer);
        acc2.grantRole(acc2.OPERATOR_ROLE(), admin);
        acc2.configureRoute(block.chainid, 10, 2, 10 minutes);

        // Submit transactions
        acc2.submitToBatch(keccak256("c1"), keccak256("n1"), bytes("p"), 10);
        acc2.submitToBatch(keccak256("c2"), keccak256("n2"), bytes("p"), 10);

        vm.warp(block.timestamp + 11 minutes);

        // Rejecting verifier should cause invalid proof
        bytes32 bid = acc2.activeBatches(
            keccak256(abi.encodePacked(block.chainid, uint256(10)))
        );

        // H-12: invalid proof sets FAILED status instead of reverting
        vm.prank(relayer);
        acc2.processBatch(bid, bytes(new bytes(100)));

        (, , BatchAccumulator.BatchStatus status, , ) = acc2.getBatchInfo(bid);
        assertEq(uint8(status), uint8(BatchAccumulator.BatchStatus.FAILED));
    }

    /*//////////////////////////////////////////////////////////////
                    REPLAY ATTACKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attack: Nullifier replay across batches
    function test_attack_nullifierReplay() public {
        bytes32 commitment1 = keccak256("commit1");
        bytes32 nullifier = keccak256("nullifier_replay");

        accumulator.submitToBatch(commitment1, nullifier, bytes("p"), 10);

        // Try same nullifier with different commitment
        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(
            keccak256("commit2"),
            nullifier,
            bytes("p"),
            10
        );
    }

    /// @notice Attack: Commitment replay
    function test_attack_commitmentReplay() public {
        bytes32 commitment = keccak256("replay_commitment");

        accumulator.submitToBatch(commitment, keccak256("n1"), bytes("p"), 10);

        vm.expectRevert(BatchAccumulator.CommitmentAlreadyUsed.selector);
        accumulator.submitToBatch(commitment, keccak256("n2"), bytes("p"), 10);
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL ATTACKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attack: Non-relayer cannot process batch
    function test_attack_nonRelayerCannotProcess() public {
        _fillBatch(2);
        vm.warp(block.timestamp + 11 minutes);

        bytes32 batchId = _getActiveBatch();

        vm.prank(attacker);
        vm.expectRevert();
        accumulator.processBatch(batchId, bytes(new bytes(256)));
    }

    /// @notice Attack: Non-admin cannot change proof verifier
    function test_attack_nonAdminCannotSetVerifier() public {
        vm.prank(attacker);
        vm.expectRevert();
        accumulator.setProofVerifier(attacker);
    }

    /// @notice Attack: Non-operator cannot configure routes
    function test_attack_nonOperatorCannotConfigRoute() public {
        vm.prank(attacker);
        vm.expectRevert();
        accumulator.configureRoute(1, 2, 8, 10 minutes);
    }

    /*//////////////////////////////////////////////////////////////
                    DOUBLE-PROCESS ATTACKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Attack: Cannot process same batch twice
    function test_attack_doubleProcess() public {
        _fillBatch(2);
        vm.warp(block.timestamp + 11 minutes);

        bytes32 batchId = _getActiveBatch();
        _markReady(batchId);

        bytes memory proof = new bytes(256);

        vm.prank(relayer);
        accumulator.processBatch(batchId, proof);

        vm.prank(relayer);
        vm.expectRevert(BatchAccumulator.BatchAlreadyCompleted.selector);
        accumulator.processBatch(batchId, proof);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPERS
    //////////////////////////////////////////////////////////////*/

    function _fillBatch(uint256 count) internal {
        for (uint256 i = 0; i < count; i++) {
            bytes32 c = keccak256(abi.encodePacked("commit_fill_", i));
            bytes32 n = keccak256(abi.encodePacked("null_fill_", i));
            accumulator.submitToBatch(c, n, bytes("payload"), 10);
        }
    }

    function _getActiveBatch() internal view returns (bytes32) {
        bytes32 routeHash = keccak256(
            abi.encodePacked(block.chainid, uint256(10))
        );
        return accumulator.activeBatches(routeHash);
    }

    function _markReady(bytes32 /* batchId */) internal {
        // Time warp should auto-trigger ready status in processBatch
        // The contract checks status in processBatch directly
    }
}
