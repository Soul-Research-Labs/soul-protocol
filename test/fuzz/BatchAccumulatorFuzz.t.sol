// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/BatchAccumulator.sol";
import "../../contracts/interfaces/IProofVerifier.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title MockBatchVerifier
 * @notice Configurable proof verifier for testing BatchAccumulator
 */
contract MockBatchVerifier is IProofVerifier {
    bool public shouldPass;
    uint256 public lastCallPublicInputCount;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function setResult(bool _shouldPass) external {
        shouldPass = _shouldPass;
    }

    function verify(
        bytes calldata,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        // Record for assertion in tests
        return shouldPass;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldPass;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldPass;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 1;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

/**
 * @title BatchAccumulator Fuzz Tests
 * @notice Property-based fuzz tests for batch accumulation and proof verification
 */
contract BatchAccumulatorFuzzTest is Test {
    BatchAccumulator public accumulator;
    MockBatchVerifier public verifier;

    address public admin;
    address public relayer;
    address public user1;

    function setUp() public {
        admin = address(this);
        relayer = makeAddr("relayer");
        user1 = makeAddr("user1");

        verifier = new MockBatchVerifier(true);

        // Deploy implementation + proxy
        BatchAccumulator impl = new BatchAccumulator();
        bytes memory initData = abi.encodeWithSelector(
            BatchAccumulator.initialize.selector,
            admin,
            address(verifier),
            makeAddr("crossChainHub")
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        accumulator = BatchAccumulator(address(proxy));

        // Grant relayer role
        accumulator.grantRole(accumulator.RELAYER_ROLE(), relayer);
        accumulator.grantRole(accumulator.OPERATOR_ROLE(), admin);

        // Configure a default route (source=block.chainid, dest=10)
        accumulator.configureRoute(block.chainid, 10, 2, 10 minutes);
    }

    /*//////////////////////////////////////////////////////////////
                    ROUTE CONFIGURATION FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: Valid route configs always succeed
    function testFuzz_configureRoute_validInputs(
        uint256 srcChain,
        uint256 dstChain,
        uint256 batchSize,
        uint256 waitTime
    ) public {
        vm.assume(srcChain > 0 && srcChain < type(uint64).max);
        vm.assume(dstChain > 0 && dstChain < type(uint64).max);
        batchSize = bound(batchSize, 2, 64);
        waitTime = bound(waitTime, 1 minutes, 1 hours);

        accumulator.configureRoute(srcChain, dstChain, batchSize, waitTime);
    }

    /// @notice Fuzz: Invalid batch sizes always revert
    function testFuzz_configureRoute_invalidBatchSize(
        uint256 batchSize
    ) public {
        vm.assume(batchSize < 2 || batchSize > 64);
        vm.expectRevert(BatchAccumulator.InvalidBatchSize.selector);
        accumulator.configureRoute(1, 2, batchSize, 10 minutes);
    }

    /// @notice Fuzz: Zero chain IDs always revert
    function testFuzz_configureRoute_zeroChainId(uint256 dstChain) public {
        vm.expectRevert(BatchAccumulator.InvalidChainId.selector);
        accumulator.configureRoute(0, dstChain, 8, 10 minutes);
    }

    /*//////////////////////////////////////////////////////////////
                    SUBMISSION FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: Unique commitments always succeed
    function testFuzz_submitToBatch_uniqueCommitments(
        bytes32 commitment,
        bytes32 nullifier
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(nullifier != bytes32(0));

        vm.prank(user1);
        bytes32 batchId = accumulator.submitToBatch(
            commitment,
            nullifier,
            bytes("encrypted_payload"),
            10
        );
        assertTrue(batchId != bytes32(0), "Batch ID should be non-zero");
    }

    /// @notice Fuzz: Duplicate commitments always revert
    function testFuzz_submitToBatch_duplicateCommitment(
        bytes32 commitment,
        bytes32 null1,
        bytes32 null2
    ) public {
        vm.assume(commitment != bytes32(0));
        vm.assume(null1 != bytes32(0));
        vm.assume(null2 != bytes32(0));
        vm.assume(null1 != null2);

        vm.prank(user1);
        accumulator.submitToBatch(commitment, null1, bytes("payload1"), 10);

        vm.prank(user1);
        vm.expectRevert(BatchAccumulator.CommitmentAlreadyUsed.selector);
        accumulator.submitToBatch(commitment, null2, bytes("payload2"), 10);
    }

    /// @notice Fuzz: Duplicate nullifiers always revert
    function testFuzz_submitToBatch_duplicateNullifier(
        bytes32 commit1,
        bytes32 commit2,
        bytes32 nullifier
    ) public {
        vm.assume(commit1 != bytes32(0));
        vm.assume(commit2 != bytes32(0));
        vm.assume(commit1 != commit2);
        vm.assume(nullifier != bytes32(0));

        vm.prank(user1);
        accumulator.submitToBatch(commit1, nullifier, bytes("p1"), 10);

        vm.prank(user1);
        vm.expectRevert(BatchAccumulator.NullifierAlreadyUsed.selector);
        accumulator.submitToBatch(commit2, nullifier, bytes("p2"), 10);
    }

    /*//////////////////////////////////////////////////////////////
                PROOF VERIFIER ADMIN FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Fuzz: Non-zero addresses accepted for proof verifier
    function testFuzz_setProofVerifier_nonZero(address newVerifier) public {
        vm.assume(newVerifier != address(0));
        accumulator.setProofVerifier(newVerifier);
        assertEq(accumulator.proofVerifier(), newVerifier);
    }

    /// @notice Zero address rejected for proof verifier
    function test_setProofVerifier_rejectsZero() public {
        vm.expectRevert(BatchAccumulator.ZeroAddress.selector);
        accumulator.setProofVerifier(address(0));
    }

    /// @notice Fuzz: Non-admin cannot set proof verifier
    function testFuzz_setProofVerifier_accessControl(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        accumulator.setProofVerifier(makeAddr("newVerifier"));
    }

    /*//////////////////////////////////////////////////////////////
                    BATCH COUNTER MONOTONICITY
    //////////////////////////////////////////////////////////////*/

    /// @notice Property: totalBatches never decreases
    function testFuzz_totalBatches_monotonic(uint8 numSubmissions) public {
        numSubmissions = uint8(bound(numSubmissions, 1, 10));
        uint256 prevTotal = accumulator.totalBatches();

        for (uint8 i = 0; i < numSubmissions; i++) {
            bytes32 commitment = keccak256(abi.encodePacked("commit", i));
            bytes32 nullifier = keccak256(abi.encodePacked("null", i));

            vm.prank(user1);
            accumulator.submitToBatch(commitment, nullifier, bytes("p"), 10);

            uint256 newTotal = accumulator.totalBatches();
            assertGe(newTotal, prevTotal, "totalBatches must be monotonic");
            prevTotal = newTotal;
        }
    }
}
