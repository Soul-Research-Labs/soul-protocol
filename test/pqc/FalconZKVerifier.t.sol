// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {FalconZKVerifier} from "../../contracts/experimental/verifiers/FalconZKVerifier.sol";
import {HybridPQCVerifier, IPQCVerifierLib} from "../../contracts/experimental/verifiers/HybridPQCVerifier.sol";
import {IPQCVerifier} from "../../contracts/interfaces/IPQCVerifier.sol";

/**
 * @title MockNoirVerifier
 * @notice Mock UltraHonk verifier for testing — always returns the configured result
 */
contract MockNoirVerifier {
    bool public shouldSucceed;

    constructor(bool _shouldSucceed) {
        shouldSucceed = _shouldSucceed;
    }

    function setResult(bool _result) external {
        shouldSucceed = _result;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return shouldSucceed;
    }
}

/**
 * @title FalconZKVerifierTest
 * @notice Comprehensive tests for the FalconZKVerifier contract
 * @dev Tests deployment, proof verification, HybridPQCVerifier integration,
 *      batch verification, replay protection, access control, and edge cases
 */
contract FalconZKVerifierTest is Test {
    FalconZKVerifier public falconVerifier;
    HybridPQCVerifier public hybridVerifier;
    MockNoirVerifier public mockNoirVerifier;

    address public admin;
    address public oracle;
    address public user1;
    address public user2;
    address public operator;

    bytes32 constant HYBRID_SIG_DOMAIN =
        keccak256("ZASEON_HYBRID_SIGNATURE_V1");
    bytes32 constant FALCON_ZK_DOMAIN = keccak256("ZASEON_FALCON_ZK_VERIFY_V1");

    // Test fixtures
    bytes32 constant TEST_MSG_HASH =
        0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890;
    bytes32 constant TEST_PK_COMMITMENT =
        0x1111111111111111111111111111111111111111111111111111111111111111;
    bytes32 constant TEST_SIG_COMMITMENT =
        0x2222222222222222222222222222222222222222222222222222222222222222;
    bytes32 constant TEST_VERIFICATION_COMMITMENT =
        0x3333333333333333333333333333333333333333333333333333333333333333;
    bytes32 constant TEST_PQC_SIG_HASH =
        0x4444444444444444444444444444444444444444444444444444444444444444;

    function setUp() public {
        admin = makeAddr("admin");
        oracle = makeAddr("oracle");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        operator = makeAddr("operator");

        vm.startPrank(admin);

        // Deploy HybridPQCVerifier
        hybridVerifier = new HybridPQCVerifier(admin, oracle);

        // Deploy mock Noir verifier (succeeds by default)
        mockNoirVerifier = new MockNoirVerifier(true);

        // Deploy FalconZKVerifier
        falconVerifier = new FalconZKVerifier(
            admin,
            address(hybridVerifier),
            address(mockNoirVerifier)
        );

        // Set FalconZKVerifier as the oracle so it can submit results
        hybridVerifier.setPQCOracle(address(falconVerifier));

        // Grant operator role
        falconVerifier.grantRole(falconVerifier.OPERATOR_ROLE(), operator);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    function test_Deployment() public view {
        assertEq(falconVerifier.hybridPQCVerifier(), address(hybridVerifier));
        assertEq(falconVerifier.noirVerifier(), address(mockNoirVerifier));
        assertTrue(
            falconVerifier.hasRole(falconVerifier.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(
            falconVerifier.hasRole(falconVerifier.OPERATOR_ROLE(), admin)
        );
        assertTrue(falconVerifier.hasRole(falconVerifier.PAUSER_ROLE(), admin));
        assertTrue(
            falconVerifier.hasRole(
                falconVerifier.VERIFIER_UPDATER_ROLE(),
                admin
            )
        );
        assertEq(falconVerifier.totalProofsVerified(), 0);
        assertEq(falconVerifier.successfulProofs(), 0);
        assertEq(falconVerifier.failedProofs(), 0);
    }

    function test_RevertDeployWithZeroAdmin() public {
        vm.expectRevert(FalconZKVerifier.ZeroAddress.selector);
        new FalconZKVerifier(
            address(0),
            address(hybridVerifier),
            address(mockNoirVerifier)
        );
    }

    function test_RevertDeployWithZeroHybridVerifier() public {
        vm.expectRevert(FalconZKVerifier.ZeroAddress.selector);
        new FalconZKVerifier(admin, address(0), address(mockNoirVerifier));
    }

    function test_DeployWithZeroNoirVerifier() public {
        // Should succeed — Noir verifier can be set later
        FalconZKVerifier v = new FalconZKVerifier(
            admin,
            address(hybridVerifier),
            address(0)
        );
        assertEq(v.noirVerifier(), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                      PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_VerifyValidProof() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        (bool valid, bytes32 resultHash) = falconVerifier.verifyFalconProof(
            proof,
            inputs,
            TEST_PQC_SIG_HASH
        );

        assertTrue(valid, "Proof should be valid");
        assertTrue(resultHash != bytes32(0), "Result hash should be non-zero");

        // Verify stats
        assertEq(falconVerifier.totalProofsVerified(), 1);
        assertEq(falconVerifier.successfulProofs(), 1);
        assertEq(falconVerifier.failedProofs(), 0);
    }

    function test_VerifyValidProofRegistersInHybridVerifier() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        (, bytes32 resultHash) = falconVerifier.verifyFalconProof(
            proof,
            inputs,
            TEST_PQC_SIG_HASH
        );

        // The result should be registered in HybridPQCVerifier
        assertTrue(
            hybridVerifier.approvedPQCResults(resultHash),
            "Result should be approved in HybridPQCVerifier"
        );
    }

    function test_VerifyFailedProof() public {
        // Configure mock to reject proofs
        mockNoirVerifier.setResult(false);

        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        (bool valid, bytes32 resultHash) = falconVerifier.verifyFalconProof(
            proof,
            inputs,
            TEST_PQC_SIG_HASH
        );

        assertFalse(valid, "Proof should be invalid");
        assertEq(resultHash, bytes32(0), "Result hash should be zero");
        assertEq(falconVerifier.failedProofs(), 1);
        assertEq(falconVerifier.successfulProofs(), 0);
    }

    function test_ResultHashMatchesHybridVerifierFormat() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();

        // Compute expected result hash (matching HybridPQCVerifier._verifyPQCViaZKProof format)
        bytes32 expectedHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                "ZK_VERIFIED",
                inputs.messageHash,
                TEST_PQC_SIG_HASH,
                inputs.signerAddress,
                IPQCVerifier.PQCAlgorithm.FN_DSA_512
            )
        );

        // Verify via the view function
        bytes32 computedHash = falconVerifier.computeResultHash(
            inputs.messageHash,
            TEST_PQC_SIG_HASH,
            inputs.signerAddress
        );

        assertEq(computedHash, expectedHash, "Result hash format mismatch");

        // Also verify through actual proof submission
        (, bytes32 resultHash) = falconVerifier.verifyFalconProof(
            _mockProof(),
            inputs,
            TEST_PQC_SIG_HASH
        );

        assertEq(resultHash, expectedHash, "Submitted result hash mismatch");
    }

    /*//////////////////////////////////////////////////////////////
                      REPLAY PROTECTION
    //////////////////////////////////////////////////////////////*/

    function test_RevertOnReplayedProof() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        // First submission succeeds
        falconVerifier.verifyFalconProof(proof, inputs, TEST_PQC_SIG_HASH);

        // Same proof should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                FalconZKVerifier.ProofAlreadyUsed.selector,
                _computeProofHash(proof, inputs)
            )
        );
        falconVerifier.verifyFalconProof(proof, inputs, TEST_PQC_SIG_HASH);
    }

    function test_DifferentProofsForSameMessageSucceed() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();

        // Different proof bytes → different proof hash
        bytes memory proof1 = abi.encodePacked(uint256(1));
        bytes memory proof2 = abi.encodePacked(uint256(2));

        (bool valid1, ) = falconVerifier.verifyFalconProof(
            proof1,
            inputs,
            TEST_PQC_SIG_HASH
        );
        assertTrue(valid1);

        (bool valid2, ) = falconVerifier.verifyFalconProof(
            proof2,
            inputs,
            TEST_PQC_SIG_HASH
        );
        assertTrue(valid2);

        assertEq(falconVerifier.totalProofsVerified(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        CHAIN ID VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_RevertOnChainIdMismatch() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        inputs.chainId = 999; // Wrong chain ID

        vm.expectRevert(
            abi.encodeWithSelector(
                FalconZKVerifier.ChainIdMismatch.selector,
                block.chainid,
                999
            )
        );
        falconVerifier.verifyFalconProof(
            _mockProof(),
            inputs,
            TEST_PQC_SIG_HASH
        );
    }

    /*//////////////////////////////////////////////////////////////
                      INPUT VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_RevertOnZeroSignerAddress() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        inputs.signerAddress = address(0);

        vm.expectRevert(FalconZKVerifier.InvalidPublicInputs.selector);
        falconVerifier.verifyFalconProof(
            _mockProof(),
            inputs,
            TEST_PQC_SIG_HASH
        );
    }

    function test_RevertWhenNoirVerifierNotSet() public {
        // Deploy without noir verifier
        vm.prank(admin);
        FalconZKVerifier plain = new FalconZKVerifier(
            admin,
            address(hybridVerifier),
            address(0)
        );

        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();

        vm.expectRevert(FalconZKVerifier.NoirVerifierNotSet.selector);
        plain.verifyFalconProof(_mockProof(), inputs, TEST_PQC_SIG_HASH);
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_BatchVerifyMultipleProofs() public {
        uint256 batchSize = 4;
        bytes[] memory proofs = new bytes[](batchSize);
        FalconZKVerifier.FalconProofPublicInputs[]
            memory inputsArray = new FalconZKVerifier.FalconProofPublicInputs[](
                batchSize
            );
        bytes32[] memory sigHashes = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            proofs[i] = abi.encodePacked(uint256(100 + i));
            inputsArray[i] = _defaultInputs();
            inputsArray[i].signerAddress = address(uint160(1000 + i));
            sigHashes[i] = bytes32(uint256(5000 + i));
        }

        bool[] memory results = falconVerifier.batchVerifyFalconProofs(
            proofs,
            inputsArray,
            sigHashes
        );

        assertEq(results.length, batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            assertTrue(results[i], "Each proof should pass");
        }

        assertEq(falconVerifier.totalProofsVerified(), batchSize);
        assertEq(falconVerifier.successfulProofs(), batchSize);
    }

    function test_BatchSkipsInvalidChainId() public {
        bytes[] memory proofs = new bytes[](2);
        FalconZKVerifier.FalconProofPublicInputs[]
            memory inputsArray = new FalconZKVerifier.FalconProofPublicInputs[](
                2
            );
        bytes32[] memory sigHashes = new bytes32[](2);

        // Valid proof
        proofs[0] = abi.encodePacked(uint256(200));
        inputsArray[0] = _defaultInputs();
        sigHashes[0] = TEST_PQC_SIG_HASH;

        // Invalid chain ID
        proofs[1] = abi.encodePacked(uint256(201));
        inputsArray[1] = _defaultInputs();
        inputsArray[1].chainId = 999;
        sigHashes[1] = bytes32(uint256(6000));

        bool[] memory results = falconVerifier.batchVerifyFalconProofs(
            proofs,
            inputsArray,
            sigHashes
        );

        assertTrue(results[0], "First proof should pass");
        assertFalse(results[1], "Second proof should fail (wrong chain ID)");
    }

    function test_BatchRevertOnArrayLengthMismatch() public {
        bytes[] memory proofs = new bytes[](2);
        FalconZKVerifier.FalconProofPublicInputs[]
            memory inputsArray = new FalconZKVerifier.FalconProofPublicInputs[](
                3
            );
        bytes32[] memory sigHashes = new bytes32[](2);

        vm.expectRevert("Array length mismatch");
        falconVerifier.batchVerifyFalconProofs(proofs, inputsArray, sigHashes);
    }

    function test_BatchRevertOnTooLargeBatch() public {
        bytes[] memory proofs = new bytes[](17);
        FalconZKVerifier.FalconProofPublicInputs[]
            memory inputsArray = new FalconZKVerifier.FalconProofPublicInputs[](
                17
            );
        bytes32[] memory sigHashes = new bytes32[](17);

        vm.expectRevert("Invalid batch size");
        falconVerifier.batchVerifyFalconProofs(proofs, inputsArray, sigHashes);
    }

    /*//////////////////////////////////////////////////////////////
                        STATISTICS
    //////////////////////////////////////////////////////////////*/

    function test_GetStats() public {
        // Submit 3 successful and 1 failed
        for (uint256 i = 0; i < 3; i++) {
            FalconZKVerifier.FalconProofPublicInputs
                memory inputs = _defaultInputs();
            inputs.signerAddress = address(uint160(2000 + i));
            falconVerifier.verifyFalconProof(
                abi.encodePacked(uint256(300 + i)),
                inputs,
                bytes32(uint256(7000 + i))
            );
        }

        // Make one fail
        mockNoirVerifier.setResult(false);
        FalconZKVerifier.FalconProofPublicInputs
            memory failInputs = _defaultInputs();
        failInputs.signerAddress = address(uint160(3000));
        falconVerifier.verifyFalconProof(
            abi.encodePacked(uint256(400)),
            failInputs,
            bytes32(uint256(8000))
        );

        (
            uint256 total,
            uint256 successful,
            uint256 failed,
            uint256 successRate
        ) = falconVerifier.getStats();

        assertEq(total, 4);
        assertEq(successful, 3);
        assertEq(failed, 1);
        assertEq(successRate, 7500); // 75% in basis points
    }

    /*//////////////////////////////////////////////////////////////
                       ACCESS CONTROL
    //////////////////////////////////////////////////////////////*/

    function test_AdminCanSetHybridVerifier() public {
        address newVerifier = makeAddr("newVerifier");

        vm.prank(admin);
        falconVerifier.setHybridPQCVerifier(newVerifier);

        assertEq(falconVerifier.hybridPQCVerifier(), newVerifier);
    }

    function test_NonAdminCannotSetHybridVerifier() public {
        vm.prank(user1);
        vm.expectRevert();
        falconVerifier.setHybridPQCVerifier(makeAddr("newVerifier"));
    }

    function test_AdminCanSetNoirVerifier() public {
        address newVerifier = makeAddr("newNoirVerifier");

        vm.prank(admin);
        falconVerifier.setNoirVerifier(newVerifier);

        assertEq(falconVerifier.noirVerifier(), newVerifier);
    }

    function test_NonAdminCannotSetNoirVerifier() public {
        vm.prank(user1);
        vm.expectRevert();
        falconVerifier.setNoirVerifier(makeAddr("newNoirVerifier"));
    }

    function test_RevertSetHybridVerifierZero() public {
        vm.prank(admin);
        vm.expectRevert(FalconZKVerifier.ZeroAddress.selector);
        falconVerifier.setHybridPQCVerifier(address(0));
    }

    function test_RevertSetNoirVerifierZero() public {
        vm.prank(admin);
        vm.expectRevert(FalconZKVerifier.ZeroAddress.selector);
        falconVerifier.setNoirVerifier(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                         PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_PauserCanPause() public {
        vm.prank(admin);
        falconVerifier.pause();

        assertTrue(falconVerifier.paused());
    }

    function test_VerificationRevertsWhenPaused() public {
        vm.prank(admin);
        falconVerifier.pause();

        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();

        vm.expectRevert();
        falconVerifier.verifyFalconProof(
            _mockProof(),
            inputs,
            TEST_PQC_SIG_HASH
        );
    }

    function test_AdminCanUnpause() public {
        vm.prank(admin);
        falconVerifier.pause();

        vm.prank(admin);
        falconVerifier.unpause();

        assertFalse(falconVerifier.paused());
    }

    function test_BatchRevertsWhenPaused() public {
        vm.prank(admin);
        falconVerifier.pause();

        bytes[] memory proofs = new bytes[](1);
        FalconZKVerifier.FalconProofPublicInputs[]
            memory inputsArray = new FalconZKVerifier.FalconProofPublicInputs[](
                1
            );
        bytes32[] memory sigHashes = new bytes32[](1);

        proofs[0] = _mockProof();
        inputsArray[0] = _defaultInputs();
        sigHashes[0] = TEST_PQC_SIG_HASH;

        vm.expectRevert();
        falconVerifier.batchVerifyFalconProofs(proofs, inputsArray, sigHashes);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_IsProofUsed() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        bytes32 proofHash = _computeProofHash(proof, inputs);

        assertFalse(falconVerifier.isProofUsed(proofHash));

        falconVerifier.verifyFalconProof(proof, inputs, TEST_PQC_SIG_HASH);

        assertTrue(falconVerifier.isProofUsed(proofHash));
    }

    function test_ComputeResultHash() public view {
        bytes32 expected = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                "ZK_VERIFIED",
                TEST_MSG_HASH,
                TEST_PQC_SIG_HASH,
                user1,
                IPQCVerifier.PQCAlgorithm.FN_DSA_512
            )
        );

        bytes32 computed = falconVerifier.computeResultHash(
            TEST_MSG_HASH,
            TEST_PQC_SIG_HASH,
            user1
        );

        assertEq(computed, expected);
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_VerifyWithDifferentSigners(address signer) public {
        vm.assume(signer != address(0));

        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        inputs.signerAddress = signer;

        bytes memory proof = abi.encodePacked(uint256(uint160(signer)));

        (bool valid, bytes32 resultHash) = falconVerifier.verifyFalconProof(
            proof,
            inputs,
            TEST_PQC_SIG_HASH
        );

        assertTrue(valid);
        assertTrue(resultHash != bytes32(0));
    }

    function testFuzz_VerifyWithDifferentMessages(bytes32 msgHash) public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        inputs.messageHash = msgHash;

        bytes memory proof = abi.encodePacked(msgHash);

        (bool valid, ) = falconVerifier.verifyFalconProof(
            proof,
            inputs,
            TEST_PQC_SIG_HASH
        );

        assertTrue(valid);
    }

    function testFuzz_ComputeResultHashDeterministic(
        bytes32 msgHash,
        bytes32 sigHash,
        address signer
    ) public view {
        bytes32 h1 = falconVerifier.computeResultHash(msgHash, sigHash, signer);
        bytes32 h2 = falconVerifier.computeResultHash(msgHash, sigHash, signer);
        assertEq(h1, h2);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTANTS
    //////////////////////////////////////////////////////////////*/

    function test_Constants() public view {
        assertEq(
            falconVerifier.HYBRID_SIG_DOMAIN(),
            keccak256("ZASEON_HYBRID_SIGNATURE_V1")
        );
        assertEq(
            falconVerifier.FALCON_ZK_DOMAIN(),
            keccak256("ZASEON_FALCON_ZK_VERIFY_V1")
        );
        assertEq(
            uint8(falconVerifier.FALCON_ALGORITHM()),
            uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
        );
        assertEq(falconVerifier.NUM_PUBLIC_INPUTS(), 6);
    }

    /*//////////////////////////////////////////////////////////////
                          EVENTS
    //////////////////////////////////////////////////////////////*/

    function test_EmitFalconProofVerified() public {
        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        bytes32 expectedResultHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                "ZK_VERIFIED",
                inputs.messageHash,
                TEST_PQC_SIG_HASH,
                inputs.signerAddress,
                IPQCVerifier.PQCAlgorithm.FN_DSA_512
            )
        );

        vm.expectEmit(true, true, false, true);
        emit FalconZKVerifier.FalconProofVerified(
            inputs.messageHash,
            inputs.signerAddress,
            inputs.pkCommitment,
            inputs.sigCommitment,
            expectedResultHash,
            true
        );

        falconVerifier.verifyFalconProof(proof, inputs, TEST_PQC_SIG_HASH);
    }

    function test_EmitFalconProofRejected() public {
        mockNoirVerifier.setResult(false);

        FalconZKVerifier.FalconProofPublicInputs
            memory inputs = _defaultInputs();
        bytes memory proof = _mockProof();

        vm.expectEmit(true, true, false, true);
        emit FalconZKVerifier.FalconProofRejected(
            inputs.messageHash,
            inputs.signerAddress,
            "Noir proof verification failed"
        );

        falconVerifier.verifyFalconProof(proof, inputs, TEST_PQC_SIG_HASH);
    }

    /*//////////////////////////////////////////////////////////////
                        HELPERS
    //////////////////////////////////////////////////////////////*/

    function _defaultInputs()
        internal
        view
        returns (FalconZKVerifier.FalconProofPublicInputs memory)
    {
        return
            FalconZKVerifier.FalconProofPublicInputs({
                messageHash: TEST_MSG_HASH,
                pkCommitment: TEST_PK_COMMITMENT,
                sigCommitment: TEST_SIG_COMMITMENT,
                signerAddress: user1,
                chainId: block.chainid,
                verificationCommitment: TEST_VERIFICATION_COMMITMENT
            });
    }

    function _mockProof() internal pure returns (bytes memory) {
        return abi.encodePacked(uint256(42), uint256(43), uint256(44));
    }

    function _computeProofHash(
        bytes memory proof,
        FalconZKVerifier.FalconProofPublicInputs memory inputs
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    FALCON_ZK_DOMAIN,
                    proof,
                    inputs.messageHash,
                    inputs.pkCommitment,
                    inputs.sigCommitment,
                    inputs.signerAddress,
                    inputs.chainId,
                    inputs.verificationCommitment
                )
            );
    }
}
