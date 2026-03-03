// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PQCBridgeAttestation} from "../../contracts/experimental/privacy/PQCBridgeAttestation.sol";
import {IPQCVerifier} from "../../contracts/interfaces/IPQCVerifier.sol";

/**
 * @title PQCBridgeAttestationTest
 * @notice Tests for PQC bridge message attestation layer
 */
contract PQCBridgeAttestationTest is Test {
    PQCBridgeAttestation public attestation;

    address public admin;
    address public attestor1;
    address public attestor2;
    address public attestor3;
    address public nonAttestor;

    uint256 constant QUORUM = 2;

    function setUp() public {
        admin = makeAddr("admin");
        attestor1 = makeAddr("attestor1");
        attestor2 = makeAddr("attestor2");
        attestor3 = makeAddr("attestor3");
        nonAttestor = makeAddr("nonAttestor");

        vm.startPrank(admin);
        attestation = new PQCBridgeAttestation(admin, address(0x1234), QUORUM);

        // Register attestors
        attestation.registerAttestor(
            attestor1,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            keccak256("attestor1_pk")
        );
        attestation.registerAttestor(
            attestor2,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            keccak256("attestor2_pk")
        );
        attestation.registerAttestor(
            attestor3,
            IPQCVerifier.PQCAlgorithm.ML_DSA_44,
            keccak256("attestor3_pk")
        );
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                           DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    function test_Deployment() public view {
        assertTrue(
            attestation.hasRole(attestation.DEFAULT_ADMIN_ROLE(), admin)
        );
        assertTrue(attestation.hasRole(attestation.OPERATOR_ROLE(), admin));
        assertTrue(attestation.hasRole(attestation.ATTESTOR_ROLE(), admin));
        assertTrue(attestation.hasRole(attestation.PAUSER_ROLE(), admin));
        assertEq(attestation.hybridPQCVerifier(), address(0x1234));
        assertEq(attestation.quorumThreshold(), QUORUM);
        assertEq(attestation.totalAttestations(), 0);
        assertEq(attestation.totalQuorumReached(), 0);
    }

    function test_RevertZeroAdmin() public {
        vm.expectRevert(PQCBridgeAttestation.ZeroAddress.selector);
        new PQCBridgeAttestation(address(0), address(0x1234), QUORUM);
    }

    function test_RevertInvalidQuorum() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                PQCBridgeAttestation.InvalidQuorumThreshold.selector,
                1
            )
        );
        new PQCBridgeAttestation(admin, address(0x1234), 1);
    }

    /*//////////////////////////////////////////////////////////////
                     ATTESTOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterAttestor() public view {
        assertTrue(attestation.hasRole(attestation.ATTESTOR_ROLE(), attestor1));
        assertEq(
            uint8(attestation.attestorAlgorithm(attestor1)),
            uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
        );
        assertEq(
            attestation.attestorKeyHash(attestor1),
            keccak256("attestor1_pk")
        );
    }

    function test_RemoveAttestor() public {
        vm.prank(admin);
        attestation.removeAttestor(attestor1);

        assertFalse(
            attestation.hasRole(attestation.ATTESTOR_ROLE(), attestor1)
        );
    }

    function test_RevertNonOperatorRegister() public {
        vm.prank(nonAttestor);
        vm.expectRevert();
        attestation.registerAttestor(
            nonAttestor,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            keccak256("key")
        );
    }

    /*//////////////////////////////////////////////////////////////
                   ATTESTATION SUBMISSION
    //////////////////////////////////////////////////////////////*/

    function test_SubmitAttestation() public {
        bytes32 msgHash = keccak256("bridge_message_1");
        bytes32 sigHash = keccak256("pqc_signature_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, sigHash, 1, 42161);

        assertEq(attestation.totalAttestations(), 1);
        assertEq(attestation.getAttestationCount(msgHash), 1);

        PQCBridgeAttestation.MessageAttestationStatus
            memory status = attestation.getAttestationStatus(msgHash);
        assertEq(status.totalAttestations, 1);
        assertEq(status.verifiedAttestations, 0);
        assertFalse(status.quorumReached);
    }

    function test_MultipleAttestations() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        vm.prank(attestor2);
        attestation.submitAttestation(msgHash, keccak256("sig2"), 1, 42161);

        assertEq(attestation.totalAttestations(), 2);
        assertEq(attestation.getAttestationCount(msgHash), 2);
    }

    function test_RevertDuplicateAttestation() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.startPrank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        vm.expectRevert(
            abi.encodeWithSelector(
                PQCBridgeAttestation.AlreadyAttested.selector,
                msgHash,
                attestor1
            )
        );
        attestation.submitAttestation(msgHash, keccak256("sig2"), 1, 42161);
        vm.stopPrank();
    }

    function test_RevertInvalidMessageHash() public {
        vm.prank(attestor1);
        vm.expectRevert(PQCBridgeAttestation.InvalidMessageHash.selector);
        attestation.submitAttestation(bytes32(0), keccak256("sig"), 1, 42161);
    }

    function test_RevertNonAttestorSubmit() public {
        vm.prank(nonAttestor);
        vm.expectRevert();
        attestation.submitAttestation(
            keccak256("msg"),
            keccak256("sig"),
            1,
            42161
        );
    }

    /*//////////////////////////////////////////////////////////////
                   ATTESTATION VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_MarkAttestationVerified() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        vm.prank(admin);
        attestation.markAttestationVerified(msgHash, 0, true);

        PQCBridgeAttestation.MessageAttestationStatus
            memory status = attestation.getAttestationStatus(msgHash);
        assertEq(status.verifiedAttestations, 1);
        assertFalse(status.quorumReached); // Need 2 for quorum
    }

    function test_QuorumReached() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        vm.prank(attestor2);
        attestation.submitAttestation(msgHash, keccak256("sig2"), 1, 42161);

        vm.startPrank(admin);
        attestation.markAttestationVerified(msgHash, 0, true);
        attestation.markAttestationVerified(msgHash, 1, true);
        vm.stopPrank();

        (bool hasQuorum, uint256 verifiedCount) = attestation.checkQuorum(
            msgHash
        );
        assertTrue(hasQuorum);
        assertEq(verifiedCount, 2);
        assertEq(attestation.totalQuorumReached(), 1);
    }

    function test_PartialVerification() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        vm.prank(attestor2);
        attestation.submitAttestation(msgHash, keccak256("sig2"), 1, 42161);

        vm.startPrank(admin);
        attestation.markAttestationVerified(msgHash, 0, true);
        attestation.markAttestationVerified(msgHash, 1, false); // invalid PQC sig
        vm.stopPrank();

        (bool hasQuorum, uint256 verifiedCount) = attestation.checkQuorum(
            msgHash
        );
        assertFalse(hasQuorum);
        assertEq(verifiedCount, 1);
    }

    function test_QuorumWithThreeAttestors() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);
        vm.prank(attestor2);
        attestation.submitAttestation(msgHash, keccak256("sig2"), 1, 42161);
        vm.prank(attestor3);
        attestation.submitAttestation(msgHash, keccak256("sig3"), 1, 42161);

        vm.startPrank(admin);
        attestation.markAttestationVerified(msgHash, 0, false); // invalid
        attestation.markAttestationVerified(msgHash, 1, true);
        attestation.markAttestationVerified(msgHash, 2, true);
        vm.stopPrank();

        (bool hasQuorum, uint256 verifiedCount) = attestation.checkQuorum(
            msgHash
        );
        assertTrue(hasQuorum);
        assertEq(verifiedCount, 2);
    }

    /*//////////////////////////////////////////////////////////////
                     ATTESTATION VALIDITY
    //////////////////////////////////////////////////////////////*/

    function test_AttestationValidity() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        assertTrue(attestation.isAttestationValid(msgHash));

        // Warp past expiry
        vm.warp(block.timestamp + 25 hours);
        assertFalse(attestation.isAttestationValid(msgHash));
    }

    function test_NonExistentAttestationInvalid() public view {
        assertFalse(attestation.isAttestationValid(keccak256("nonexistent")));
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetQuorumThreshold() public {
        vm.prank(admin);
        attestation.setQuorumThreshold(3);

        assertEq(attestation.quorumThreshold(), 3);
    }

    function test_RevertSetQuorumBelowMin() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                PQCBridgeAttestation.InvalidQuorumThreshold.selector,
                1
            )
        );
        attestation.setQuorumThreshold(1);
    }

    function test_SetHybridPQCVerifier() public {
        address newVerifier = makeAddr("newVerifier");

        vm.prank(admin);
        attestation.setHybridPQCVerifier(newVerifier);

        assertEq(attestation.hybridPQCVerifier(), newVerifier);
    }

    function test_PauseUnpause() public {
        vm.startPrank(admin);
        attestation.pause();
        assertTrue(attestation.paused());

        attestation.unpause();
        assertFalse(attestation.paused());
        vm.stopPrank();
    }

    function test_RevertSubmitWhenPaused() public {
        vm.prank(admin);
        attestation.pause();

        vm.prank(attestor1);
        vm.expectRevert();
        attestation.submitAttestation(
            keccak256("msg"),
            keccak256("sig"),
            1,
            42161
        );
    }

    /*//////////////////////////////////////////////////////////////
                          STATS
    //////////////////////////////////////////////////////////////*/

    function test_GetStats() public {
        bytes32 msgHash = keccak256("bridge_message_1");

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, keccak256("sig1"), 1, 42161);

        (uint256 totalAttest, uint256 totalQuorum) = attestation.getStats();
        assertEq(totalAttest, 1);
        assertEq(totalQuorum, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SubmitAndVerify(bytes32 msgHash, bytes32 sigHash) public {
        vm.assume(msgHash != bytes32(0));

        vm.prank(attestor1);
        attestation.submitAttestation(msgHash, sigHash, 1, 42161);

        assertEq(attestation.getAttestationCount(msgHash), 1);
    }

    function testFuzz_QuorumThreshold(uint256 threshold) public {
        threshold = bound(threshold, 2, 100);

        vm.prank(admin);
        attestation.setQuorumThreshold(threshold);

        assertEq(attestation.quorumThreshold(), threshold);
    }
}
