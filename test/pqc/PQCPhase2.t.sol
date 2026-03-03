// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {HybridPQCVerifier, IPQCVerifierLib} from "../../contracts/experimental/verifiers/HybridPQCVerifier.sol";
import {IPQCVerifier} from "../../contracts/interfaces/IPQCVerifier.sol";

/**
 * @title PQCPhase2Test
 * @notice Tests for Phase 2 HybridPQCVerifier upgrades:
 *         - Verification backend management
 *         - Precompile address configuration
 *         - KEM session lifecycle
 *         - STARKProof struct integration
 */
contract PQCPhase2Test is Test {
    HybridPQCVerifier public verifier;

    address public admin;
    address public oracle;
    address public user1;
    address public user2;

    uint256 constant FN_DSA_512_PK_SIZE = 897;
    uint256 constant ML_KEM_768_PK_SIZE = 1184;

    bytes32 constant PQC_KEY_DOMAIN =
        keccak256("ZASEON_PQC_KEY_REGISTRATION_V1");

    function setUp() public {
        admin = makeAddr("admin");
        oracle = makeAddr("oracle");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");

        vm.startPrank(admin);
        verifier = new HybridPQCVerifier(admin, oracle);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                  VERIFICATION BACKEND MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_DefaultBackendIsOracle() public view {
        assertEq(
            uint8(
                verifier.algorithmBackend(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
            ),
            uint8(HybridPQCVerifier.VerificationBackend.ORACLE)
        );
    }

    function test_SetVerificationBackendToPrecompile() public {
        vm.prank(admin);
        verifier.setVerificationBackend(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            HybridPQCVerifier.VerificationBackend.PRECOMPILE
        );

        assertEq(
            uint8(
                verifier.algorithmBackend(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
            ),
            uint8(HybridPQCVerifier.VerificationBackend.PRECOMPILE)
        );
    }

    function test_SetVerificationBackendToZKProof() public {
        vm.prank(admin);
        verifier.setVerificationBackend(
            IPQCVerifier.PQCAlgorithm.ML_DSA_44,
            HybridPQCVerifier.VerificationBackend.ZK_PROOF
        );

        assertEq(
            uint8(
                verifier.algorithmBackend(IPQCVerifier.PQCAlgorithm.ML_DSA_44)
            ),
            uint8(HybridPQCVerifier.VerificationBackend.ZK_PROOF)
        );
    }

    function test_RevertNonAdminSetBackend() public {
        vm.prank(user1);
        vm.expectRevert();
        verifier.setVerificationBackend(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            HybridPQCVerifier.VerificationBackend.PRECOMPILE
        );
    }

    /*//////////////////////////////////////////////////////////////
                    PRECOMPILE ADDRESS CONFIG
    //////////////////////////////////////////////////////////////*/

    function test_SetPrecompileAddress() public {
        address precompile = makeAddr("precompile");

        vm.prank(admin);
        verifier.setPrecompileAddress(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            precompile
        );

        assertEq(
            verifier.precompileAddresses(IPQCVerifier.PQCAlgorithm.FN_DSA_512),
            precompile
        );
    }

    function test_RevertSetZeroPrecompile() public {
        vm.prank(admin);
        vm.expectRevert(HybridPQCVerifier.ZeroAddress.selector);
        verifier.setPrecompileAddress(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            address(0)
        );
    }

    function test_RevertNonAdminSetPrecompile() public {
        vm.prank(user1);
        vm.expectRevert();
        verifier.setPrecompileAddress(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            makeAddr("precompile")
        );
    }

    /*//////////////////////////////////////////////////////////////
                      KEM SESSION LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_InitiateKEMSession() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );

        assertTrue(sessionId != bytes32(0));
        assertEq(verifier.totalKEMSessions(), 1);

        (
            bytes32 sid,
            address initiator,
            address responder,
            ,
            bytes32 ctHash,
            ,
            uint256 createdAt,
            uint256 expiresAt,
            bool completed
        ) = verifier.kemSessions(sessionId);

        assertEq(sid, sessionId);
        assertEq(initiator, user1);
        assertEq(responder, user2);
        assertEq(ctHash, keccak256("ciphertext"));
        assertEq(createdAt, block.timestamp);
        assertEq(expiresAt, block.timestamp + 1 hours);
        assertFalse(completed);
    }

    function test_CompleteKEMSession() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );

        bytes32 sharedSecretHash = keccak256("shared_secret");

        vm.prank(user2);
        verifier.completeKEMSession(sessionId, sharedSecretHash);

        (, , , , , bytes32 ssHash, , , bool completed) = verifier.kemSessions(
            sessionId
        );
        assertTrue(completed);
        assertEq(ssHash, sharedSecretHash);
    }

    function test_RevertNonResponderComplete() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );

        vm.prank(user1); // not the responder
        vm.expectRevert("Not responder");
        verifier.completeKEMSession(sessionId, keccak256("secret"));
    }

    function test_RevertDoubleComplete() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );

        vm.startPrank(user2);
        verifier.completeKEMSession(sessionId, keccak256("secret"));

        vm.expectRevert("Already completed");
        verifier.completeKEMSession(sessionId, keccak256("secret2"));
        vm.stopPrank();
    }

    function test_RevertExpiredSession() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );

        vm.warp(block.timestamp + 2 hours);

        vm.prank(user2);
        vm.expectRevert("Session expired");
        verifier.completeKEMSession(sessionId, keccak256("secret"));
    }

    function test_RevertKEMWithSignatureAlgorithm() public {
        vm.prank(user1);
        vm.expectRevert("Not a KEM algorithm");
        verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512, // signature, not KEM
            keccak256("ciphertext"),
            1 hours
        );
    }

    function test_RevertKEMWithSelfResponder() public {
        vm.prank(user1);
        vm.expectRevert("Invalid responder");
        verifier.initiateKEMSession(
            user1, // self
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );
    }

    function test_RevertKEMWithZeroResponder() public {
        vm.prank(user1);
        vm.expectRevert("Invalid responder");
        verifier.initiateKEMSession(
            address(0),
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );
    }

    function test_RevertKEMInvalidDuration() public {
        vm.prank(user1);
        vm.expectRevert("Invalid duration");
        verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            0
        );
    }

    function test_RevertKEMExcessiveDuration() public {
        vm.prank(user1);
        vm.expectRevert("Invalid duration");
        verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            8 days
        );
    }

    function test_RevertKEMWhenPaused() public {
        vm.prank(admin);
        verifier.pause();

        vm.prank(user1);
        vm.expectRevert();
        verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ciphertext"),
            1 hours
        );
    }

    /*//////////////////////////////////////////////////////////////
                   KEM SESSION - ALL VARIANTS
    //////////////////////////////////////////////////////////////*/

    function test_KEMSession_ML_KEM_512() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_512,
            keccak256("ciphertext_512"),
            1 hours
        );
        assertTrue(sessionId != bytes32(0));
    }

    function test_KEMSession_ML_KEM_1024() public {
        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_1024,
            keccak256("ciphertext_1024"),
            1 hours
        );
        assertTrue(sessionId != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                   MULTIPLE KEM SESSIONS
    //////////////////////////////////////////////////////////////*/

    function test_MultipleKEMSessions() public {
        vm.startPrank(user1);

        bytes32 s1 = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ct1"),
            1 hours
        );
        bytes32 s2 = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_512,
            keccak256("ct2"),
            2 hours
        );

        vm.stopPrank();

        assertTrue(s1 != s2);
        assertEq(verifier.totalKEMSessions(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                        FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_KEMSessionDuration(uint256 duration) public {
        duration = bound(duration, 1, 7 days);

        vm.prank(user1);
        bytes32 sessionId = verifier.initiateKEMSession(
            user2,
            IPQCVerifier.PQCAlgorithm.ML_KEM_768,
            keccak256("ct"),
            duration
        );

        (, , , , , , , uint256 expiresAt, ) = verifier.kemSessions(sessionId);
        assertEq(expiresAt, block.timestamp + duration);
    }

    function testFuzz_VerificationBackend(uint8 backendIdx) public {
        backendIdx = uint8(bound(backendIdx, 0, 2));
        HybridPQCVerifier.VerificationBackend backend = HybridPQCVerifier
            .VerificationBackend(backendIdx);

        vm.prank(admin);
        verifier.setVerificationBackend(
            IPQCVerifier.PQCAlgorithm.FN_DSA_512,
            backend
        );

        assertEq(
            uint8(
                verifier.algorithmBackend(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
            ),
            uint8(backend)
        );
    }
}
