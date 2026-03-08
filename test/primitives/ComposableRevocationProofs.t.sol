// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/primitives/ComposableRevocationProofs.sol";

contract ComposableRevocationProofsTest is Test {
    ComposableRevocationProofs crp;
    address admin = address(0xA);
    address manager = address(0xB);
    address operator = address(0xC);
    address verifierAddr = address(0xD);
    address user1 = address(0xE);

    bytes32 constant REVOCATION_MANAGER_ROLE =
        0x02ee075c7da8b2fd2f3c683fd86848a232efcddcc392f4e81fb8fb4f80bc8333;
    bytes32 constant ACCUMULATOR_OPERATOR_ROLE =
        0x4859a9a09eae5a428737d4845e8d3a5c48c9e22c00db19e1877c6fe0ef9488d9;
    bytes32 constant VERIFIER_ROLE =
        0x0ce23c3e399818cfee81a7ab0880f714e53d7672b08df0fa62f2843416e1ea09;

    function setUp() public {
        vm.prank(admin);
        crp = new ComposableRevocationProofs();

        vm.startPrank(admin);
        crp.grantRole(REVOCATION_MANAGER_ROLE, manager);
        crp.grantRole(ACCUMULATOR_OPERATOR_ROLE, operator);
        crp.grantRole(VERIFIER_ROLE, verifierAddr);
        vm.stopPrank();
    }

    /* ══════════════════════════════════════════════════
              HELPER
       ══════════════════════════════════════════════════ */

    function _createAccumulator() internal returns (bytes32) {
        vm.prank(operator);
        return crp.createAccumulator(bytes32(uint256(0x1234)));
    }

    /* ══════════════════════════════════════════════════
              CREATE ACCUMULATOR
       ══════════════════════════════════════════════════ */

    function test_createAccumulator_success() public {
        bytes32 accId = _createAccumulator();
        assertNotEq(accId, bytes32(0));
        assertEq(crp.totalAccumulators(), 1);

        ComposableRevocationProofs.RevocationAccumulator memory acc = crp
            .getAccumulator(accId);
        assertEq(acc.currentValue, bytes32(uint256(0x1234)));
        assertEq(acc.version, 1);
        assertEq(acc.elementCount, 0);
        assertTrue(acc.isActive);
    }

    function test_createAccumulator_multipleUnique() public {
        bytes32 id1 = _createAccumulator();
        bytes32 id2 = _createAccumulator();
        assertNotEq(id1, id2);
        assertEq(crp.totalAccumulators(), 2);
    }

    function test_createAccumulator_revertsNotOperator() public {
        vm.prank(user1);
        vm.expectRevert();
        crp.createAccumulator(bytes32(uint256(1)));
    }

    function test_createAccumulator_revertsWhenPaused() public {
        vm.prank(admin);
        crp.pause();

        vm.prank(operator);
        vm.expectRevert();
        crp.createAccumulator(bytes32(uint256(1)));
    }

    function test_getActiveAccumulators() public {
        _createAccumulator();
        _createAccumulator();
        bytes32[] memory active = crp.getActiveAccumulators();
        assertEq(active.length, 2);
    }

    /* ══════════════════════════════════════════════════
              REVOKE CREDENTIAL
       ══════════════════════════════════════════════════ */

    function test_revokeCredential_success() public {
        bytes32 accId = _createAccumulator();
        bytes32 credHash = bytes32(uint256(0xCAFE));
        bytes32 witness = bytes32(uint256(0xBEEF));

        vm.prank(manager);
        bytes32 entryId = crp.revokeCredential(
            accId,
            credHash,
            witness,
            "policy violation"
        );

        assertNotEq(entryId, bytes32(0));
        assertTrue(crp.isCredentialRevoked(accId, credHash));
        assertEq(crp.totalRevocations(), 1);

        ComposableRevocationProofs.RevocationAccumulator memory acc = crp
            .getAccumulator(accId);
        assertEq(acc.version, 2);
        assertEq(acc.elementCount, 1);
    }

    function test_revokeCredential_revertsAlready() public {
        bytes32 accId = _createAccumulator();
        bytes32 credHash = bytes32(uint256(0xCAFE));

        vm.prank(manager);
        crp.revokeCredential(accId, credHash, bytes32(0), "first");

        vm.prank(manager);
        vm.expectRevert(ComposableRevocationProofs.AlreadyRevoked.selector);
        crp.revokeCredential(accId, credHash, bytes32(0), "duplicate");
    }

    function test_revokeCredential_revertsAccumulatorNotFound() public {
        vm.prank(manager);
        vm.expectRevert(
            ComposableRevocationProofs.AccumulatorNotFound.selector
        );
        crp.revokeCredential(
            bytes32(uint256(999)),
            bytes32(uint256(1)),
            bytes32(0),
            ""
        );
    }

    function test_revokeCredential_revertsInactive() public {
        bytes32 accId = _createAccumulator();
        vm.prank(admin);
        crp.deactivateAccumulator(accId);

        vm.prank(manager);
        vm.expectRevert(
            ComposableRevocationProofs.AccumulatorInactive.selector
        );
        crp.revokeCredential(accId, bytes32(uint256(1)), bytes32(0), "");
    }

    function test_revokeCredential_revertsNotManager() public {
        bytes32 accId = _createAccumulator();
        vm.prank(user1);
        vm.expectRevert();
        crp.revokeCredential(accId, bytes32(uint256(1)), bytes32(0), "");
    }

    function test_revokeCredential_updatesHistory() public {
        bytes32 accId = _createAccumulator();
        bytes32 v1 = crp.getAccumulatorValueAtVersion(accId, 1);
        assertEq(v1, bytes32(uint256(0x1234)));

        vm.prank(manager);
        crp.revokeCredential(accId, bytes32(uint256(0xCAFE)), bytes32(0), "");

        bytes32 v2 = crp.getAccumulatorValueAtVersion(accId, 2);
        assertNotEq(v2, bytes32(0));
        assertNotEq(v2, v1);
    }

    /* ══════════════════════════════════════════════════
              BATCH REVOKE
       ══════════════════════════════════════════════════ */

    function test_batchRevokeCredentials_success() public {
        bytes32 accId = _createAccumulator();
        bytes32[] memory creds = new bytes32[](3);
        creds[0] = bytes32(uint256(1));
        creds[1] = bytes32(uint256(2));
        creds[2] = bytes32(uint256(3));
        bytes32[] memory witnesses = new bytes32[](3);

        vm.prank(manager);
        crp.batchRevokeCredentials(accId, creds, witnesses, "batch");

        assertTrue(crp.isCredentialRevoked(accId, creds[0]));
        assertTrue(crp.isCredentialRevoked(accId, creds[1]));
        assertTrue(crp.isCredentialRevoked(accId, creds[2]));
        assertEq(crp.totalRevocations(), 3);
    }

    function test_batchRevokeCredentials_skipsDuplicates() public {
        bytes32 accId = _createAccumulator();

        // Revoke first credential
        vm.prank(manager);
        crp.revokeCredential(accId, bytes32(uint256(1)), bytes32(0), "");

        // Batch includes already-revoked cred
        bytes32[] memory creds = new bytes32[](2);
        creds[0] = bytes32(uint256(1)); // already revoked
        creds[1] = bytes32(uint256(2)); // new
        bytes32[] memory witnesses = new bytes32[](2);

        vm.prank(manager);
        crp.batchRevokeCredentials(accId, creds, witnesses, "batch");

        assertTrue(crp.isCredentialRevoked(accId, creds[1]));
        // elementCount: 1 from single + 1 from batch (skipped dup)
        ComposableRevocationProofs.RevocationAccumulator memory acc = crp
            .getAccumulator(accId);
        assertEq(acc.elementCount, 2);
    }

    /* ══════════════════════════════════════════════════
              UNREVOKE CREDENTIAL
       ══════════════════════════════════════════════════ */

    function test_unrevokeCredential_success() public {
        bytes32 accId = _createAccumulator();
        bytes32 credHash = bytes32(uint256(0xCAFE));

        vm.prank(manager);
        crp.revokeCredential(accId, credHash, bytes32(0), "test");
        assertTrue(crp.isCredentialRevoked(accId, credHash));

        vm.prank(manager);
        crp.unrevokeCredential(accId, credHash);
        assertFalse(crp.isCredentialRevoked(accId, credHash));
    }

    function test_unrevokeCredential_revertsNotRevoked() public {
        bytes32 accId = _createAccumulator();
        vm.prank(manager);
        vm.expectRevert(ComposableRevocationProofs.NotRevoked.selector);
        crp.unrevokeCredential(accId, bytes32(uint256(0xCAFE)));
    }

    /* ══════════════════════════════════════════════════
              NON-MEMBERSHIP PROOF
       ══════════════════════════════════════════════════ */

    function test_submitNonMembershipProof_success() public {
        bytes32 accId = _createAccumulator();
        bytes32 credHash = bytes32(uint256(0xCAFE));
        bytes memory proof = abi.encode("zk-proof-data");

        vm.prank(user1);
        bytes32 proofId = crp.submitNonMembershipProof(
            accId,
            credHash,
            proof,
            3600
        );

        assertNotEq(proofId, bytes32(0));
        assertEq(crp.totalProofs(), 1);

        ComposableRevocationProofs.NonMembershipProof memory p = crp
            .getNonMembershipProof(proofId);
        assertEq(p.accumulatorId, accId);
        assertEq(p.credentialHash, credHash);
        assertFalse(p.isVerified);
    }

    function test_submitNonMembershipProof_revertsAccNotFound() public {
        vm.prank(user1);
        vm.expectRevert(
            ComposableRevocationProofs.AccumulatorNotFound.selector
        );
        crp.submitNonMembershipProof(
            bytes32(uint256(999)),
            bytes32(0),
            "",
            3600
        );
    }

    /* ══════════════════════════════════════════════════
              DELTA UPDATE
       ══════════════════════════════════════════════════ */

    function test_publishDeltaUpdate_success() public {
        bytes32 accId = _createAccumulator();

        // Revoke a credential to advance version
        vm.prank(manager);
        crp.revokeCredential(accId, bytes32(uint256(1)), bytes32(0), "");

        bytes32[] memory added = new bytes32[](1);
        added[0] = bytes32(uint256(1));

        vm.prank(operator);
        bytes32 updateId = crp.publishDeltaUpdate(
            accId,
            1,
            2,
            added,
            bytes32(uint256(0xDEAD))
        );

        assertNotEq(updateId, bytes32(0));
        ComposableRevocationProofs.DeltaUpdate memory du = crp.getDeltaUpdate(
            updateId
        );
        assertEq(du.fromVersion, 1);
        assertEq(du.toVersion, 2);
    }

    function test_publishDeltaUpdate_revertsVersionMismatch() public {
        bytes32 accId = _createAccumulator();
        bytes32[] memory added = new bytes32[](0);

        vm.prank(operator);
        vm.expectRevert(ComposableRevocationProofs.VersionMismatch.selector);
        crp.publishDeltaUpdate(accId, 1, 99, added, bytes32(0));
    }

    /* ══════════════════════════════════════════════════
              COMPOSABLE PROOF
       ══════════════════════════════════════════════════ */

    function test_createComposableProof_success() public {
        bytes32 accId = _createAccumulator();

        vm.prank(user1);
        bytes32 proofId = crp.submitNonMembershipProof(
            accId,
            bytes32(uint256(0xCAFE)),
            "proof",
            3600
        );

        bytes32[] memory additional = new bytes32[](1);
        additional[0] = bytes32(uint256(0xABC));

        vm.prank(user1);
        bytes32 compId = crp.createComposableProof(proofId, additional);
        assertNotEq(compId, bytes32(0));

        ComposableRevocationProofs.ComposableProof memory cp = crp
            .getComposableProof(compId);
        assertEq(cp.nonMembershipProofId, proofId);
        assertFalse(cp.isValid);
    }

    function test_createComposableProof_revertsProofNotFound() public {
        bytes32[] memory additional = new bytes32[](0);
        vm.prank(user1);
        vm.expectRevert(ComposableRevocationProofs.ProofNotFound.selector);
        crp.createComposableProof(bytes32(uint256(999)), additional);
    }

    /* ══════════════════════════════════════════════════
              ADMIN FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_deactivateAccumulator() public {
        bytes32 accId = _createAccumulator();

        vm.prank(admin);
        crp.deactivateAccumulator(accId);

        ComposableRevocationProofs.RevocationAccumulator memory acc = crp
            .getAccumulator(accId);
        assertFalse(acc.isActive);
    }

    function test_setNonMembershipVerifier() public {
        address v = address(0x99);
        vm.prank(admin);
        crp.setNonMembershipVerifier(v);
        assertEq(crp.nonMembershipVerifier(), v);
    }

    function test_setNonMembershipVerifier_revertsZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(ComposableRevocationProofs.ZeroAddress.selector);
        crp.setNonMembershipVerifier(address(0));
    }

    /* ══════════════════════════════════════════════════
              PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_unpause() public {
        vm.prank(admin);
        crp.pause();
        assertTrue(crp.paused());

        vm.prank(admin);
        crp.unpause();
        assertFalse(crp.paused());
    }

    function test_pause_revertsNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        crp.pause();
    }

    /* ══════════════════════════════════════════════════
              VIEW FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_getRevocationEntry() public {
        bytes32 accId = _createAccumulator();
        vm.prank(manager);
        bytes32 entryId = crp.revokeCredential(
            accId,
            bytes32(uint256(0xCAFE)),
            bytes32(uint256(0xBEEF)),
            "violation"
        );

        ComposableRevocationProofs.RevocationEntry memory entry = crp
            .getRevocationEntry(entryId);
        assertEq(entry.accumulatorId, accId);
        assertEq(entry.credentialHash, bytes32(uint256(0xCAFE)));
        assertEq(entry.witness, bytes32(uint256(0xBEEF)));
    }
}
