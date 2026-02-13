// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/ExecutionAgnosticStateCommitments.sol";

/* ─── Mock verifier ─────────────────────────────────────────────── */

contract MockAttestationVerifier is IProofVerifier {
    bool public returnValue = true;

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return returnValue;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view override returns (bool) {
        return returnValue;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view override returns (bool) {
        return returnValue;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 4;
    }

    function isReady() external pure override returns (bool) {
        return true;
    }

    function setReturnValue(bool v) external {
        returnValue = v;
    }
}

/* ─── Test contract ──────────────────────────────────────────────── */

contract ExecutionAgnosticStateCommitmentsTest is Test {
    ExecutionAgnosticStateCommitments public easc;
    MockAttestationVerifier public verifier;

    address admin = address(0xA);
    address backendAdmin = address(0xB);
    address registrar = address(0xC);
    address nobody = address(0xDEAD);

    bytes32 BACKEND_ADMIN_ROLE;
    bytes32 COMMITMENT_REGISTRAR_ROLE;

    function setUp() public {
        verifier = new MockAttestationVerifier();

        vm.startPrank(admin);
        easc = new ExecutionAgnosticStateCommitments();

        BACKEND_ADMIN_ROLE = easc.BACKEND_ADMIN_ROLE();
        COMMITMENT_REGISTRAR_ROLE = easc.COMMITMENT_REGISTRAR_ROLE();

        easc.grantRole(BACKEND_ADMIN_ROLE, backendAdmin);
        easc.grantRole(COMMITMENT_REGISTRAR_ROLE, registrar);
        easc.setAttestationVerifier(address(verifier));
        vm.stopPrank();
    }

    /* ── Backend Management ─────────────────────────── */

    function test_registerBackend_happyPath() public {
        vm.prank(backendAdmin);
        bytes32 bid = easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "SP1-Backend",
            bytes32(uint256(0xAABB)),
            bytes32(uint256(0xCCDD))
        );

        assertTrue(bid != bytes32(0));
        assertEq(easc.totalBackends(), 1);

        ExecutionAgnosticStateCommitments.ExecutionBackend memory b = easc
            .getBackend(bid);
        assertEq(b.name, "SP1-Backend");
        assertTrue(b.isActive);
        assertEq(b.trustScore, easc.MAX_TRUST_SCORE());
    }

    function test_registerBackend_revertsDuplicate() public {
        vm.startPrank(backendAdmin);
        easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "SP1-Backend",
            bytes32(uint256(0xAABB)),
            bytes32(uint256(0xCCDD))
        );

        // Same params at same timestamp => same backendId
        vm.expectRevert();
        easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "SP1-Backend",
            bytes32(uint256(0xAABB)),
            bytes32(uint256(0xCCDD))
        );
        vm.stopPrank();
    }

    function test_registerBackend_unauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "test",
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
    }

    function test_updateBackendTrust_clamps() public {
        vm.prank(backendAdmin);
        bytes32 bid = easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.TEE,
            "SGX",
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        vm.prank(backendAdmin);
        easc.updateBackendTrust(bid, 20000); // above MAX

        ExecutionAgnosticStateCommitments.ExecutionBackend memory b = easc
            .getBackend(bid);
        assertEq(b.trustScore, easc.MAX_TRUST_SCORE());
    }

    function test_updateBackendTrust_revertsNotFound() public {
        vm.prank(backendAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionAgnosticStateCommitments.BackendNotFound.selector,
                bytes32(uint256(999))
            )
        );
        easc.updateBackendTrust(bytes32(uint256(999)), 5000);
    }

    function test_deactivateBackend() public {
        vm.prank(backendAdmin);
        bytes32 bid = easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.Native,
            "Native-1",
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        vm.prank(backendAdmin);
        easc.deactivateBackend(bid);

        ExecutionAgnosticStateCommitments.ExecutionBackend memory b = easc
            .getBackend(bid);
        assertFalse(b.isActive);
    }

    /* ── Commitment Management ──────────────────────── */

    function _registerDefaultBackend() internal returns (bytes32) {
        vm.prank(backendAdmin);
        return
            easc.registerBackend(
                ExecutionAgnosticStateCommitments.BackendType.ZkVM,
                "DefaultZK",
                bytes32(uint256(0xAA)),
                bytes32(uint256(0xBB))
            );
    }

    function test_createCommitment_happyPath() public {
        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        assertTrue(cid != bytes32(0));
        assertEq(easc.totalCommitments(), 1);

        ExecutionAgnosticStateCommitments.CommitmentView memory cv = easc
            .getCommitment(cid);
        assertEq(cv.stateHash, bytes32(uint256(1)));
        assertEq(cv.nullifier, bytes32(uint256(3)));
        assertFalse(cv.isFinalized);
    }

    function test_createCommitment_revertsZeroStateHash() public {
        vm.prank(registrar);
        vm.expectRevert(
            ExecutionAgnosticStateCommitments.ZeroStateHash.selector
        );
        easc.createCommitment(
            bytes32(0),
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
    }

    function test_createCommitment_revertsZeroNullifier() public {
        vm.prank(registrar);
        vm.expectRevert(
            ExecutionAgnosticStateCommitments.ZeroNullifier.selector
        );
        easc.createCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(0)
        );
    }

    function testFuzz_createCommitment(
        bytes32 stateHash,
        bytes32 transHash,
        bytes32 nullifier
    ) public {
        vm.assume(stateHash != bytes32(0) && nullifier != bytes32(0));
        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(stateHash, transHash, nullifier);
        assertTrue(cid != bytes32(0));
    }

    /* ── Attestation ────────────────────────────────── */

    function test_attestCommitment_autoFinalizes() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        // requiredAttestations is 1 by default, so one attestation finalizes
        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));

        ExecutionAgnosticStateCommitments.CommitmentView memory cv = easc
            .getCommitment(cid);
        assertTrue(cv.isFinalized);
        assertEq(cv.attestationCount, 1);
    }

    function test_attestCommitment_revertsInactiveBackend() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(backendAdmin);
        easc.deactivateBackend(bid);

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionAgnosticStateCommitments.BackendInactive.selector,
                bid
            )
        );
        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));
    }

    function test_attestCommitment_revertsAlreadyAttested() public {
        bytes32 bid = _registerDefaultBackend();

        // Require 2 attestations so first doesn't finalize
        vm.prank(backendAdmin);
        easc.setRequiredAttestations(2);

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionAgnosticStateCommitments.AlreadyAttested.selector,
                cid,
                bid
            )
        );
        easc.attestCommitment(cid, bid, hex"5678", bytes32(uint256(100)));
    }

    function test_attestCommitment_revertsLowTrust() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(backendAdmin);
        easc.updateBackendTrust(bid, 100); // below minTrustScore(5000)

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionAgnosticStateCommitments.BackendTrustTooLow.selector,
                bid,
                100
            )
        );
        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));
    }

    function test_attestCommitment_revertsInvalidProof() public {
        bytes32 bid = _registerDefaultBackend();
        verifier.setReturnValue(false);

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        vm.expectRevert(
            ExecutionAgnosticStateCommitments.InvalidAttestationProof.selector
        );
        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));
    }

    /* ── Consume ────────────────────────────────────── */

    function test_consumeCommitment_happyPath() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));

        vm.prank(registrar);
        easc.consumeCommitment(cid);

        assertTrue(easc.usedNullifiers(bytes32(uint256(30))));
    }

    function test_consumeCommitment_revertsNotFinalized() public {
        // require 2 so it won't auto-finalize
        vm.prank(backendAdmin);
        easc.setRequiredAttestations(2);

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionAgnosticStateCommitments
                    .CommitmentNotFinalized
                    .selector,
                cid
            )
        );
        easc.consumeCommitment(cid);
    }

    function test_consumeCommitment_revertsDoubleSpend() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));

        vm.prank(registrar);
        easc.consumeCommitment(cid);

        vm.prank(registrar);
        vm.expectRevert(
            abi.encodeWithSelector(
                ExecutionAgnosticStateCommitments.NullifierAlreadyUsed.selector,
                bytes32(uint256(30))
            )
        );
        easc.consumeCommitment(cid);
    }

    /* ── View functions ─────────────────────────────── */

    function test_isCommitmentValid_returnsTrueWhenFinalized() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(registrar);
        bytes32 cid = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        easc.attestCommitment(cid, bid, hex"1234", bytes32(uint256(99)));
        assertTrue(easc.isCommitmentValid(cid));
    }

    function test_batchCheckCommitments() public {
        bytes32 bid = _registerDefaultBackend();

        vm.prank(registrar);
        bytes32 cid1 = easc.createCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30))
        );

        vm.prank(registrar);
        bytes32 cid2 = easc.createCommitment(
            bytes32(uint256(40)),
            bytes32(uint256(50)),
            bytes32(uint256(60))
        );

        easc.attestCommitment(cid1, bid, hex"1234", bytes32(uint256(99)));

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = cid1;
        ids[1] = cid2;
        bool[] memory results = easc.batchCheckCommitments(ids);

        assertTrue(results[0]);
        assertFalse(results[1]);
    }

    function test_getBackendsByType() public {
        vm.startPrank(backendAdmin);
        easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "ZK-1",
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.warp(block.timestamp + 1);
        easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "ZK-2",
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        vm.stopPrank();

        bytes32[] memory zkBackends = easc.getBackendsByType(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM
        );
        assertEq(zkBackends.length, 2);
    }

    function test_getActiveBackends() public {
        vm.startPrank(backendAdmin);
        bytes32 bid1 = easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "ZK-1",
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.warp(block.timestamp + 1);
        easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.TEE,
            "TEE-1",
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        easc.deactivateBackend(bid1);
        vm.stopPrank();

        bytes32[] memory active = easc.getActiveBackends();
        assertEq(active.length, 1);
    }

    /* ── Admin ──────────────────────────────────────── */

    function test_setRequiredAttestations() public {
        vm.prank(backendAdmin);
        easc.setRequiredAttestations(3);
        assertEq(easc.requiredAttestations(), 3);
    }

    function test_setMinTrustScore() public {
        vm.prank(backendAdmin);
        easc.setMinTrustScore(7000);
        assertEq(easc.minTrustScore(), 7000);
    }

    function test_pauseUnpause() public {
        vm.prank(admin);
        easc.pause();

        vm.prank(registrar);
        vm.expectRevert();
        easc.createCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );

        vm.prank(admin);
        easc.unpause();

        vm.prank(registrar);
        easc.createCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );
    }
}
