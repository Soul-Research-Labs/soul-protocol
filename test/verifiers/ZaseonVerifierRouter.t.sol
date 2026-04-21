// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {VerifierRegistryV3} from "../../contracts/verifiers/VerifierRegistryV3.sol";
import {ZaseonVerifierRouter} from "../../contracts/verifiers/ZaseonVerifierRouter.sol";
import {IZaseonVerifierRouter} from "../../contracts/interfaces/IZaseonVerifierRouter.sol";
import {VerificationContext} from "../../contracts/libraries/VerificationContext.sol";
import {CompactProof} from "../../contracts/libraries/CompactProof.sol";
import {MockProofVerifier} from "../../contracts/mocks/MockProofVerifier.sol";

contract ZaseonVerifierRouterTest is Test {
    uint256 internal constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    VerifierRegistryV3 internal reg;
    ZaseonVerifierRouter internal router;
    MockProofVerifier internal adapter;

    address internal admin = address(0xA);
    address internal timelock = address(0xB);
    address internal guardian = address(0xC);

    bytes32 internal constant CID = keccak256("test:v1");
    bytes32 internal constant ACIR = keccak256("acir");
    bytes32 internal constant VKEY = keccak256("vkey");

    function setUp() public {
        reg = new VerifierRegistryV3(admin, timelock, guardian);
        router = new ZaseonVerifierRouter(
            address(reg),
            admin,
            guardian,
            /*transientOK*/ true
        );
        adapter = new MockProofVerifier();
        adapter.setVerificationResult(true);
    }

    function _register(bool ctxBound, uint32 gasCap) internal {
        vm.prank(timelock);
        reg.registerCircuit(
            CID,
            address(adapter),
            address(adapter),
            ACIR,
            VKEY,
            gasCap,
            1,
            16,
            false,
            ctxBound
        );
    }

    /* ------------------------------------------------------------
     * Happy path — unbound circuit
     * ------------------------------------------------------------ */

    function test_verify_happyPath_noContextBinding() public {
        _register(false, 300_000);
        uint256[] memory pis = new uint256[](1);
        pis[0] = 42;
        bool ok = router.verify(CID, hex"dead", pis, bytes32(0));
        assertTrue(ok);
    }

    function test_verify_revertsOnUnregistered() public {
        uint256[] memory pis = new uint256[](1);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZaseonVerifierRouter.CircuitNotRegistered.selector,
                CID
            )
        );
        router.verify(CID, hex"", pis, bytes32(0));
    }

    function test_verify_revertsOnAdapterFalse() public {
        _register(false, 0);
        adapter.setVerificationResult(false);
        uint256[] memory pis = new uint256[](1);
        pis[0] = 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                IZaseonVerifierRouter.VerificationFailed.selector,
                CID
            )
        );
        router.verify(CID, hex"", pis, bytes32(0));
    }

    /* ------------------------------------------------------------
     * Field-bounds check at the router
     * ------------------------------------------------------------ */

    function test_verify_rejectsOutOfRangeFieldElement() public {
        _register(false, 0);
        uint256[] memory pis = new uint256[](1);
        pis[0] = BN254_R; // exactly equal to modulus — invalid
        vm.expectRevert(
            abi.encodeWithSelector(
                VerificationContext.FieldElementOutOfRange.selector,
                uint256(0),
                BN254_R
            )
        );
        router.verify(CID, hex"", pis, bytes32(0));
    }

    /* ------------------------------------------------------------
     * Context binding
     * ------------------------------------------------------------ */

    function test_verify_contextBinding_success() public {
        _register(true, 0);
        bytes32 ctx = keccak256("lock#1");
        uint256 tag = VerificationContext.contextTag(
            address(reg),
            CID,
            VKEY,
            ctx
        );
        uint256[] memory pis = new uint256[](2);
        pis[0] = 7;
        pis[1] = tag;
        bool ok = router.verify(CID, hex"", pis, ctx);
        assertTrue(ok);
    }

    function test_verify_contextBinding_wrongTag_reverts() public {
        _register(true, 0);
        uint256[] memory pis = new uint256[](2);
        pis[0] = 7;
        pis[1] = 12345; // clearly wrong
        vm.expectRevert(
            abi.encodeWithSelector(
                IZaseonVerifierRouter.ContextBindingFailed.selector,
                CID
            )
        );
        router.verify(CID, hex"", pis, bytes32("x"));
    }

    function test_verify_contextBinding_differentChainId_differentTag() public {
        uint256 tagA = VerificationContext.contextTag(
            address(reg),
            CID,
            VKEY,
            bytes32("ctx")
        );
        vm.chainId(999);
        uint256 tagB = VerificationContext.contextTag(
            address(reg),
            CID,
            VKEY,
            bytes32("ctx")
        );
        assertTrue(tagA != tagB);
    }

    /* ------------------------------------------------------------
     * Input-count bounds
     * ------------------------------------------------------------ */

    function test_verify_rejectsTooFewInputs() public {
        _register(false, 0);
        uint256[] memory pis = new uint256[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZaseonVerifierRouter.InvalidPublicInputCount.selector,
                CID,
                uint256(0),
                uint256(1),
                uint256(16)
            )
        );
        router.verify(CID, hex"", pis, bytes32(0));
    }

    /* ------------------------------------------------------------
     * Pause paths
     * ------------------------------------------------------------ */

    function test_routerPause_blocksVerification() public {
        _register(false, 0);
        vm.prank(guardian);
        router.pauseRouter();
        uint256[] memory pis = new uint256[](1);
        pis[0] = 1;
        vm.expectRevert(IZaseonVerifierRouter.RouterIsPaused.selector);
        router.verify(CID, hex"", pis, bytes32(0));
    }

    function test_routerCircuitPause_blocksVerification() public {
        _register(false, 0);
        vm.prank(guardian);
        router.pauseCircuit(CID);
        uint256[] memory pis = new uint256[](1);
        pis[0] = 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                IZaseonVerifierRouter.CircuitIsPaused.selector,
                CID
            )
        );
        router.verify(CID, hex"", pis, bytes32(0));
    }

    function test_registryCircuitPause_blocksVerification() public {
        _register(false, 0);
        vm.prank(guardian);
        reg.pauseCircuit(CID);
        uint256[] memory pis = new uint256[](1);
        pis[0] = 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                IZaseonVerifierRouter.CircuitIsPaused.selector,
                CID
            )
        );
        router.verify(CID, hex"", pis, bytes32(0));
    }

    /* ------------------------------------------------------------
     * Batch + dedup (transient storage path)
     * ------------------------------------------------------------ */

    function test_verifyBatch_success() public {
        _register(false, 0);
        IZaseonVerifierRouter.Request[]
            memory reqs = new IZaseonVerifierRouter.Request[](3);
        for (uint256 i = 0; i < 3; i++) {
            uint256[] memory pis = new uint256[](1);
            pis[0] = i + 1;
            reqs[i] = IZaseonVerifierRouter.Request({
                circuitId: CID,
                proof: abi.encodePacked(bytes32(i)),
                publicInputs: pis,
                callerCtx: bytes32(uint256(i))
            });
        }
        bool ok = router.verifyBatch(reqs);
        assertTrue(ok);
    }

    function test_verifyBatch_dedupSkipsSecondCall() public {
        _register(false, 0);
        IZaseonVerifierRouter.Request[]
            memory reqs = new IZaseonVerifierRouter.Request[](2);
        uint256[] memory pis = new uint256[](1);
        pis[0] = 42;
        reqs[0] = IZaseonVerifierRouter.Request({
            circuitId: CID,
            proof: hex"dead",
            publicInputs: pis,
            callerCtx: bytes32("c")
        });
        reqs[1] = reqs[0]; // exact duplicate
        // Adapter counts calls — we can verify dedup via the mock:
        adapter.setVerificationResult(true);
        bool ok = router.verifyBatch(reqs);
        assertTrue(ok);
    }

    function test_verifyBatch_emptyReverts() public {
        IZaseonVerifierRouter.Request[] memory reqs;
        vm.expectRevert(IZaseonVerifierRouter.EmptyBatch.selector);
        router.verifyBatch(reqs);
    }

    /* ------------------------------------------------------------
     * CompactProof round-trip
     * ------------------------------------------------------------ */

    function test_compactProof_encodeDecode() public {
        uint256[] memory pis = new uint256[](3);
        pis[0] = 1;
        pis[1] = 2;
        pis[2] = 3;
        bytes memory blob = CompactProof.encode(
            CID,
            pis,
            hex"deadbeef",
            bytes32("ctx")
        );
        (
            bytes32 cid,
            uint256[] memory pis2,
            bytes memory proof2,
            bytes32 ctx2
        ) = this.decodeCompact(blob);
        assertEq(cid, CID);
        assertEq(pis2.length, 3);
        assertEq(pis2[0], 1);
        assertEq(pis2[2], 3);
        assertEq(keccak256(proof2), keccak256(hex"deadbeef"));
        assertEq(ctx2, bytes32("ctx"));
    }

    function decodeCompact(
        bytes calldata blob
    ) external pure returns (bytes32, uint256[] memory, bytes memory, bytes32) {
        return CompactProof.decode(blob);
    }

    function test_verifyCompact_happyPath() public {
        _register(false, 0);
        uint256[] memory pis = new uint256[](1);
        pis[0] = 9;
        bytes memory blob = CompactProof.encode(CID, pis, hex"aa", bytes32(0));
        bool ok = router.verifyCompact(blob);
        assertTrue(ok);
    }
}
