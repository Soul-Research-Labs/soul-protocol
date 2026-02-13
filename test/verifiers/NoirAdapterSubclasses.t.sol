// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/adapters/CommitmentAdapter.sol";
import "../../contracts/verifiers/adapters/ComplianceAdapter.sol";
import "../../contracts/verifiers/adapters/CrossChainAdapter.sol";
import "../../contracts/verifiers/adapters/PolicyVerifierAdapter.sol";
import "../../contracts/verifiers/adapters/PrivateTransferAdapter.sol";
import "../../contracts/verifiers/adapters/SwapProofAdapter.sol";
import "../../contracts/verifiers/adapters/NoirVerifierAdapter.sol";

/* ============ Mock NoirVerifier ============ */
contract MockNoirVerifier {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function setResult(bool _v) external {
        result = _v;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return result;
    }
}

/* ============ Test Contract ============ */
contract NoirAdapterSubclassTest is Test {
    MockNoirVerifier public mockVerifier;

    CommitmentAdapter public commitment;
    ComplianceAdapter public compliance;
    CrossChainAdapter public crossChain;
    PolicyVerifierAdapter public policy;
    PrivateTransferAdapter public privateTx;
    SwapProofAdapter public swap;

    function setUp() public {
        mockVerifier = new MockNoirVerifier(true);

        commitment = new CommitmentAdapter(address(mockVerifier));
        compliance = new ComplianceAdapter(address(mockVerifier));
        crossChain = new CrossChainAdapter(address(mockVerifier));
        policy = new PolicyVerifierAdapter(address(mockVerifier));
        privateTx = new PrivateTransferAdapter(address(mockVerifier));
        swap = new SwapProofAdapter(address(mockVerifier));
    }

    /* ──── Helpers ──── */

    /// @dev Build a packed publicInputs bytes for _prepareSignals
    /// Format: first 32 bytes = length (number of signals), then 32 bytes per signal
    function _packSignals(
        uint256[] memory vals
    ) internal pure returns (bytes memory) {
        bytes memory packed = new bytes(32 + vals.length * 32);
        assembly {
            // Store length at offset 32 (skip bytes length prefix)
            mstore(add(packed, 32), mload(vals))
        }
        for (uint256 i = 0; i < vals.length; i++) {
            assembly {
                mstore(
                    add(add(packed, 64), mul(i, 32)),
                    mload(add(add(vals, 32), mul(i, 32)))
                )
            }
        }
        return packed;
    }

    /* ========================================================
                       DEPLOYMENT & CONSTANTS
       ======================================================== */

    function test_commitment_publicInputCount() public view {
        assertEq(commitment.getPublicInputCount(), 3);
    }

    function test_compliance_publicInputCount() public view {
        assertEq(compliance.getPublicInputCount(), 16);
    }

    function test_crossChain_publicInputCount() public view {
        assertEq(crossChain.getPublicInputCount(), 7);
    }

    function test_policy_publicInputCount() public view {
        assertEq(policy.getPublicInputCount(), 4);
    }

    function test_privateTx_publicInputCount() public view {
        assertEq(privateTx.getPublicInputCount(), 16);
    }

    function test_swap_publicInputCount() public view {
        assertEq(swap.getPublicInputCount(), 11);
    }

    function test_allAdapters_isReady() public view {
        assertTrue(commitment.isReady());
        assertTrue(compliance.isReady());
        assertTrue(crossChain.isReady());
        assertTrue(policy.isReady());
        assertTrue(privateTx.isReady());
        assertTrue(swap.isReady());
    }

    function test_allAdapters_noirVerifierSet() public view {
        assertEq(commitment.noirVerifier(), address(mockVerifier));
        assertEq(compliance.noirVerifier(), address(mockVerifier));
        assertEq(crossChain.noirVerifier(), address(mockVerifier));
        assertEq(policy.noirVerifier(), address(mockVerifier));
        assertEq(privateTx.noirVerifier(), address(mockVerifier));
        assertEq(swap.noirVerifier(), address(mockVerifier));
    }

    /* ========================================================
                       COMMITMENT ADAPTER (3 signals, circuitPassed check)
       ======================================================== */

    function test_commitment_verify_success() public {
        uint256[] memory vals = new uint256[](3);
        vals[0] = 1; // circuitPassed = true
        vals[1] = 42;
        vals[2] = 100;
        bytes memory packed = _packSignals(vals);

        bool result = commitment.verify(bytes32(0), hex"dead", packed);
        assertTrue(result);
    }

    function test_commitment_verify_circuitFailed() public {
        uint256[] memory vals = new uint256[](3);
        vals[0] = 0; // circuitPassed = false
        vals[1] = 42;
        vals[2] = 100;
        bytes memory packed = _packSignals(vals);

        bool result = commitment.verify(bytes32(0), hex"dead", packed);
        assertFalse(result);
    }

    function test_commitment_verify_wrongSignalCount() public {
        uint256[] memory vals = new uint256[](2);
        vals[0] = 1;
        vals[1] = 42;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("SIG_COUNT_MISMATCH: COMMITMENT");
        commitment.verify(bytes32(0), hex"dead", packed);
    }

    function test_commitment_verify_verifierRejects() public {
        mockVerifier.setResult(false);

        uint256[] memory vals = new uint256[](3);
        vals[0] = 1; // circuitPassed = true but verifier rejects
        vals[1] = 42;
        vals[2] = 100;
        bytes memory packed = _packSignals(vals);

        bool result = commitment.verify(bytes32(0), hex"dead", packed);
        assertFalse(result);
    }

    /* ========================================================
                       COMPLIANCE ADAPTER (16 signals, circuitPassed check)
       ======================================================== */

    function test_compliance_verify_success() public {
        uint256[] memory vals = new uint256[](16);
        vals[0] = 1; // circuitPassed
        for (uint256 i = 1; i < 16; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = compliance.verify(bytes32(0), hex"dead", packed);
        assertTrue(result);
    }

    function test_compliance_verify_circuitFailed() public {
        uint256[] memory vals = new uint256[](16);
        vals[0] = 0; // circuitPassed = false
        for (uint256 i = 1; i < 16; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = compliance.verify(bytes32(0), hex"dead", packed);
        assertFalse(result);
    }

    function test_compliance_verify_wrongSignalCount() public {
        uint256[] memory vals = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("SIG_COUNT_MISMATCH: COMPLIANCE");
        compliance.verify(bytes32(0), hex"dead", packed);
    }

    /* ========================================================
                       CROSS-CHAIN ADAPTER (7 signals, circuitPassed check)
       ======================================================== */

    function test_crossChain_verify_success() public {
        uint256[] memory vals = new uint256[](7);
        vals[0] = 1;
        for (uint256 i = 1; i < 7; i++) vals[i] = i * 10;
        bytes memory packed = _packSignals(vals);

        bool result = crossChain.verify(bytes32(0), hex"dead", packed);
        assertTrue(result);
    }

    function test_crossChain_verify_circuitFailed() public {
        uint256[] memory vals = new uint256[](7);
        vals[0] = 0; // fail
        for (uint256 i = 1; i < 7; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = crossChain.verify(bytes32(0), hex"dead", packed);
        assertFalse(result);
    }

    function test_crossChain_verify_wrongSignalCount() public {
        uint256[] memory vals = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("SIG_COUNT_MISMATCH: CROSS_CHAIN");
        crossChain.verify(bytes32(0), hex"dead", packed);
    }

    /* ========================================================
                       POLICY ADAPTER (4 signals, circuitPassed check)
       ======================================================== */

    function test_policy_verify_success() public {
        uint256[] memory vals = new uint256[](4);
        vals[0] = 1;
        vals[1] = 10;
        vals[2] = 20;
        vals[3] = 30;
        bytes memory packed = _packSignals(vals);

        bool result = policy.verify(bytes32(0), hex"dead", packed);
        assertTrue(result);
    }

    function test_policy_verify_circuitFailed() public {
        uint256[] memory vals = new uint256[](4);
        vals[0] = 0;
        vals[1] = 10;
        vals[2] = 20;
        vals[3] = 30;
        bytes memory packed = _packSignals(vals);

        bool result = policy.verify(bytes32(0), hex"dead", packed);
        assertFalse(result);
    }

    function test_policy_verify_wrongSignalCount() public {
        uint256[] memory vals = new uint256[](3);
        for (uint256 i = 0; i < 3; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("SIG_COUNT_MISMATCH: POLICY");
        policy.verify(bytes32(0), hex"dead", packed);
    }

    /* ========================================================
                       PRIVATE TRANSFER ADAPTER (16 signals, NO circuitPassed check)
       ======================================================== */

    function test_privateTx_verify_success() public {
        uint256[] memory vals = new uint256[](16);
        for (uint256 i = 0; i < 16; i++) vals[i] = i + 1;
        bytes memory packed = _packSignals(vals);

        bool result = privateTx.verify(bytes32(0), hex"dead", packed);
        assertTrue(result);
    }

    function test_privateTx_verify_noCircuitPassedGuard() public {
        // Signal[0] = 0 should still pass through to verifier (no circuitPassed check)
        uint256[] memory vals = new uint256[](16);
        vals[0] = 0; // Would fail in commitment/compliance adapters, but not here
        for (uint256 i = 1; i < 16; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = privateTx.verify(bytes32(0), hex"dead", packed);
        assertTrue(result); // Passes through — no circuitPassed guard
    }

    function test_privateTx_verify_wrongSignalCount() public {
        uint256[] memory vals = new uint256[](10);
        for (uint256 i = 0; i < 10; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("SIG_COUNT_MISMATCH: PRIVATE_TRANSFER");
        privateTx.verify(bytes32(0), hex"dead", packed);
    }

    /* ========================================================
                       SWAP PROOF ADAPTER (11 signals, NO circuitPassed check)
       ======================================================== */

    function test_swap_verify_success() public {
        uint256[] memory vals = new uint256[](11);
        for (uint256 i = 0; i < 11; i++) vals[i] = i + 1;
        bytes memory packed = _packSignals(vals);

        bool result = swap.verify(bytes32(0), hex"dead", packed);
        assertTrue(result);
    }

    function test_swap_verify_noCircuitPassedGuard() public {
        uint256[] memory vals = new uint256[](11);
        vals[0] = 0; // No guard check
        for (uint256 i = 1; i < 11; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = swap.verify(bytes32(0), hex"dead", packed);
        assertTrue(result); // Passes through — no circuitPassed guard
    }

    function test_swap_verify_wrongSignalCount() public {
        uint256[] memory vals = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("SIG_COUNT_MISMATCH: SWAP_PROOF");
        swap.verify(bytes32(0), hex"dead", packed);
    }

    /* ========================================================
                   INHERITED BASE CLASS FUNCTIONS
       ======================================================== */

    function test_verifySingle_delegatesToNoirVerifier() public {
        // verifySingle wraps single input into bytes32[] and calls _verifyNoir
        // _verifyNoir checks length == getPublicInputCount(), so verifySingle
        // only works if adapter expects 1 input — none do; all should revert
        vm.expectRevert("SIG_COUNT_MISMATCH");
        commitment.verifySingle(hex"dead", 42);
    }

    function test_verify_uint256Array_delegatesToNoirVerifier() public {
        // verify(bytes, uint256[]) converts to bytes32[] and calls _verifyNoir
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = 1;
        inputs[1] = 42;
        inputs[2] = 100;

        bool result = commitment.verify(hex"dead", inputs);
        assertTrue(result);
    }

    function test_verify_uint256Array_wrongCount() public {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = 42;

        vm.expectRevert("SIG_COUNT_MISMATCH");
        commitment.verify(hex"dead", inputs);
    }

    function test_verifyProof_delegatesViaVerify() public {
        // verifyProof(bytes, bytes) calls this.verify(bytes32(0), proof, publicInputs)
        uint256[] memory vals = new uint256[](3);
        vals[0] = 1;
        vals[1] = 42;
        vals[2] = 100;
        bytes memory packed = _packSignals(vals);

        bool result = commitment.verifyProof(hex"dead", packed);
        assertTrue(result);
    }

    /* ========================================================
                       FIELD OVERFLOW CHECK
       ======================================================== */

    function test_prepareSignals_fieldOverflow() public {
        // Any signal >= BN254 scalar field should revert with FIELD_OVERFLOW
        uint256 FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256[] memory vals = new uint256[](3);
        vals[0] = 1;
        vals[1] = FIELD_MOD; // overflow
        vals[2] = 100;
        bytes memory packed = _packSignals(vals);

        vm.expectRevert("FIELD_OVERFLOW");
        commitment.verify(bytes32(0), hex"dead", packed);
    }

    /* ========================================================
                       FUZZ TESTS
       ======================================================== */

    function testFuzz_commitment_circuitPassedGuard(uint256 signal0) public {
        uint256 FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        vm.assume(signal0 < FIELD_MOD);

        uint256[] memory vals = new uint256[](3);
        vals[0] = signal0;
        vals[1] = 42;
        vals[2] = 100;
        bytes memory packed = _packSignals(vals);

        bool result = commitment.verify(bytes32(0), hex"dead", packed);
        if (signal0 == 1) {
            assertTrue(result);
        } else {
            assertFalse(result); // circuitPassed check rejects non-1 values
        }
    }

    function testFuzz_privateTx_noGuard(uint256 signal0) public {
        uint256 FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        vm.assume(signal0 < FIELD_MOD);

        uint256[] memory vals = new uint256[](16);
        vals[0] = signal0;
        for (uint256 i = 1; i < 16; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = privateTx.verify(bytes32(0), hex"dead", packed);
        assertTrue(result); // Always passes through (no guard)
    }

    function testFuzz_swap_noGuard(uint256 signal0) public {
        uint256 FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        vm.assume(signal0 < FIELD_MOD);

        uint256[] memory vals = new uint256[](11);
        vals[0] = signal0;
        for (uint256 i = 1; i < 11; i++) vals[i] = i;
        bytes memory packed = _packSignals(vals);

        bool result = swap.verify(bytes32(0), hex"dead", packed);
        assertTrue(result); // Always passes through (no guard)
    }
}
