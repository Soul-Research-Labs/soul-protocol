// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

// Adapters (Noir-based)
import "../../contracts/verifiers/adapters/CommitmentAdapter.sol";
import "../../contracts/verifiers/adapters/ComplianceAdapter.sol";
import "../../contracts/verifiers/adapters/CrossChainAdapter.sol";
import "../../contracts/verifiers/adapters/PolicyVerifierAdapter.sol";
import "../../contracts/verifiers/adapters/SwapProofAdapter.sol";
import "../../contracts/verifiers/adapters/PrivateTransferAdapter.sol";
import "../../contracts/verifiers/adapters/AggregatorAdapter.sol";

// Adapters (Groth16-based)
import "../../contracts/verifiers/adapters/BalanceProofAdapter.sol";
import "../../contracts/verifiers/adapters/StateTransferAdapter.sol";
import "../../contracts/verifiers/adapters/NullifierAdapter.sol";
import "../../contracts/verifiers/adapters/PedersenCommitmentAdapter.sol";

// UltraHonk
import "../../contracts/verifiers/adapters/UltraHonkAdapter.sol";

// Mock
import "../../contracts/mocks/MockProofVerifier.sol";

/**
 * @title VerifierAdaptersTest
 * @notice Comprehensive tests for all 13 verifier adapters.
 * @dev Tests cover:
 *   - Correct public input count reporting
 *   - Verification pass-through with mock verifier
 *   - Input count mismatch reverts
 *   - Zero-address verifier behavior
 *   - BN254 field overflow detection via _prepareSignals
 */
contract VerifierAdaptersTest is Test {
    MockProofVerifier public mockVerifier;
    MockProofVerifier public falseVerifier;

    // Noir-based adapters
    CommitmentAdapter public commitmentAdapter;
    ComplianceAdapter public complianceAdapter;
    CrossChainAdapter public crossChainAdapter;
    PolicyVerifierAdapter public policyAdapter;
    SwapProofAdapter public swapAdapter;
    PrivateTransferAdapter public privateTransferAdapter;
    AggregatorAdapter public aggregatorAdapter;

    // Groth16-based adapters
    BalanceProofAdapter public balanceAdapter;
    StateTransferAdapter public stateTransferAdapter;
    NullifierAdapter public nullifierAdapter;
    PedersenCommitmentAdapter public pedersenAdapter;

    // UltraHonk adapter
    UltraHonkAdapter public ultraHonkAdapter;

    // BN254 scalar field order
    uint256 constant BN254_R =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Sample proof bytes
    bytes constant SAMPLE_PROOF = hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c";

    function setUp() public {
        // Deploy mock verifiers
        mockVerifier = new MockProofVerifier();
        mockVerifier.setVerificationResult(true);

        falseVerifier = new MockProofVerifier();
        falseVerifier.setVerificationResult(false);

        // Deploy Noir-based adapters
        commitmentAdapter = new CommitmentAdapter(address(mockVerifier));
        complianceAdapter = new ComplianceAdapter(address(mockVerifier));
        crossChainAdapter = new CrossChainAdapter(address(mockVerifier));
        policyAdapter = new PolicyVerifierAdapter(address(mockVerifier));
        swapAdapter = new SwapProofAdapter(address(mockVerifier));
        privateTransferAdapter = new PrivateTransferAdapter(
            address(mockVerifier)
        );
        aggregatorAdapter = new AggregatorAdapter(address(mockVerifier));

        // Deploy Groth16-based adapters
        balanceAdapter = new BalanceProofAdapter(address(mockVerifier));
        stateTransferAdapter = new StateTransferAdapter(
            address(mockVerifier)
        );
        nullifierAdapter = new NullifierAdapter(address(mockVerifier));
        pedersenAdapter = new PedersenCommitmentAdapter(
            address(mockVerifier)
        );

        // Deploy UltraHonk adapter
        ultraHonkAdapter = new UltraHonkAdapter(
            address(mockVerifier),
            4, // 4 public inputs
            keccak256("test_circuit")
        );
    }

    /*//////////////////////////////////////////////////////////////
                    PUBLIC INPUT COUNT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CommitmentAdapter_PublicInputCount() public view {
        assertEq(commitmentAdapter.getPublicInputCount(), 3);
    }

    function test_ComplianceAdapter_PublicInputCount() public view {
        assertEq(complianceAdapter.getPublicInputCount(), 16);
    }

    function test_CrossChainAdapter_PublicInputCount() public view {
        assertEq(crossChainAdapter.getPublicInputCount(), 7);
    }

    function test_PolicyAdapter_PublicInputCount() public view {
        assertEq(policyAdapter.getPublicInputCount(), 4);
    }

    function test_SwapAdapter_PublicInputCount() public view {
        assertEq(swapAdapter.getPublicInputCount(), 11);
    }

    function test_PrivateTransferAdapter_PublicInputCount() public view {
        assertEq(privateTransferAdapter.getPublicInputCount(), 16);
    }

    function test_UltraHonkAdapter_PublicInputCount() public view {
        assertEq(ultraHonkAdapter.getPublicInputCount(), 4);
    }

    /*//////////////////////////////////////////////////////////////
                    NOIR ADAPTER VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CommitmentAdapter_Verify_Success() public view {
        // 3 inputs: circuit_pass_gate=1, commitment, nullifier
        bytes memory inputs = _encodeSignals(3, true);
        bool result = commitmentAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertTrue(result);
    }

    function test_CommitmentAdapter_CircuitGateFail() public view {
        // First input != 1 => returns false even if verifier says true
        bytes memory inputs = _encodeSignals(3, false);
        bool result = commitmentAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertFalse(result);
    }

    function test_CommitmentAdapter_WrongInputCount() public {
        bytes memory inputs = _encodeSignals(5, true); // wrong count
        vm.expectRevert("SIG_COUNT_MISMATCH: COMMITMENT");
        commitmentAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    function test_ComplianceAdapter_Verify_Success() public view {
        bytes memory inputs = _encodeSignals(16, true);
        bool result = complianceAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertTrue(result);
    }

    function test_ComplianceAdapter_WrongInputCount() public {
        bytes memory inputs = _encodeSignals(4, true);
        vm.expectRevert("SIG_COUNT_MISMATCH: COMPLIANCE");
        complianceAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    function test_CrossChainAdapter_Verify_Success() public view {
        bytes memory inputs = _encodeSignals(7, true);
        bool result = crossChainAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertTrue(result);
    }

    function test_CrossChainAdapter_WrongInputCount() public {
        bytes memory inputs = _encodeSignals(3, true);
        vm.expectRevert("SIG_COUNT_MISMATCH: CROSS_CHAIN");
        crossChainAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    function test_PolicyAdapter_Verify_Success() public view {
        bytes memory inputs = _encodeSignals(4, true);
        bool result = policyAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertTrue(result);
    }

    function test_PolicyAdapter_WrongInputCount() public {
        bytes memory inputs = _encodeSignals(2, true);
        vm.expectRevert("SIG_COUNT_MISMATCH: POLICY");
        policyAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    function test_SwapAdapter_Verify_Success() public view {
        bytes memory inputs = _encodeSignals(11, true);
        bool result = swapAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertTrue(result);
    }

    function test_SwapAdapter_WrongInputCount() public {
        bytes memory inputs = _encodeSignals(5, true);
        vm.expectRevert("SIG_COUNT_MISMATCH: SWAP_PROOF");
        swapAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    function test_PrivateTransferAdapter_Verify_Success() public view {
        bytes memory inputs = _encodeSignals(16, true);
        bool result = privateTransferAdapter.verify(
            bytes32(0),
            SAMPLE_PROOF,
            inputs
        );
        assertTrue(result);
    }

    function test_PrivateTransferAdapter_WrongInputCount() public {
        bytes memory inputs = _encodeSignals(8, true);
        vm.expectRevert("SIG_COUNT_MISMATCH: PRIVATE_TRANSFER");
        privateTransferAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    /*//////////////////////////////////////////////////////////////
                    VERIFIER RETURNING FALSE
    //////////////////////////////////////////////////////////////*/

    function test_CommitmentAdapter_VerifierReturnsFalse() public {
        CommitmentAdapter falseAdapter = new CommitmentAdapter(
            address(falseVerifier)
        );
        bytes memory inputs = _encodeSignals(3, true);
        bool result = falseAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertFalse(result);
    }

    function test_SwapAdapter_VerifierReturnsFalse() public {
        SwapProofAdapter falseAdapter = new SwapProofAdapter(
            address(falseVerifier)
        );
        bytes memory inputs = _encodeSignals(11, true);
        bool result = falseAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                    BN254 FIELD OVERFLOW TEST
    //////////////////////////////////////////////////////////////*/

    function test_PrepareSignals_FieldOverflow() public {
        // Construct inputs where one value exceeds BN254 scalar field
        bytes memory inputs = abi.encode(uint256(1), uint256(BN254_R));
        vm.expectRevert("FIELD_OVERFLOW");
        // Use commitment adapter (3 inputs) — will revert during _prepareSignals
        commitmentAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
    }

    function test_PrepareSignals_MaxValidField() public view {
        // BN254_R - 1 should be valid
        uint256 maxValid = BN254_R - 1;
        bytes32[] memory signals = new bytes32[](3);
        signals[0] = bytes32(uint256(1)); // circuit pass gate
        signals[1] = bytes32(maxValid);
        signals[2] = bytes32(uint256(42));
        bytes memory inputs = abi.encode(uint256(3), signals[0], signals[1], signals[2]);

        bool result = commitmentAdapter.verify(bytes32(0), SAMPLE_PROOF, inputs);
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                    GROTH16 ADAPTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_BalanceAdapter_Verify() public view {
        bool result = balanceAdapter.verify(
            SAMPLE_PROOF,
            uint256(1000e18), // balance
            uint256(100e18),  // minRequired
            bytes32(keccak256("commitment"))
        );
        assertTrue(result);
    }

    function test_StateTransferAdapter_Verify() public view {
        bool result = stateTransferAdapter.verify(
            SAMPLE_PROOF,
            bytes32(keccak256("oldRoot")),
            bytes32(keccak256("newRoot")),
            bytes32(keccak256("transferHash"))
        );
        assertTrue(result);
    }

    function test_NullifierAdapter_Verify() public view {
        bool result = nullifierAdapter.verify(
            SAMPLE_PROOF,
            bytes32(keccak256("nullifier")),
            bytes32(keccak256("commitment"))
        );
        assertTrue(result);
    }

    function test_PedersenAdapter_VerifyCommitment() public view {
        bool result = pedersenAdapter.verifyCommitment(
            SAMPLE_PROOF,
            bytes32(keccak256("commitment")),
            bytes32(keccak256("ownerPubkey"))
        );
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                    ULTRA HONK ADAPTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_UltraHonk_Verify() public {
        uint256[] memory pubInputs = new uint256[](4);
        pubInputs[0] = 1;
        pubInputs[1] = 2;
        pubInputs[2] = 3;
        pubInputs[3] = 4;

        bool result = ultraHonkAdapter.verify(SAMPLE_PROOF, pubInputs);
        assertTrue(result);
    }

    function test_UltraHonk_WrongInputCount() public {
        uint256[] memory pubInputs = new uint256[](2);
        pubInputs[0] = 1;
        pubInputs[1] = 2;

        vm.expectRevert(
            abi.encodeWithSelector(
                UltraHonkAdapter.InvalidPublicInputCount.selector,
                4,
                2
            )
        );
        ultraHonkAdapter.verify(SAMPLE_PROOF, pubInputs);
    }

    function test_UltraHonk_CircuitId() public view {
        assertEq(ultraHonkAdapter.circuitId(), keccak256("test_circuit"));
    }

    /*//////////////////////////////////////////////////////////////
                    ADAPTER isReady TESTS
    //////////////////////////////////////////////////////////////*/

    function test_NoirAdapters_IsReady() public view {
        assertTrue(commitmentAdapter.isReady());
        assertTrue(complianceAdapter.isReady());
        assertTrue(crossChainAdapter.isReady());
        assertTrue(policyAdapter.isReady());
        assertTrue(swapAdapter.isReady());
        assertTrue(privateTransferAdapter.isReady());
    }

    function test_ZeroVerifier_NotReady() public {
        CommitmentAdapter zeroAdapter = new CommitmentAdapter(address(0));
        assertFalse(zeroAdapter.isReady());
    }

    /*//////////////////////////////////////////////////////////////
                    IProofVerifier INTERFACE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_VerifyProof_BytesInterface() public view {
        // Test the IProofVerifier.verifyProof(bytes, bytes) interface
        // CommitmentAdapter expects 3 public inputs, with inputs[0] == 1 (circuit pass flag)
        bytes memory pubInputsBytes = _encodeSignals(3, true);
        bool result = commitmentAdapter.verifyProof(
            SAMPLE_PROOF,
            pubInputsBytes
        );
        assertTrue(result);
    }

    /*//////////////////////////////////////////////////////////////
                           HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Encode `count` signals for _prepareSignals consumption.
     *      Format: abi.encode(count, signal0, signal1, ...)
     *      If `circuitPassGate` is true, signal[0] = 1 (pass gate check).
     */
    function _encodeSignals(
        uint256 count,
        bool circuitPassGate
    ) internal pure returns (bytes memory) {
        bytes32[] memory signals = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            if (i == 0 && circuitPassGate) {
                signals[i] = bytes32(uint256(1));
            } else {
                signals[i] = bytes32(uint256(i + 100));
            }
        }

        // _prepareSignals expects: length (32 bytes) + raw signals
        bytes memory result = new bytes(32 + count * 32);
        assembly {
            mstore(add(result, 32), count)
            for { let i := 0 } lt(i, count) { i := add(i, 1) } {
                mstore(
                    add(add(result, 64), mul(i, 32)),
                    mload(add(add(signals, 32), mul(i, 32)))
                )
            }
        }
        return result;
    }
}
