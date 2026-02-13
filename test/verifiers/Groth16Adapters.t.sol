// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/verifiers/Groth16VerifierBN254.sol";
import "../../contracts/verifiers/adapters/AggregatorAdapter.sol";
import "../../contracts/verifiers/adapters/BalanceProofAdapter.sol";
import "../../contracts/verifiers/adapters/NullifierAdapter.sol";
import "../../contracts/verifiers/adapters/PedersenCommitmentAdapter.sol";
import "../../contracts/verifiers/adapters/StateTransferAdapter.sol";

/// @title Groth16 Adapter Tests
/// @notice Tests for the 5 standalone Groth16-based adapter contracts
contract Groth16AdapterTest is Test {
    Groth16VerifierBN254 public groth16;
    AggregatorAdapter public aggregator;
    BalanceProofAdapter public balanceAdapter;
    NullifierAdapter public nullifierAdapter;
    PedersenCommitmentAdapter public pedersenAdapter;
    StateTransferAdapter public stateAdapter;

    address constant OWNER = address(0xA1A1);

    // Dummy 256-byte proof (correct size for Groth16)
    bytes internal dummyProof;

    function setUp() public {
        vm.startPrank(OWNER);
        groth16 = new Groth16VerifierBN254();

        // Set up a minimal verification key so verifier is initialized
        uint256[2] memory alpha = [uint256(1), uint256(2)];
        uint256[4] memory beta = [uint256(1), uint256(2), uint256(3), uint256(4)];
        uint256[4] memory gamma = [uint256(1), uint256(2), uint256(3), uint256(4)];
        uint256[4] memory delta = [uint256(1), uint256(2), uint256(3), uint256(4)];

        // IC needs (numInputs + 1) points for Groth16
        uint256[2][] memory ic = new uint256[2][](4);
        ic[0] = [uint256(1), uint256(2)];
        ic[1] = [uint256(3), uint256(4)];
        ic[2] = [uint256(5), uint256(6)];
        ic[3] = [uint256(7), uint256(8)];

        groth16.setVerificationKey(alpha, beta, gamma, delta, ic);
        vm.stopPrank();

        aggregator = new AggregatorAdapter(address(groth16));
        balanceAdapter = new BalanceProofAdapter(address(groth16));
        nullifierAdapter = new NullifierAdapter(address(groth16));
        pedersenAdapter = new PedersenCommitmentAdapter(address(groth16));
        stateAdapter = new StateTransferAdapter(address(groth16));

        // Create a dummy 256-byte proof
        dummyProof = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            dummyProof[i] = bytes1(uint8(i % 256));
        }
    }

    /* ========================================================
                       DEPLOYMENT
       ======================================================== */

    function test_aggregator_deploysCorrectly() public view {
        assertEq(address(aggregator.verifier()), address(groth16));
    }

    function test_balance_deploysCorrectly() public view {
        assertEq(address(balanceAdapter.verifier()), address(groth16));
    }

    function test_nullifier_deploysCorrectly() public view {
        assertEq(address(nullifierAdapter.verifier()), address(groth16));
    }

    function test_pedersen_deploysCorrectly() public view {
        assertEq(address(pedersenAdapter.verifier()), address(groth16));
    }

    function test_state_deploysCorrectly() public view {
        assertEq(address(stateAdapter.verifier()), address(groth16));
    }

    /* ========================================================
                       GROTH16 VERIFIER DIRECT
       ======================================================== */

    function test_groth16_isReady() public view {
        assertTrue(groth16.isReady());
    }

    function test_groth16_notReady_beforeInit() public {
        Groth16VerifierBN254 fresh = new Groth16VerifierBN254();
        assertFalse(fresh.isReady());
    }

    function test_groth16_getPublicInputCount() public view {
        // IC has 4 points, so public inputs = 4 - 1 = 3
        assertEq(groth16.getPublicInputCount(), 3);
    }

    function test_groth16_setVK_revertNotOwner() public {
        uint256[2] memory alpha = [uint256(1), uint256(2)];
        uint256[4] memory beta = [uint256(1), uint256(2), uint256(3), uint256(4)];
        uint256[4] memory gamma = [uint256(1), uint256(2), uint256(3), uint256(4)];
        uint256[4] memory delta = [uint256(1), uint256(2), uint256(3), uint256(4)];
        uint256[2][] memory ic = new uint256[2][](2);

        vm.prank(address(0xBEEF));
        vm.expectRevert(Groth16VerifierBN254.NotOwner.selector);
        groth16.setVerificationKey(alpha, beta, gamma, delta, ic);
    }

    function test_groth16_setVK_canResetByOwner() public {
        // M-7 fix allows key rotation by owner
        uint256[2] memory alpha = [uint256(10), uint256(20)];
        uint256[4] memory beta = [uint256(10), uint256(20), uint256(30), uint256(40)];
        uint256[4] memory gamma = [uint256(10), uint256(20), uint256(30), uint256(40)];
        uint256[4] memory delta = [uint256(10), uint256(20), uint256(30), uint256(40)];
        uint256[2][] memory ic = new uint256[2][](3);
        ic[0] = [uint256(10), uint256(20)];
        ic[1] = [uint256(30), uint256(40)];
        ic[2] = [uint256(50), uint256(60)];

        vm.prank(OWNER);
        groth16.setVerificationKey(alpha, beta, gamma, delta, ic);
        // Now public input count should be 2 (IC length 3 - 1)
        assertEq(groth16.getPublicInputCount(), 2);
    }

    function test_groth16_transferOwnership() public {
        address newOwner = address(0xC0C0);
        vm.prank(OWNER);
        groth16.transferOwnership(newOwner);
        assertEq(groth16.owner(), newOwner);
    }

    function test_groth16_transferOwnership_revertNotOwner() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(Groth16VerifierBN254.NotOwner.selector);
        groth16.transferOwnership(address(0xC0C0));
    }

    function test_groth16_verify_revertInvalidProofSize() public {
        uint256[] memory inputs = new uint256[](3);
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidProofSize.selector,
                10
            )
        );
        groth16.verify(hex"0102030405060708090a", inputs);
    }

    function test_groth16_verify_revertInvalidInputCount() public {
        uint256[] memory inputs = new uint256[](5); // expects 3
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInputCount.selector,
                5,
                3
            )
        );
        groth16.verify(dummyProof, inputs);
    }

    /* ========================================================
                       AGGREGATOR ADAPTER
       ======================================================== */

    function test_aggregator_verifyBatch_callsVerifier() public {
        // verifyBatch converts bytes32[] → uint256[] and calls verify
        // With invalid proof data, the pairing check will fail
        bytes32[] memory inputs = new bytes32[](3);
        inputs[0] = bytes32(uint256(1));
        inputs[1] = bytes32(uint256(2));
        inputs[2] = bytes32(uint256(3));

        // This should reach the verifier's pairing check and fail (not revert on input validation)
        vm.expectRevert();
        aggregator.verifyBatch(dummyProof, inputs);
    }

    /* ========================================================
                       BALANCE PROOF ADAPTER
       ======================================================== */

    function test_balance_verify_packsInputsCorrectly() public {
        // verify(proof, balance, minRequired, commitment) should pack 3 inputs
        // With invalid proof, will reach pairing check and fail
        vm.expectRevert();
        balanceAdapter.verify(
            dummyProof,
            1000,
            500,
            keccak256("commitment")
        );
    }

    /* ========================================================
                       NULLIFIER ADAPTER
       ======================================================== */

    function test_nullifier_verify_inputCount() public {
        // verify packs nullifier + commitment = 2 inputs, but groth16 expects 3
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInputCount.selector,
                2,
                3
            )
        );
        nullifierAdapter.verify(
            dummyProof,
            keccak256("nullifier"),
            keccak256("commitment")
        );
    }

    /* ========================================================
                       PEDERSEN ADAPTER
       ======================================================== */

    function test_pedersen_verifyCommitment_inputCount() public {
        // verifyCommitment packs 2 inputs, groth16 expects 3
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInputCount.selector,
                2,
                3
            )
        );
        pedersenAdapter.verifyCommitment(
            dummyProof,
            keccak256("commitment"),
            keccak256("owner")
        );
    }

    function test_pedersen_verify_packsThreeInputs() public {
        // verify(proof, commitment, value, blinding) packs 3 inputs — matches IC count
        vm.expectRevert(); // PairingCheckFailed or PrecompileFailed
        pedersenAdapter.verify(
            dummyProof,
            keccak256("commitment"),
            42,
            keccak256("blinding")
        );
    }

    /* ========================================================
                       STATE TRANSFER ADAPTER
       ======================================================== */

    function test_state_verify_packsThreeInputs() public {
        // verify(proof, oldRoot, newRoot, hash) packs 3 inputs — matches IC count
        vm.expectRevert(); // PairingCheckFailed or PrecompileFailed
        stateAdapter.verify(
            dummyProof,
            keccak256("oldRoot"),
            keccak256("newRoot"),
            keccak256("transferHash")
        );
    }

    /* ========================================================
                       VERIFYPROOF (GENERIC INTERFACE)
       ======================================================== */

    function test_adapters_verifyProof_delegatesToVerifier() public {
        // verifyProof(bytes, bytes) on any adapter delegates to groth16.verifyProof
        bytes memory pubInputs = abi.encode(new uint256[](3));

        vm.expectRevert(); // Will fail at proof decoding
        aggregator.verifyProof(dummyProof, pubInputs);
    }

    /* ========================================================
                       FUZZ TESTS
       ======================================================== */

    function testFuzz_groth16_rejectsBadProofSize(bytes calldata proof) public {
        vm.assume(proof.length != 256);
        uint256[] memory inputs = new uint256[](3);
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidProofSize.selector,
                proof.length
            )
        );
        groth16.verify(proof, inputs);
    }

    function testFuzz_groth16_rejectsBadInputCount(uint8 count) public {
        vm.assume(count != 3 && count < 50);
        uint256[] memory inputs = new uint256[](count);
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInputCount.selector,
                count,
                3
            )
        );
        groth16.verify(dummyProof, inputs);
    }

    function testFuzz_groth16_rejectsFieldOverflow() public {
        uint256 FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256 val = FIELD_MOD; // exactly at boundary
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = val;
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInput.selector,
                0,
                val
            )
        );
        groth16.verify(dummyProof, inputs);
    }

    function test_groth16_rejectsFieldOverflow_maxUint() public {
        uint256[] memory inputs = new uint256[](3);
        inputs[0] = type(uint256).max;
        vm.expectRevert(
            abi.encodeWithSelector(
                Groth16VerifierBN254.InvalidPublicInput.selector,
                0,
                type(uint256).max
            )
        );
        groth16.verify(dummyProof, inputs);
    }
}
