// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EVMUniversalAdapter} from "../../contracts/adapters/EVMUniversalAdapter.sol";
import {IUniversalChainAdapter} from "../../contracts/interfaces/IUniversalChainAdapter.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";
import {UniversalChainRegistry} from "../../contracts/libraries/UniversalChainRegistry.sol";

/// @notice Mock verifier that accepts all proofs
contract AcceptAllVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure override returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 4;
    }

    function getVerificationKeyHash() external pure returns (bytes32) {
        return bytes32(0);
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

/// @notice Mock verifier that rejects all proofs
contract RejectAllVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure override returns (bool) {
        return false;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure override returns (bool) {
        return false;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure override returns (bool) {
        return false;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 4;
    }

    function getVerificationKeyHash() external pure returns (bytes32) {
        return bytes32(0);
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

/// @title EVMUniversalAdapterFuzz
/// @notice Fuzz tests for EVMUniversalAdapter proof verification and state transfer logic
contract EVMUniversalAdapterFuzz is Test {
    EVMUniversalAdapter public adapter;
    AcceptAllVerifier public acceptVerifier;
    RejectAllVerifier public rejectVerifier;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public operator = makeAddr("operator");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    bytes32 public thisChainId;

    function setUp() public {
        vm.startPrank(admin);

        adapter = new EVMUniversalAdapter(
            admin,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            "Test Chain"
        );

        acceptVerifier = new AcceptAllVerifier();
        rejectVerifier = new RejectAllVerifier();

        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(OPERATOR_ROLE, operator);

        thisChainId = adapter.getUniversalChainId();

        vm.stopPrank();
    }

    // =========================================================================
    // PROOF VERIFICATION DELEGATION TESTS
    // =========================================================================

    /// @notice Fuzz: receiveEncryptedState reverts without registered verifier
    function testFuzz_receiveEncryptedState_revertsWithoutVerifier(
        bytes32 transferId,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"deadbeef",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer);
    }

    /// @notice Fuzz: receiveEncryptedState succeeds with valid verifier
    function testFuzz_receiveEncryptedState_succeedsWithVerifier(
        bytes32 transferId,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);

        // Register accepting verifier
        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"deadbeef",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        bool success = adapter.receiveEncryptedState(transfer);
        assertTrue(success, "Transfer should succeed with valid verifier");
    }

    /// @notice Fuzz: receiveEncryptedState reverts with rejecting verifier
    function testFuzz_receiveEncryptedState_revertsWithRejectingVerifier(
        bytes32 transferId,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);

        // Register rejecting verifier
        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(rejectVerifier)
        );

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"deadbeef",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer);
    }

    // =========================================================================
    // NULLIFIER REPLAY PROTECTION
    // =========================================================================

    /// @notice Fuzz: same nullifier cannot be used twice
    function testFuzz_nullifierReplayPrevention(
        bytes32 transferId1,
        bytes32 transferId2,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);
        vm.assume(transferId1 != transferId2);

        // Register accepting verifier
        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer1 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId1,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"deadbeef",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        adapter.receiveEncryptedState(transfer1);

        // Second transfer with same nullifier should revert
        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer2 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId2,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"deadbeef",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer2);
    }

    // =========================================================================
    // ACCESS CONTROL
    // =========================================================================

    /// @notice Fuzz: non-relayer cannot receive encrypted state
    function testFuzz_accessControl_nonRelayerCannotReceive(
        address caller
    ) public {
        vm.assume(caller != relayer);
        vm.assume(caller != admin);
        vm.assume(caller != address(0));

        // Register accepting verifier
        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: bytes32(uint256(1)),
                sourceChainId: bytes32(uint256(2)),
                destChainId: thisChainId,
                stateCommitment: bytes32(uint256(3)),
                encryptedPayload: hex"deadbeef",
                nullifier: bytes32(uint256(4)),
                newCommitment: bytes32(uint256(5)),
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(caller);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer);
    }

    /// @notice Fuzz: non-operator cannot set proof verifier
    function testFuzz_accessControl_nonOperatorCannotSetVerifier(
        address caller
    ) public {
        vm.assume(caller != operator);
        vm.assume(caller != admin);
        vm.assume(caller != address(0));

        vm.prank(caller);
        vm.expectRevert();
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );
    }

    // =========================================================================
    // STATE COMMITMENT CORRECTNESS
    // =========================================================================

    /// @notice Fuzz: state commitment is correctly stored after transfer
    function testFuzz_stateCommitmentStorage(
        bytes32 transferId,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);

        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"aa",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        adapter.receiveEncryptedState(transfer);

        assertEq(
            adapter.stateCommitments(transferId),
            stateCommitment,
            "State commitment must be stored correctly"
        );
    }

    /// @notice Fuzz: transfer ID replay prevention
    function testFuzz_transferIdReplayPrevention(
        bytes32 transferId,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier1,
        bytes32 nullifier2,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);
        vm.assume(nullifier1 != nullifier2);

        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer1 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"aa",
                nullifier: nullifier1,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        adapter.receiveEncryptedState(transfer1);

        // Same transferId with different nullifier should still revert
        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer2 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"aa",
                nullifier: nullifier2,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer2);
    }

    /// @notice Fuzz: statistics monotonically increase
    function testFuzz_statisticsMonotonic(
        bytes32 transferId,
        bytes32 sourceChainId,
        bytes32 stateCommitment,
        bytes32 nullifier,
        bytes32 newCommitment
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(sourceChainId != thisChainId);

        vm.prank(operator);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );

        (uint256 proofsBefore, uint256 receivedBefore, , uint256 nullifiersBefore) = adapter.getStats();

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: transferId,
                sourceChainId: sourceChainId,
                destChainId: thisChainId,
                stateCommitment: stateCommitment,
                encryptedPayload: hex"aa",
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: hex"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            });

        vm.prank(relayer);
        adapter.receiveEncryptedState(transfer);

        (uint256 proofsAfter, uint256 receivedAfter, , uint256 nullifiersAfter) = adapter.getStats();

        assertGe(receivedAfter, receivedBefore + 1, "Received counter must increase");
        assertGe(nullifiersAfter, nullifiersBefore + 1, "Nullifier counter must increase");
    }
}
