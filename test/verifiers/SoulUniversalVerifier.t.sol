// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SoulUniversalVerifier} from "../../contracts/verifiers/SoulUniversalVerifier.sol";

/// @dev Mock verifier for Groth16 (verifyProof selector)
contract MockGroth16Verifier {
    bool public returnVal = true;

    function setReturn(bool _val) external {
        returnVal = _val;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return returnVal;
    }
}

/// @dev Mock verifier for Noir/SP1/generic (verify(bytes32,bytes,bytes) selector)
contract MockGenericVerifier {
    bool public returnVal = true;

    function setReturn(bool _val) external {
        returnVal = _val;
    }

    function verify(
        bytes32,
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return returnVal;
    }
}

/// @dev Mock verifier registry that maps circuit hashes to verifiers
contract MockVerifierRegistry {
    mapping(bytes32 => address) public verifiers;

    function setVerifier(bytes32 circuitHash, address verifier) external {
        verifiers[circuitHash] = verifier;
    }

    function getVerifier(bytes32 circuitHash) external view returns (address) {
        return verifiers[circuitHash];
    }
}

contract SoulUniversalVerifierTest is Test {
    SoulUniversalVerifier public verifier;
    MockGroth16Verifier public groth16Verifier;
    MockGenericVerifier public noirVerifier;
    MockGenericVerifier public sp1Verifier;

    address public owner;
    address public user1;

    function setUp() public {
        owner = address(this);
        user1 = makeAddr("user1");

        verifier = new SoulUniversalVerifier();
        groth16Verifier = new MockGroth16Verifier();
        noirVerifier = new MockGenericVerifier();
        sp1Verifier = new MockGenericVerifier();

        // Register verifiers
        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.Groth16,
            address(groth16Verifier),
            300_000
        );
        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.Noir,
            address(noirVerifier),
            400_000
        );
        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.SP1,
            address(sp1Verifier),
            500_000
        );
    }

    // ──────── Helpers ────────

    function _makeNoirProof(
        bytes32 vkey,
        bytes memory publicInputs
    ) internal pure returns (SoulUniversalVerifier.UniversalProof memory) {
        return
            SoulUniversalVerifier.UniversalProof({
                system: SoulUniversalVerifier.ProofSystem.Noir,
                vkeyOrCircuitHash: vkey,
                publicInputsHash: keccak256(publicInputs),
                proof: hex"deadbeef"
            });
    }

    function _makeSP1Proof(
        bytes32 vkey,
        bytes memory publicInputs
    ) internal pure returns (SoulUniversalVerifier.UniversalProof memory) {
        return
            SoulUniversalVerifier.UniversalProof({
                system: SoulUniversalVerifier.ProofSystem.SP1,
                vkeyOrCircuitHash: vkey,
                publicInputsHash: keccak256(publicInputs),
                proof: hex"cafe"
            });
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_Owner() public view {
        assertEq(verifier.owner(), owner);
    }

    function test_Constructor_DefaultGasLimit() public view {
        assertEq(verifier.defaultGasLimit(), 500_000);
    }

    function test_Constructor_TotalVerifiedZero() public view {
        assertEq(verifier.totalVerified(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                     VERIFIER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterVerifier() public view {
        SoulUniversalVerifier.VerifierConfig memory config = verifier
            .getVerifier(SoulUniversalVerifier.ProofSystem.Groth16);

        assertEq(config.verifier, address(groth16Verifier));
        assertTrue(config.active);
        assertEq(config.gasLimit, 300_000);
    }

    function test_RegisterVerifier_EmitsEvent() public {
        MockGenericVerifier plonkVerifier = new MockGenericVerifier();

        vm.expectEmit(true, false, false, true);
        emit SoulUniversalVerifier.VerifierRegistered(
            SoulUniversalVerifier.ProofSystem.Plonk,
            address(plonkVerifier)
        );

        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.Plonk,
            address(plonkVerifier),
            200_000
        );
    }

    function test_RegisterVerifier_RevertZeroAddress() public {
        vm.expectRevert(SoulUniversalVerifier.InvalidVerifier.selector);
        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.Plonk,
            address(0),
            200_000
        );
    }

    function test_RegisterVerifier_RevertNotOwner() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSignature(
                "OwnableUnauthorizedAccount(address)",
                user1
            )
        );
        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.Plonk,
            address(noirVerifier),
            200_000
        );
    }

    function test_RegisterVerifier_RevertInvalidGasLimit() public {
        // Note: registerVerifier does NOT revert on gasLimit=0,
        // it falls back to defaultGasLimit. So test that behavior instead.
        verifier.registerVerifier(
            SoulUniversalVerifier.ProofSystem.Plonk,
            address(noirVerifier),
            0
        );
        SoulUniversalVerifier.VerifierConfig memory config = verifier
            .getVerifier(SoulUniversalVerifier.ProofSystem.Plonk);
        assertEq(config.gasLimit, verifier.defaultGasLimit());
    }

    function test_DeactivateVerifier() public {
        verifier.deactivateVerifier(
            SoulUniversalVerifier.ProofSystem.Groth16
        );

        SoulUniversalVerifier.VerifierConfig memory config = verifier
            .getVerifier(SoulUniversalVerifier.ProofSystem.Groth16);
        assertFalse(config.active);
    }

    function test_DeactivateVerifier_EmitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit SoulUniversalVerifier.VerifierDeactivated(
            SoulUniversalVerifier.ProofSystem.Noir
        );
        verifier.deactivateVerifier(SoulUniversalVerifier.ProofSystem.Noir);
    }

    function test_UpdateGasLimit() public {
        verifier.updateGasLimit(
            SoulUniversalVerifier.ProofSystem.Noir,
            999_999
        );

        SoulUniversalVerifier.VerifierConfig memory config = verifier
            .getVerifier(SoulUniversalVerifier.ProofSystem.Noir);
        assertEq(config.gasLimit, 999_999);
    }

    function test_SetVerifierRegistry() public {
        MockVerifierRegistry reg = new MockVerifierRegistry();
        verifier.setVerifierRegistry(address(reg));
        assertEq(verifier.verifierRegistry(), address(reg));
    }

    /*//////////////////////////////////////////////////////////////
                        PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_Verify_Noir() public {
        bytes32 vkey = keccak256("noir_vkey");
        bytes memory publicInputs = hex"aabbccdd";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            vkey,
            publicInputs
        );

        (bool valid, uint256 gasUsed) = verifier.verify(proof, publicInputs);
        assertTrue(valid);
        assertGt(gasUsed, 0);
    }

    function test_Verify_SP1() public {
        bytes32 vkey = keccak256("sp1_vkey");
        bytes memory publicInputs = hex"11223344";

        SoulUniversalVerifier.UniversalProof memory proof = _makeSP1Proof(
            vkey,
            publicInputs
        );

        (bool valid, ) = verifier.verify(proof, publicInputs);
        assertTrue(valid);
    }

    function test_Verify_MarksDeduplicated() public {
        bytes32 vkey = keccak256("dedup_vkey");
        bytes memory publicInputs = hex"ded0";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            vkey,
            publicInputs
        );

        verifier.verify(proof, publicInputs);

        // Compute proof hash same way contract does (abi.encode, keccak of proof)
        bytes32 proofHash = keccak256(
            abi.encode(
                proof.system,
                proof.vkeyOrCircuitHash,
                proof.publicInputsHash,
                keccak256(proof.proof)
            )
        );
        assertTrue(verifier.isVerified(proofHash));
    }

    function test_Verify_RevertAlreadyVerified() public {
        bytes32 vkey = keccak256("already_vkey");
        bytes memory publicInputs = hex"a1ead0";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            vkey,
            publicInputs
        );

        verifier.verify(proof, publicInputs);

        vm.expectRevert(SoulUniversalVerifier.AlreadyVerified.selector);
        verifier.verify(proof, publicInputs);
    }

    function test_Verify_RevertInactiveVerifier() public {
        verifier.deactivateVerifier(SoulUniversalVerifier.ProofSystem.Noir);

        bytes memory publicInputs = hex"1ac71e";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            keccak256("inactive_vkey"),
            publicInputs
        );

        vm.expectRevert(SoulUniversalVerifier.VerifierNotActive.selector);
        verifier.verify(proof, publicInputs);
    }

    function test_Verify_RevertUnregisteredVerifier() public {
        bytes memory publicInputs = hex"0e9d";

        SoulUniversalVerifier.UniversalProof memory proof = SoulUniversalVerifier
            .UniversalProof({
                system: SoulUniversalVerifier.ProofSystem.Plonk, // Not registered
                vkeyOrCircuitHash: keccak256("unreg_vkey"),
                publicInputsHash: keccak256(publicInputs),
                proof: hex"aa"
            });

        // Unregistered verifier has active=false by default, hits VerifierNotActive first
        vm.expectRevert(SoulUniversalVerifier.VerifierNotActive.selector);
        verifier.verify(proof, publicInputs);
    }

    function test_Verify_RevertPublicInputsMismatch() public {
        bytes memory publicInputs = hex"001a";
        bytes memory wrongInputs = hex"002b";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            keccak256("mismatch_vkey"),
            publicInputs // hash matches publicInputs
        );

        vm.expectRevert(SoulUniversalVerifier.PublicInputsMismatch.selector);
        verifier.verify(proof, wrongInputs); // but we pass wrongInputs
    }

    function test_Verify_FailedVerification() public {
        noirVerifier.setReturn(false);

        bytes memory publicInputs = hex"fa11";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            keccak256("fail_vkey"),
            publicInputs
        );

        (bool valid, ) = verifier.verify(proof, publicInputs);
        assertFalse(valid);
    }

    function test_Verify_IncrementsTotalVerified() public {
        bytes memory publicInputs = hex"c000";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            keccak256("count_vkey"),
            publicInputs
        );

        verifier.verify(proof, publicInputs);
        assertEq(verifier.totalVerified(), 1);
    }

    function test_Verify_EmitsEvent() public {
        bytes memory publicInputs = hex"e0e0";

        SoulUniversalVerifier.UniversalProof memory proof = _makeNoirProof(
            keccak256("event_vkey"),
            publicInputs
        );

        vm.recordLogs();
        verifier.verify(proof, publicInputs);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                keccak256("ProofVerified(bytes32,uint8,uint256)")
            ) {
                found = true;
                break;
            }
        }
        assertTrue(found, "ProofVerified event not emitted");
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_BatchVerify() public {
        SoulUniversalVerifier.UniversalProof[]
            memory proofs = new SoulUniversalVerifier.UniversalProof[](2);

        bytes memory pi1 = hex"ba0c01";
        bytes memory pi2 = hex"ba0c02";

        proofs[0] = _makeNoirProof(keccak256("vk1"), pi1);
        proofs[1] = _makeSP1Proof(keccak256("vk2"), pi2);

        bytes[] memory publicInputsArray = new bytes[](2);
        publicInputsArray[0] = pi1;
        publicInputsArray[1] = pi2;

        bool[] memory results = verifier.batchVerify(
            proofs,
            publicInputsArray
        );

        assertEq(results.length, 2);
        assertTrue(results[0]);
        assertTrue(results[1]);
        assertEq(verifier.totalVerified(), 2);
    }

    function test_BatchVerify_RevertLengthMismatch() public {
        SoulUniversalVerifier.UniversalProof[]
            memory proofs = new SoulUniversalVerifier.UniversalProof[](2);

        proofs[0] = _makeNoirProof(keccak256("vk1"), hex"0001");
        proofs[1] = _makeNoirProof(keccak256("vk2"), hex"0002");

        bytes[] memory publicInputsArray = new bytes[](1); // Mismatch
        publicInputsArray[0] = hex"0001";

        vm.expectRevert(SoulUniversalVerifier.LengthMismatch.selector);
        verifier.batchVerify(proofs, publicInputsArray);
    }

    function test_BatchVerify_PartialFailure() public {
        noirVerifier.setReturn(false);

        SoulUniversalVerifier.UniversalProof[]
            memory proofs = new SoulUniversalVerifier.UniversalProof[](2);

        bytes memory pi1 = hex"aa0001";
        bytes memory pi2 = hex"bb0002";

        proofs[0] = _makeNoirProof(keccak256("pvk1"), pi1);
        proofs[1] = _makeSP1Proof(keccak256("pvk2"), pi2);

        bytes[] memory publicInputsArray = new bytes[](2);
        publicInputsArray[0] = pi1;
        publicInputsArray[1] = pi2;

        bool[] memory results = verifier.batchVerify(
            proofs,
            publicInputsArray
        );

        assertFalse(results[0]); // Noir fails
        assertTrue(results[1]); // SP1 passes
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_IsVerified_Default() public view {
        assertFalse(verifier.isVerified(keccak256("nope")));
    }

    function test_GetVerifier_Unregistered() public view {
        SoulUniversalVerifier.VerifierConfig memory config = verifier
            .getVerifier(SoulUniversalVerifier.ProofSystem.Recursive);

        assertEq(config.verifier, address(0));
        assertFalse(config.active);
        assertEq(config.gasLimit, 0);
        assertEq(config.totalVerified, 0);
    }

    function test_GetStats() public view {
        (
            SoulUniversalVerifier.ProofSystem[] memory systems,
            uint256[] memory verified,
            bool[] memory active
        ) = verifier.getStats();

        assertEq(systems.length, 8);
        assertEq(verified.length, 8);
        assertEq(active.length, 8);

        // Groth16, Noir, SP1 should be active
        assertTrue(active[0]); // Groth16
        assertTrue(active[2]); // Noir
        assertTrue(active[3]); // SP1
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_Verify_UniqueProofs(bytes32 vkey, bytes16 salt) public {
        vm.assume(vkey != bytes32(0));

        bytes memory publicInputs = abi.encodePacked(vkey, salt);

        SoulUniversalVerifier.UniversalProof memory proof = SoulUniversalVerifier
            .UniversalProof({
                system: SoulUniversalVerifier.ProofSystem.Noir,
                vkeyOrCircuitHash: vkey,
                publicInputsHash: keccak256(publicInputs),
                proof: abi.encodePacked(salt)
            });

        (bool valid, ) = verifier.verify(proof, publicInputs);
        assertTrue(valid);
    }

    function testFuzz_UpdateGasLimit(uint256 gasLimit) public {
        gasLimit = bound(gasLimit, 1, 10_000_000);

        verifier.updateGasLimit(
            SoulUniversalVerifier.ProofSystem.Noir,
            gasLimit
        );

        SoulUniversalVerifier.VerifierConfig memory config = verifier
            .getVerifier(SoulUniversalVerifier.ProofSystem.Noir);
        assertEq(config.gasLimit, gasLimit);
    }
}
