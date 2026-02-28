// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/experimental/verifiers/ZaseonNewZKVerifiers.sol";

/// @dev Mock SP1 Gateway
contract MockSP1Gateway {
    bool public result;

    constructor(bool _result) {
        result = _result;
    }

    function verifyProof(
        bytes32,
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return result;
    }
}

contract ZaseonNewZKVerifiersTest is Test {
    ZaseonSP1Verifier public sp1;
    ZaseonPlonky3Verifier public plonky3;
    ZaseonJoltVerifier public jolt;
    ZaseonBiniusVerifier public binius;

    MockSP1Gateway public gateway;

    address owner = address(0xAD01);
    address alice = address(0xBEEF);

    // Shared test data
    bytes32 constant VKEY = keccak256("vkey_1");
    bytes32 constant PROGRAM_HASH = keccak256("program_1");
    bytes32 constant CIRCUIT_HASH = keccak256("circuit_1");

    function setUp() public {
        gateway = new MockSP1Gateway(true);

        vm.startPrank(owner);
        sp1 = new ZaseonSP1Verifier(address(gateway));
        plonky3 = new ZaseonPlonky3Verifier();
        jolt = new ZaseonJoltVerifier();
        binius = new ZaseonBiniusVerifier();
        vm.stopPrank();
    }

    // ═══════════════════ SP1 Verifier ═══════════════════

    function test_sp1_deploy() public view {
        assertEq(sp1.owner(), owner);
        assertEq(sp1.sp1Gateway(), address(gateway));
        assertEq(sp1.totalVerified(), 0);
    }

    function test_sp1_registerVKey() public {
        vm.prank(owner);
        sp1.registerVKey(VKEY, PROGRAM_HASH);

        (bytes32 vkHash, bytes32 progHash, bool active, ) = sp1
            .verificationKeys(VKEY);
        assertEq(vkHash, VKEY);
        assertEq(progHash, PROGRAM_HASH);
        assertTrue(active);
    }

    function test_sp1_registerVKey_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        sp1.registerVKey(VKEY, PROGRAM_HASH);
    }

    function test_sp1_registerVKey_duplicateReverts() public {
        vm.startPrank(owner);
        sp1.registerVKey(VKEY, PROGRAM_HASH);
        vm.expectRevert();
        sp1.registerVKey(VKEY, PROGRAM_HASH);
        vm.stopPrank();
    }

    function test_sp1_deactivateVKey() public {
        vm.startPrank(owner);
        sp1.registerVKey(VKEY, PROGRAM_HASH);
        sp1.deactivateVKey(VKEY);
        vm.stopPrank();

        (, , bool active, ) = sp1.verificationKeys(VKEY);
        assertFalse(active);
    }

    function test_sp1_verify() public {
        vm.prank(owner);
        sp1.registerVKey(VKEY, PROGRAM_HASH);

        bytes memory pubValues = abi.encode(uint256(42));
        ZaseonSP1Verifier.SP1Proof memory proof = ZaseonSP1Verifier.SP1Proof({
            vkeyHash: VKEY,
            publicValuesHash: keccak256(pubValues),
            proof: bytes("proof_data")
        });

        bool valid = sp1.verify(proof, pubValues);
        assertTrue(valid);
        assertEq(sp1.totalVerified(), 1);
    }

    function test_sp1_verify_unregisteredReverts() public {
        bytes memory pubValues = abi.encode(uint256(1));
        ZaseonSP1Verifier.SP1Proof memory proof = ZaseonSP1Verifier.SP1Proof({
            vkeyHash: keccak256("unknown"),
            publicValuesHash: keccak256(pubValues),
            proof: bytes("p")
        });

        vm.expectRevert();
        sp1.verify(proof, pubValues);
    }

    function test_sp1_updateGateway() public {
        address newGW = address(0xFACE);
        vm.prank(owner);
        sp1.updateGateway(newGW);
        assertEq(sp1.sp1Gateway(), newGW);
    }

    function test_sp1_updateGateway_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        sp1.updateGateway(address(0xFACE));
    }

    // ═══════════════════ Plonky3 Verifier ═══════════════════

    function test_plonky3_deploy() public view {
        assertEq(plonky3.owner(), owner);
        assertEq(plonky3.totalVerified(), 0);
    }

    function test_plonky3_registerCircuit() public {
        vm.prank(owner);
        plonky3.registerCircuit(CIRCUIT_HASH, 3, 1024);

        (
            bytes32 circHash,
            uint256 numInputs,
            uint256 degree,
            bool active
        ) = plonky3.circuits(CIRCUIT_HASH);
        assertEq(circHash, CIRCUIT_HASH);
        assertEq(numInputs, 3);
        assertEq(degree, 1024);
        assertTrue(active);
    }

    function test_plonky3_registerCircuit_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        plonky3.registerCircuit(CIRCUIT_HASH, 3, 1024);
    }

    function test_plonky3_verify() public {
        vm.prank(owner);
        plonky3.registerCircuit(CIRCUIT_HASH, 2, 1024);

        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = bytes32(uint256(1));
        inputs[1] = bytes32(uint256(2));

        ZaseonPlonky3Verifier.Plonky3Proof memory proof = ZaseonPlonky3Verifier
            .Plonky3Proof({
                circuitHash: CIRCUIT_HASH,
                publicInputs: inputs,
                commitmentHash: keccak256("commitment"),
                openingProof: bytes("opening_proof")
            });

        bool valid = plonky3.verify(proof);
        assertTrue(valid);
        assertEq(plonky3.totalVerified(), 1);
    }

    function test_plonky3_verify_wrongInputCountReverts() public {
        vm.prank(owner);
        plonky3.registerCircuit(CIRCUIT_HASH, 3, 1024);

        bytes32[] memory inputs = new bytes32[](2); // expected 3
        inputs[0] = bytes32(uint256(1));
        inputs[1] = bytes32(uint256(2));

        ZaseonPlonky3Verifier.Plonky3Proof memory proof = ZaseonPlonky3Verifier
            .Plonky3Proof({
                circuitHash: CIRCUIT_HASH,
                publicInputs: inputs,
                commitmentHash: keccak256("c"),
                openingProof: bytes("p")
            });

        vm.expectRevert();
        plonky3.verify(proof);
    }

    function test_plonky3_verify_emptyOpeningReverts() public {
        vm.prank(owner);
        plonky3.registerCircuit(CIRCUIT_HASH, 1, 512);

        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = bytes32(uint256(1));

        ZaseonPlonky3Verifier.Plonky3Proof memory proof = ZaseonPlonky3Verifier
            .Plonky3Proof({
                circuitHash: CIRCUIT_HASH,
                publicInputs: inputs,
                commitmentHash: keccak256("c"),
                openingProof: bytes("") // empty
            });

        vm.expectRevert();
        plonky3.verify(proof);
    }

    // ═══════════════════ Jolt Verifier ═══════════════════

    function test_jolt_deploy() public view {
        assertEq(jolt.owner(), owner);
        assertEq(jolt.totalVerified(), 0);
    }

    function test_jolt_registerProgram() public {
        vm.prank(owner);
        jolt.registerProgram(PROGRAM_HASH, 1_000_000);

        (bytes32 progHash, uint256 maxCycles, bool active) = jolt.programs(
            PROGRAM_HASH
        );
        assertEq(progHash, PROGRAM_HASH);
        assertEq(maxCycles, 1_000_000);
        assertTrue(active);
    }

    function test_jolt_registerProgram_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        jolt.registerProgram(PROGRAM_HASH, 1_000_000);
    }

    function test_jolt_verify() public {
        vm.prank(owner);
        jolt.registerProgram(PROGRAM_HASH, 1_000_000);

        ZaseonJoltVerifier.JoltProof memory proof = ZaseonJoltVerifier.JoltProof({
            programHash: PROGRAM_HASH,
            inputHash: keccak256("input"),
            outputHash: keccak256("output"),
            sumcheckProof: bytes("sumcheck"),
            lookupProof: bytes("lookup"),
            memoryProof: bytes("memory")
        });

        bool valid = jolt.verify(proof);
        assertTrue(valid);
        assertEq(jolt.totalVerified(), 1);
    }

    function test_jolt_verify_emptySumcheckReverts() public {
        vm.prank(owner);
        jolt.registerProgram(PROGRAM_HASH, 1_000_000);

        ZaseonJoltVerifier.JoltProof memory proof = ZaseonJoltVerifier.JoltProof({
            programHash: PROGRAM_HASH,
            inputHash: keccak256("i"),
            outputHash: keccak256("o"),
            sumcheckProof: bytes(""),
            lookupProof: bytes("l"),
            memoryProof: bytes("m")
        });

        vm.expectRevert();
        jolt.verify(proof);
    }

    function test_jolt_verify_emptyLookupReverts() public {
        vm.prank(owner);
        jolt.registerProgram(PROGRAM_HASH, 1_000_000);

        ZaseonJoltVerifier.JoltProof memory proof = ZaseonJoltVerifier.JoltProof({
            programHash: PROGRAM_HASH,
            inputHash: keccak256("i"),
            outputHash: keccak256("o"),
            sumcheckProof: bytes("s"),
            lookupProof: bytes(""),
            memoryProof: bytes("m")
        });

        vm.expectRevert();
        jolt.verify(proof);
    }

    function test_jolt_verify_emptyMemoryReverts() public {
        vm.prank(owner);
        jolt.registerProgram(PROGRAM_HASH, 1_000_000);

        ZaseonJoltVerifier.JoltProof memory proof = ZaseonJoltVerifier.JoltProof({
            programHash: PROGRAM_HASH,
            inputHash: keccak256("i"),
            outputHash: keccak256("o"),
            sumcheckProof: bytes("s"),
            lookupProof: bytes("l"),
            memoryProof: bytes("")
        });

        vm.expectRevert();
        jolt.verify(proof);
    }

    function test_jolt_verify_unregisteredReverts() public {
        ZaseonJoltVerifier.JoltProof memory proof = ZaseonJoltVerifier.JoltProof({
            programHash: keccak256("unknown"),
            inputHash: keccak256("i"),
            outputHash: keccak256("o"),
            sumcheckProof: bytes("s"),
            lookupProof: bytes("l"),
            memoryProof: bytes("m")
        });

        vm.expectRevert();
        jolt.verify(proof);
    }

    // ═══════════════════ Binius Verifier ═══════════════════

    function test_binius_deploy() public view {
        assertEq(binius.owner(), owner);
        assertEq(binius.totalVerified(), 0);
    }

    function test_binius_registerCircuit() public {
        vm.prank(owner);
        binius.registerCircuit(CIRCUIT_HASH);
        assertTrue(binius.registeredCircuits(CIRCUIT_HASH));
    }

    function test_binius_registerCircuit_nonOwnerReverts() public {
        vm.prank(alice);
        vm.expectRevert();
        binius.registerCircuit(CIRCUIT_HASH);
    }

    function test_binius_verify() public {
        vm.prank(owner);
        binius.registerCircuit(CIRCUIT_HASH);

        ZaseonBiniusVerifier.BiniusProof memory proof = ZaseonBiniusVerifier
            .BiniusProof({
                circuitHash: CIRCUIT_HASH,
                publicInputHash: keccak256("inputs"),
                oracleCommitment: keccak256("oracle"),
                sumcheckProof: bytes("sumcheck"),
                foldingProof: bytes("folding")
            });

        bool valid = binius.verify(proof);
        assertTrue(valid);
        assertEq(binius.totalVerified(), 1);
    }

    function test_binius_verify_emptySumcheckReverts() public {
        vm.prank(owner);
        binius.registerCircuit(CIRCUIT_HASH);

        ZaseonBiniusVerifier.BiniusProof memory proof = ZaseonBiniusVerifier
            .BiniusProof({
                circuitHash: CIRCUIT_HASH,
                publicInputHash: keccak256("i"),
                oracleCommitment: keccak256("o"),
                sumcheckProof: bytes(""),
                foldingProof: bytes("f")
            });

        vm.expectRevert();
        binius.verify(proof);
    }

    function test_binius_verify_emptyFoldingReverts() public {
        vm.prank(owner);
        binius.registerCircuit(CIRCUIT_HASH);

        ZaseonBiniusVerifier.BiniusProof memory proof = ZaseonBiniusVerifier
            .BiniusProof({
                circuitHash: CIRCUIT_HASH,
                publicInputHash: keccak256("i"),
                oracleCommitment: keccak256("o"),
                sumcheckProof: bytes("s"),
                foldingProof: bytes("")
            });

        vm.expectRevert();
        binius.verify(proof);
    }

    function test_binius_verify_unregisteredReverts() public {
        ZaseonBiniusVerifier.BiniusProof memory proof = ZaseonBiniusVerifier
            .BiniusProof({
                circuitHash: keccak256("unknown"),
                publicInputHash: keccak256("i"),
                oracleCommitment: keccak256("o"),
                sumcheckProof: bytes("s"),
                foldingProof: bytes("f")
            });

        vm.expectRevert();
        binius.verify(proof);
    }

    // ═══════════════════ Fuzz Tests ═══════════════════

    function testFuzz_sp1_registerVKey(bytes32 vkey, bytes32 progHash) public {
        vm.assume(vkey != bytes32(0));
        vm.assume(progHash != bytes32(0));

        vm.prank(owner);
        sp1.registerVKey(vkey, progHash);

        (bytes32 vkHash, , bool active, ) = sp1.verificationKeys(vkey);
        assertEq(vkHash, vkey);
        assertTrue(active);
    }

    function testFuzz_jolt_registerProgram(
        bytes32 hash,
        uint256 cycles
    ) public {
        vm.assume(hash != bytes32(0));
        cycles = bound(cycles, 1, 10_000_000);

        vm.prank(owner);
        jolt.registerProgram(hash, cycles);

        (, uint256 maxCycles, ) = jolt.programs(hash);
        assertEq(maxCycles, cycles);
    }
}
