// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";
import {UltraHonkAdapter} from "../../contracts/verifiers/adapters/UltraHonkAdapter.sol";
import {CrossDomainNullifierAlgebra} from "../../contracts/primitives/CrossDomainNullifierAlgebra.sol";
import {ExecutionAgnosticStateCommitments} from "../../contracts/primitives/ExecutionAgnosticStateCommitments.sol";
import {PolicyBoundProofs} from "../../contracts/primitives/PolicyBoundProofs.sol";

/**
 * @title MockHonkVerifier
 * @notice Configurable mock for UltraHonk verifier
 */
contract MockHonkVerifier {
    bool public shouldPass;

    constructor(bool _shouldPass) {
        shouldPass = _shouldPass;
    }

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return shouldPass;
    }
}

/**
 * @title MockProofVerifier
 * @notice Direct IProofVerifier mock for testing
 */
contract MockProofVerifier is IProofVerifier {
    bool public shouldPass;
    uint256 public expectedInputCount;

    constructor(bool _shouldPass, uint256 _expectedInputCount) {
        shouldPass = _shouldPass;
        expectedInputCount = _expectedInputCount;
    }

    function setShouldPass(bool _pass) external {
        shouldPass = _pass;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view override returns (bool) {
        return shouldPass;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view override returns (bool) {
        return shouldPass;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view override returns (bool) {
        return shouldPass;
    }

    function getPublicInputCount() external view override returns (uint256) {
        return expectedInputCount;
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

/**
 * @title PrivacyLayerHardeningTest
 * @notice Phase 3 integration tests — verifies all 5 contracts require
 *         real ZK verifiers instead of proof-length placeholder checks.
 */
contract PrivacyLayerHardeningTest is Test {
    // ─── Contracts ──────────────────────────────────────────────
    CrossDomainNullifierAlgebra public cdna;
    ExecutionAgnosticStateCommitments public easc;
    PolicyBoundProofs public pbp;

    // ─── Verifiers ──────────────────────────────────────────────
    MockProofVerifier public passingVerifier;
    MockProofVerifier public failingVerifier;
    MockHonkVerifier public mockHonk;
    UltraHonkAdapter public adapter;

    // ─── Actors ──────────────────────────────────────────────────
    address public admin = address(0xAD);
    address public bridge = address(0xBB);
    address public registrar = address(0xCC);
    address public attester = address(0xEE);
    address public unauthorized = address(0x99);

    // ─── CDNA Roles ─────────────────────────────────────────────
    bytes32 constant BRIDGE_ROLE =
        0x52ba824bfabc2bcfcdf7f0edbb486ebb05e1836c90e78047efeb949990f72e5f;
    bytes32 constant NULLIFIER_REGISTRAR_ROLE =
        0x5505d4e1c339d2da96b423eae372f08e27c4388c7bee6502a760802a80405236;
    bytes32 constant DOMAIN_ADMIN_ROLE =
        0x7792e66be7e1c65b630a8198da6bf1636e24cd26934ca652e146dd12060d06fb;

    function setUp() public {
        vm.startPrank(admin);

        // Deploy verifiers
        passingVerifier = new MockProofVerifier(true, 4);
        failingVerifier = new MockProofVerifier(false, 4);
        mockHonk = new MockHonkVerifier(true);
        adapter = new UltraHonkAdapter(
            address(mockHonk),
            4,
            bytes32("test_circuit")
        );

        // Deploy CDNA
        cdna = new CrossDomainNullifierAlgebra();
        cdna.grantRole(BRIDGE_ROLE, bridge);
        cdna.grantRole(NULLIFIER_REGISTRAR_ROLE, registrar);
        cdna.grantRole(DOMAIN_ADMIN_ROLE, admin);

        // Deploy EASC
        easc = new ExecutionAgnosticStateCommitments();
        easc.grantRole(easc.BACKEND_ADMIN_ROLE(), admin);
        easc.grantRole(easc.COMMITMENT_REGISTRAR_ROLE(), attester);

        // Deploy PBP
        pbp = new PolicyBoundProofs();
        // admin already has POLICY_ADMIN_ROLE from constructor

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
              HELPER: Set up CDNA domain + parent nullifier
    //////////////////////////////////////////////////////////////*/

    function _setupCDNA()
        internal
        returns (bytes32 domainId, bytes32 parentNullifier)
    {
        vm.prank(admin);
        domainId = cdna.registerDomain(1, bytes32("app1"), 0);

        bytes32 commitment = keccak256("commitment1");
        bytes32 transitionId = keccak256("transition1");

        vm.prank(registrar);
        cdna.registerNullifier(domainId, commitment, commitment, transitionId);

        (, , , , , bytes32 domainSep, , ) = cdna.domains(domainId);
        parentNullifier = cdna.computeNullifier(
            commitment,
            domainSep,
            transitionId
        );
    }

    /*//////////////////////////////////////////////////////////////
              HELPER: Set up EASC backend + commitment
    //////////////////////////////////////////////////////////////*/

    function _setupEASC()
        internal
        returns (bytes32 backendId, bytes32 commitmentId)
    {
        vm.prank(admin);
        backendId = easc.registerBackend(
            ExecutionAgnosticStateCommitments.BackendType.ZkVM,
            "TestVM",
            keccak256("attestKey"),
            keccak256("configHash")
        );

        bytes32 stateHash = keccak256("state1");
        bytes32 nullifier = keccak256("nullifier1");

        vm.prank(attester);
        commitmentId = easc.createCommitment(
            stateHash,
            keccak256("transitionHash"),
            nullifier
        );
    }

    /*//////////////////////////////////////////////////////////////
              HELPER: Set up PBP policy + VK
    //////////////////////////////////////////////////////////////*/

    function _setupPBP()
        internal
        returns (bytes32 vkHash, bytes32 policyHash, bytes32 domainSep)
    {
        policyHash = keccak256("policy1");

        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: policyHash,
                name: "AML Compliance",
                description: "Anti-money laundering policy",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: type(uint256).max,
                allowedAssets: new bytes32[](0),
                blockedCountries: new bytes32[](0),
                createdAt: 0,
                expiresAt: 0,
                isActive: true
            });

        vm.startPrank(admin);
        pbp.registerPolicy(policy);

        vkHash = keccak256("vk1");
        domainSep = pbp.bindVerificationKey(vkHash, policyHash);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                CROSSDOMAIN NULLIFIER ALGEBRA TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CDNA_RevertsWithoutVerifier() public {
        (bytes32 domainId, bytes32 parentNullifier) = _setupCDNA();

        bytes memory fakeProof = new bytes(512);
        vm.prank(bridge);
        vm.expectRevert("Derivation verifier not configured");
        cdna.registerDerivedNullifier(
            parentNullifier,
            domainId,
            keccak256("transition2"),
            fakeProof
        );
    }

    function test_CDNA_VerifierSetterAccessControl() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        cdna.setDerivationVerifier(address(passingVerifier));
    }

    function test_CDNA_RejectsZeroVerifier() public {
        vm.prank(admin);
        vm.expectRevert("Zero verifier address");
        cdna.setDerivationVerifier(address(0));
    }

    function test_CDNA_AcceptsWithPassingVerifier() public {
        vm.prank(admin);
        cdna.setDerivationVerifier(address(passingVerifier));

        (bytes32 domainId, bytes32 parentNullifier) = _setupCDNA();

        bytes memory proof = new bytes(256);
        vm.prank(bridge);
        bytes32 child = cdna.registerDerivedNullifier(
            parentNullifier,
            domainId,
            keccak256("transition2"),
            proof
        );

        assertTrue(cdna.nullifierExists(child), "Child nullifier should exist");
    }

    function test_CDNA_RejectsWithFailingVerifier() public {
        vm.prank(admin);
        cdna.setDerivationVerifier(address(failingVerifier));

        (bytes32 domainId, bytes32 parentNullifier) = _setupCDNA();

        bytes memory proof = new bytes(256);
        vm.prank(bridge);
        vm.expectRevert();
        cdna.registerDerivedNullifier(
            parentNullifier,
            domainId,
            keccak256("transition2"),
            proof
        );
    }

    function test_CDNA_EmitsVerifierUpdateEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit CrossDomainNullifierAlgebra.DerivationVerifierUpdated(
            address(passingVerifier)
        );
        cdna.setDerivationVerifier(address(passingVerifier));
    }

    /*//////////////////////////////////////////////////////////////
            EXECUTION AGNOSTIC STATE COMMITMENTS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EASC_RevertsWithoutVerifier() public {
        (bytes32 backendId, bytes32 commitmentId) = _setupEASC();

        bytes memory fakeProof = new bytes(128);
        vm.prank(attester);
        vm.expectRevert("Attestation verifier not configured");
        easc.attestCommitment(
            commitmentId,
            backendId,
            fakeProof,
            keccak256("exec")
        );
    }

    function test_EASC_VerifierSetterAccessControl() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        easc.setAttestationVerifier(address(passingVerifier));
    }

    function test_EASC_RejectsZeroVerifier() public {
        vm.prank(admin);
        vm.expectRevert("Zero verifier address");
        easc.setAttestationVerifier(address(0));
    }

    function test_EASC_AcceptsWithPassingVerifier() public {
        vm.prank(admin);
        easc.setAttestationVerifier(address(passingVerifier));

        (bytes32 backendId, bytes32 commitmentId) = _setupEASC();

        bytes memory proof = new bytes(64);
        vm.prank(attester);
        easc.attestCommitment(
            commitmentId,
            backendId,
            proof,
            keccak256("exec")
        );

        // Verify attestation recorded
        ExecutionAgnosticStateCommitments.CommitmentView memory view_ = easc
            .getCommitment(commitmentId);
        assertEq(view_.attestationCount, 1, "Attestation should be recorded");
    }

    function test_EASC_RejectsWithFailingVerifier() public {
        vm.prank(admin);
        easc.setAttestationVerifier(address(failingVerifier));

        (bytes32 backendId, bytes32 commitmentId) = _setupEASC();

        bytes memory proof = new bytes(64);
        vm.prank(attester);
        vm.expectRevert();
        easc.attestCommitment(
            commitmentId,
            backendId,
            proof,
            keccak256("exec")
        );
    }

    function test_EASC_EmitsVerifierUpdateEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit ExecutionAgnosticStateCommitments.AttestationVerifierUpdated(
            address(passingVerifier)
        );
        easc.setAttestationVerifier(address(passingVerifier));
    }

    /*//////////////////////////////////////////////////////////////
                      POLICY BOUND PROOFS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PBP_FailsWithoutVerifier() public {
        (bytes32 vkHash, bytes32 policyHash, bytes32 domainSep) = _setupPBP();

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = policyHash;

        PolicyBoundProofs.BoundProof memory proof = PolicyBoundProofs
            .BoundProof({
                proof: new bytes(512),
                policyHash: policyHash,
                domainSeparator: domainSep,
                publicInputs: publicInputs,
                generatedAt: uint64(block.timestamp),
                expiresAt: 0
            });

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, vkHash);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Policy verifier not configured");
    }

    function test_PBP_VerifierSetterAccessControl() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        pbp.setPolicyVerifier(address(passingVerifier));
    }

    function test_PBP_RejectsZeroVerifier() public {
        vm.prank(admin);
        vm.expectRevert("Zero verifier address");
        pbp.setPolicyVerifier(address(0));
    }

    function test_PBP_AcceptsWithPassingVerifier() public {
        vm.prank(admin);
        pbp.setPolicyVerifier(address(passingVerifier));

        (bytes32 vkHash, bytes32 policyHash, bytes32 domainSep) = _setupPBP();

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = policyHash;

        PolicyBoundProofs.BoundProof memory proof = PolicyBoundProofs
            .BoundProof({
                proof: new bytes(256),
                policyHash: policyHash,
                domainSeparator: domainSep,
                publicInputs: publicInputs,
                generatedAt: uint64(block.timestamp),
                expiresAt: 0
            });

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, vkHash);
        assertTrue(
            result.proofValid,
            "Proof should pass with passing verifier"
        );
        assertTrue(result.policyValid, "Policy should be valid");
    }

    function test_PBP_RejectsWithFailingVerifier() public {
        vm.prank(admin);
        pbp.setPolicyVerifier(address(failingVerifier));

        (bytes32 vkHash, bytes32 policyHash, bytes32 domainSep) = _setupPBP();

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = policyHash;

        PolicyBoundProofs.BoundProof memory proof = PolicyBoundProofs
            .BoundProof({
                proof: new bytes(256),
                policyHash: policyHash,
                domainSeparator: domainSep,
                publicInputs: publicInputs,
                generatedAt: uint64(block.timestamp),
                expiresAt: 0
            });

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, vkHash);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "SNARK proof verification failed");
    }

    function test_PBP_EmitsVerifierUpdateEvent() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, false);
        emit PolicyBoundProofs.PolicyVerifierUpdated(address(passingVerifier));
        pbp.setPolicyVerifier(address(passingVerifier));
    }

    /*//////////////////////////////////////////////////////////////
                     ULTRAHONK ADAPTER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Adapter_VerifyProofBytesBytes() public view {
        uint256[] memory inputs = new uint256[](4);
        inputs[0] = 1;
        inputs[1] = 2;
        inputs[2] = 3;
        inputs[3] = 4;

        bytes memory publicInputs = abi.encode(inputs);
        bool result = adapter.verifyProof(new bytes(100), publicInputs);
        assertTrue(result, "verifyProof should work for shielded pool");
    }

    function test_Adapter_RejectsWhenHonkFails() public {
        mockHonk.setShouldPass(false);

        uint256[] memory inputs = new uint256[](4);
        inputs[0] = 1;
        inputs[1] = 2;
        inputs[2] = 3;
        inputs[3] = 4;

        bool result = adapter.verify(new bytes(100), inputs);
        assertFalse(result, "Should fail when honk rejects");
    }

    function test_Adapter_RejectsWrongInputCount() public {
        uint256[] memory inputs = new uint256[](2);
        inputs[0] = 1;
        inputs[1] = 2;

        vm.expectRevert();
        adapter.verify(new bytes(100), inputs);
    }

    /*//////////////////////////////////////////////////////////////
            CROSS-CUTTING: LENGTH-CHECKS ARE GONE
    //////////////////////////////////////////////////////////////*/

    function test_LengthCheckGone_CDNA() public {
        (bytes32 domainId, bytes32 parentNullifier) = _setupCDNA();

        // 512-byte proof should NOT pass without real verifier
        bytes memory bigProof = new bytes(512);
        vm.prank(bridge);
        vm.expectRevert("Derivation verifier not configured");
        cdna.registerDerivedNullifier(
            parentNullifier,
            domainId,
            keccak256("t2"),
            bigProof
        );
    }

    function test_LengthCheckGone_EASC() public {
        (bytes32 backendId, bytes32 commitmentId) = _setupEASC();

        // 128-byte proof should NOT pass without real verifier
        bytes memory bigProof = new bytes(128);
        vm.prank(attester);
        vm.expectRevert("Attestation verifier not configured");
        easc.attestCommitment(
            commitmentId,
            backendId,
            bigProof,
            keccak256("exec")
        );
    }

    function test_LengthCheckGone_PBP() public {
        (bytes32 vkHash, bytes32 policyHash, bytes32 domainSep) = _setupPBP();

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = policyHash;

        PolicyBoundProofs.BoundProof memory proof = PolicyBoundProofs
            .BoundProof({
                proof: new bytes(512),
                policyHash: policyHash,
                domainSeparator: domainSep,
                publicInputs: publicInputs,
                generatedAt: uint64(block.timestamp),
                expiresAt: 0
            });

        // 512-byte proof should NOT pass without real verifier
        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, vkHash);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Policy verifier not configured");
    }
}
