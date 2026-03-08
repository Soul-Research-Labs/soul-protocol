// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/primitives/PolicyBoundProofs.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/// @notice Mock policy verifier that returns configurable results
contract MockPolicyVerifier is IProofVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool val) external {
        shouldVerify = val;
    }

    function verify(
        bytes calldata,
        uint256[] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external view returns (bool) {
        return shouldVerify;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 3;
    }

    function isReady() external pure returns (bool) {
        return true;
    }
}

/// @notice Mock verifier that always reverts
contract RevertingVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        revert("boom");
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        revert("boom");
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        revert("boom");
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 0;
    }

    function isReady() external pure returns (bool) {
        return false;
    }
}

contract PolicyBoundProofsTest is Test {
    PolicyBoundProofs public pbp;
    MockPolicyVerifier public policyVerifier;
    RevertingVerifier public revertVerifier;

    address public admin = address(this);
    address public verifierRole = makeAddr("verifierRole");
    address public policyAdmin = makeAddr("policyAdmin");
    address public user1 = makeAddr("user1");

    bytes32 constant POLICY_HASH = keccak256("policyRules");
    bytes32 constant VK_HASH = keccak256("verificationKey");

    function setUp() public {
        pbp = new PolicyBoundProofs();
        policyVerifier = new MockPolicyVerifier();
        revertVerifier = new RevertingVerifier();

        // Grant roles
        pbp.grantRole(pbp.VERIFIER_ROLE(), verifierRole);
        pbp.grantRole(pbp.POLICY_ADMIN_ROLE(), policyAdmin);

        // Set up policy verifier
        pbp.setPolicyVerifier(address(policyVerifier));
    }

    /*//////////////////////////////////////////////////////////////
                        HELPERS
    //////////////////////////////////////////////////////////////*/

    function _registerDefaultPolicy() internal returns (bytes32 policyId) {
        bytes32[] memory allowedAssets = new bytes32[](0);
        bytes32[] memory blockedCountries = new bytes32[](0);

        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: POLICY_HASH,
                name: "KYC Policy",
                description: "Basic KYC compliance",
                requiresIdentity: true,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: type(uint256).max,
                allowedAssets: allowedAssets,
                blockedCountries: blockedCountries,
                createdAt: 0,
                expiresAt: uint64(block.timestamp + 365 days),
                isActive: true
            });

        vm.prank(policyAdmin);
        policyId = pbp.registerPolicy(policy);
    }

    function _bindDefaultVK() internal returns (bytes32 domainSep) {
        _registerDefaultPolicy();
        vm.prank(policyAdmin);
        domainSep = pbp.bindVerificationKey(VK_HASH, POLICY_HASH);
    }

    function _buildBoundProof(
        bytes32 policyHash,
        bytes32 domainSep
    ) internal view returns (PolicyBoundProofs.BoundProof memory) {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = policyHash; // Include policy commitment

        return
            PolicyBoundProofs.BoundProof({
                proof: hex"deadbeef",
                policyHash: policyHash,
                domainSeparator: domainSep,
                publicInputs: publicInputs,
                generatedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 24 hours)
            });
    }

    /*//////////////////////////////////////////////////////////////
                         CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_GrantsRoles() public view {
        assertTrue(pbp.hasRole(pbp.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pbp.hasRole(pbp.POLICY_ADMIN_ROLE(), admin));
    }

    function test_Constructor_DefaultValues() public view {
        assertEq(pbp.totalPolicies(), 0);
        assertEq(pbp.totalVerificationKeys(), 0);
        assertEq(pbp.defaultProofValidity(), 24 hours);
    }

    /*//////////////////////////////////////////////////////////////
                      POLICY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterPolicy_Success() public {
        bytes32 policyId = _registerDefaultPolicy();

        assertTrue(policyId != bytes32(0));
        assertEq(pbp.totalPolicies(), 1);

        PolicyBoundProofs.DisclosurePolicy memory p = pbp.getPolicy(policyId);
        assertEq(p.policyHash, POLICY_HASH);
        assertEq(p.name, "KYC Policy");
        assertTrue(p.requiresIdentity);
        assertTrue(p.isActive);
    }

    function test_RegisterPolicy_RevertEmptyName() public {
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: POLICY_HASH,
                name: "",
                description: "desc",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: 0,
                isActive: true
            });

        vm.prank(policyAdmin);
        vm.expectRevert(PolicyBoundProofs.EmptyPolicyName.selector);
        pbp.registerPolicy(policy);
    }

    function test_RegisterPolicy_RevertUnauthorized() public {
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: POLICY_HASH,
                name: "Test",
                description: "",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: 0,
                isActive: true
            });

        vm.prank(user1);
        vm.expectRevert();
        pbp.registerPolicy(policy);
    }

    function test_RegisterPolicy_EmitsEvent() public {
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: POLICY_HASH,
                name: "Test Policy",
                description: "",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: 0,
                isActive: true
            });

        vm.prank(policyAdmin);
        vm.expectEmit(false, true, false, false);
        emit PolicyBoundProofs.PolicyRegistered(
            bytes32(0),
            POLICY_HASH,
            "Test Policy"
        );
        pbp.registerPolicy(policy);
    }

    /*//////////////////////////////////////////////////////////////
                     POLICY DEACTIVATION
    //////////////////////////////////////////////////////////////*/

    function test_DeactivatePolicy_Success() public {
        bytes32 policyId = _registerDefaultPolicy();

        vm.prank(policyAdmin);
        pbp.deactivatePolicy(policyId);

        assertFalse(pbp.isPolicyValid(policyId));
    }

    function test_DeactivatePolicy_RevertNotFound() public {
        bytes32 fakePolicyId = keccak256("fake");
        vm.prank(policyAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBoundProofs.PolicyNotFound.selector,
                fakePolicyId
            )
        );
        pbp.deactivatePolicy(fakePolicyId);
    }

    /*//////////////////////////////////////////////////////////////
                  VERIFICATION KEY BINDING
    //////////////////////////////////////////////////////////////*/

    function test_BindVerificationKey_Success() public {
        bytes32 domainSep = _bindDefaultVK();

        assertTrue(domainSep != bytes32(0));
        assertEq(pbp.totalVerificationKeys(), 1);

        PolicyBoundProofs.BoundVerificationKey memory vk = pbp
            .getVerificationKey(VK_HASH);
        assertEq(vk.vkHash, VK_HASH);
        assertEq(vk.policyHash, POLICY_HASH);
        assertEq(vk.domainSeparator, domainSep);
        assertTrue(vk.isActive);
    }

    function test_BindVerificationKey_RevertAlreadyBound() public {
        _bindDefaultVK();

        vm.prank(policyAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBoundProofs.VerificationKeyAlreadyBound.selector,
                VK_HASH
            )
        );
        pbp.bindVerificationKey(VK_HASH, POLICY_HASH);
    }

    function test_BindVerificationKey_RevertPolicyNotFound() public {
        bytes32 fakePolicyHash = keccak256("fakePolicy");
        vm.prank(policyAdmin);
        // Policy hash maps to zero policyId, which has createdAt == 0
        vm.expectRevert(
            abi.encodeWithSelector(
                PolicyBoundProofs.PolicyNotFound.selector,
                bytes32(0)
            )
        );
        pbp.bindVerificationKey(VK_HASH, fakePolicyHash);
    }

    function test_BindVerificationKey_ZeroPolicyHash() public {
        // Binding to zero policy hash should be allowed (no policy)
        vm.prank(policyAdmin);
        bytes32 domainSep = pbp.bindVerificationKey(VK_HASH, bytes32(0));
        assertTrue(domainSep != bytes32(0));
    }

    function test_BindVerificationKey_DomainSeparatorConsistency() public {
        _bindDefaultVK();
        bytes32 expected = pbp.computeDomainSeparator(VK_HASH, POLICY_HASH);
        PolicyBoundProofs.BoundVerificationKey memory vk = pbp
            .getVerificationKey(VK_HASH);
        assertEq(vk.domainSeparator, expected);
    }

    /*//////////////////////////////////////////////////////////////
                      PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_VerifyBoundProof_Success() public {
        bytes32 domainSep = _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertTrue(result.proofValid);
        assertTrue(result.policyValid);
        assertTrue(result.withinScope);
        assertTrue(result.notExpired);
    }

    function test_VerifyBoundProof_VkNotFound() public {
        bytes32 domainSep = keccak256(abi.encodePacked(VK_HASH, POLICY_HASH));
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );

        bytes32 fakeVk = keccak256("noVk");
        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, fakeVk);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Verification key not found");
    }

    function test_VerifyBoundProof_PolicyMismatch() public {
        bytes32 domainSep = _bindDefaultVK();
        bytes32 wrongPolicyHash = keccak256("wrongPolicy");
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            wrongPolicyHash,
            domainSep
        );

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Proof out of policy scope");
    }

    function test_VerifyBoundProof_InvalidDomainSep() public {
        _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            keccak256("bad")
        );

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Invalid domain separator");
    }

    function test_VerifyBoundProof_Expired() public {
        bytes32 domainSep = _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );
        // Warp forward so that a past expiresAt is > 0 and < block.timestamp
        vm.warp(1000);
        proof.expiresAt = uint64(block.timestamp - 1);

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Proof expired");
    }

    function test_VerifyBoundProof_PolicyInactive() public {
        bytes32 policyId = _registerDefaultPolicy();
        vm.prank(policyAdmin);
        pbp.bindVerificationKey(VK_HASH, POLICY_HASH);
        bytes32 domainSep = pbp.computeDomainSeparator(VK_HASH, POLICY_HASH);

        // Deactivate policy
        vm.prank(policyAdmin);
        pbp.deactivatePolicy(policyId);

        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );
        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Policy inactive");
    }

    function test_VerifyBoundProof_VerifierFails() public {
        bytes32 domainSep = _bindDefaultVK();
        policyVerifier.setShouldVerify(false);

        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );
        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "SNARK proof verification failed");
    }

    function test_VerifyBoundProof_VerifierReverts() public {
        bytes32 domainSep = _bindDefaultVK();
        // Switch to reverting verifier
        pbp.setPolicyVerifier(address(revertVerifier));

        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );
        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Verifier call failed");
    }

    function test_VerifyBoundProof_NoPolicyCommitment() public {
        bytes32 domainSep = _bindDefaultVK();

        // Build proof WITHOUT policy hash in public inputs
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("something_else");

        PolicyBoundProofs.BoundProof memory proof = PolicyBoundProofs
            .BoundProof({
                proof: hex"deadbeef",
                policyHash: POLICY_HASH,
                domainSeparator: domainSep,
                publicInputs: publicInputs,
                generatedAt: uint64(block.timestamp),
                expiresAt: uint64(block.timestamp + 24 hours)
            });

        PolicyBoundProofs.VerificationResult memory result = pbp
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(
            result.failureReason,
            "Policy commitment not in public inputs"
        );
    }

    function test_VerifyBoundProof_NoVerifierConfigured() public {
        // Deploy fresh PBP without verifier
        PolicyBoundProofs pbp2 = new PolicyBoundProofs();
        pbp2.grantRole(pbp2.POLICY_ADMIN_ROLE(), policyAdmin);

        // Register policy and bind vk
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: POLICY_HASH,
                name: "Test",
                description: "",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: uint64(block.timestamp + 365 days),
                isActive: true
            });

        vm.prank(policyAdmin);
        pbp2.registerPolicy(policy);

        vm.prank(policyAdmin);
        bytes32 domainSep = pbp2.bindVerificationKey(VK_HASH, POLICY_HASH);

        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );
        PolicyBoundProofs.VerificationResult memory result = pbp2
            .verifyBoundProof(proof, VK_HASH);
        assertFalse(result.proofValid);
        assertEq(result.failureReason, "Policy verifier not configured");
    }

    /*//////////////////////////////////////////////////////////////
                    VERIFY AND CONSUME PROOF
    //////////////////////////////////////////////////////////////*/

    function test_VerifyAndConsumeProof_Success() public {
        bytes32 domainSep = _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );

        vm.prank(verifierRole);
        pbp.verifyAndConsumeProof(proof, VK_HASH);

        assertEq(pbp.policyUsageCount(POLICY_HASH), 1);
    }

    function test_VerifyAndConsumeProof_RevertReplay() public {
        bytes32 domainSep = _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );

        vm.prank(verifierRole);
        pbp.verifyAndConsumeProof(proof, VK_HASH);

        // Same proof again
        vm.prank(verifierRole);
        vm.expectRevert(); // ProofAlreadyUsed
        pbp.verifyAndConsumeProof(proof, VK_HASH);
    }

    function test_VerifyAndConsumeProof_RevertUnauthorized() public {
        bytes32 domainSep = _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );

        vm.prank(user1);
        vm.expectRevert();
        pbp.verifyAndConsumeProof(proof, VK_HASH);
    }

    function test_VerifyAndConsumeProof_RevertWhenPaused() public {
        bytes32 domainSep = _bindDefaultVK();
        PolicyBoundProofs.BoundProof memory proof = _buildBoundProof(
            POLICY_HASH,
            domainSep
        );

        pbp.pause();

        vm.prank(verifierRole);
        vm.expectRevert();
        pbp.verifyAndConsumeProof(proof, VK_HASH);
    }

    /*//////////////////////////////////////////////////////////////
                    DOMAIN SEPARATOR UTILS
    //////////////////////////////////////////////////////////////*/

    function test_ComputeDomainSeparator_Deterministic() public view {
        bytes32 d1 = pbp.computeDomainSeparator(VK_HASH, POLICY_HASH);
        bytes32 d2 = pbp.computeDomainSeparator(VK_HASH, POLICY_HASH);
        assertEq(d1, d2);
    }

    function test_ComputeDomainSeparator_DifferentInputs() public view {
        bytes32 d1 = pbp.computeDomainSeparator(VK_HASH, POLICY_HASH);
        bytes32 d2 = pbp.computeDomainSeparator(VK_HASH, keccak256("other"));
        assertTrue(d1 != d2);
    }

    function test_GetVkByDomain() public {
        bytes32 domainSep = _bindDefaultVK();
        assertEq(pbp.getVkByDomain(domainSep), VK_HASH);
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_IsPolicyValid_Active() public {
        bytes32 policyId = _registerDefaultPolicy();
        assertTrue(pbp.isPolicyValid(policyId));
    }

    function test_IsPolicyValid_Inactive() public {
        bytes32 policyId = _registerDefaultPolicy();
        vm.prank(policyAdmin);
        pbp.deactivatePolicy(policyId);
        assertFalse(pbp.isPolicyValid(policyId));
    }

    function test_IsPolicyValid_Expired() public {
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: keccak256("expiring"),
                name: "Expiring Policy",
                description: "",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: uint64(block.timestamp + 1 hours),
                isActive: true
            });

        vm.prank(policyAdmin);
        bytes32 policyId = pbp.registerPolicy(policy);

        assertTrue(pbp.isPolicyValid(policyId));
        vm.warp(block.timestamp + 2 hours);
        assertFalse(pbp.isPolicyValid(policyId));
    }

    function test_IsPolicyValid_NotFound() public view {
        assertFalse(pbp.isPolicyValid(keccak256("nonexistent")));
    }

    function test_GetPolicyIds_Paginated() public {
        _registerDefaultPolicy();

        // Register another policy
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy2 = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: keccak256("policy2"),
                name: "Policy 2",
                description: "",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: 0,
                isActive: true
            });

        vm.prank(policyAdmin);
        pbp.registerPolicy(policy2);

        bytes32[] memory page1 = pbp.getPolicyIds(0, 1);
        assertEq(page1.length, 1);

        bytes32[] memory page2 = pbp.getPolicyIds(1, 10);
        assertEq(page2.length, 1);

        bytes32[] memory empty2 = pbp.getPolicyIds(10, 1);
        assertEq(empty2.length, 0);
    }

    function test_GetVkHashes_Paginated() public {
        _bindDefaultVK();

        bytes32[] memory hashes = pbp.getVkHashes(0, 10);
        assertEq(hashes.length, 1);
        assertEq(hashes[0], VK_HASH);

        bytes32[] memory empty2 = pbp.getVkHashes(10, 1);
        assertEq(empty2.length, 0);
    }

    function test_BatchCheckPolicies() public {
        bytes32 policyId = _registerDefaultPolicy();

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = policyId;
        ids[1] = keccak256("nonexistent");

        bool[] memory results = pbp.batchCheckPolicies(ids);
        assertTrue(results[0]);
        assertFalse(results[1]);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetDefaultProofValidity() public {
        vm.prank(policyAdmin);
        pbp.setDefaultProofValidity(48 hours);
        assertEq(pbp.defaultProofValidity(), 48 hours);
    }

    function test_SetPolicyVerifier() public {
        address newVerifier = makeAddr("newVerifier");
        pbp.setPolicyVerifier(newVerifier);
        assertEq(address(pbp.policyVerifier()), newVerifier);
    }

    function test_SetPolicyVerifier_RevertZeroAddress() public {
        vm.expectRevert(PolicyBoundProofs.ZeroVerifierAddress.selector);
        pbp.setPolicyVerifier(address(0));
    }

    function test_PauseUnpause() public {
        pbp.pause();
        assertTrue(pbp.paused());
        pbp.unpause();
        assertFalse(pbp.paused());
    }

    function test_Pause_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        pbp.pause();
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ComputeDomainSeparator_Unique(
        bytes32 vk1,
        bytes32 vk2,
        bytes32 ph
    ) public view {
        vm.assume(vk1 != vk2);
        bytes32 d1 = pbp.computeDomainSeparator(vk1, ph);
        bytes32 d2 = pbp.computeDomainSeparator(vk2, ph);
        assertTrue(d1 != d2);
    }

    function testFuzz_PolicyRegistration(string calldata name) public {
        vm.assume(bytes(name).length > 0 && bytes(name).length < 256);
        bytes32[] memory empty = new bytes32[](0);
        PolicyBoundProofs.DisclosurePolicy memory policy = PolicyBoundProofs
            .DisclosurePolicy({
                policyId: bytes32(0),
                policyHash: keccak256(abi.encodePacked(name)),
                name: name,
                description: "",
                requiresIdentity: false,
                requiresJurisdiction: false,
                requiresAmount: false,
                requiresCounterparty: false,
                minAmount: 0,
                maxAmount: 0,
                allowedAssets: empty,
                blockedCountries: empty,
                createdAt: 0,
                expiresAt: 0,
                isActive: true
            });

        vm.prank(policyAdmin);
        bytes32 policyId = pbp.registerPolicy(policy);
        assertTrue(policyId != bytes32(0));
    }
}
