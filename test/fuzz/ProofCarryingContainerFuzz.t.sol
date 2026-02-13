// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/ProofCarryingContainer.sol";

contract ProofCarryingContainerFuzz is Test {
    ProofCarryingContainer public pc3;

    address public admin = address(0xA);
    address public verifier = address(0xB);
    address public user1 = address(0xF1);
    address public user2 = address(0xF2);

    bytes32 internal CONTAINER_ADMIN_ROLE;
    bytes32 internal VERIFIER_ROLE;

    function setUp() public {
        vm.prank(admin);
        pc3 = new ProofCarryingContainer();

        CONTAINER_ADMIN_ROLE = pc3.CONTAINER_ADMIN_ROLE();
        VERIFIER_ROLE = pc3.VERIFIER_ROLE();

        vm.startPrank(admin);
        pc3.grantRole(VERIFIER_ROLE, verifier);
        // Disable real verification so tests don't require a real VerifierRegistry
        pc3.setRealVerification(false);
        vm.stopPrank();
    }

    // =====================================================================
    // Section 1 — Container Creation
    // =====================================================================

    function test_createContainer_happyPath() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        ProofCarryingContainer.Container memory c = pc3.getContainer(cId);
        assertEq(c.stateCommitment, bytes32(uint256(1)));
        assertEq(c.nullifier, bytes32(uint256(2)));
        assertFalse(c.isConsumed);
        assertEq(pc3.totalContainers(), 1);
    }

    function testFuzz_createContainer(bytes32 state, bytes32 nullifier) public {
        vm.assume(state != bytes32(0) && nullifier != bytes32(0));
        (bytes32 cId, ) = _createDefaultContainer(state, nullifier);
        assertEq(pc3.getContainer(cId).stateCommitment, state);
    }

    function test_createContainer_emptyPayloadReverts() public {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainer.InvalidContainerData.selector);
        pc3.createContainer(
            "",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_payloadTooLargeReverts() public {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        bytes memory bigPayload = new bytes(pc3.MAX_PAYLOAD_SIZE() + 1);
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.PayloadTooLarge.selector,
                bigPayload.length,
                pc3.MAX_PAYLOAD_SIZE()
            )
        );
        pc3.createContainer(
            bigPayload,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_zeroStateReverts() public {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainer.InvalidContainerData.selector);
        pc3.createContainer(
            "payload",
            bytes32(0),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_zeroNullifierReverts() public {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainer.InvalidContainerData.selector);
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(0),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_proofTooSmallReverts() public {
        bytes memory smallProof = new bytes(128); // < MIN_PROOF_SIZE
        ProofCarryingContainer.ProofBundle
            memory proofs = ProofCarryingContainer.ProofBundle({
                validityProof: smallProof,
                policyProof: new bytes(pc3.MIN_PROOF_SIZE()),
                nullifierProof: new bytes(pc3.MIN_PROOF_SIZE()),
                proofHash: bytes32(0),
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 24 hours
            });
        proofs.proofHash = keccak256(
            abi.encode(
                proofs.validityProof,
                proofs.policyProof,
                proofs.nullifierProof
            )
        );

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ProofTooSmall.selector,
                smallProof.length,
                pc3.MIN_PROOF_SIZE()
            )
        );
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_unsupportedPolicyReverts() public {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        bytes32 unknownPolicy = keccak256("unknown_policy");
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.UnsupportedPolicy.selector,
                unknownPolicy
            )
        );
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            unknownPolicy
        );
    }

    function test_createContainer_withSupportedPolicy() public {
        bytes32 policyHash = keccak256("ofac_policy");
        vm.prank(admin);
        pc3.addPolicy(policyHash);

        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            policyHash
        );
    }

    function test_createContainer_zeroPolicySkipsCheck() public {
        // bytes32(0) policyHash should skip policy validation
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_consumedNullifierReverts() public {
        bytes32 nullifier = bytes32(uint256(42));
        _createDefaultContainer(bytes32(uint256(1)), nullifier);

        // Consume the container
        bytes32 cId = _computeContainerId(bytes32(uint256(1)), nullifier);
        vm.prank(verifier);
        pc3.consumeContainer(cId);

        // Try to create another container with same nullifier
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.NullifierAlreadyConsumed.selector,
                nullifier
            )
        );
        pc3.createContainer(
            "payload2",
            bytes32(uint256(3)),
            nullifier,
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_duplicateIdReverts() public {
        bytes32 state = bytes32(uint256(1));
        bytes32 nullifier = bytes32(uint256(2));
        _createDefaultContainer(state, nullifier);

        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        bytes32 cId = _computeContainerId(state, nullifier);
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerAlreadyExists.selector,
                cId
            )
        );
        pc3.createContainer("payload2", state, nullifier, proofs, bytes32(0));
    }

    function test_createContainer_invalidProofHashReverts() public {
        bytes memory vProof = new bytes(pc3.MIN_PROOF_SIZE());
        bytes memory pProof = new bytes(pc3.MIN_PROOF_SIZE());
        bytes memory nProof = new bytes(pc3.MIN_PROOF_SIZE());
        ProofCarryingContainer.ProofBundle memory proofs = ProofCarryingContainer
            .ProofBundle({
                validityProof: vProof,
                policyProof: pProof,
                nullifierProof: nProof,
                proofHash: bytes32(uint256(0xBAD)), // Wrong hash
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 24 hours
            });

        vm.prank(user1);
        vm.expectRevert(ProofCarryingContainer.InvalidProofBundle.selector);
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    function test_createContainer_pausedReverts() public {
        vm.prank(admin);
        pc3.pause();

        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        vm.expectRevert();
        pc3.createContainer(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0)
        );
    }

    // =====================================================================
    // Section 2 — Container Verification
    // =====================================================================

    function test_verifyContainer_valid() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        ProofCarryingContainer.VerificationResult memory r = pc3
            .verifyContainer(cId);
        assertTrue(r.validityValid);
        assertTrue(r.notExpired);
        assertTrue(r.notConsumed);
    }

    function test_verifyContainer_expired() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        // Warp past proof expiry
        vm.warp(block.timestamp + 25 hours);
        ProofCarryingContainer.VerificationResult memory r = pc3
            .verifyContainer(cId);
        assertFalse(r.notExpired, "should be expired");
    }

    function test_verifyContainer_consumed() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        vm.prank(verifier);
        pc3.consumeContainer(cId);

        ProofCarryingContainer.VerificationResult memory r = pc3
            .verifyContainer(cId);
        assertFalse(r.notConsumed, "should be consumed");
    }

    function test_verifyContainer_notFound() public {
        ProofCarryingContainer.VerificationResult memory r = pc3
            .verifyContainer(bytes32(uint256(999)));
        assertEq(r.failureReason, "Container not found");
    }

    // =====================================================================
    // Section 3 — Container Consumption
    // =====================================================================

    function test_consumeContainer_happyPath() public {
        (bytes32 cId, bytes32 nullifier) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );

        assertFalse(pc3.isNullifierConsumed(nullifier));
        vm.prank(verifier);
        pc3.consumeContainer(cId);

        assertTrue(pc3.isNullifierConsumed(nullifier));
        assertTrue(pc3.getContainer(cId).isConsumed);
    }

    function test_consumeContainer_notFoundReverts() public {
        bytes32 fake = bytes32(uint256(999));
        vm.prank(verifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerNotFound.selector,
                fake
            )
        );
        pc3.consumeContainer(fake);
    }

    function test_consumeContainer_alreadyConsumedReverts() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.prank(verifier);
        pc3.consumeContainer(cId);

        vm.prank(verifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerAlreadyConsumed.selector,
                cId
            )
        );
        pc3.consumeContainer(cId);
    }

    function testFuzz_consumeContainer_unauthorizedReverts(
        address caller
    ) public {
        vm.assume(caller != verifier && caller != admin);
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.prank(caller);
        vm.expectRevert();
        pc3.consumeContainer(cId);
    }

    function test_consumeContainer_pausedReverts() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.prank(admin);
        pc3.pause();

        vm.prank(verifier);
        vm.expectRevert();
        pc3.consumeContainer(cId);
    }

    // =====================================================================
    // Section 4 — Cross-chain Import
    // =====================================================================

    function test_importContainer_happyPath() public {
        bytes32 state = bytes32(uint256(0xA));
        bytes32 nullifier = bytes32(uint256(0xB));
        uint64 sourceChainId = 42161;
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();

        bytes memory containerData = abi.encode(
            "encrypted_payload",
            state,
            nullifier,
            proofs,
            bytes32(0), // policyHash
            sourceChainId
        );

        bytes memory sourceChainProof = new bytes(pc3.MIN_PROOF_SIZE());

        vm.prank(user1);
        pc3.importContainer(containerData, sourceChainProof);
    }

    function test_importContainer_consumedNullifierReverts() public {
        bytes32 nullifier = bytes32(uint256(0xB));
        // First create and consume a container with this nullifier
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(0xA)),
            nullifier
        );
        vm.prank(verifier);
        pc3.consumeContainer(cId);

        // Now try to import with same nullifier
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        bytes memory containerData = abi.encode(
            "encrypted_payload",
            bytes32(uint256(0xC)),
            nullifier,
            proofs,
            bytes32(0),
            uint64(42161)
        );
        bytes memory sourceChainProof = new bytes(pc3.MIN_PROOF_SIZE());

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.NullifierAlreadyConsumed.selector,
                nullifier
            )
        );
        pc3.importContainer(containerData, sourceChainProof);
    }

    function test_importContainer_shortProofReverts() public {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        bytes memory containerData = abi.encode(
            "payload",
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            proofs,
            bytes32(0),
            uint64(42161)
        );
        bytes memory shortProof = new bytes(10);

        vm.prank(user1);
        vm.expectRevert();
        pc3.importContainer(containerData, shortProof);
    }

    // =====================================================================
    // Section 5 — Export Container
    // =====================================================================

    function test_exportContainer_happyPath() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        bytes memory exported = pc3.exportContainer(cId);
        assertGt(exported.length, 0);
    }

    function test_exportContainer_notFoundReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerNotFound.selector,
                bytes32(uint256(999))
            )
        );
        pc3.exportContainer(bytes32(uint256(999)));
    }

    function test_exportContainer_consumedReverts() public {
        (bytes32 cId, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.prank(verifier);
        pc3.consumeContainer(cId);

        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerAlreadyConsumed.selector,
                cId
            )
        );
        pc3.exportContainer(cId);
    }

    // =====================================================================
    // Section 6 — Policy Management
    // =====================================================================

    function testFuzz_addPolicy(bytes32 policyHash) public {
        vm.prank(admin);
        pc3.addPolicy(policyHash);
        assertTrue(pc3.supportedPolicies(policyHash));
    }

    function testFuzz_removePolicy(bytes32 policyHash) public {
        vm.prank(admin);
        pc3.addPolicy(policyHash);
        assertTrue(pc3.supportedPolicies(policyHash));

        vm.prank(admin);
        pc3.removePolicy(policyHash);
        assertFalse(pc3.supportedPolicies(policyHash));
    }

    function testFuzz_addPolicy_unauthorizedReverts(address caller) public {
        vm.assume(caller != admin);
        vm.prank(caller);
        vm.expectRevert();
        pc3.addPolicy(keccak256("policy"));
    }

    // =====================================================================
    // Section 7 — Admin Functions
    // =====================================================================

    function testFuzz_setProofValidityWindow(uint256 window) public {
        vm.prank(admin);
        pc3.setProofValidityWindow(window);
        assertEq(pc3.proofValidityWindow(), window);
    }

    function testFuzz_setVerifierRegistry(address registry) public {
        vm.prank(admin);
        pc3.setVerifierRegistry(registry);
    }

    function test_setRealVerification_toggle() public {
        vm.prank(admin);
        pc3.setRealVerification(true);
        assertTrue(pc3.useRealVerification());

        vm.prank(admin);
        pc3.setRealVerification(false);
        assertFalse(pc3.useRealVerification());
    }

    function test_pauseUnpause() public {
        vm.prank(admin);
        pc3.pause();
        assertTrue(pc3.paused());

        vm.prank(admin);
        pc3.unpause();
        assertFalse(pc3.paused());
    }

    // =====================================================================
    // Section 8 — View Functions
    // =====================================================================

    function test_getContainerIds_pagination() public {
        // Create 5 containers
        for (uint256 i = 1; i <= 5; i++) {
            _createDefaultContainer(bytes32(i), bytes32(i + 100));
        }

        // Get first 3
        bytes32[] memory page1 = pc3.getContainerIds(0, 3);
        assertEq(page1.length, 3);

        // Get next 3 (only 2 remain)
        bytes32[] memory page2 = pc3.getContainerIds(3, 3);
        assertEq(page2.length, 2);
    }

    function test_getContainerIds_emptyStart() public view {
        bytes32[] memory result = pc3.getContainerIds(0, 10);
        assertEq(result.length, 0);
    }

    function test_batchVerifyContainers() public {
        (bytes32 cId1, ) = _createDefaultContainer(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        (bytes32 cId2, ) = _createDefaultContainer(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = cId1;
        ids[1] = cId2;

        ProofCarryingContainer.VerificationResult[] memory results = pc3
            .batchVerifyContainers(ids);
        assertEq(results.length, 2);
        assertTrue(results[0].validityValid);
        assertTrue(results[1].validityValid);
    }

    function test_isNullifierConsumed() public {
        bytes32 nullifier = bytes32(uint256(42));
        assertFalse(pc3.isNullifierConsumed(nullifier));

        _createDefaultContainer(bytes32(uint256(1)), nullifier);
        assertFalse(pc3.isNullifierConsumed(nullifier)); // created but not consumed

        bytes32 cId = _computeContainerId(bytes32(uint256(1)), nullifier);
        vm.prank(verifier);
        pc3.consumeContainer(cId);
        assertTrue(pc3.isNullifierConsumed(nullifier)); // now consumed
    }

    // =====================================================================
    // Section 9 — Container ID determinism
    // =====================================================================

    function testFuzz_containerIdDeterministic(
        bytes32 state,
        bytes32 nullifier
    ) public {
        vm.assume(state != bytes32(0) && nullifier != bytes32(0));
        bytes32 expected = keccak256(
            abi.encodePacked(state, nullifier, uint64(block.chainid))
        );
        bytes32 computed = _computeContainerId(state, nullifier);
        assertEq(computed, expected);
    }

    // =====================================================================
    // Section 10 — Proof bundle fuzz
    // =====================================================================

    function testFuzz_proofBundleIntegrity(
        bytes32 seed1,
        bytes32 seed2,
        bytes32 seed3
    ) public {
        bytes memory vProof = abi.encodePacked(
            seed1,
            new bytes(pc3.MIN_PROOF_SIZE())
        );
        bytes memory pProof = abi.encodePacked(
            seed2,
            new bytes(pc3.MIN_PROOF_SIZE())
        );
        bytes memory nProof = abi.encodePacked(
            seed3,
            new bytes(pc3.MIN_PROOF_SIZE())
        );

        bytes32 expectedHash = keccak256(abi.encode(vProof, pProof, nProof));

        ProofCarryingContainer.ProofBundle
            memory proofs = ProofCarryingContainer.ProofBundle({
                validityProof: vProof,
                policyProof: pProof,
                nullifierProof: nProof,
                proofHash: expectedHash,
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 24 hours
            });

        vm.prank(user1);
        pc3.createContainer(
            "payload",
            bytes32(
                uint256(
                    uint256(keccak256(abi.encodePacked(seed1, seed2))) %
                        type(uint256).max
                ) + 1
            ),
            bytes32(
                uint256(
                    uint256(keccak256(abi.encodePacked(seed2, seed3))) %
                        type(uint256).max
                ) + 1
            ),
            proofs,
            bytes32(0)
        );
    }

    // =====================================================================
    // Helpers
    // =====================================================================

    function _makeProofBundle()
        internal
        view
        returns (ProofCarryingContainer.ProofBundle memory)
    {
        bytes memory vProof = new bytes(pc3.MIN_PROOF_SIZE());
        bytes memory pProof = new bytes(pc3.MIN_PROOF_SIZE());
        bytes memory nProof = new bytes(pc3.MIN_PROOF_SIZE());
        bytes32 hash = keccak256(abi.encode(vProof, pProof, nProof));

        return
            ProofCarryingContainer.ProofBundle({
                validityProof: vProof,
                policyProof: pProof,
                nullifierProof: nProof,
                proofHash: hash,
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 24 hours
            });
    }

    function _createDefaultContainer(
        bytes32 state,
        bytes32 nullifier
    ) internal returns (bytes32 cId, bytes32 nullifierOut) {
        ProofCarryingContainer.ProofBundle memory proofs = _makeProofBundle();
        vm.prank(user1);
        cId = pc3.createContainer(
            "default_payload",
            state,
            nullifier,
            proofs,
            bytes32(0)
        );
        nullifierOut = nullifier;
    }

    function _computeContainerId(
        bytes32 state,
        bytes32 nullifier
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(state, nullifier, uint64(block.chainid))
            );
    }
}
