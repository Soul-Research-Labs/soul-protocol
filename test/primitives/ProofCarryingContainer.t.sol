// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/ProofCarryingContainer.sol";

/// @title ProofCarryingContainerTest
/// @notice Comprehensive unit tests for the ProofCarryingContainer (PC³) primitive
contract ProofCarryingContainerTest is Test {
    ProofCarryingContainer public pc3;

    address public admin = address(0xAD);
    address public verifier = address(0xBE);
    address public user = address(0xCA);

    bytes32 public constant CONTAINER_ADMIN_ROLE =
        0xd0079826f5316a30be81f752efa53f9a84b4f3a6f49fcc124be773400a02ee85;
    bytes32 public constant VERIFIER_ROLE =
        0x0ce23c3e399818cfee81a7ab0880f714e53d7672b08df0fa62f2843416e1ea09;

    // Reusable test data
    bytes public validPayload;
    bytes32 public commitment;
    bytes32 public nullifier;
    bytes32 public policyHash;
    ProofCarryingContainer.ProofBundle public validBundle;

    function setUp() public {
        vm.startPrank(admin);
        pc3 = new ProofCarryingContainer();

        // Set to test mode (skip SNARK verification)
        pc3.setRealVerification(false);

        // Grant verifier role
        pc3.grantRole(VERIFIER_ROLE, verifier);

        vm.stopPrank();

        // Build reusable test data
        validPayload = _makePayload(512);
        commitment = keccak256("test-commitment");
        nullifier = keccak256("test-nullifier");
        policyHash = bytes32(0); // no policy

        // Build valid proof bundle
        bytes memory proof256 = _makePayload(256);
        validBundle = ProofCarryingContainer.ProofBundle({
            validityProof: proof256,
            policyProof: proof256,
            nullifierProof: proof256,
            proofHash: keccak256(abi.encode(proof256, proof256, proof256)),
            proofTimestamp: block.timestamp,
            proofExpiry: block.timestamp + 24 hours
        });
    }

    /*//////////////////////////////////////////////////////////////
                          DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_deployment_setsChainId() public view {
        assertEq(pc3.CHAIN_ID(), block.chainid);
    }

    function test_deployment_defaultVerificationMode() public {
        // Deploy fresh — default is true
        ProofCarryingContainer fresh = new ProofCarryingContainer();
        assertTrue(fresh.useRealVerification());
    }

    function test_deployment_grantsAdminRoles() public view {
        assertTrue(pc3.hasRole(pc3.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(pc3.hasRole(CONTAINER_ADMIN_ROLE, admin));
    }

    function test_deployment_defaultProofValidityWindow() public view {
        assertEq(pc3.proofValidityWindow(), 24 hours);
    }

    /*//////////////////////////////////////////////////////////////
                      CONTAINER CREATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_createContainer_success() public {
        vm.prank(user);
        bytes32 containerId = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        assertTrue(containerId != bytes32(0));
        assertEq(pc3.totalContainers(), 1);

        ProofCarryingContainer.Container memory c = pc3.getContainer(
            containerId
        );
        assertEq(c.stateCommitment, commitment);
        assertEq(c.nullifier, nullifier);
        assertEq(c.chainId, uint64(block.chainid));
        assertEq(c.version, 1);
        assertFalse(c.isVerified);
        assertFalse(c.isConsumed);
    }

    function test_createContainer_revertsEmptyPayload() public {
        vm.prank(user);
        vm.expectRevert(ProofCarryingContainer.InvalidContainerData.selector);
        pc3.createContainer("", commitment, nullifier, validBundle, policyHash);
    }

    function test_createContainer_revertsPayloadTooLarge() public {
        bytes memory hugePayload = _makePayload(1 << (20 + 1)); // > 1MB
        vm.prank(user);
        // PayloadTooLarge has params, just check it reverts
        vm.expectRevert();
        pc3.createContainer(
            hugePayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );
    }

    function test_createContainer_revertsZeroCommitment() public {
        vm.prank(user);
        vm.expectRevert(ProofCarryingContainer.InvalidContainerData.selector);
        pc3.createContainer(
            validPayload,
            bytes32(0),
            nullifier,
            validBundle,
            policyHash
        );
    }

    function test_createContainer_revertsZeroNullifier() public {
        vm.prank(user);
        vm.expectRevert(ProofCarryingContainer.InvalidContainerData.selector);
        pc3.createContainer(
            validPayload,
            commitment,
            bytes32(0),
            validBundle,
            policyHash
        );
    }

    function test_createContainer_revertsProofTooSmall() public {
        ProofCarryingContainer.ProofBundle memory smallBundle = ProofCarryingContainer
            .ProofBundle({
                validityProof: _makePayload(100), // < MIN_PROOF_SIZE (256)
                policyProof: _makePayload(256),
                nullifierProof: _makePayload(256),
                proofHash: bytes32(0),
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 1 hours
            });

        vm.prank(user);
        vm.expectRevert();
        pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            smallBundle,
            policyHash
        );
    }

    function test_createContainer_revertsUnsupportedPolicy() public {
        bytes32 unknownPolicy = keccak256("unknown-policy");

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.UnsupportedPolicy.selector,
                unknownPolicy
            )
        );
        pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            unknownPolicy
        );
    }

    function test_createContainer_revertsNullifierAlreadyConsumed() public {
        // Create and consume a container first
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(verifier);
        pc3.consumeContainer(cid);

        // Try creating with same nullifier
        bytes32 commitment2 = keccak256("commitment-2");
        ProofCarryingContainer.ProofBundle memory bundle2 = validBundle;
        bundle2.proofHash = keccak256(
            abi.encode(
                bundle2.validityProof,
                bundle2.policyProof,
                bundle2.nullifierProof
            )
        );

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.NullifierAlreadyConsumed.selector,
                nullifier
            )
        );
        pc3.createContainer(
            validPayload,
            commitment2,
            nullifier,
            bundle2,
            policyHash
        );
    }

    function test_createContainer_revertsDuplicateContainerId() public {
        vm.prank(user);
        pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        // Same commitment + nullifier + chainId = same container ID
        vm.prank(user);
        vm.expectRevert();
        pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );
    }

    function test_createContainer_revertsInvalidProofHash() public {
        ProofCarryingContainer.ProofBundle memory badBundle = ProofCarryingContainer
            .ProofBundle({
                validityProof: _makePayload(256),
                policyProof: _makePayload(256),
                nullifierProof: _makePayload(256),
                proofHash: bytes32(uint256(1)), // wrong hash
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 1 hours
            });

        vm.prank(user);
        vm.expectRevert(ProofCarryingContainer.InvalidProofBundle.selector);
        pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            badBundle,
            policyHash
        );
    }

    function test_createContainer_revertsWhenPaused() public {
        vm.prank(admin);
        pc3.pause();

        vm.prank(user);
        vm.expectRevert();
        pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );
    }

    function test_createContainer_withSupportedPolicy() public {
        bytes32 policy = keccak256("OFAC");
        vm.prank(admin);
        pc3.addPolicy(policy);

        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policy
        );
        ProofCarryingContainer.Container memory c = pc3.getContainer(cid);
        assertEq(c.policyHash, policy);
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFICATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_verifyContainer_success() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        ProofCarryingContainer.VerificationResult memory result = pc3
            .verifyContainer(cid);
        assertTrue(result.validityValid);
        assertTrue(result.policyValid);
        assertTrue(result.nullifierValid);
        assertTrue(result.notExpired);
        assertTrue(result.notConsumed);
    }

    function test_verifyContainer_notFound() public view {
        ProofCarryingContainer.VerificationResult memory result = pc3
            .verifyContainer(bytes32(uint256(999)));
        assertFalse(result.validityValid);
        assertEq(result.failureReason, "Container not found");
    }

    function test_verifyContainer_expired() public {
        // Create with expiry
        ProofCarryingContainer.ProofBundle memory expiringBundle = validBundle;
        expiringBundle.proofExpiry = block.timestamp + 1 hours;

        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            expiringBundle,
            policyHash
        );

        // Warp past expiry
        vm.warp(block.timestamp + 2 hours);

        ProofCarryingContainer.VerificationResult memory result = pc3
            .verifyContainer(cid);
        assertFalse(result.notExpired);
        assertEq(result.failureReason, "Proof expired");
    }

    function test_verifyContainer_consumed() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(verifier);
        pc3.consumeContainer(cid);

        ProofCarryingContainer.VerificationResult memory result = pc3
            .verifyContainer(cid);
        assertFalse(result.notConsumed);
        assertEq(result.failureReason, "Container already consumed");
    }

    function test_batchVerifyContainers() public {
        bytes32[] memory ids = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            bytes32 c = keccak256(abi.encodePacked("commitment-", i));
            bytes32 n = keccak256(abi.encodePacked("nullifier-", i));
            bytes memory proof256 = _makePayload(256);
            ProofCarryingContainer.ProofBundle
                memory bundle = ProofCarryingContainer.ProofBundle({
                    validityProof: proof256,
                    policyProof: proof256,
                    nullifierProof: proof256,
                    proofHash: keccak256(
                        abi.encode(proof256, proof256, proof256)
                    ),
                    proofTimestamp: block.timestamp,
                    proofExpiry: block.timestamp + 24 hours
                });

            vm.prank(user);
            ids[i] = pc3.createContainer(
                validPayload,
                c,
                n,
                bundle,
                bytes32(0)
            );
        }

        ProofCarryingContainer.VerificationResult[] memory results = pc3
            .batchVerifyContainers(ids);
        assertEq(results.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(results[i].validityValid);
            assertTrue(results[i].notExpired);
            assertTrue(results[i].notConsumed);
        }
    }

    /*//////////////////////////////////////////////////////////////
                       CONSUMPTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_consumeContainer_success() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(verifier);
        pc3.consumeContainer(cid);

        ProofCarryingContainer.Container memory c = pc3.getContainer(cid);
        assertTrue(c.isConsumed);
        assertTrue(pc3.isNullifierConsumed(nullifier));
    }

    function test_consumeContainer_revertsNotFound() public {
        vm.prank(verifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerNotFound.selector,
                bytes32(uint256(999))
            )
        );
        pc3.consumeContainer(bytes32(uint256(999)));
    }

    function test_consumeContainer_revertsAlreadyConsumed() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(verifier);
        pc3.consumeContainer(cid);

        vm.prank(verifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerAlreadyConsumed.selector,
                cid
            )
        );
        pc3.consumeContainer(cid);
    }

    function test_consumeContainer_revertsWithoutRole() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(user); // user doesn't have VERIFIER_ROLE
        vm.expectRevert();
        pc3.consumeContainer(cid);
    }

    function test_consumeContainer_revertsWhenPaused() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(admin);
        pc3.pause();

        vm.prank(verifier);
        vm.expectRevert();
        pc3.consumeContainer(cid);
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-CHAIN IMPORT/EXPORT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_exportContainer_success() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        bytes memory exported = pc3.exportContainer(cid);
        assertTrue(exported.length > 0);
    }

    function test_exportContainer_revertsNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerNotFound.selector,
                bytes32(uint256(42))
            )
        );
        pc3.exportContainer(bytes32(uint256(42)));
    }

    function test_exportContainer_revertsIfConsumed() public {
        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash
        );

        vm.prank(verifier);
        pc3.consumeContainer(cid);

        vm.expectRevert(
            abi.encodeWithSelector(
                ProofCarryingContainer.ContainerAlreadyConsumed.selector,
                cid
            )
        );
        pc3.exportContainer(cid);
    }

    function test_importContainer_success() public {
        // Encode container data for import (different source chain)
        uint64 sourceChain = 137; // Polygon
        bytes memory proof256 = _makePayload(256);
        ProofCarryingContainer.ProofBundle
            memory bundle = ProofCarryingContainer.ProofBundle({
                validityProof: proof256,
                policyProof: proof256,
                nullifierProof: proof256,
                proofHash: keccak256(abi.encode(proof256, proof256, proof256)),
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 24 hours
            });

        bytes memory containerData = abi.encode(
            validPayload,
            commitment,
            nullifier,
            bundle,
            policyHash,
            sourceChain
        );

        vm.prank(user);
        bytes32 cid = pc3.importContainer(containerData, _makePayload(256));

        ProofCarryingContainer.Container memory c = pc3.getContainer(cid);
        assertEq(c.chainId, sourceChain);
        assertEq(c.stateCommitment, commitment);
        assertFalse(c.isConsumed);
    }

    function test_importContainer_revertsShortProof() public {
        bytes memory containerData = abi.encode(
            validPayload,
            commitment,
            nullifier,
            validBundle,
            policyHash,
            uint64(137)
        );

        vm.prank(user);
        vm.expectRevert(ProofCarryingContainer.InvalidProofBundle.selector);
        pc3.importContainer(containerData, _makePayload(100)); // < MIN_PROOF_SIZE
    }

    /*//////////////////////////////////////////////////////////////
                       POLICY MANAGEMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_addPolicy() public {
        bytes32 policy = keccak256("OFAC");

        vm.prank(admin);
        pc3.addPolicy(policy);

        assertTrue(pc3.supportedPolicies(policy));
    }

    function test_removePolicy() public {
        bytes32 policy = keccak256("OFAC");

        vm.prank(admin);
        pc3.addPolicy(policy);
        assertTrue(pc3.supportedPolicies(policy));

        vm.prank(admin);
        pc3.removePolicy(policy);
        assertFalse(pc3.supportedPolicies(policy));
    }

    function test_addPolicy_revertsWithoutRole() public {
        vm.prank(user);
        vm.expectRevert();
        pc3.addPolicy(keccak256("OFAC"));
    }

    /*//////////////////////////////////////////////////////////////
                     ADMIN FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_setProofValidityWindow() public {
        vm.prank(admin);
        pc3.setProofValidityWindow(48 hours);
        assertEq(pc3.proofValidityWindow(), 48 hours);
    }

    function test_setVerifierRegistry() public {
        address newRegistry = address(0xDE);
        vm.prank(admin);
        pc3.setVerifierRegistry(newRegistry);
        assertEq(address(pc3.verifierRegistry()), newRegistry);
    }

    function test_setRealVerification() public {
        vm.startPrank(admin);
        pc3.setRealVerification(true);
        assertTrue(pc3.useRealVerification());
        pc3.setRealVerification(false);
        assertFalse(pc3.useRealVerification());
        vm.stopPrank();
    }

    function test_lockVerificationMode() public {
        vm.startPrank(admin);
        pc3.lockVerificationMode();

        assertTrue(pc3.verificationLocked());
        assertTrue(pc3.useRealVerification());

        // After locking, cannot disable
        vm.expectRevert(
            ProofCarryingContainer.VerificationModePermanentlyLocked.selector
        );
        pc3.setRealVerification(false);
        vm.stopPrank();
    }

    function test_lockVerificationMode_revertsWithoutAdmin() public {
        vm.prank(user);
        vm.expectRevert();
        pc3.lockVerificationMode();
    }

    function test_pause_unpause() public {
        vm.startPrank(admin);
        pc3.pause();
        assertTrue(pc3.paused());
        pc3.unpause();
        assertFalse(pc3.paused());
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                       VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getContainerIds_pagination() public {
        // Create 5 containers
        for (uint256 i = 0; i < 5; i++) {
            bytes32 c = keccak256(abi.encodePacked("c-", i));
            bytes32 n = keccak256(abi.encodePacked("n-", i));
            bytes memory proof256 = _makePayload(256);
            ProofCarryingContainer.ProofBundle
                memory bundle = ProofCarryingContainer.ProofBundle({
                    validityProof: proof256,
                    policyProof: proof256,
                    nullifierProof: proof256,
                    proofHash: keccak256(
                        abi.encode(proof256, proof256, proof256)
                    ),
                    proofTimestamp: block.timestamp,
                    proofExpiry: block.timestamp + 24 hours
                });

            vm.prank(user);
            pc3.createContainer(validPayload, c, n, bundle, bytes32(0));
        }

        assertEq(pc3.totalContainers(), 5);

        // Get page 1 (offset=0, limit=2)
        bytes32[] memory page1 = pc3.getContainerIds(0, 2);
        assertEq(page1.length, 2);

        // Get page 2 (offset=2, limit=2)
        bytes32[] memory page2 = pc3.getContainerIds(2, 2);
        assertEq(page2.length, 2);

        // Get last page (offset=4, limit=10)
        bytes32[] memory page3 = pc3.getContainerIds(4, 10);
        assertEq(page3.length, 1);

        // Past end
        bytes32[] memory empty = pc3.getContainerIds(100, 10);
        assertEq(empty.length, 0);
    }

    function test_isNullifierConsumed_false() public view {
        assertFalse(pc3.isNullifierConsumed(keccak256("random")));
    }

    function test_getContainer_nonExistent() public view {
        ProofCarryingContainer.Container memory c = pc3.getContainer(
            bytes32(uint256(999))
        );
        assertEq(c.createdAt, 0);
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_createContainer_differentCommitments(
        bytes32 commitmentSeed
    ) public {
        vm.assume(commitmentSeed != bytes32(0));

        bytes32 n = keccak256(abi.encodePacked("nullifier-", commitmentSeed));

        bytes memory proof256 = _makePayload(256);
        ProofCarryingContainer.ProofBundle
            memory bundle = ProofCarryingContainer.ProofBundle({
                validityProof: proof256,
                policyProof: proof256,
                nullifierProof: proof256,
                proofHash: keccak256(abi.encode(proof256, proof256, proof256)),
                proofTimestamp: block.timestamp,
                proofExpiry: block.timestamp + 24 hours
            });

        vm.prank(user);
        bytes32 cid = pc3.createContainer(
            validPayload,
            commitmentSeed,
            n,
            bundle,
            bytes32(0)
        );

        ProofCarryingContainer.Container memory c = pc3.getContainer(cid);
        assertEq(c.stateCommitment, commitmentSeed);
    }

    function testFuzz_containerIdDeterministic(
        bytes32 c,
        bytes32 n
    ) public pure {
        vm.assume(c != bytes32(0) && n != bytes32(0));
        uint64 chain = 1;

        bytes32 id1 = keccak256(abi.encodePacked(c, n, chain));
        bytes32 id2 = keccak256(abi.encodePacked(c, n, chain));
        assertEq(id1, id2);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPERS
    //////////////////////////////////////////////////////////////*/

    function _makePayload(uint256 size) internal pure returns (bytes memory) {
        bytes memory data = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            data[i] = bytes1(uint8(i % 256));
        }
        return data;
    }
}
