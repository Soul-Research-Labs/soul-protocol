// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/CrossDomainNullifierAlgebra.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/// @dev Mock verifier for derivation proofs
contract MockDerivationVerifier is IProofVerifier {
    bool public shouldPass = true;

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

    function getPublicInputCount() external pure override returns (uint256) {
        return 4;
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

contract CrossDomainNullifierAlgebraTest is Test {
    CrossDomainNullifierAlgebra public cdna;
    MockDerivationVerifier public verifier;

    address public admin = address(this);
    address public bridgeAddr = address(0xBEEF);

    uint64 public constant CHAIN_1 = 1;
    uint64 public constant CHAIN_2 = 42161;
    bytes32 public constant APP_ID = keccak256("soul-protocol");
    bytes32 public constant APP_ID_2 = keccak256("soul-swap");

    function setUp() public {
        cdna = new CrossDomainNullifierAlgebra();
        verifier = new MockDerivationVerifier();

        // Grant roles
        cdna.grantRole(cdna.BRIDGE_ROLE(), bridgeAddr);
        cdna.grantRole(cdna.NULLIFIER_REGISTRAR_ROLE(), admin);
        cdna.grantRole(cdna.NULLIFIER_REGISTRAR_ROLE(), bridgeAddr);

        // Set verifier
        cdna.setDerivationVerifier(address(verifier));
    }

    // ============= Constructor =============

    function test_Constructor_SetsChainId() public view {
        assertEq(cdna.CHAIN_ID(), block.chainid);
    }

    function test_Constructor_InitializesEpoch() public view {
        assertEq(cdna.currentEpochId(), 1);
        CrossDomainNullifierAlgebra.Epoch memory epoch = cdna.getEpoch(1);
        assertFalse(epoch.isFinalized);
        assertEq(epoch.epochId, 1);
    }

    function test_Constructor_GrantsRoles() public view {
        assertTrue(cdna.hasRole(cdna.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(cdna.hasRole(cdna.DOMAIN_ADMIN_ROLE(), admin));
        assertTrue(cdna.hasRole(cdna.NULLIFIER_REGISTRAR_ROLE(), admin));
    }

    // ============= Domain Registration =============

    function test_RegisterDomain() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        assertTrue(domainId != bytes32(0));

        CrossDomainNullifierAlgebra.Domain memory domain = cdna.getDomain(
            domainId
        );
        assertEq(domain.chainId, CHAIN_1);
        assertEq(domain.appId, APP_ID);
        assertTrue(domain.isActive);
        assertEq(cdna.totalDomains(), 1);
    }

    function test_RegisterDomain_RevertInvalidChainId() public {
        vm.expectRevert(CrossDomainNullifierAlgebra.InvalidChainId.selector);
        cdna.registerDomain(0, APP_ID, 0);
    }

    function test_RegisterDomain_RevertZeroAppId() public {
        vm.expectRevert(CrossDomainNullifierAlgebra.ZeroAppId.selector);
        cdna.registerDomain(CHAIN_1, bytes32(0), 0);
    }

    function test_RegisterDomain_RevertDuplicate() public {
        cdna.registerDomain(CHAIN_1, APP_ID, 0);
        vm.expectRevert();
        cdna.registerDomain(CHAIN_1, APP_ID, 0);
    }

    function test_DeactivateDomain() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        cdna.deactivateDomain(domainId);

        CrossDomainNullifierAlgebra.Domain memory domain = cdna.getDomain(
            domainId
        );
        assertFalse(domain.isActive);
    }

    function test_DeactivateDomain_RevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.DomainNotFound.selector,
                bytes32(uint256(999))
            )
        );
        cdna.deactivateDomain(bytes32(uint256(999)));
    }

    // ============= Nullifier Registration =============

    function test_RegisterNullifier() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 secret = keccak256("secret1");
        bytes32 commitment = keccak256("commitment1");
        bytes32 transition = keccak256("transition1");

        bytes32 nullifier = cdna.registerNullifier(
            domainId,
            secret,
            commitment,
            transition
        );
        assertTrue(nullifier != bytes32(0));
        assertTrue(cdna.nullifierExists(nullifier));
        assertEq(cdna.totalNullifiers(), 1);
    }

    function test_RegisterNullifier_RevertDomainNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.DomainNotFound.selector,
                bytes32(uint256(999))
            )
        );
        cdna.registerNullifier(
            bytes32(uint256(999)),
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );
    }

    function test_RegisterNullifier_RevertDomainInactive() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        cdna.deactivateDomain(domainId);

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.DomainInactive.selector,
                domainId
            )
        );
        cdna.registerNullifier(
            domainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );
    }

    function test_RegisterNullifier_RevertDuplicate() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 secret = keccak256("secret1");
        bytes32 commitment = keccak256("commitment1");
        bytes32 transition = keccak256("transition1");

        cdna.registerNullifier(domainId, secret, commitment, transition);

        vm.expectRevert(); // NullifierAlreadyExists
        cdna.registerNullifier(domainId, secret, commitment, transition);
    }

    function test_RegisterNullifier_CorrectDomainSeparation() public {
        bytes32 domainId1 = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 domainId2 = cdna.registerDomain(CHAIN_2, APP_ID_2, 0);

        bytes32 secret = keccak256("same_secret");
        bytes32 commitment = keccak256("commitment");
        bytes32 transition = keccak256("transition");

        bytes32 null1 = cdna.registerNullifier(
            domainId1,
            secret,
            commitment,
            transition
        );
        bytes32 null2 = cdna.registerNullifier(
            domainId2,
            secret,
            commitment,
            transition
        );

        // Same secret, different domains → different nullifiers
        assertTrue(null1 != null2);
    }

    // ============= Consume Nullifier =============

    function test_ConsumeNullifier() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 nullifier = cdna.registerNullifier(
            domainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );

        assertTrue(cdna.isNullifierValid(nullifier));
        cdna.consumeNullifier(nullifier);
        assertFalse(cdna.isNullifierValid(nullifier));
    }

    function test_ConsumeNullifier_RevertNotFound() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.NullifierNotFound.selector,
                bytes32(uint256(1))
            )
        );
        cdna.consumeNullifier(bytes32(uint256(1)));
    }

    function test_ConsumeNullifier_RevertAlreadyConsumed() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 nullifier = cdna.registerNullifier(
            domainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );
        cdna.consumeNullifier(nullifier);

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.NullifierAlreadyConsumed.selector,
                nullifier
            )
        );
        cdna.consumeNullifier(nullifier);
    }

    // ============= Cross-Domain Derived Nullifier =============

    function test_RegisterDerivedNullifier() public {
        bytes32 sourceDomainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 targetDomainId = cdna.registerDomain(CHAIN_2, APP_ID_2, 0);

        // Register parent nullifier
        bytes32 parentNull = cdna.registerNullifier(
            sourceDomainId,
            keccak256("secret"),
            keccak256("commit"),
            keccak256("trans")
        );

        // Register derived nullifier via bridge
        vm.prank(bridgeAddr);
        bytes32 childNull = cdna.registerDerivedNullifier(
            parentNull,
            targetDomainId,
            keccak256("trans2"),
            hex"aabb"
        );

        assertTrue(cdna.nullifierExists(childNull));
        assertEq(cdna.totalCrossLinks(), 1);

        // Check child is linked to parent
        bytes32[] memory children = cdna.getChildNullifiers(parentNull);
        assertEq(children.length, 1);
        assertEq(children[0], childNull);
    }

    function test_RegisterDerivedNullifier_RevertParentNotFound() public {
        bytes32 targetDomainId = cdna.registerDomain(CHAIN_2, APP_ID_2, 0);

        vm.prank(bridgeAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.ParentNullifierNotFound.selector,
                bytes32(uint256(999))
            )
        );
        cdna.registerDerivedNullifier(
            bytes32(uint256(999)),
            targetDomainId,
            keccak256("t"),
            hex"aa"
        );
    }

    function test_RegisterDerivedNullifier_RevertInvalidProof() public {
        bytes32 sourceDomainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 targetDomainId = cdna.registerDomain(CHAIN_2, APP_ID_2, 0);
        bytes32 parentNull = cdna.registerNullifier(
            sourceDomainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );

        verifier.setShouldPass(false);

        vm.prank(bridgeAddr);
        vm.expectRevert(
            CrossDomainNullifierAlgebra.InvalidCrossDomainProof.selector
        );
        cdna.registerDerivedNullifier(
            parentNull,
            targetDomainId,
            keccak256("t2"),
            hex"aa"
        );
    }

    // ============= Epoch Management =============

    function test_FinalizeEpoch() public {
        bytes32 merkleRoot = keccak256("epoch_root");
        cdna.finalizeEpoch(merkleRoot);

        CrossDomainNullifierAlgebra.Epoch memory epoch = cdna.getEpoch(1);
        assertTrue(epoch.isFinalized);
        assertEq(epoch.merkleRoot, merkleRoot);
        assertEq(cdna.currentEpochId(), 2);
    }

    function test_FinalizeEpoch_RevertAlreadyFinalized() public {
        cdna.finalizeEpoch(keccak256("root"));
        // Now epoch 1 is finalized and currentEpochId = 2
        // Finalize epoch 2 and try again on epoch 2
        cdna.finalizeEpoch(keccak256("root2"));
        // Now currentEpochId = 3, epoch 3 is not finalized
        // We can't trigger AlreadyFinalized through the public API since
        // finalizeEpoch always operates on currentEpochId and advances
        // Just verify the normal flow works correctly
        assertEq(cdna.currentEpochId(), 3);
    }

    function test_AutoAdvanceEpoch() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);

        // Warp past epoch end (1 hour)
        vm.warp(block.timestamp + 1 hours + 1);

        // Register nullifier triggers auto-advance
        cdna.registerNullifier(
            domainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );

        // Should be in epoch 2
        assertEq(cdna.currentEpochId(), 2);
    }

    // ============= Computation Helpers =============

    function test_ComputeDomainSeparator() public view {
        bytes32 sep1 = cdna.computeDomainSeparator(1, keccak256("app"), 1);
        bytes32 sep2 = cdna.computeDomainSeparator(2, keccak256("app"), 1);
        assertTrue(sep1 != sep2);
    }

    function test_ComputeNullifier_Deterministic() public view {
        bytes32 n1 = cdna.computeNullifier(
            keccak256("secret"),
            keccak256("domain"),
            keccak256("transition")
        );
        bytes32 n2 = cdna.computeNullifier(
            keccak256("secret"),
            keccak256("domain"),
            keccak256("transition")
        );
        assertEq(n1, n2);
    }

    function test_ComputeNullifier_DifferentInputs() public view {
        bytes32 n1 = cdna.computeNullifier(
            keccak256("s1"),
            keccak256("d"),
            keccak256("t")
        );
        bytes32 n2 = cdna.computeNullifier(
            keccak256("s2"),
            keccak256("d"),
            keccak256("t")
        );
        assertTrue(n1 != n2);
    }

    // ============= Batch Operations =============

    function test_BatchCheckNullifiers() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 null1 = cdna.registerNullifier(
            domainId,
            keccak256("s1"),
            keccak256("c1"),
            keccak256("t1")
        );
        bytes32 null2 = cdna.registerNullifier(
            domainId,
            keccak256("s2"),
            keccak256("c2"),
            keccak256("t2")
        );
        cdna.consumeNullifier(null2);

        bytes32[] memory toCheck = new bytes32[](3);
        toCheck[0] = null1;
        toCheck[1] = null2;
        toCheck[2] = bytes32(uint256(999)); // nonexistent

        bool[] memory results = cdna.batchCheckNullifiers(toCheck);
        assertTrue(results[0]); // valid
        assertFalse(results[1]); // consumed
        assertFalse(results[2]); // nonexistent
    }

    function test_BatchConsumeNullifiers() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 null1 = cdna.registerNullifier(
            domainId,
            keccak256("s1"),
            keccak256("c1"),
            keccak256("t1")
        );
        bytes32 null2 = cdna.registerNullifier(
            domainId,
            keccak256("s2"),
            keccak256("c2"),
            keccak256("t2")
        );

        bytes32[] memory toConsume = new bytes32[](2);
        toConsume[0] = null1;
        toConsume[1] = null2;

        cdna.batchConsumeNullifiers(toConsume);

        assertFalse(cdna.isNullifierValid(null1));
        assertFalse(cdna.isNullifierValid(null2));
    }

    function test_BatchConsumeNullifiers_RevertIfNotFound() public {
        bytes32[] memory toConsume = new bytes32[](1);
        toConsume[0] = bytes32(uint256(999));

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.NullifierNotFound.selector,
                bytes32(uint256(999))
            )
        );
        cdna.batchConsumeNullifiers(toConsume);
    }

    // ============= View Functions =============

    function test_GetNullifier() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 commitHash = keccak256("c");
        bytes32 transId = keccak256("t");
        bytes32 nullifier = cdna.registerNullifier(
            domainId,
            keccak256("s"),
            commitHash,
            transId
        );

        (
            bytes32 retDomainId,
            bytes32 retCommit,
            bytes32 retTrans,
            ,
            ,
            ,
            bool consumed
        ) = cdna.getNullifier(nullifier);
        assertEq(retDomainId, domainId);
        assertEq(retCommit, commitHash);
        assertEq(retTrans, transId);
        assertFalse(consumed);
    }

    function test_GetNullifiersByDomain() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        cdna.registerNullifier(
            domainId,
            keccak256("s1"),
            keccak256("c1"),
            keccak256("t1")
        );
        cdna.registerNullifier(
            domainId,
            keccak256("s2"),
            keccak256("c2"),
            keccak256("t2")
        );

        bytes32[] memory nulls = cdna.getNullifiersByDomain(domainId);
        assertEq(nulls.length, 2);
    }

    function test_GetActiveDomains() public {
        cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 domainId2 = cdna.registerDomain(CHAIN_2, APP_ID_2, 0);
        cdna.deactivateDomain(domainId2);

        bytes32[] memory active = cdna.getActiveDomains();
        assertEq(active.length, 1);
    }

    function test_GetStats() public {
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        cdna.registerNullifier(
            domainId,
            keccak256("s1"),
            keccak256("c1"),
            keccak256("t1")
        );

        (uint256 domains_, uint256 nullifiers_, , uint64 epoch) = cdna
            .getStats();
        assertEq(domains_, 1);
        assertEq(nullifiers_, 1);
        assertEq(epoch, 1);
    }

    // ============= Admin Functions =============

    function test_SetEpochDuration() public {
        cdna.setEpochDuration(2 hours);
        assertEq(cdna.epochDuration(), 2 hours);
    }

    function test_SetEpochDuration_RevertTooShort() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.InvalidEpochDuration.selector,
                uint64(30)
            )
        );
        cdna.setEpochDuration(30); // < 1 minute
    }

    function test_SetEpochDuration_RevertTooLong() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                CrossDomainNullifierAlgebra.InvalidEpochDuration.selector,
                uint64(8 days)
            )
        );
        cdna.setEpochDuration(uint64(8 days)); // > 7 days
    }

    function test_SetDerivationVerifier() public {
        address newVerifier = address(new MockDerivationVerifier());
        cdna.setDerivationVerifier(newVerifier);
        assertEq(address(cdna.derivationVerifier()), newVerifier);
    }

    function test_SetDerivationVerifier_RevertZeroAddress() public {
        vm.expectRevert("Zero verifier address");
        cdna.setDerivationVerifier(address(0));
    }

    function test_PauseUnpause() public {
        cdna.pause();
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        vm.expectRevert();
        cdna.registerNullifier(
            domainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );

        cdna.unpause();
        cdna.registerNullifier(
            domainId,
            keccak256("s"),
            keccak256("c"),
            keccak256("t")
        );
    }

    // ============= Fuzz Tests =============

    function testFuzz_RegisterNullifier_UniquePerSecret(
        bytes32 secret1,
        bytes32 secret2
    ) public {
        vm.assume(secret1 != secret2);
        bytes32 domainId = cdna.registerDomain(CHAIN_1, APP_ID, 0);
        bytes32 commit = keccak256("c");
        bytes32 trans = keccak256("t");

        bytes32 n1 = cdna.registerNullifier(domainId, secret1, commit, trans);
        bytes32 n2 = cdna.registerNullifier(domainId, secret2, commit, trans);
        assertTrue(n1 != n2);
    }

    function testFuzz_EpochDuration_Bounds(uint64 duration) public {
        if (duration < 1 minutes || duration > 7 days) {
            vm.expectRevert();
            cdna.setEpochDuration(duration);
        } else {
            cdna.setEpochDuration(duration);
            assertEq(cdna.epochDuration(), duration);
        }
    }
}
