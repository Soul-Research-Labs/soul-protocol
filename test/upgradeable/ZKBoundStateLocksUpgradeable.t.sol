// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ZKBoundStateLocksUpgradeable} from "../../contracts/upgradeable/ZKBoundStateLocksUpgradeable.sol";
import {MockProofVerifier} from "../../contracts/mocks/MockProofVerifier.sol";

/**
 * @title ZKBoundStateLocksUpgradeable Tests
 * @notice Tests initialization, lock creation, ZK unlock, optimistic unlock,
 *         domain registration, verifier management, access control, and upgrade safety.
 */
contract ZKBoundStateLocksUpgradeableTest is Test {
    ZKBoundStateLocksUpgradeable public impl;
    ZKBoundStateLocksUpgradeable public locks;
    MockProofVerifier public verifier;

    address admin = address(this);
    address user = makeAddr("user");
    address operator = makeAddr("operator");
    address challenger = makeAddr("challenger");

    bytes32 constant OLD_STATE = keccak256("oldState");
    bytes32 constant NEW_STATE = keccak256("newState");
    bytes32 constant PREDICATE = keccak256("predicate");
    bytes32 constant POLICY = bytes32(0);
    bytes32 constant NULLIFIER = keccak256("nullifier");
    bytes32 constant VK_HASH = keccak256("verifier_key");

    bytes32 testDomain;

    function setUp() public {
        verifier = new MockProofVerifier();
        impl = new ZKBoundStateLocksUpgradeable();
        bytes memory data = abi.encodeCall(
            impl.initialize,
            (admin, address(verifier))
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
        locks = ZKBoundStateLocksUpgradeable(payable(address(proxy)));

        // Register a verifier key
        locks.registerVerifier(VK_HASH, address(verifier));

        // Register domain for the test chain (31337 in Foundry)
        testDomain = locks.registerDomain(
            uint64(block.chainid),
            0,
            0,
            "Foundry Test"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializerSetsAdmin() public view {
        assertTrue(locks.hasRole(locks.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_InitializerSetsAllRoles() public view {
        assertTrue(locks.hasRole(locks.LOCK_ADMIN_ROLE(), admin));
        assertTrue(locks.hasRole(locks.VERIFIER_ADMIN_ROLE(), admin));
        assertTrue(locks.hasRole(locks.DOMAIN_ADMIN_ROLE(), admin));
        assertTrue(locks.hasRole(locks.DISPUTE_RESOLVER_ROLE(), admin));
        assertTrue(locks.hasRole(locks.OPERATOR_ROLE(), admin));
        assertTrue(locks.hasRole(locks.RECOVERY_ROLE(), admin));
        assertTrue(locks.hasRole(locks.UPGRADER_ROLE(), admin));
    }

    function test_InitializerSetsProofVerifier() public view {
        assertEq(address(locks.proofVerifier()), address(verifier));
    }

    function test_InitialStatsZero() public view {
        assertEq(locks.totalLocksCreated(), 0);
        assertEq(locks.totalLocksUnlocked(), 0);
        assertEq(locks.totalOptimisticUnlocks(), 0);
        assertEq(locks.totalDisputes(), 0);
    }

    function test_CannotDoubleInitialize() public {
        vm.expectRevert();
        locks.initialize(admin, address(verifier));
    }

    function test_CannotInitializeWithZeroAdmin() public {
        ZKBoundStateLocksUpgradeable newImpl = new ZKBoundStateLocksUpgradeable();
        vm.expectRevert(ZKBoundStateLocksUpgradeable.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(newImpl.initialize, (address(0), address(verifier)))
        );
    }

    function test_CannotInitializeWithZeroVerifier() public {
        ZKBoundStateLocksUpgradeable newImpl = new ZKBoundStateLocksUpgradeable();
        vm.expectRevert(ZKBoundStateLocksUpgradeable.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(newImpl.initialize, (admin, address(0)))
        );
    }

    /*//////////////////////////////////////////////////////////////
                         DEFAULT DOMAINS
    //////////////////////////////////////////////////////////////*/

    function test_DefaultDomainsRegistered() public view {
        // The initializer calls _registerDefaultDomains() which registers
        // common chain domains. Verify Ethereum mainnet (chainId 1) domain.
        bytes32 ethDomain = locks.generateDomainSeparator(1, 0, 0);
        (uint64 dChainId, , , , bool isActive, ) = locks.domains(ethDomain);
        assertEq(dChainId, 1);
        assertTrue(isActive);
    }

    /*//////////////////////////////////////////////////////////////
                          LOCK CREATION
    //////////////////////////////////////////////////////////////*/

    function _getDefaultDomain() internal view returns (bytes32) {
        return testDomain;
    }

    function _createLock() internal returns (bytes32) {
        return
            locks.createLock(
                OLD_STATE,
                PREDICATE,
                POLICY,
                _getDefaultDomain(),
                0 // no deadline
            );
    }

    function test_CreateLock() public {
        bytes32 lockId = _createLock();
        assertTrue(lockId != bytes32(0));
        assertEq(locks.totalLocksCreated(), 1);
        assertEq(locks.userLockCount(admin), 1);
    }

    function test_CreateLock_WithDeadline() public {
        uint64 deadline = uint64(block.timestamp + 1 hours);
        bytes32 lockId = locks.createLock(
            OLD_STATE,
            PREDICATE,
            POLICY,
            _getDefaultDomain(),
            deadline
        );
        assertTrue(lockId != bytes32(0));

        (, , , , , , , uint64 storedDeadline, ) = locks.locks(lockId);
        assertEq(storedDeadline, deadline);
    }

    function test_CreateLock_ExpiredDeadlineReverts() public {
        // Warp to a time > 1 so that (timestamp - 1) != 0
        vm.warp(100);
        uint64 pastDeadline = uint64(block.timestamp - 1);
        vm.expectRevert();
        locks.createLock(
            OLD_STATE,
            PREDICATE,
            POLICY,
            _getDefaultDomain(),
            pastDeadline
        );
    }

    function test_CreateLock_InvalidDomainReverts() public {
        bytes32 invalidDomain = keccak256("nonexistent");
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocksUpgradeable.InvalidDomainSeparator.selector,
                invalidDomain
            )
        );
        locks.createLock(OLD_STATE, PREDICATE, POLICY, invalidDomain, 0);
    }

    function test_CreateLock_WhenPausedReverts() public {
        locks.pause();
        vm.expectRevert();
        _createLock();
    }

    /*//////////////////////////////////////////////////////////////
                           ZK UNLOCK
    //////////////////////////////////////////////////////////////*/

    function test_Unlock_WithValidProof() public {
        bytes32 lockId = _createLock();

        verifier.setVerificationResult(true);

        ZKBoundStateLocksUpgradeable.UnlockProof
            memory proof = ZKBoundStateLocksUpgradeable.UnlockProof({
                lockId: lockId,
                zkProof: hex"deadbeef",
                newStateCommitment: NEW_STATE,
                nullifier: NULLIFIER,
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });

        locks.unlock(proof);

        assertEq(locks.totalLocksUnlocked(), 1);
        assertTrue(locks.nullifierUsed(NULLIFIER));
    }

    function test_Unlock_InvalidProofReverts() public {
        bytes32 lockId = _createLock();

        verifier.setVerificationResult(false);

        ZKBoundStateLocksUpgradeable.UnlockProof
            memory proof = ZKBoundStateLocksUpgradeable.UnlockProof({
                lockId: lockId,
                zkProof: hex"deadbeef",
                newStateCommitment: NEW_STATE,
                nullifier: NULLIFIER,
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocksUpgradeable.InvalidProof.selector,
                lockId
            )
        );
        locks.unlock(proof);

        // Nullifier should NOT be consumed on failed proof
        assertFalse(locks.nullifierUsed(NULLIFIER));
    }

    function test_Unlock_DoubleSpendReverts() public {
        bytes32 lockId1 = _createLock();
        bytes32 lockId2 = locks.createLock(
            keccak256("state2"),
            PREDICATE,
            POLICY,
            _getDefaultDomain(),
            0
        );

        verifier.setVerificationResult(true);

        ZKBoundStateLocksUpgradeable.UnlockProof
            memory proof1 = ZKBoundStateLocksUpgradeable.UnlockProof({
                lockId: lockId1,
                zkProof: hex"deadbeef",
                newStateCommitment: NEW_STATE,
                nullifier: NULLIFIER,
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });

        locks.unlock(proof1);

        // Try reusing the same nullifier
        ZKBoundStateLocksUpgradeable.UnlockProof memory proof2 = ZKBoundStateLocksUpgradeable
            .UnlockProof({
                lockId: lockId2,
                zkProof: hex"deadbeef",
                newStateCommitment: keccak256("new2"),
                nullifier: NULLIFIER, // same nullifier
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocksUpgradeable.NullifierAlreadyUsed.selector,
                NULLIFIER
            )
        );
        locks.unlock(proof2);
    }

    /*//////////////////////////////////////////////////////////////
                       OPTIMISTIC UNLOCK
    //////////////////////////////////////////////////////////////*/

    function test_OptimisticUnlock() public {
        bytes32 lockId = _createLock();
        verifier.setVerificationResult(true);

        ZKBoundStateLocksUpgradeable.UnlockProof
            memory proof = ZKBoundStateLocksUpgradeable.UnlockProof({
                lockId: lockId,
                zkProof: hex"deadbeef",
                newStateCommitment: NEW_STATE,
                nullifier: NULLIFIER,
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });

        locks.optimisticUnlock{value: 0.01 ether}(proof);
        assertEq(locks.totalOptimisticUnlocks(), 1);
    }

    function test_OptimisticUnlock_InsufficientBondReverts() public {
        bytes32 lockId = _createLock();

        ZKBoundStateLocksUpgradeable.UnlockProof
            memory proof = ZKBoundStateLocksUpgradeable.UnlockProof({
                lockId: lockId,
                zkProof: hex"deadbeef",
                newStateCommitment: NEW_STATE,
                nullifier: NULLIFIER,
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocksUpgradeable.InsufficientBond.selector,
                0.01 ether,
                0.005 ether
            )
        );
        locks.optimisticUnlock{value: 0.005 ether}(proof);
    }

    /*//////////////////////////////////////////////////////////////
                     VERIFIER & DOMAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterVerifier() public {
        bytes32 newVkHash = keccak256("new_vk");
        MockProofVerifier newVerifier = new MockProofVerifier();

        locks.registerVerifier(newVkHash, address(newVerifier));
        assertEq(locks.verifiers(newVkHash), address(newVerifier));
    }

    function test_RegisterVerifier_DuplicateReverts() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocksUpgradeable.VerifierAlreadyRegistered.selector,
                VK_HASH
            )
        );
        locks.registerVerifier(VK_HASH, address(verifier));
    }

    function test_RegisterDomain() public {
        bytes32 domainSep = locks.registerDomain(42161, 1, 0, "Arbitrum App");

        (
            uint64 chainId_,
            uint64 appId_,
            uint32 epoch_,
            ,
            bool isActive_,

        ) = locks.domains(domainSep);
        assertEq(chainId_, 42161);
        assertEq(appId_, 1);
        assertEq(epoch_, 0);
        assertTrue(isActive_);
    }

    /*//////////////////////////////////////////////////////////////
                        PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_Pause() public {
        locks.pause();
        assertTrue(locks.paused());
    }

    function test_Unpause() public {
        locks.pause();
        locks.unpause();
        assertFalse(locks.paused());
    }

    /*//////////////////////////////////////////////////////////////
                         UPGRADE SAFETY
    //////////////////////////////////////////////////////////////*/

    function test_UpgradeOnlyUpgrader() public {
        ZKBoundStateLocksUpgradeable newImpl = new ZKBoundStateLocksUpgradeable();
        locks.upgradeToAndCall(address(newImpl), "");
    }

    function test_UpgradeRevertsWithoutRole() public {
        ZKBoundStateLocksUpgradeable newImpl = new ZKBoundStateLocksUpgradeable();
        vm.prank(user);
        vm.expectRevert();
        locks.upgradeToAndCall(address(newImpl), "");
    }

    function test_UpgradePreservesLocks() public {
        // Create a lock
        bytes32 lockId = _createLock();

        // Upgrade
        ZKBoundStateLocksUpgradeable newImpl = new ZKBoundStateLocksUpgradeable();
        locks.upgradeToAndCall(address(newImpl), "");

        // Lock state preserved
        (
            bytes32 storedLockId,
            bytes32 storedOldState,
            ,
            ,
            ,
            address storedLockedBy,
            ,
            ,

        ) = locks.locks(lockId);

        assertEq(storedLockId, lockId);
        assertEq(storedOldState, OLD_STATE);
        assertEq(storedLockedBy, admin);
        assertEq(locks.totalLocksCreated(), 1);
        assertEq(address(locks.proofVerifier()), address(verifier));
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_CreateLock(
        bytes32 stateCommitment,
        bytes32 predicateHash
    ) public {
        vm.assume(stateCommitment != bytes32(0));
        vm.assume(predicateHash != bytes32(0));

        bytes32 lockId = locks.createLock(
            stateCommitment,
            predicateHash,
            bytes32(0),
            _getDefaultDomain(),
            0
        );

        assertTrue(lockId != bytes32(0));
        assertEq(locks.totalLocksCreated(), 1);
    }
}
