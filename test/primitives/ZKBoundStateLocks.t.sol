// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/ZKBoundStateLocks.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/// @notice Mock proof verifier that allows controlling verification results
contract MockZKVerifier is IProofVerifier {
    bool public shouldVerify = true;

    function setShouldVerify(bool _val) external {
        shouldVerify = _val;
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
        return 6;
    }

    function isReady() external pure returns (bool) {
        return true;
    }

    /// @dev Handles staticcall from ZKBoundStateLocks._verifyProof when using registered verifier
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external view returns (bool) {
        return shouldVerify;
    }
}

/// @notice Mock verifier that always fails
contract FailingZKVerifier is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure returns (bool) {
        return false;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return false;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure returns (bool) {
        return false;
    }

    function getPublicInputCount() external pure returns (uint256) {
        return 6;
    }

    function isReady() external pure returns (bool) {
        return true;
    }

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return false;
    }
}

contract ZKBoundStateLocksTest is Test {
    ZKBoundStateLocks public zksl;
    MockZKVerifier public verifier;
    FailingZKVerifier public failVerifier;

    address public admin = address(this);
    address public operator = makeAddr("operator");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    address public disputeResolver = makeAddr("disputeResolver");
    address public recovery = makeAddr("recovery");

    // Default domain — Ethereum mainnet
    bytes32 public ethDomain;

    // Common test values
    bytes32 constant STATE_COMMIT = keccak256("oldState");
    bytes32 constant TRANSITION_HASH = keccak256("transition");
    bytes32 constant POLICY_HASH = keccak256("policy");
    bytes32 constant NULLIFIER = keccak256("nullifier1");
    bytes32 constant VK_HASH = keccak256("vk1");

    function setUp() public {
        verifier = new MockZKVerifier();
        failVerifier = new FailingZKVerifier();

        zksl = new ZKBoundStateLocks(address(verifier));

        // Grant roles
        zksl.grantRole(zksl.OPERATOR_ROLE(), operator);
        zksl.grantRole(zksl.DISPUTE_RESOLVER_ROLE(), disputeResolver);
        zksl.grantRole(zksl.RECOVERY_ROLE(), recovery);

        // Compute Ethereum mainnet domain
        ethDomain = zksl.generateDomainSeparator(1, 0, 0);
    }

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_GrantsAllRoles() public view {
        assertTrue(zksl.hasRole(zksl.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(zksl.hasRole(zksl.LOCK_ADMIN_ROLE(), admin));
        assertTrue(zksl.hasRole(zksl.VERIFIER_ADMIN_ROLE(), admin));
        assertTrue(zksl.hasRole(zksl.DOMAIN_ADMIN_ROLE(), admin));
        assertTrue(zksl.hasRole(zksl.DISPUTE_RESOLVER_ROLE(), admin));
        assertTrue(zksl.hasRole(zksl.OPERATOR_ROLE(), admin));
        assertTrue(zksl.hasRole(zksl.RECOVERY_ROLE(), admin));
    }

    function test_Constructor_SetsProofVerifier() public view {
        assertEq(address(zksl.proofVerifier()), address(verifier));
    }

    function test_Constructor_RegistersDefaultDomains() public view {
        // Ethereum mainnet
        (uint64 chainId, , , , , ) = zksl.domains(ethDomain);
        assertEq(chainId, 1);

        // Optimism
        bytes32 opDomain = zksl.generateDomainSeparator(10, 0, 0);
        (chainId, , , , , ) = zksl.domains(opDomain);
        assertEq(chainId, 10);

        // Polygon
        bytes32 polyDomain = zksl.generateDomainSeparator(137, 0, 0);
        (chainId, , , , , ) = zksl.domains(polyDomain);
        assertEq(chainId, 137);
    }

    function test_Constructor_RegistersExtendedDomains() public view {
        // Arbitrum One (42161 > 65535 → extended)
        bytes32 arbDomain = zksl.generateDomainSeparatorExtended(42161, 0, 0);
        (uint64 chainId, , , , , ) = zksl.domains(arbDomain);
        assertEq(chainId, 42161);

        // Base
        bytes32 baseDomain = zksl.generateDomainSeparatorExtended(8453, 0, 0);
        (chainId, , , , , ) = zksl.domains(baseDomain);
        assertEq(chainId, 8453);
    }

    /*//////////////////////////////////////////////////////////////
                          CREATE LOCK
    //////////////////////////////////////////////////////////////*/

    function test_CreateLock_Success() public {
        vm.prank(user1);
        bytes32 lockId = zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );

        assertTrue(lockId != bytes32(0));
        assertEq(zksl.getActiveLockCount(), 1);
        assertEq(zksl.userLockCount(user1), 1);
    }

    function test_CreateLock_WithDeadline() public {
        uint64 deadline = uint64(block.timestamp + 1 days);
        vm.prank(user1);
        bytes32 lockId = zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            deadline
        );

        ZKBoundStateLocks.ZKSLock memory lock = zksl.getLock(lockId);
        assertEq(lock.unlockDeadline, deadline);
        assertFalse(lock.isUnlocked);
    }

    function test_CreateLock_RevertExpiredDeadline() public {
        // Warp to a meaningful time so block.timestamp - 1 is not zero
        vm.warp(1000);
        uint64 pastDeadline = uint64(block.timestamp);
        // createLock checks unlockDeadline <= block.timestamp → revert
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockExpired.selector,
                bytes32(0),
                pastDeadline
            )
        );
        zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            pastDeadline
        );
    }

    function test_CreateLock_RevertInvalidDomain() public {
        bytes32 badDomain = keccak256("nonexistent");
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InvalidDomainSeparator.selector,
                badDomain
            )
        );
        zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            badDomain,
            0
        );
    }

    function test_CreateLock_RevertWhenPaused() public {
        zksl.pause();
        vm.prank(user1);
        vm.expectRevert();
        zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );
    }

    function test_CreateLock_IncrementsTotalLocksCreated() public {
        vm.prank(user1);
        zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );
        assertEq(zksl.totalLocksCreated(), 1);

        vm.prank(user2);
        zksl.createLock(
            keccak256("state2"),
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );
        assertEq(zksl.totalLocksCreated(), 2);
    }

    function test_CreateLock_EmitsEvent() public {
        vm.prank(user1);
        vm.expectEmit(false, true, true, false);
        emit ZKBoundStateLocks.LockCreated(
            bytes32(0),
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            user1,
            0
        );
        zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );
    }

    /*//////////////////////////////////////////////////////////////
                              UNLOCK
    //////////////////////////////////////////////////////////////*/

    function _createDefaultLock() internal returns (bytes32 lockId) {
        vm.prank(user1);
        lockId = zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );
    }

    function _buildUnlockProof(
        bytes32 lockId
    ) internal pure returns (ZKBoundStateLocks.UnlockProof memory) {
        return
            ZKBoundStateLocks.UnlockProof({
                lockId: lockId,
                zkProof: hex"deadbeef",
                newStateCommitment: keccak256("newState"),
                nullifier: NULLIFIER,
                verifierKeyHash: VK_HASH,
                auxiliaryData: ""
            });
    }

    function test_Unlock_Success() public {
        bytes32 lockId = _createDefaultLock();

        // Register verifier for VK_HASH
        zksl.registerVerifier(VK_HASH, address(verifier));

        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.prank(user2);
        zksl.unlock(proof);

        ZKBoundStateLocks.ZKSLock memory lock = zksl.getLock(lockId);
        assertTrue(lock.isUnlocked);
        assertTrue(zksl.nullifierUsed(NULLIFIER));
        assertEq(zksl.getActiveLockCount(), 0);
        assertEq(zksl.totalLocksUnlocked(), 1);
    }

    function test_Unlock_WithGeneralProofVerifier() public {
        bytes32 lockId = _createDefaultLock();
        // No registered verifier — falls back to proofVerifier
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.prank(user2);
        zksl.unlock(proof);

        assertTrue(zksl.getLock(lockId).isUnlocked);
    }

    function test_Unlock_RevertNonExistentLock() public {
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(
            keccak256("fake")
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockDoesNotExist.selector,
                bytes32(0)
            )
        );
        zksl.unlock(proof);
    }

    function test_Unlock_RevertAlreadyUnlocked() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        zksl.unlock(proof);

        ZKBoundStateLocks.UnlockProof memory proof2 = proof;
        proof2.nullifier = keccak256("nullifier2");

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockAlreadyUnlocked.selector,
                lockId
            )
        );
        zksl.unlock(proof2);
    }

    function test_Unlock_RevertNullifierAlreadyUsed() public {
        bytes32 lockId1 = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof1 = _buildUnlockProof(
            lockId1
        );
        zksl.unlock(proof1);

        // Create another lock, try same nullifier
        vm.prank(user1);
        bytes32 lockId2 = zksl.createLock(
            keccak256("state2"),
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );
        ZKBoundStateLocks.UnlockProof memory proof2 = _buildUnlockProof(
            lockId2
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.NullifierAlreadyUsed.selector,
                NULLIFIER
            )
        );
        zksl.unlock(proof2);
    }

    function test_Unlock_RevertInvalidProof() public {
        bytes32 lockId = _createDefaultLock();
        verifier.setShouldVerify(false);

        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InvalidProof.selector,
                lockId
            )
        );
        zksl.unlock(proof);

        // Nullifier should NOT be consumed after failed proof
        assertFalse(zksl.nullifierUsed(NULLIFIER));
    }

    function test_Unlock_RevertExpiredDeadline() public {
        uint64 deadline = uint64(block.timestamp + 1 hours);
        vm.prank(user1);
        bytes32 lockId = zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            deadline
        );

        // Warp past deadline
        vm.warp(deadline + 1);

        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockExpired.selector,
                lockId,
                deadline
            )
        );
        zksl.unlock(proof);
    }

    function test_Unlock_TracksCommitmentChain() public {
        bytes32 lockId = _createDefaultLock();
        bytes32 newCommit = keccak256("newState");

        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        zksl.unlock(proof);

        assertEq(zksl.commitmentSuccessor(STATE_COMMIT), newCommit);
        assertEq(zksl.commitmentPredecessor(newCommit), STATE_COMMIT);
    }

    function test_Unlock_StoresReceipt() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.prank(user2);
        zksl.unlock(proof);

        (
            bytes32 receiptLockId,
            bytes32 newCommit,
            bytes32 nullifier,
            bytes32 domain,
            address unlockedBy,
            uint64 unlockedAt
        ) = zksl.unlockReceipts(lockId);

        assertEq(receiptLockId, lockId);
        assertEq(newCommit, keccak256("newState"));
        assertEq(nullifier, NULLIFIER);
        assertEq(domain, ethDomain);
        assertEq(unlockedBy, user2);
        assertEq(unlockedAt, uint64(block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                       OPTIMISTIC UNLOCK
    //////////////////////////////////////////////////////////////*/

    function test_OptimisticUnlock_Success() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        (address unlocker, uint64 unlockTime, , , , bool disputed, , ) = zksl
            .optimisticUnlocks(lockId);

        assertEq(unlocker, user2);
        assertGt(unlockTime, 0);
        assertFalse(disputed);
        assertEq(zksl.totalOptimisticUnlocks(), 1);
    }

    function test_OptimisticUnlock_RevertInsufficientBond() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InsufficientBond.selector,
                zksl.MIN_BOND_AMOUNT(),
                0.001 ether
            )
        );
        zksl.optimisticUnlock{value: 0.001 ether}(proof);
    }

    function test_OptimisticUnlock_ReservesNullifier() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        assertTrue(zksl.nullifierUsed(NULLIFIER));
    }

    /*//////////////////////////////////////////////////////////////
                    FINALIZE OPTIMISTIC UNLOCK
    //////////////////////////////////////////////////////////////*/

    function test_FinalizeOptimisticUnlock_Success() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.05 ether}(proof);

        uint256 balBefore = user2.balance;

        // Warp past dispute window
        vm.warp(block.timestamp + zksl.DISPUTE_WINDOW() + 1);

        vm.prank(user2);
        zksl.finalizeOptimisticUnlock(lockId);

        assertTrue(zksl.getLock(lockId).isUnlocked);
        // Bond returned
        assertEq(user2.balance, balBefore + 0.05 ether);
    }

    function test_FinalizeOptimisticUnlock_RevertNoOptimistic() public {
        bytes32 fakeLockId = keccak256("fake");
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.NoOptimisticUnlock.selector,
                fakeLockId
            )
        );
        zksl.finalizeOptimisticUnlock(fakeLockId);
    }

    function test_FinalizeOptimisticUnlock_RevertWindowStillOpen() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        // Don't warp — window is still open
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.DisputeWindowStillOpen.selector,
                lockId,
                uint64(block.timestamp + zksl.DISPUTE_WINDOW())
            )
        );
        zksl.finalizeOptimisticUnlock(lockId);
    }

    function test_FinalizeOptimisticUnlock_RevertAlreadyDisputed() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        // Register failing verifier for VK_HASH so challenge succeeds (fraud proof)
        zksl.registerVerifier(VK_HASH, address(failVerifier));

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        // Challenge with same proof (fraud proof: verifier returns false)
        address challenger = makeAddr("challenger");
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);

        // Now try finalize — should revert
        vm.warp(block.timestamp + zksl.DISPUTE_WINDOW() + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.AlreadyDisputed.selector,
                lockId
            )
        );
        zksl.finalizeOptimisticUnlock(lockId);
    }

    /*//////////////////////////////////////////////////////////////
                   CHALLENGE OPTIMISTIC UNLOCK
    //////////////////////////////////////////////////////////////*/

    function test_ChallengeOptimisticUnlock_FraudProofSuccess() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        // Register a failing verifier
        zksl.registerVerifier(VK_HASH, address(failVerifier));

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.05 ether}(proof);

        address challenger = makeAddr("challenger");
        vm.deal(challenger, 1 ether);
        uint256 balBefore = challenger.balance;

        vm.prank(challenger);
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);

        // Challenger gets bond + stake back
        assertEq(
            challenger.balance,
            balBefore - 0.01 ether + 0.05 ether + 0.01 ether
        );
        assertEq(zksl.totalDisputes(), 1);
    }

    function test_ChallengeOptimisticUnlock_FailedChallenge() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        // Use verifier that returns true (proof is valid, so challenge fails)
        zksl.registerVerifier(VK_HASH, address(verifier));

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.05 ether}(proof);

        uint256 user2BalBefore = user2.balance;

        address challenger = makeAddr("challenger2");
        vm.deal(challenger, 1 ether);
        uint256 challengerBalBefore = challenger.balance;

        vm.prank(challenger);
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);

        // Challenger loses stake (sent to unlocker)
        assertEq(challenger.balance, challengerBalBefore - 0.01 ether);
        assertEq(user2.balance, user2BalBefore + 0.01 ether);
    }

    function test_ChallengeOptimisticUnlock_RevertInsufficientStake() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        address challenger = makeAddr("challenger");
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InsufficientChallengerStake.selector,
                zksl.MIN_CHALLENGER_STAKE(),
                0.001 ether
            )
        );
        zksl.challengeOptimisticUnlock{value: 0.001 ether}(lockId, proof);
    }

    function test_ChallengeOptimisticUnlock_RevertWindowClosed() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        // Warp past window
        vm.warp(block.timestamp + zksl.DISPUTE_WINDOW() + 1);

        address challenger = makeAddr("challenger");
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.ChallengeWindowClosed.selector,
                lockId
            )
        );
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);
    }

    function test_ChallengeOptimisticUnlock_RevertAlreadyDisputed() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        zksl.registerVerifier(VK_HASH, address(failVerifier));

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.05 ether}(proof);

        address challenger1 = makeAddr("challenger1");
        vm.deal(challenger1, 1 ether);
        vm.prank(challenger1);
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);

        address challenger2 = makeAddr("challenger2");
        vm.deal(challenger2, 1 ether);
        vm.prank(challenger2);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.AlreadyDisputed.selector,
                lockId
            )
        );
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, proof);
    }

    function test_ChallengeOptimisticUnlock_RevertInvalidConflictProof()
        public
    {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.01 ether}(proof);

        // Build evidence with wrong lockId
        ZKBoundStateLocks.UnlockProof memory badEvidence = proof;
        badEvidence.lockId = keccak256("wrong");

        address challenger = makeAddr("challenger");
        vm.deal(challenger, 1 ether);
        vm.prank(challenger);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.InvalidConflictProof.selector,
                lockId
            )
        );
        zksl.challengeOptimisticUnlock{value: 0.01 ether}(lockId, badEvidence);
    }

    /*//////////////////////////////////////////////////////////////
                      VERIFIER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterVerifier_Success() public {
        zksl.registerVerifier(VK_HASH, address(verifier));
        assertEq(zksl.verifiers(VK_HASH), address(verifier));
    }

    function test_RegisterVerifier_RevertAlreadyRegistered() public {
        zksl.registerVerifier(VK_HASH, address(verifier));
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.VerifierAlreadyRegistered.selector,
                VK_HASH
            )
        );
        zksl.registerVerifier(VK_HASH, address(failVerifier));
    }

    function test_RegisterVerifier_RevertZeroAddress() public {
        vm.expectRevert(ZKBoundStateLocks.InvalidVerifierAddress.selector);
        zksl.registerVerifier(VK_HASH, address(0));
    }

    function test_RegisterVerifier_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        zksl.registerVerifier(VK_HASH, address(verifier));
    }

    /*//////////////////////////////////////////////////////////////
                       DOMAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterDomain_Success() public {
        bytes32 newDomain = zksl.registerDomain(99999, 1, 0, "TestChain");

        (
            uint64 chainId,
            uint64 appId,
            uint32 epoch,
            string memory name,
            bool isActive,

        ) = zksl.domains(newDomain);
        assertEq(chainId, 99999);
        assertEq(appId, 1);
        assertEq(epoch, 0);
        assertEq(name, "TestChain");
        assertTrue(isActive);
    }

    function test_RegisterDomain_RevertDuplicate() public {
        zksl.registerDomain(99999, 1, 0, "TestChain");
        bytes32 domainSep = zksl.generateDomainSeparatorExtended(99999, 1, 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.DomainAlreadyExists.selector,
                domainSep
            )
        );
        zksl.registerDomain(99999, 1, 0, "TestChain2");
    }

    function test_RegisterDomain_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        zksl.registerDomain(99999, 1, 0, "TestChain");
    }

    /*//////////////////////////////////////////////////////////////
                        RECOVERY
    //////////////////////////////////////////////////////////////*/

    function test_RecoverLock_Success() public {
        bytes32 lockId = _createDefaultLock();

        vm.prank(recovery);
        zksl.recoverLock(lockId, recovery);

        assertTrue(zksl.getLock(lockId).isUnlocked);
        assertEq(zksl.getActiveLockCount(), 0);
    }

    function test_RecoverLock_RevertInvalidLock() public {
        bytes32 fake = keccak256("fake");
        vm.prank(recovery);
        vm.expectRevert(
            abi.encodeWithSelector(ZKBoundStateLocks.InvalidLock.selector, fake)
        );
        zksl.recoverLock(fake, recovery);
    }

    function test_RecoverLock_RevertAlreadyUnlocked() public {
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        zksl.unlock(proof);

        vm.prank(recovery);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockAlreadyUnlocked.selector,
                lockId
            )
        );
        zksl.recoverLock(lockId, recovery);
    }

    function test_RecoverLock_RevertUnauthorized() public {
        bytes32 lockId = _createDefaultLock();
        vm.prank(user1);
        vm.expectRevert();
        zksl.recoverLock(lockId, user1);
    }

    function test_RecoverLock_PreventDoubleRecovery() public {
        bytes32 lockId = _createDefaultLock();

        vm.prank(recovery);
        zksl.recoverLock(lockId, recovery);

        vm.prank(recovery);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZKBoundStateLocks.LockAlreadyUnlocked.selector,
                lockId
            )
        );
        zksl.recoverLock(lockId, recovery);
    }

    /*//////////////////////////////////////////////////////////////
                      DOMAIN SEPARATOR UTILS
    //////////////////////////////////////////////////////////////*/

    function test_GenerateDomainSeparator_Deterministic() public view {
        bytes32 sep1 = zksl.generateDomainSeparator(1, 0, 0);
        bytes32 sep2 = zksl.generateDomainSeparator(1, 0, 0);
        assertEq(sep1, sep2);
    }

    function test_GenerateDomainSeparator_DifferentInputs() public view {
        bytes32 sep1 = zksl.generateDomainSeparator(1, 0, 0);
        bytes32 sep2 = zksl.generateDomainSeparator(2, 0, 0);
        assertTrue(sep1 != sep2);
    }

    function test_GenerateDomainSeparatorExtended_Deterministic() public view {
        bytes32 sep1 = zksl.generateDomainSeparatorExtended(42161, 1, 0);
        bytes32 sep2 = zksl.generateDomainSeparatorExtended(42161, 1, 0);
        assertEq(sep1, sep2);
    }

    function test_GenerateNullifier_Deterministic() public view {
        bytes32 secret = keccak256("mySecret");
        bytes32 lockId = keccak256("lock1");
        bytes32 n1 = zksl.generateNullifier(secret, lockId, ethDomain);
        bytes32 n2 = zksl.generateNullifier(secret, lockId, ethDomain);
        assertEq(n1, n2);
    }

    function test_GenerateNullifier_DifferentSecrets() public view {
        bytes32 lockId = keccak256("lock1");
        bytes32 n1 = zksl.generateNullifier(
            keccak256("secret1"),
            lockId,
            ethDomain
        );
        bytes32 n2 = zksl.generateNullifier(
            keccak256("secret2"),
            lockId,
            ethDomain
        );
        assertTrue(n1 != n2);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetActiveLockIds_Paginated() public {
        // Create 3 locks
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(user1);
            zksl.createLock(
                keccak256(abi.encodePacked("state", i)),
                TRANSITION_HASH,
                POLICY_HASH,
                ethDomain,
                0
            );
        }

        bytes32[] memory page1 = zksl.getActiveLockIds(0, 2);
        assertEq(page1.length, 2);

        bytes32[] memory page2 = zksl.getActiveLockIds(2, 2);
        assertEq(page2.length, 1);

        bytes32[] memory empty = zksl.getActiveLockIds(10, 2);
        assertEq(empty.length, 0);
    }

    function test_GetActiveLockIds_Unpaginated() public {
        vm.prank(user1);
        zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            0
        );

        bytes32[] memory ids = zksl.getActiveLockIds();
        assertEq(ids.length, 1);
    }

    function test_CanUnlock() public {
        bytes32 lockId = _createDefaultLock();
        assertTrue(zksl.canUnlock(lockId));

        // Unlock it
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        zksl.unlock(proof);
        assertFalse(zksl.canUnlock(lockId));
    }

    function test_CanUnlock_WithExpiredDeadline() public {
        uint64 deadline = uint64(block.timestamp + 1 hours);
        vm.prank(user1);
        bytes32 lockId = zksl.createLock(
            STATE_COMMIT,
            TRANSITION_HASH,
            POLICY_HASH,
            ethDomain,
            deadline
        );

        assertTrue(zksl.canUnlock(lockId));

        vm.warp(deadline + 1);
        assertFalse(zksl.canUnlock(lockId));
    }

    function test_GetCommitmentChain() public {
        // Create and unlock a lock to form a chain
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        zksl.unlock(proof);

        bytes32[] memory chain = zksl.getCommitmentChain(STATE_COMMIT, 5);
        assertEq(chain.length, 2);
        assertEq(chain[0], STATE_COMMIT);
        assertEq(chain[1], keccak256("newState"));
    }

    function test_GetStats() public {
        bytes32 lockId = _createDefaultLock();
        (
            uint256 created,
            uint256 unlocked,
            uint256 active,
            uint256 optimistic,
            uint256 disputed
        ) = zksl.getStats();
        assertEq(created, 1);
        assertEq(unlocked, 0);
        assertEq(active, 1);
        assertEq(optimistic, 0);
        assertEq(disputed, 0);

        // Unlock
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);
        zksl.unlock(proof);

        (created, unlocked, active, optimistic, disputed) = zksl.getStats();
        assertEq(created, 1);
        assertEq(unlocked, 1);
        assertEq(active, 0);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_Pause_Unpause() public {
        zksl.pause();
        assertTrue(zksl.paused());

        zksl.unpause();
        assertFalse(zksl.paused());
    }

    function test_Pause_RevertUnauthorized() public {
        vm.prank(user1);
        vm.expectRevert();
        zksl.pause();
    }

    function test_ConfirmRoleSeparation() public {
        // First revoke operational roles from admin
        zksl.revokeRole(zksl.DISPUTE_RESOLVER_ROLE(), admin);
        zksl.revokeRole(zksl.RECOVERY_ROLE(), admin);
        zksl.revokeRole(zksl.OPERATOR_ROLE(), admin);

        zksl.confirmRoleSeparation();
        assertTrue(zksl.rolesSeparated());
    }

    function test_ConfirmRoleSeparation_RevertIfAdminHoldsOperationalRoles()
        public
    {
        // Admin still holds DISPUTE_RESOLVER_ROLE
        vm.expectRevert("Admin must not hold operational roles");
        zksl.confirmRoleSeparation();
    }

    /*//////////////////////////////////////////////////////////////
                          FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_CreateLock_DeterministicId(
        bytes32 stateCommit,
        bytes32 transitionHash,
        bytes32 policyHash
    ) public {
        vm.prank(user1);
        bytes32 lockId = zksl.createLock(
            stateCommit,
            transitionHash,
            policyHash,
            ethDomain,
            0
        );
        assertTrue(lockId != bytes32(0));
        assertEq(zksl.getActiveLockCount(), 1);
    }

    function testFuzz_GenerateNullifier_UniquePerSecret(
        bytes32 secret1,
        bytes32 secret2
    ) public view {
        vm.assume(secret1 != secret2);
        bytes32 lockId = keccak256("lock");
        bytes32 n1 = zksl.generateNullifier(secret1, lockId, ethDomain);
        bytes32 n2 = zksl.generateNullifier(secret2, lockId, ethDomain);
        assertTrue(n1 != n2);
    }

    function testFuzz_DomainSeparator_UniquePerChain(
        uint16 chainId1,
        uint16 chainId2
    ) public view {
        vm.assume(chainId1 != chainId2);
        bytes32 d1 = zksl.generateDomainSeparator(chainId1, 0, 0);
        bytes32 d2 = zksl.generateDomainSeparator(chainId2, 0, 0);
        assertTrue(d1 != d2);
    }

    /*//////////////////////////////////////////////////////////////
                        RECEIVE ETH
    //////////////////////////////////////////////////////////////*/

    /// @notice Contract should be able to receive ETH for bond handling
    function test_ReceiveETH() public {
        // ZKBoundStateLocks doesn't have a receive function by default,
        // but it receives ETH via optimistic unlock bonds and challenges.
        // The contract uses call{value:} to send ETH, so no receive needed on its end.
        // This test verifies the bond flow works end to end.
        bytes32 lockId = _createDefaultLock();
        ZKBoundStateLocks.UnlockProof memory proof = _buildUnlockProof(lockId);

        vm.deal(user2, 1 ether);
        vm.prank(user2);
        zksl.optimisticUnlock{value: 0.1 ether}(proof);

        assertEq(address(zksl).balance, 0.1 ether);
    }
}
