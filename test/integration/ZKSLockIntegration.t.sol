// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/integrations/ZKSLockIntegration.sol";
import "../../contracts/primitives/ZKBoundStateLocks.sol";

/* ============ Mock: ZKBoundStateLocks ============ */
contract MockZKSLocks {
    bytes32[] public queuedLockIds;
    uint256 public lockIdIndex;
    bytes32 public nextNullifier;
    uint256 public createLockCallCount;
    bool public unlockCalled;
    bytes32 public lastUnlockedLockId;

    mapping(bytes32 => bool) public lockUnlocked;

    function queueLockId(bytes32 id) external {
        queuedLockIds.push(id);
    }

    function createLock(
        bytes32,
        bytes32,
        bytes32,
        bytes32,
        uint64
    ) external returns (bytes32) {
        createLockCallCount++;
        bytes32 id = queuedLockIds[lockIdIndex];
        lockIdIndex++;
        return id;
    }

    function unlock(ZKBoundStateLocks.UnlockProof calldata proof) external {
        unlockCalled = true;
        lastUnlockedLockId = proof.lockId;
        lockUnlocked[proof.lockId] = true;
    }

    function generateNullifier(
        bytes32,
        bytes32,
        bytes32
    ) external view returns (bytes32) {
        return nextNullifier;
    }

    function setNextNullifier(bytes32 n) external {
        nextNullifier = n;
    }

    // 9-element tuple matching ZKSLock struct
    function locks(
        bytes32 lockId
    )
        external
        view
        returns (
            bytes32,
            bytes32,
            bytes32,
            bytes32,
            bytes32,
            address,
            uint64,
            uint64,
            bool
        )
    {
        return (
            lockId,
            bytes32(0), // oldStateCommitment
            bytes32(0), // transitionPredicateHash
            bytes32(0), // policyHash
            bytes32(0), // domainSeparator
            address(0), // lockedBy
            0, // createdAt
            0, // unlockDeadline
            lockUnlocked[lockId] // isUnlocked
        );
    }
}

/* ============ Mock: ProofCarryingContainer ============ */
contract MockPC3 {
    // Mirror ProofBundle struct layout
    struct MockProofBundle {
        bytes validityProof;
        bytes policyProof;
        bytes nullifierProof;
        bytes32 proofHash;
        uint256 proofTimestamp;
        uint256 proofExpiry;
    }

    struct MockContainer {
        bytes encryptedPayload;
        bytes32 stateCommitment;
        bytes32 nullifier;
        MockProofBundle proofs;
        bytes32 policyHash;
        uint64 chainId;
        uint64 createdAt;
        uint32 version;
        bool isVerified;
        bool isConsumed;
    }

    mapping(bytes32 => MockContainer) internal _containers;

    function setContainerStateCommitment(
        bytes32 containerId,
        bytes32 sc
    ) external {
        _containers[containerId].stateCommitment = sc;
    }

    // 10-element tuple matching auto-generated containers getter
    function containers(
        bytes32 containerId
    )
        external
        view
        returns (
            bytes memory,
            bytes32,
            bytes32,
            MockProofBundle memory,
            bytes32,
            uint64,
            uint64,
            uint32,
            bool,
            bool
        )
    {
        MockContainer storage c = _containers[containerId];
        return (
            c.encryptedPayload,
            c.stateCommitment,
            c.nullifier,
            c.proofs,
            c.policyHash,
            c.chainId,
            c.createdAt,
            c.version,
            c.isVerified,
            c.isConsumed
        );
    }
}

/* ============ Mock: CrossDomainNullifierAlgebra ============ */
contract MockCDNA {
    bool public registerCalled;
    uint256 public registerCallCount;

    function registerNullifier(
        bytes32,
        bytes32,
        bytes32,
        bytes32
    ) external returns (bytes32) {
        registerCalled = true;
        registerCallCount++;
        return bytes32(0);
    }
}

/* ============ Test Contract ============ */
contract ZKSLockIntegrationTest is Test {
    ZKSLockIntegration public integration;
    MockZKSLocks public mockZkSlocks;
    MockPC3 public mockPc3;
    MockCDNA public mockCdna;

    bytes32 constant CONTAINER_ID = keccak256("container1");
    bytes32 constant STATE_COMMITMENT = keccak256("stateCommitment");
    bytes32 constant TRANSITION_HASH = keccak256("transition");
    bytes32 constant POLICY_HASH = keccak256("policy");
    bytes32 constant DOMAIN_ID = keccak256("domain");
    bytes32 constant COMMITMENT_HASH = keccak256("commitment");
    bytes32 constant USER_ENTROPY = keccak256("entropy");
    bytes32 constant NULLIFIER = keccak256("nullifier");

    event ContainerLocked(
        bytes32 indexed containerId,
        bytes32 indexed lockId,
        bytes32 stateCommitment
    );
    event ContainerUnlocked(
        bytes32 indexed containerId,
        bytes32 indexed lockId,
        bytes32 newStateCommitment
    );
    event CrossDomainLockCreated(
        bytes32 indexed lockId,
        bytes32 indexed sourceDomainId,
        bytes32 indexed targetDomainId,
        bytes32 nullifier
    );
    event NullifierBound(
        bytes32 indexed lockId,
        bytes32 indexed nullifier,
        bytes32 domainId
    );

    function setUp() public {
        mockZkSlocks = new MockZKSLocks();
        mockPc3 = new MockPC3();
        mockCdna = new MockCDNA();
        integration = new ZKSLockIntegration(
            address(mockZkSlocks),
            address(mockPc3),
            address(mockCdna)
        );
    }

    /* --------------------------------------------------------
                       HELPER: compute expected lockId
       -------------------------------------------------------- */
    function _expectedLockId(
        bytes32 stateCommit,
        bytes32 transitionPredHash,
        bytes32 policyBind,
        bytes32 domainSep
    ) internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    stateCommit,
                    transitionPredHash,
                    policyBind,
                    domainSep,
                    address(integration),
                    block.chainid,
                    block.timestamp
                )
            );
    }

    /* ========================================================
                       DEPLOYMENT
       ======================================================== */

    function test_deploy_setsImmutables() public view {
        assertTrue(address(integration) != address(0));
    }

    function test_deploy_integrationEnabledByDefault() public view {
        assertTrue(integration.integrationEnabled());
    }

    function test_deploy_defaultDomainSeparatorSet() public view {
        bytes32 expected = keccak256(
            abi.encodePacked(
                block.chainid,
                address(integration),
                "ZKSLockIntegration"
            )
        );
        assertEq(integration.defaultDomainSeparator(), expected);
    }

    /* ========================================================
                       lockContainer
       ======================================================== */

    function test_lockContainer_success_defaultDomain() public {
        bytes32 domainSep = integration.defaultDomainSeparator();
        // Set up container's stateCommitment
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);

        // Compute expected lockId
        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            domainSep
        );
        mockZkSlocks.queueLockId(expectedId);

        vm.expectEmit(true, true, false, true);
        emit ContainerLocked(CONTAINER_ID, expectedId, STATE_COMMITMENT);

        bytes32 lockId = integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0), // uses default domain separator
            0
        );

        assertEq(lockId, expectedId);
        assertEq(integration.containerToLock(CONTAINER_ID), lockId);
        assertEq(integration.lockToContainer(lockId), CONTAINER_ID);
    }

    function test_lockContainer_success_customDomain() public {
        bytes32 customDomain = keccak256("custom");
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);

        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            customDomain
        );
        mockZkSlocks.queueLockId(expectedId);

        bytes32 lockId = integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            customDomain,
            0
        );
        assertEq(lockId, expectedId);
    }

    function test_lockContainer_revert_integrationDisabled() public {
        integration.setIntegrationEnabled(false);
        vm.expectRevert(ZKSLockIntegration.IntegrationDisabled.selector);
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );
    }

    function test_lockContainer_revert_alreadyLocked() public {
        bytes32 domainSep = integration.defaultDomainSeparator();
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);

        // Lock container once
        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            domainSep
        );
        mockZkSlocks.queueLockId(expectedId);
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );

        // Try to lock again
        vm.expectRevert(ZKSLockIntegration.ContainerAlreadyLocked.selector);
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );
    }

    function test_lockContainer_revert_lockIdMismatch() public {
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);
        // Queue wrong lockId
        mockZkSlocks.queueLockId(keccak256("wrong"));

        vm.expectRevert(); // LockIdMismatch
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );
    }

    /* ========================================================
                       unlockContainer
       ======================================================== */

    function test_unlockContainer_success() public {
        // First, lock a container
        bytes32 domainSep = integration.defaultDomainSeparator();
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);
        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            domainSep
        );
        mockZkSlocks.queueLockId(expectedId);
        bytes32 lockId = integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );

        // Now unlock
        bytes32 newStateCommitment = keccak256("newState");
        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: lockId,
                zkProof: hex"dead",
                newStateCommitment: newStateCommitment,
                nullifier: NULLIFIER,
                verifierKeyHash: bytes32(0),
                auxiliaryData: ""
            });

        vm.expectEmit(true, true, false, true);
        emit ContainerUnlocked(CONTAINER_ID, lockId, newStateCommitment);

        integration.unlockContainer(CONTAINER_ID, proof);

        // Verify bindings cleared
        assertEq(integration.containerToLock(CONTAINER_ID), bytes32(0));
        assertEq(integration.lockToContainer(lockId), bytes32(0));
        assertTrue(mockZkSlocks.unlockCalled());
        assertEq(mockZkSlocks.lastUnlockedLockId(), lockId);
    }

    function test_unlockContainer_revert_noLock() public {
        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: keccak256("any"),
                zkProof: "",
                newStateCommitment: bytes32(0),
                nullifier: bytes32(0),
                verifierKeyHash: bytes32(0),
                auxiliaryData: ""
            });

        vm.expectRevert(ZKSLockIntegration.InvalidLockId.selector);
        integration.unlockContainer(CONTAINER_ID, proof);
    }

    function test_unlockContainer_revert_proofLockIdMismatch() public {
        // Lock a container
        bytes32 domainSep = integration.defaultDomainSeparator();
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);
        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            domainSep
        );
        mockZkSlocks.queueLockId(expectedId);
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );

        // Unlock with wrong lockId in proof
        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: keccak256("wrong"),
                zkProof: "",
                newStateCommitment: bytes32(0),
                nullifier: bytes32(0),
                verifierKeyHash: bytes32(0),
                auxiliaryData: ""
            });

        vm.expectRevert(ZKSLockIntegration.InvalidLockId.selector);
        integration.unlockContainer(CONTAINER_ID, proof);
    }

    function test_unlockContainer_revert_integrationDisabled() public {
        integration.setIntegrationEnabled(false);

        ZKBoundStateLocks.UnlockProof memory proof = ZKBoundStateLocks
            .UnlockProof({
                lockId: bytes32(0),
                zkProof: "",
                newStateCommitment: bytes32(0),
                nullifier: bytes32(0),
                verifierKeyHash: bytes32(0),
                auxiliaryData: ""
            });

        vm.expectRevert(ZKSLockIntegration.IntegrationDisabled.selector);
        integration.unlockContainer(CONTAINER_ID, proof);
    }

    /* ========================================================
                       createCrossDomainLock
       ======================================================== */

    function test_createCrossDomainLock_success() public {
        bytes32 lockIdVal = keccak256("crossDomainLock");
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(NULLIFIER);

        vm.expectEmit(true, true, false, true);
        emit NullifierBound(lockIdVal, NULLIFIER, DOMAIN_ID);

        (bytes32 lockId, bytes32 nullifier) = integration.createCrossDomainLock(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            DOMAIN_ID,
            COMMITMENT_HASH,
            POLICY_HASH,
            USER_ENTROPY
        );

        assertEq(lockId, lockIdVal);
        assertEq(nullifier, NULLIFIER);
        assertEq(integration.lockToNullifier(lockId), NULLIFIER);
        assertEq(integration.nullifierToLock(NULLIFIER), lockId);
        assertTrue(mockCdna.registerCalled());
    }

    function test_createCrossDomainLock_revert_integrationDisabled() public {
        integration.setIntegrationEnabled(false);
        vm.expectRevert(ZKSLockIntegration.IntegrationDisabled.selector);
        integration.createCrossDomainLock(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            DOMAIN_ID,
            COMMITMENT_HASH,
            POLICY_HASH,
            USER_ENTROPY
        );
    }

    function test_createCrossDomainLock_revert_zeroEntropy() public {
        vm.expectRevert(ZKSLockIntegration.UserEntropyRequired.selector);
        integration.createCrossDomainLock(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            DOMAIN_ID,
            COMMITMENT_HASH,
            POLICY_HASH,
            bytes32(0) // zero entropy
        );
    }

    function test_createCrossDomainLock_registersCDNA() public {
        mockZkSlocks.queueLockId(keccak256("lock1"));
        mockZkSlocks.setNextNullifier(NULLIFIER);

        integration.createCrossDomainLock(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            DOMAIN_ID,
            COMMITMENT_HASH,
            POLICY_HASH,
            USER_ENTROPY
        );

        assertEq(mockCdna.registerCallCount(), 1);
    }

    /* ========================================================
                       createAtomicLock
       ======================================================== */

    function test_createAtomicLock_success_noPayload() public {
        bytes32 lockIdVal = keccak256("atomicLock");
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(NULLIFIER);

        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: bytes32(0),
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 0,
                userEntropy: USER_ENTROPY,
                encryptedPayload: ""
            });

        (bytes32 lockId, bytes32 containerId, bytes32 nullifier) = integration
            .createAtomicLock(params);

        assertEq(lockId, lockIdVal);
        assertEq(containerId, bytes32(0)); // no payload → no container
        assertEq(nullifier, NULLIFIER);
        assertEq(integration.lockToNullifier(lockId), NULLIFIER);
        assertEq(integration.nullifierToLock(NULLIFIER), lockId);
    }

    function test_createAtomicLock_success_withPayload() public {
        bytes32 lockIdVal = keccak256("atomicLock2");
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(NULLIFIER);

        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: DOMAIN_ID,
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 1000,
                userEntropy: USER_ENTROPY,
                encryptedPayload: hex"cafebabe"
            });

        (bytes32 lockId, bytes32 containerId, ) = integration.createAtomicLock(
            params
        );

        assertEq(lockId, lockIdVal);
        assertTrue(containerId != bytes32(0)); // payload → container created
        assertEq(integration.containerToLock(containerId), lockId);
        assertEq(integration.lockToContainer(lockId), containerId);
    }

    function test_createAtomicLock_emitsEvent() public {
        bytes32 lockIdVal = keccak256("atomicEvent");
        bytes32 domainSep = integration.defaultDomainSeparator();
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(NULLIFIER);

        vm.expectEmit(true, true, true, true);
        emit CrossDomainLockCreated(
            lockIdVal,
            domainSep,
            bytes32(block.chainid),
            NULLIFIER
        );

        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: bytes32(0),
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 0,
                userEntropy: USER_ENTROPY,
                encryptedPayload: ""
            });

        integration.createAtomicLock(params);
    }

    function test_createAtomicLock_revert_integrationDisabled() public {
        integration.setIntegrationEnabled(false);

        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: bytes32(0),
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 0,
                userEntropy: USER_ENTROPY,
                encryptedPayload: ""
            });

        vm.expectRevert(ZKSLockIntegration.IntegrationDisabled.selector);
        integration.createAtomicLock(params);
    }

    function test_createAtomicLock_revert_zeroEntropy() public {
        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: bytes32(0),
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 0,
                userEntropy: bytes32(0),
                encryptedPayload: ""
            });

        vm.expectRevert(ZKSLockIntegration.UserEntropyRequired.selector);
        integration.createAtomicLock(params);
    }

    function test_createAtomicLock_usesCustomDomainSep() public {
        bytes32 lockIdVal = keccak256("atomicCustom");
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(NULLIFIER);

        bytes32 customDomain = keccak256("myDomain");

        vm.expectEmit(true, true, true, true);
        emit CrossDomainLockCreated(
            lockIdVal,
            customDomain,
            bytes32(block.chainid),
            NULLIFIER
        );

        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: customDomain,
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 0,
                userEntropy: USER_ENTROPY,
                encryptedPayload: ""
            });

        integration.createAtomicLock(params);
    }

    function test_createAtomicLock_doesNotCallCDNA() public {
        mockZkSlocks.queueLockId(keccak256("noCdna"));
        mockZkSlocks.setNextNullifier(NULLIFIER);

        ZKSLockIntegration.AtomicLockParams memory params = ZKSLockIntegration
            .AtomicLockParams({
                stateCommitment: STATE_COMMITMENT,
                transitionPredicateHash: TRANSITION_HASH,
                policyBinding: POLICY_HASH,
                domainSeparator: bytes32(0),
                commitmentHash: COMMITMENT_HASH,
                unlockDeadline: 0,
                userEntropy: USER_ENTROPY,
                encryptedPayload: ""
            });

        integration.createAtomicLock(params);
        assertFalse(mockCdna.registerCalled());
    }

    /* ========================================================
                       batchCreateLocks
       ======================================================== */

    function test_batchCreateLocks_success() public {
        bytes32[] memory commits = new bytes32[](3);
        bytes32[] memory transitions = new bytes32[](3);
        bytes32[] memory policies = new bytes32[](3);
        uint64[] memory deadlines = new uint64[](3);

        for (uint256 i = 0; i < 3; i++) {
            commits[i] = keccak256(abi.encode("commit", i));
            transitions[i] = keccak256(abi.encode("transition", i));
            policies[i] = keccak256(abi.encode("policy", i));
            deadlines[i] = uint64(1000 + i);
            mockZkSlocks.queueLockId(keccak256(abi.encode("batchLock", i)));
        }

        bytes32[] memory lockIds = integration.batchCreateLocks(
            commits,
            transitions,
            policies,
            bytes32(0),
            deadlines
        );

        assertEq(lockIds.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(lockIds[i], keccak256(abi.encode("batchLock", i)));
        }
        assertEq(mockZkSlocks.createLockCallCount(), 3);
    }

    function test_batchCreateLocks_revert_integrationDisabled() public {
        integration.setIntegrationEnabled(false);

        bytes32[] memory commits = new bytes32[](1);
        bytes32[] memory transitions = new bytes32[](1);
        bytes32[] memory policies = new bytes32[](1);
        uint64[] memory deadlines = new uint64[](1);

        vm.expectRevert(ZKSLockIntegration.IntegrationDisabled.selector);
        integration.batchCreateLocks(
            commits,
            transitions,
            policies,
            bytes32(0),
            deadlines
        );
    }

    function test_batchCreateLocks_customDomainSep() public {
        bytes32[] memory commits = new bytes32[](2);
        bytes32[] memory transitions = new bytes32[](2);
        bytes32[] memory policies = new bytes32[](2);
        uint64[] memory deadlines = new uint64[](2);
        bytes32 customDom = keccak256("batchDomain");

        for (uint256 i = 0; i < 2; i++) {
            commits[i] = keccak256(abi.encode("c", i));
            transitions[i] = keccak256(abi.encode("t", i));
            policies[i] = keccak256(abi.encode("p", i));
            mockZkSlocks.queueLockId(keccak256(abi.encode("bl", i)));
        }

        bytes32[] memory lockIds = integration.batchCreateLocks(
            commits,
            transitions,
            policies,
            customDom,
            deadlines
        );
        assertEq(lockIds.length, 2);
    }

    /* ========================================================
                       VIEW FUNCTIONS
       ======================================================== */

    function test_getLockInfo_afterLock() public {
        bytes32 domainSep = integration.defaultDomainSeparator();
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);
        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            domainSep
        );
        mockZkSlocks.queueLockId(expectedId);
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );

        (, bytes32 containerId, bytes32 nullifier, bool isLocked) = integration
            .getLockInfo(expectedId);

        assertEq(containerId, CONTAINER_ID);
        assertEq(nullifier, bytes32(0)); // no nullifier for container lock
        assertTrue(isLocked); // mock returns isUnlocked=false by default
    }

    function test_isContainerLocked_true() public {
        bytes32 domainSep = integration.defaultDomainSeparator();
        mockPc3.setContainerStateCommitment(CONTAINER_ID, STATE_COMMITMENT);
        bytes32 expectedId = _expectedLockId(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            POLICY_HASH,
            domainSep
        );
        mockZkSlocks.queueLockId(expectedId);
        integration.lockContainer(
            CONTAINER_ID,
            TRANSITION_HASH,
            POLICY_HASH,
            bytes32(0),
            0
        );

        assertTrue(integration.isContainerLocked(CONTAINER_ID));
    }

    function test_isContainerLocked_false_noLock() public view {
        assertFalse(integration.isContainerLocked(CONTAINER_ID));
    }

    function test_getLockForNullifier() public {
        bytes32 lockIdVal = keccak256("nullifierLock");
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(NULLIFIER);

        integration.createCrossDomainLock(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            DOMAIN_ID,
            COMMITMENT_HASH,
            POLICY_HASH,
            USER_ENTROPY
        );

        assertEq(integration.getLockForNullifier(NULLIFIER), lockIdVal);
    }

    function test_getLockForNullifier_unknown() public view {
        assertEq(
            integration.getLockForNullifier(keccak256("unknown")),
            bytes32(0)
        );
    }

    /* ========================================================
                       ADMIN
       ======================================================== */

    function test_setIntegrationEnabled_toggle() public {
        assertTrue(integration.integrationEnabled());
        integration.setIntegrationEnabled(false);
        assertFalse(integration.integrationEnabled());
        integration.setIntegrationEnabled(true);
        assertTrue(integration.integrationEnabled());
    }

    function test_setDefaultDomainSeparator() public {
        bytes32 newSep = keccak256("newDomain");
        integration.setDefaultDomainSeparator(newSep);
        assertEq(integration.defaultDomainSeparator(), newSep);
    }

    /* ========================================================
                       FUZZ TESTS
       ======================================================== */

    function testFuzz_lockContainer(
        bytes32 containerId,
        bytes32 tHash,
        bytes32 pHash
    ) public {
        vm.assume(containerId != bytes32(0));
        bytes32 sc = keccak256(abi.encode(containerId, "sc"));
        mockPc3.setContainerStateCommitment(containerId, sc);

        bytes32 domainSep = integration.defaultDomainSeparator();
        bytes32 expectedId = _expectedLockId(sc, tHash, pHash, domainSep);
        mockZkSlocks.queueLockId(expectedId);

        bytes32 lockId = integration.lockContainer(
            containerId,
            tHash,
            pHash,
            bytes32(0),
            0
        );
        assertEq(lockId, expectedId);
        assertEq(integration.containerToLock(containerId), lockId);
    }

    function testFuzz_createCrossDomainLock(bytes32 entropy) public {
        vm.assume(entropy != bytes32(0));

        bytes32 lockIdVal = keccak256(abi.encode("fuzzLock", entropy));
        mockZkSlocks.queueLockId(lockIdVal);
        mockZkSlocks.setNextNullifier(
            keccak256(abi.encode("fuzzNull", entropy))
        );

        (bytes32 lockId, bytes32 nullifier) = integration.createCrossDomainLock(
            STATE_COMMITMENT,
            TRANSITION_HASH,
            DOMAIN_ID,
            COMMITMENT_HASH,
            POLICY_HASH,
            entropy
        );

        assertEq(lockId, lockIdVal);
        assertEq(integration.lockToNullifier(lockId), nullifier);
        assertEq(integration.nullifierToLock(nullifier), lockId);
    }

    function testFuzz_batchCreateLocks_size(uint8 count) public {
        vm.assume(count > 0 && count <= 10);

        bytes32[] memory commits = new bytes32[](count);
        bytes32[] memory transitions = new bytes32[](count);
        bytes32[] memory policies = new bytes32[](count);
        uint64[] memory deadlines = new uint64[](count);

        for (uint256 i = 0; i < count; i++) {
            commits[i] = keccak256(abi.encode("fc", i));
            transitions[i] = keccak256(abi.encode("ft", i));
            policies[i] = keccak256(abi.encode("fp", i));
            deadlines[i] = uint64(i + 1);
            mockZkSlocks.queueLockId(keccak256(abi.encode("fbl", i)));
        }

        bytes32[] memory lockIds = integration.batchCreateLocks(
            commits,
            transitions,
            policies,
            bytes32(0),
            deadlines
        );
        assertEq(lockIds.length, count);
    }
}
