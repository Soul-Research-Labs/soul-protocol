// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/primitives/Soulv2Orchestrator.sol";

/* ─── Mock contracts for orchestrator dependencies ──────────────── */

contract MockPC3 is IProofCarryingContainer {
    uint256 public override totalContainers;
    mapping(bytes32 => bool) public consumed;
    mapping(bytes32 => bool) public nullifiers;

    function consumeContainer(bytes32 id) external override {
        consumed[id] = true;
    }

    function isNullifierConsumed(
        bytes32 n
    ) external view override returns (bool) {
        return nullifiers[n];
    }

    function setTotalContainers(uint256 n) external {
        totalContainers = n;
    }

    function setNullifier(bytes32 n, bool v) external {
        nullifiers[n] = v;
    }
}

contract MockPBP is IPolicyBoundProofs {
    uint256 public override totalPolicies;
    mapping(bytes32 => bool) public policies;

    function isPolicyValid(bytes32 p) external view override returns (bool) {
        return policies[p];
    }

    function setTotalPolicies(uint256 n) external {
        totalPolicies = n;
    }

    function addPolicy(bytes32 p) external {
        policies[p] = true;
        totalPolicies++;
    }
}

contract MockEASC is IExecutionAgnosticStateCommitments {
    uint256 public override totalCommitments;
    bytes32 public lastCommitmentId;

    function createCommitment(
        bytes32 stateHash,
        bytes32 transitionHash,
        bytes32 nullifier
    ) external override returns (bytes32) {
        lastCommitmentId = keccak256(
            abi.encode(stateHash, transitionHash, nullifier)
        );
        totalCommitments++;
        return lastCommitmentId;
    }

    function attestCommitment(
        bytes32,
        bytes32,
        bytes calldata,
        bytes32
    ) external override {}

    function setTotalCommitments(uint256 n) external {
        totalCommitments = n;
    }
}

contract MockCDNA is ICrossDomainNullifierAlgebra {
    uint256 public override totalDomains;
    mapping(bytes32 => bool) public nullifiers;
    bytes32 public lastRegistered;

    function registerNullifier(
        bytes32,
        bytes32 nullifierValue,
        bytes32,
        bytes32
    ) external override returns (bytes32) {
        bytes32 id = keccak256(abi.encode(nullifierValue, block.timestamp));
        nullifiers[id] = true;
        lastRegistered = id;
        return id;
    }

    function consumeNullifier(bytes32 n) external override {
        nullifiers[n] = false;
    }

    function nullifierExists(bytes32 n) external view override returns (bool) {
        return nullifiers[n];
    }

    function setTotalDomains(uint256 n) external {
        totalDomains = n;
    }
}

/* ─── Test contract ──────────────────────────────────────────────── */

contract Soulv2OrchestratorTest is Test {
    Soulv2Orchestrator public orch;
    MockPC3 public pc3;
    MockPBP public pbp;
    MockEASC public easc;
    MockCDNA public cdna;

    address admin = address(0xA);
    address operator = address(0xB);
    address nobody = address(0xDEAD);

    bytes32 ORCHESTRATOR_ROLE;

    function setUp() public {
        pc3 = new MockPC3();
        pbp = new MockPBP();
        easc = new MockEASC();
        cdna = new MockCDNA();

        pc3.setTotalContainers(5);
        pbp.setTotalPolicies(3);
        easc.setTotalCommitments(2);
        cdna.setTotalDomains(4);

        vm.prank(admin);
        orch = new Soulv2Orchestrator(
            address(pc3),
            address(pbp),
            address(easc),
            address(cdna)
        );

        ORCHESTRATOR_ROLE = orch.ORCHESTRATOR_ROLE();

        vm.startPrank(admin);
        orch.grantRole(ORCHESTRATOR_ROLE, operator);
        vm.stopPrank();
    }

    /* ── Constructor ────────────────────────────────── */

    function test_constructor_setsAddresses() public view {
        assertEq(address(orch.pc3()), address(pc3));
        assertEq(address(orch.pbp()), address(pbp));
        assertEq(address(orch.easc()), address(easc));
        assertEq(address(orch.cdna()), address(cdna));
    }

    function test_constructor_adminHasRole() public view {
        assertTrue(orch.hasRole(orch.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(orch.hasRole(ORCHESTRATOR_ROLE, admin));
    }

    /* ── checkConnections ───────────────────────────── */

    function test_checkConnections_returnsTrue() public view {
        (bool pc3Ok, bool pbpOk, bool eascOk, bool cdnaOk) = orch
            .checkConnections();
        assertTrue(pc3Ok);
        assertTrue(pbpOk);
        assertTrue(eascOk);
        assertTrue(cdnaOk);
    }

    /* ── registerContainerInDomain ──────────────────── */

    function test_registerContainerInDomain_happyPath() public {
        bytes32 cid = bytes32(uint256(1));
        bytes32 cnull = bytes32(uint256(2));
        bytes32 sc = bytes32(uint256(3));
        bytes32 did = bytes32(uint256(10));

        vm.prank(operator);
        bytes32 nul = orch.registerContainerInDomain(cid, cnull, sc, did);

        assertEq(orch.containerToDomain(cid), did);
        assertTrue(nul != bytes32(0));
    }

    function test_registerContainerInDomain_revertsZeroContainerId() public {
        vm.prank(operator);
        vm.expectRevert(Soulv2Orchestrator.InvalidContainerId.selector);
        orch.registerContainerInDomain(
            bytes32(0),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3))
        );
    }

    function test_registerContainerInDomain_revertsZeroDomainId() public {
        vm.prank(operator);
        vm.expectRevert(Soulv2Orchestrator.InvalidDomainId.selector);
        orch.registerContainerInDomain(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(0)
        );
    }

    function test_registerContainerInDomain_revertsUnauthorized() public {
        vm.prank(nobody);
        vm.expectRevert();
        orch.registerContainerInDomain(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
    }

    function testFuzz_registerContainerInDomain(
        bytes32 cid,
        bytes32 cnull,
        bytes32 sc,
        bytes32 did
    ) public {
        vm.assume(cid != bytes32(0) && did != bytes32(0));
        vm.prank(operator);
        orch.registerContainerInDomain(cid, cnull, sc, did);
        assertEq(orch.containerToDomain(cid), did);
    }

    /* ── createPolicyBoundCommitment ────────────────── */

    function test_createPolicyBoundCommitment_happyPath() public {
        bytes32 pid = bytes32(uint256(2));
        pbp.addPolicy(pid);

        vm.prank(operator);
        bytes32 commId = orch.createPolicyBoundCommitment(
            bytes32(uint256(10)),
            bytes32(uint256(20)),
            bytes32(uint256(30)),
            pid
        );

        assertTrue(commId != bytes32(0));
    }

    function test_createPolicyBoundCommitment_revertsInvalidPolicy() public {
        vm.prank(operator);
        vm.expectRevert(Soulv2Orchestrator.InvalidPolicyId.selector);
        orch.createPolicyBoundCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(0)
        );
    }

    function test_createPolicyBoundCommitment_revertsUnknownPolicy() public {
        bytes32 unknownPolicy = bytes32(uint256(999));
        vm.prank(operator);
        vm.expectRevert(Soulv2Orchestrator.InvalidPolicyId.selector);
        orch.createPolicyBoundCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            unknownPolicy
        );
    }

    /* ── createCoordinatedTransition ────────────────── */

    function test_createCoordinatedTransition_happyPath() public {
        bytes32 cid = bytes32(uint256(1));
        bytes32 cnull = bytes32(uint256(2));
        bytes32 sh = bytes32(uint256(3));
        bytes32 th = bytes32(uint256(4));
        bytes32 did = bytes32(uint256(5));
        bytes32 pid = bytes32(0); // no policy

        vm.prank(operator);
        bytes32 tid = orch.createCoordinatedTransition(
            cid,
            cnull,
            sh,
            th,
            did,
            pid
        );

        assertTrue(tid != bytes32(0));
        assertEq(orch.totalTransitions(), 1);
    }

    function test_createCoordinatedTransition_withPolicy() public {
        bytes32 pid = bytes32(uint256(99));
        pbp.addPolicy(pid);

        vm.prank(operator);
        bytes32 tid = orch.createCoordinatedTransition(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            pid
        );

        assertTrue(tid != bytes32(0));
    }

    function test_createCoordinatedTransition_revertsInvalidContainerId()
        public
    {
        vm.prank(operator);
        vm.expectRevert(Soulv2Orchestrator.InvalidContainerId.selector);
        orch.createCoordinatedTransition(
            bytes32(0),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(0)
        );
    }

    function test_createCoordinatedTransition_revertsInvalidDomainId() public {
        vm.prank(operator);
        vm.expectRevert(Soulv2Orchestrator.InvalidDomainId.selector);
        orch.createCoordinatedTransition(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(0),
            bytes32(0)
        );
    }

    function testFuzz_createCoordinatedTransition(
        bytes32 cid,
        bytes32 cnull,
        bytes32 sh,
        bytes32 th,
        bytes32 did
    ) public {
        vm.assume(cid != bytes32(0));
        vm.assume(did != bytes32(0));

        vm.prank(operator);
        bytes32 tid = orch.createCoordinatedTransition(
            cid,
            cnull,
            sh,
            th,
            did,
            bytes32(0)
        );
        assertTrue(tid != bytes32(0));
    }

    /* ── completeCoordinatedTransition ──────────────── */

    function test_completeCoordinatedTransition_happyPath() public {
        vm.prank(operator);
        bytes32 tid = orch.createCoordinatedTransition(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(0)
        );

        vm.prank(operator);
        orch.completeCoordinatedTransition(
            tid,
            bytes32(uint256(99)),
            hex"AABB",
            bytes32(uint256(100))
        );
    }

    function test_completeCoordinatedTransition_revertsNotFound() public {
        bytes32 fakeTid = bytes32(uint256(999));
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                Soulv2Orchestrator.TransitionNotFound.selector,
                fakeTid
            )
        );
        orch.completeCoordinatedTransition(
            fakeTid,
            bytes32(uint256(1)),
            hex"AA",
            bytes32(uint256(2))
        );
    }

    function test_completeCoordinatedTransition_revertsAlreadyComplete()
        public
    {
        vm.startPrank(operator);
        bytes32 tid = orch.createCoordinatedTransition(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(0)
        );
        orch.completeCoordinatedTransition(
            tid,
            bytes32(uint256(99)),
            hex"AABB",
            bytes32(uint256(100))
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                Soulv2Orchestrator.TransitionAlreadyComplete.selector,
                tid
            )
        );
        orch.completeCoordinatedTransition(
            tid,
            bytes32(uint256(99)),
            hex"AABB",
            bytes32(uint256(100))
        );
        vm.stopPrank();
    }

    /* ── Pause / Unpause ────────────────────────────── */

    function test_pause_blocksOperations() public {
        vm.prank(admin);
        orch.pause();

        vm.prank(operator);
        vm.expectRevert();
        orch.registerContainerInDomain(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
    }

    function test_unpause_resumesOperations() public {
        vm.prank(admin);
        orch.pause();

        vm.prank(admin);
        orch.unpause();

        vm.prank(operator);
        orch.registerContainerInDomain(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
    }

    /* ── Access control ─────────────────────────────── */

    function test_onlyOrchestratorRole_canOperate() public {
        vm.prank(nobody);
        vm.expectRevert();
        orch.registerContainerInDomain(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );

        vm.prank(nobody);
        vm.expectRevert();
        orch.createPolicyBoundCommitment(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );

        vm.prank(nobody);
        vm.expectRevert();
        orch.createCoordinatedTransition(
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );
    }

    /* ── Multiple transitions ───────────────────────── */

    function test_multipleTransitions_incrementCounter() public {
        vm.startPrank(operator);
        for (uint256 i = 1; i <= 5; i++) {
            orch.createCoordinatedTransition(
                bytes32(i),
                bytes32(i + 100),
                bytes32(i + 200),
                bytes32(i + 300),
                bytes32(i + 400),
                bytes32(0)
            );
        }
        assertEq(orch.totalTransitions(), 5);
        vm.stopPrank();
    }
}
