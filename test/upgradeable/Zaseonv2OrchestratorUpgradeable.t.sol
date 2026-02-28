// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/Zaseonv2OrchestratorUpgradeable.sol";

contract Zaseonv2OrchestratorUpgradeableTest is Test {
    Zaseonv2OrchestratorUpgradeable orch;
    address admin = address(0xA0A0);
    address operator = address(0xB0B0);
    address user1 = address(0xC0C0);
    address pc3 = address(0x1010);
    address pbp = address(0x2020);
    address easc = address(0x3030);
    address cdna = address(0x4040);

    // Cached primitive IDs
    bytes32 PC3_PRIM;
    bytes32 PBP_PRIM;
    bytes32 CDNA_PRIM;

    function setUp() public {
        Zaseonv2OrchestratorUpgradeable impl = new Zaseonv2OrchestratorUpgradeable();
        bytes memory initData = abi.encodeCall(
            Zaseonv2OrchestratorUpgradeable.initialize,
            (admin, pc3, pbp, easc, cdna)
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        orch = Zaseonv2OrchestratorUpgradeable(address(proxy));

        PC3_PRIM = orch.PC3_PRIMITIVE();
        PBP_PRIM = orch.PBP_PRIMITIVE();
        CDNA_PRIM = orch.CDNA_PRIMITIVE();
    }

    /* ══════════════════════════════════════════════════
              INITIALIZATION
       ══════════════════════════════════════════════════ */

    function test_initialize_setsAdmin() public view {
        assertTrue(orch.hasRole(orch.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(orch.hasRole(orch.ORCHESTRATOR_ADMIN_ROLE(), admin));
        assertTrue(orch.hasRole(orch.OPERATOR_ROLE(), admin));
        assertTrue(orch.hasRole(orch.UPGRADER_ROLE(), admin));
    }

    function test_initialize_setsPrimitives() public view {
        assertEq(orch.proofCarryingContainer(), pc3);
        assertEq(orch.policyBoundProofs(), pbp);
        assertEq(orch.executionAgnosticStateCommitments(), easc);
        assertEq(orch.crossDomainNullifierAlgebra(), cdna);
    }

    function test_initialize_activatesPrimitives() public view {
        assertTrue(orch.primitiveActive(orch.PC3_PRIMITIVE()));
        assertTrue(orch.primitiveActive(orch.PBP_PRIMITIVE()));
        assertTrue(orch.primitiveActive(orch.EASC_PRIMITIVE()));
        assertTrue(orch.primitiveActive(orch.CDNA_PRIMITIVE()));
    }

    function test_initialize_setsVersion() public view {
        assertEq(orch.contractVersion(), 1);
    }

    function test_initialize_cannotCallTwice() public {
        vm.expectRevert();
        orch.initialize(admin, pc3, pbp, easc, cdna);
    }

    /* ══════════════════════════════════════════════════
              EXECUTE PRIVATE TRANSFER
       ══════════════════════════════════════════════════ */

    function _validRequest()
        internal
        view
        returns (Zaseonv2OrchestratorUpgradeable.OperationRequest memory)
    {
        return
            Zaseonv2OrchestratorUpgradeable.OperationRequest({
                stateCommitment: bytes32(uint256(1)),
                nullifier: bytes32(uint256(2)),
                validityProof: new bytes(256),
                policyProof: new bytes(0),
                nullifierProof: new bytes(0),
                proofHash: bytes32(0),
                policyId: bytes32(0),
                recipient: user1,
                amount: 1 ether,
                timestamp: block.timestamp
            });
    }

    function test_executePrivateTransfer_success() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        vm.prank(user1);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory result = orch
            .executePrivateTransfer(req);

        assertTrue(result.success);
        assertNotEq(result.operationId, bytes32(0));
        assertEq(orch.totalOperations(), 1);
        assertEq(orch.successfulOperations(), 1);
        assertEq(orch.failedOperations(), 0);
    }

    function test_executePrivateTransfer_incrementsUserCount() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        vm.prank(user1);
        orch.executePrivateTransfer(req);
        assertEq(orch.getUserOperationCount(user1), 1);
    }

    function test_executePrivateTransfer_failsZeroCommitment() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        req.stateCommitment = bytes32(0);
        vm.prank(user1);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory result = orch
            .executePrivateTransfer(req);
        assertFalse(result.success);
        assertEq(orch.failedOperations(), 1);
    }

    function test_executePrivateTransfer_failsZeroNullifier() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        req.nullifier = bytes32(0);
        vm.prank(user1);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory result = orch
            .executePrivateTransfer(req);
        assertFalse(result.success);
    }

    function test_executePrivateTransfer_failsZeroRecipient() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        req.recipient = address(0);
        vm.prank(user1);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory result = orch
            .executePrivateTransfer(req);
        assertFalse(result.success);
    }

    function test_executePrivateTransfer_revertsShortProof() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        req.validityProof = new bytes(100); // too short
        vm.prank(user1);
        vm.expectRevert("Validity proof too short");
        orch.executePrivateTransfer(req);
    }

    function test_executePrivateTransfer_uniqueOperationIds() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        vm.startPrank(user1);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory r1 = orch
            .executePrivateTransfer(req);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory r2 = orch
            .executePrivateTransfer(req);
        vm.stopPrank();
        assertNotEq(r1.operationId, r2.operationId);
    }

    function test_executePrivateTransfer_revertsWhenPaused() public {
        vm.prank(admin);
        orch.pause();
        vm.expectRevert();
        vm.prank(user1);
        orch.executePrivateTransfer(_validRequest());
    }

    function test_executePrivateTransfer_revertsInactivePrimitive() public {
        vm.startPrank(admin);
        orch.setPrimitiveActive(PC3_PRIM, false);
        vm.stopPrank();

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                Zaseonv2OrchestratorUpgradeable.PrimitiveNotActive.selector,
                PC3_PRIM
            )
        );
        orch.executePrivateTransfer(_validRequest());
    }

    /* ══════════════════════════════════════════════════
              VIEW FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_getSystemStatus() public view {
        Zaseonv2OrchestratorUpgradeable.SystemStatus memory status = orch
            .getSystemStatus();
        assertTrue(status.pc3Active);
        assertTrue(status.pbpActive);
        assertTrue(status.eascActive);
        assertTrue(status.cdnaActive);
        assertEq(status.totalOperations, 0);
    }

    function test_getOperationResult() public {
        Zaseonv2OrchestratorUpgradeable.OperationRequest
            memory req = _validRequest();
        vm.prank(user1);
        Zaseonv2OrchestratorUpgradeable.OperationResult memory result = orch
            .executePrivateTransfer(req);

        Zaseonv2OrchestratorUpgradeable.OperationResult memory stored = orch
            .getOperationResult(result.operationId);
        assertEq(stored.operationId, result.operationId);
        assertTrue(stored.success);
    }

    function test_getImplementationVersion() public view {
        assertEq(
            keccak256(bytes(orch.getImplementationVersion())),
            keccak256("1.0.0")
        );
    }

    /* ══════════════════════════════════════════════════
              ADMIN FUNCTIONS
       ══════════════════════════════════════════════════ */

    function test_updatePrimitive_pc3() public {
        address newPc3 = address(0x99);
        vm.prank(admin);
        orch.updatePrimitive(PC3_PRIM, newPc3);
        assertEq(orch.proofCarryingContainer(), newPc3);
    }

    function test_updatePrimitive_allPrimitives() public {
        vm.startPrank(admin);
        orch.updatePrimitive(PBP_PRIM, address(0x91));
        orch.updatePrimitive(keccak256("EASC"), address(0x92));
        orch.updatePrimitive(CDNA_PRIM, address(0x93));
        vm.stopPrank();

        assertEq(orch.policyBoundProofs(), address(0x91));
        assertEq(orch.executionAgnosticStateCommitments(), address(0x92));
        assertEq(orch.crossDomainNullifierAlgebra(), address(0x93));
    }

    function test_updatePrimitive_revertsInvalidId() public {
        vm.prank(admin);
        vm.expectRevert(
            Zaseonv2OrchestratorUpgradeable.InvalidOperation.selector
        );
        orch.updatePrimitive(bytes32(uint256(999)), address(0x99));
    }

    function test_updatePrimitive_revertsNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        orch.updatePrimitive(PC3_PRIM, address(0x99));
    }

    function test_setPrimitiveActive() public {
        vm.prank(admin);
        orch.setPrimitiveActive(PC3_PRIM, false);
        assertFalse(orch.primitiveActive(PC3_PRIM));

        vm.prank(admin);
        orch.setPrimitiveActive(PC3_PRIM, true);
        assertTrue(orch.primitiveActive(PC3_PRIM));
    }

    /* ══════════════════════════════════════════════════
              PAUSE / UNPAUSE
       ══════════════════════════════════════════════════ */

    function test_pause_onlyAdmin() public {
        vm.prank(admin);
        orch.pause();
        assertTrue(orch.paused());
    }

    function test_unpause_onlyAdmin() public {
        vm.prank(admin);
        orch.pause();
        vm.prank(admin);
        orch.unpause();
        assertFalse(orch.paused());
    }

    function test_pause_revertsNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        orch.pause();
    }

    /* ══════════════════════════════════════════════════
              UPGRADE AUTHORIZATION
       ══════════════════════════════════════════════════ */

    function test_upgrade_revertsNotUpgrader() public {
        Zaseonv2OrchestratorUpgradeable newImpl = new Zaseonv2OrchestratorUpgradeable();
        vm.prank(user1);
        vm.expectRevert();
        orch.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgrade_succeeds() public {
        Zaseonv2OrchestratorUpgradeable newImpl = new Zaseonv2OrchestratorUpgradeable();
        vm.prank(admin);
        orch.upgradeToAndCall(address(newImpl), "");
        assertEq(orch.contractVersion(), 2);
    }

    /* ══════════════════════════════════════════════════
              PRIMITIVE CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_primitiveConstants() public view {
        assertEq(orch.PC3_PRIMITIVE(), keccak256("PC3"));
        assertEq(orch.PBP_PRIMITIVE(), keccak256("PBP"));
        assertEq(orch.EASC_PRIMITIVE(), keccak256("EASC"));
        assertEq(orch.CDNA_PRIMITIVE(), keccak256("CDNA"));
    }
}
