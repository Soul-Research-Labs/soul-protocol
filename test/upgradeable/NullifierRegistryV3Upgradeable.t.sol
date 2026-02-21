// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NullifierRegistryV3Upgradeable} from "../../contracts/upgradeable/NullifierRegistryV3Upgradeable.sol";

/**
 * @title NullifierRegistryV3Upgradeable Tests
 * @notice Tests initialization, nullifier registration, batch operations,
 *         cross-chain receipt, merkle tree, access control, and upgrade safety.
 */
contract NullifierRegistryV3UpgradeableTest is Test {
    NullifierRegistryV3Upgradeable public impl;
    NullifierRegistryV3Upgradeable public registry;

    address admin = address(this);
    address registrar = makeAddr("registrar");
    address bridgeRole = makeAddr("bridge");
    address emergency = makeAddr("emergency");
    address user = makeAddr("user");

    bytes32 constant NULLIFIER_1 = keccak256("nullifier_1");
    bytes32 constant NULLIFIER_2 = keccak256("nullifier_2");
    bytes32 constant NULLIFIER_3 = keccak256("nullifier_3");
    bytes32 constant COMMITMENT_1 = keccak256("commitment_1");
    bytes32 constant COMMITMENT_2 = keccak256("commitment_2");
    bytes32 constant COMMITMENT_3 = keccak256("commitment_3");

    function setUp() public {
        impl = new NullifierRegistryV3Upgradeable();
        bytes memory data = abi.encodeCall(impl.initialize, (admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), data);
        registry = NullifierRegistryV3Upgradeable(address(proxy));

        // Grant roles
        registry.grantRole(registry.REGISTRAR_ROLE(), registrar);
        registry.grantRole(registry.BRIDGE_ROLE(), bridgeRole);
        registry.grantRole(registry.EMERGENCY_ROLE(), emergency);
    }

    /*//////////////////////////////////////////////////////////////
                         INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializerSetsAdmin() public view {
        assertTrue(registry.hasRole(registry.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_InitializerSetsRoles() public view {
        assertTrue(registry.hasRole(registry.REGISTRAR_ROLE(), admin));
        assertTrue(registry.hasRole(registry.BRIDGE_ROLE(), admin));
        assertTrue(registry.hasRole(registry.EMERGENCY_ROLE(), admin));
        assertTrue(registry.hasRole(registry.UPGRADER_ROLE(), admin));
    }

    function test_InitializerSetsChainId() public view {
        assertEq(registry.chainId(), block.chainid);
    }

    function test_ContractVersion() public view {
        assertEq(registry.contractVersion(), 1);
    }

    function test_InitialMerkleRoot() public view {
        // Initial root is the empty tree root (hash of all zeros)
        bytes32 root = registry.merkleRoot();
        assertTrue(root != bytes32(0));
        assertTrue(registry.historicalRoots(root));
    }

    function test_InitialTotalNullifiers() public view {
        assertEq(registry.totalNullifiers(), 0);
    }

    function test_CannotDoubleInitialize() public {
        vm.expectRevert();
        registry.initialize(admin);
    }

    function test_CannotInitializeWithZeroAddress() public {
        NullifierRegistryV3Upgradeable newImpl = new NullifierRegistryV3Upgradeable();
        vm.expectRevert(NullifierRegistryV3Upgradeable.ZeroAddress.selector);
        new ERC1967Proxy(
            address(newImpl),
            abi.encodeCall(newImpl.initialize, (address(0)))
        );
    }

    /*//////////////////////////////////////////////////////////////
                      SINGLE REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterNullifier() public {
        vm.prank(registrar);
        uint256 index = registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        assertEq(index, 0);
        assertTrue(registry.isNullifierUsed(NULLIFIER_1));
        assertTrue(registry.exists(NULLIFIER_1));
        assertEq(registry.totalNullifiers(), 1);
    }

    function test_RegisterNullifier_CannotRegisterTwice() public {
        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        vm.prank(registrar);
        vm.expectRevert();
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);
    }

    function test_RegisterNullifier_ZeroNullifierReverts() public {
        vm.prank(registrar);
        vm.expectRevert();
        registry.registerNullifier(bytes32(0), COMMITMENT_1);
    }

    function test_RegisterNullifier_OnlyRegistrar() public {
        vm.prank(user);
        vm.expectRevert();
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);
    }

    function test_RegisterNullifier_UpdatesMerkleRoot() public {
        bytes32 rootBefore = registry.merkleRoot();

        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        bytes32 rootAfter = registry.merkleRoot();
        assertTrue(rootBefore != rootAfter);
        assertTrue(registry.historicalRoots(rootAfter));
    }

    /*//////////////////////////////////////////////////////////////
                       BATCH REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_BatchRegister() public {
        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = NULLIFIER_1;
        nullifiers[1] = NULLIFIER_2;
        nullifiers[2] = NULLIFIER_3;

        bytes32[] memory commitments = new bytes32[](3);
        commitments[0] = COMMITMENT_1;
        commitments[1] = COMMITMENT_2;
        commitments[2] = COMMITMENT_3;

        vm.prank(registrar);
        uint256 startIndex = registry.batchRegisterNullifiers(
            nullifiers,
            commitments
        );

        assertEq(startIndex, 0);
        assertEq(registry.totalNullifiers(), 3);
        assertTrue(registry.isNullifierUsed(NULLIFIER_1));
        assertTrue(registry.isNullifierUsed(NULLIFIER_2));
        assertTrue(registry.isNullifierUsed(NULLIFIER_3));
    }

    function test_BatchRegister_EmptyCommitments() public {
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = NULLIFIER_1;
        nullifiers[1] = NULLIFIER_2;

        bytes32[] memory emptyCommitments = new bytes32[](0);

        vm.prank(registrar);
        registry.batchRegisterNullifiers(nullifiers, emptyCommitments);

        assertEq(registry.totalNullifiers(), 2);
    }

    function test_BatchRegister_EmptyArrayReverts() public {
        bytes32[] memory empty = new bytes32[](0);

        vm.prank(registrar);
        vm.expectRevert();
        registry.batchRegisterNullifiers(empty, empty);
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN NULLIFIERS
    //////////////////////////////////////////////////////////////*/

    function test_ReceiveCrossChainNullifiers() public {
        uint256 sourceChain = 42161;
        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = NULLIFIER_1;
        nullifiers[1] = NULLIFIER_2;

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = COMMITMENT_1;
        commitments[1] = COMMITMENT_2;

        bytes32 sourceMerkleRoot = keccak256("source_root");

        vm.prank(bridgeRole);
        registry.receiveCrossChainNullifiers(
            sourceChain,
            nullifiers,
            commitments,
            sourceMerkleRoot
        );

        assertTrue(registry.isNullifierUsed(NULLIFIER_1));
        assertTrue(registry.isNullifierUsed(NULLIFIER_2));
    }

    function test_ReceiveCrossChainNullifiers_SameChainReverts() public {
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = NULLIFIER_1;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = COMMITMENT_1;

        vm.prank(bridgeRole);
        vm.expectRevert();
        registry.receiveCrossChainNullifiers(
            block.chainid,
            nullifiers,
            commitments,
            bytes32(0)
        );
    }

    function test_ReceiveCrossChainNullifiers_OnlyBridge() public {
        bytes32[] memory nullifiers = new bytes32[](1);
        nullifiers[0] = NULLIFIER_1;
        bytes32[] memory commitments = new bytes32[](1);
        commitments[0] = COMMITMENT_1;

        vm.prank(user);
        vm.expectRevert();
        registry.receiveCrossChainNullifiers(
            42161,
            nullifiers,
            commitments,
            bytes32(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_Exists() public {
        assertFalse(registry.exists(NULLIFIER_1));

        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        assertTrue(registry.exists(NULLIFIER_1));
    }

    function test_BatchExists() public {
        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        bytes32[] memory nullifiers = new bytes32[](2);
        nullifiers[0] = NULLIFIER_1;
        nullifiers[1] = NULLIFIER_2;

        bool[] memory results = registry.batchExists(nullifiers);
        assertTrue(results[0]);
        assertFalse(results[1]);
    }

    function test_IsValidRoot() public view {
        bytes32 root = registry.merkleRoot();
        assertTrue(registry.isValidRoot(root));
        assertFalse(registry.isValidRoot(keccak256("bad_root")));
    }

    function test_GetNullifierData() public {
        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        NullifierRegistryV3Upgradeable.NullifierData memory data = registry
            .getNullifierData(NULLIFIER_1);

        assertEq(data.commitment, COMMITMENT_1);
        assertEq(data.index, 0);
        assertEq(data.registrar, registrar);
    }

    function test_GetTreeStats() public {
        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        (uint256 count, bytes32 root, uint256 historySize) = registry
            .getTreeStats();

        assertEq(count, 1);
        assertTrue(root != bytes32(0));
        assertTrue(historySize > 0);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_AddRegistrar() public {
        address newRegistrar = makeAddr("newRegistrar");
        registry.addRegistrar(newRegistrar);
        assertTrue(registry.hasRole(registry.REGISTRAR_ROLE(), newRegistrar));
    }

    function test_RemoveRegistrar() public {
        registry.removeRegistrar(registrar);
        assertFalse(registry.hasRole(registry.REGISTRAR_ROLE(), registrar));
    }

    function test_Pause() public {
        vm.prank(emergency);
        registry.pause();
        assertTrue(registry.paused());
    }

    function test_Unpause() public {
        vm.prank(emergency);
        registry.pause();
        registry.unpause(); // admin
        assertFalse(registry.paused());
    }

    function test_RegisterWhenPausedReverts() public {
        vm.prank(emergency);
        registry.pause();

        vm.prank(registrar);
        vm.expectRevert();
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);
    }

    /*//////////////////////////////////////////////////////////////
                         UPGRADE SAFETY
    //////////////////////////////////////////////////////////////*/

    function test_UpgradeOnlyUpgrader() public {
        NullifierRegistryV3Upgradeable newImpl = new NullifierRegistryV3Upgradeable();
        registry.upgradeToAndCall(address(newImpl), "");
        assertEq(registry.contractVersion(), 2);
    }

    function test_UpgradeRevertsWithoutRole() public {
        NullifierRegistryV3Upgradeable newImpl = new NullifierRegistryV3Upgradeable();
        vm.prank(user);
        vm.expectRevert();
        registry.upgradeToAndCall(address(newImpl), "");
    }

    function test_UpgradePreservesNullifiers() public {
        // Register a nullifier
        vm.prank(registrar);
        registry.registerNullifier(NULLIFIER_1, COMMITMENT_1);

        bytes32 rootBefore = registry.merkleRoot();

        // Upgrade
        NullifierRegistryV3Upgradeable newImpl = new NullifierRegistryV3Upgradeable();
        registry.upgradeToAndCall(address(newImpl), "");

        // State preserved
        assertTrue(registry.isNullifierUsed(NULLIFIER_1));
        assertEq(registry.totalNullifiers(), 1);
        assertEq(registry.merkleRoot(), rootBefore);
        assertEq(registry.chainId(), block.chainid);
        assertEq(registry.contractVersion(), 2);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterUnique(
        bytes32 nullifier,
        bytes32 commitment
    ) public {
        vm.assume(nullifier != bytes32(0));

        vm.prank(registrar);
        registry.registerNullifier(nullifier, commitment);

        assertTrue(registry.isNullifierUsed(nullifier));
        assertEq(registry.totalNullifiers(), 1);
    }
}
