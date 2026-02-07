// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PrivacyRouter} from "../../contracts/core/PrivacyRouter.sol";
import {UniversalShieldedPool} from "../../contracts/privacy/UniversalShieldedPool.sol";

/**
 * @title PrivacyRouterTest
 * @notice Tests for the Privacy Router facade
 */
contract PrivacyRouterTest is Test {
    PrivacyRouter public router;
    UniversalShieldedPool public pool;

    address public admin = makeAddr("admin");
    address public user = makeAddr("user");
    address public recipient = makeAddr("recipient");

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    function setUp() public {
        vm.startPrank(admin);

        // Deploy pool in test mode
        pool = new UniversalShieldedPool(admin, address(0), true);

        // Deploy router with pool but no other components
        router = new PrivacyRouter(
            admin,
            address(pool),
            address(0), // crossChainHub
            address(0), // stealthRegistry
            address(0), // nullifierManager
            address(0), // compliance (disabled)
            address(0) // proofTranslator
        );

        // Disable compliance for testing
        router.setComplianceEnabled(false);

        vm.stopPrank();

        vm.deal(user, 100 ether);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializeCorrectly() public view {
        assertEq(router.shieldedPool(), address(pool));
        assertFalse(router.complianceEnabled());
        assertEq(router.operationNonce(), 0);
    }

    function test_ComponentAddresses() public view {
        assertEq(router.shieldedPool(), address(pool));
        assertEq(router.crossChainHub(), address(0));
        assertEq(router.stealthRegistry(), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        DEPOSIT ETH VIA ROUTER
    //////////////////////////////////////////////////////////////*/

    function test_DepositETH() public {
        bytes32 commitment = keccak256(
            abi.encodePacked("router_secret", uint256(1 ether))
        );

        vm.prank(user);
        bytes32 opId = router.depositETH{value: 1 ether}(commitment);

        assertTrue(opId != bytes32(0), "Operation ID should be generated");

        // Check receipt
        (
            bytes32 receiptId,
            PrivacyRouter.OperationType opType,
            ,
            bytes32 commitHash,
            bool success
        ) = router.receipts(opId);
        assertEq(receiptId, opId);
        assertEq(uint8(opType), uint8(PrivacyRouter.OperationType.DEPOSIT));
        assertEq(commitHash, commitment);
        assertTrue(success);
    }

    function test_RevertDepositETHZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(PrivacyRouter.ZeroAmount.selector)
        );
        router.depositETH{value: 0}(keccak256("zero"));
    }

    /*//////////////////////////////////////////////////////////////
                       QUERY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_GetOperationCount() public {
        bytes32 c1 = keccak256(abi.encodePacked("op1", uint256(1)));
        bytes32 c2 = keccak256(abi.encodePacked("op2", uint256(2)));

        vm.startPrank(user);
        router.depositETH{value: 1 ether}(c1);
        router.depositETH{value: 1 ether}(c2);
        vm.stopPrank();

        assertEq(
            router.getOperationCount(PrivacyRouter.OperationType.DEPOSIT),
            2
        );
        assertEq(
            router.getOperationCount(PrivacyRouter.OperationType.WITHDRAW),
            0
        );
    }

    function test_GetReceipt() public {
        bytes32 commitment = keccak256(
            abi.encodePacked("receipt_test", uint256(1))
        );

        vm.prank(user);
        bytes32 opId = router.depositETH{value: 1 ether}(commitment);

        PrivacyRouter.OperationReceipt memory receipt = router.getReceipt(opId);
        assertEq(receipt.operationId, opId);
        assertTrue(receipt.success);
        assertEq(receipt.timestamp, block.timestamp);
    }

    function test_CheckComplianceDisabled() public view {
        assertTrue(
            router.checkCompliance(user),
            "Should pass when compliance disabled"
        );
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetComponent() public {
        address newPool = makeAddr("newPool");

        vm.prank(admin);
        router.setComponent("shieldedPool", newPool);

        assertEq(router.shieldedPool(), newPool);
    }

    function test_RevertSetComponentZeroAddress() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(PrivacyRouter.ZeroAddress.selector)
        );
        router.setComponent("shieldedPool", address(0));
    }

    function test_RevertSetInvalidComponent() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(PrivacyRouter.InvalidParams.selector)
        );
        router.setComponent("invalidName", makeAddr("something"));
    }

    function test_SetComplianceEnabled() public {
        vm.prank(admin);
        router.setComplianceEnabled(true);
        assertTrue(router.complianceEnabled());
    }

    function test_SetMinimumKYCTier() public {
        vm.prank(admin);
        router.setMinimumKYCTier(2);
        assertEq(router.minimumKYCTier(), 2);
    }

    function test_PauseAndUnpause() public {
        vm.startPrank(admin);
        router.pause();

        vm.expectRevert();
        vm.stopPrank();
        vm.prank(user);
        router.depositETH{value: 1 ether}(keccak256("paused"));

        vm.prank(admin);
        router.unpause();

        // Should work again
        vm.prank(user);
        router.depositETH{value: 1 ether}(keccak256("unpaused"));
    }

    /*//////////////////////////////////////////////////////////////
                       CROSS-CHAIN REVERT
    //////////////////////////////////////////////////////////////*/

    function test_RevertCrossChainNoHub() public {
        PrivacyRouter.CrossChainTransferParams memory params = PrivacyRouter
            .CrossChainTransferParams({
                destChainId: 42161,
                recipientStealth: keccak256("stealth"),
                amount: 1 ether,
                privacyLevel: 3,
                proofSystem: 0,
                proof: new bytes(128),
                publicInputs: new bytes32[](1),
                proofHash: keccak256("proof")
            });

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivacyRouter.ComponentNotSet.selector,
                "crossChainHub"
            )
        );
        router.initiatePrivateTransfer{value: 1 ether}(params);
    }

    function test_RevertStealthNoRegistry() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                PrivacyRouter.ComponentNotSet.selector,
                "stealthRegistry"
            )
        );
        router.registerStealthMetaAddress(new bytes(33), new bytes(33), 0, 1);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_DepositETHGeneratesUniqueOpIds(
        uint256 amount1,
        uint256 amount2
    ) public {
        vm.assume(amount1 >= 0.001 ether && amount1 <= 10 ether);
        vm.assume(amount2 >= 0.001 ether && amount2 <= 10 ether);
        vm.deal(user, amount1 + amount2);

        bytes32 c1 = keccak256(abi.encodePacked("fuzz1", amount1));
        bytes32 c2 = keccak256(abi.encodePacked("fuzz2", amount2));
        vm.assume(c1 != c2);

        vm.startPrank(user);
        bytes32 opId1 = router.depositETH{value: amount1}(c1);
        bytes32 opId2 = router.depositETH{value: amount2}(c2);
        vm.stopPrank();

        assertTrue(opId1 != opId2, "Operation IDs should be unique");
    }
}
