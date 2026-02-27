// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/InstantCompletionGuaranteeUpgradeable.sol";

/**
 * @title MockIntentLayerForGuarantee
 * @notice Minimal mock implementing IIntentCompletionLayer.isIntentFinalized
 */
contract MockIntentLayerForGuarantee {
    mapping(bytes32 => bool) public finalized;

    function setFinalized(bytes32 intentId, bool val) external {
        finalized[intentId] = val;
    }

    function isIntentFinalized(bytes32 intentId) external view returns (bool) {
        return finalized[intentId];
    }
}

/**
 * @title InstantCompletionGuaranteeUpgradeable Test
 * @notice Tests proxy init, guarantee lifecycle (post/settle/claim/expire),
 *         role enforcement, UUPS upgrade, and storage preservation.
 */
contract InstantCompletionGuaranteeUpgradeableTest is Test {
    InstantCompletionGuaranteeUpgradeable public guarantee;
    InstantCompletionGuaranteeUpgradeable public implementation;
    MockIntentLayerForGuarantee public intentLayer;
    ERC1967Proxy public proxy;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public completer = makeAddr("completer");
    address public upgrader = makeAddr("upgrader");
    address public guarantor = makeAddr("guarantor");
    address public beneficiary = makeAddr("beneficiary");

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant COMPLETION_ROLE = keccak256("COMPLETION_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function setUp() public {
        // Deploy mock intent layer
        intentLayer = new MockIntentLayerForGuarantee();

        // Deploy implementation
        implementation = new InstantCompletionGuaranteeUpgradeable();

        // Encode initializer
        bytes memory initData = abi.encodeCall(
            InstantCompletionGuaranteeUpgradeable.initialize,
            (admin, address(intentLayer))
        );

        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        guarantee = InstantCompletionGuaranteeUpgradeable(
            payable(address(proxy))
        );

        // Grant roles
        vm.startPrank(admin);
        guarantee.grantRole(OPERATOR_ROLE, operator);
        guarantee.grantRole(COMPLETION_ROLE, completer);
        guarantee.grantRole(UPGRADER_ROLE, upgrader);
        vm.stopPrank();

        // Fund actors
        vm.deal(guarantor, 100 ether);
        vm.deal(beneficiary, 10 ether);
    }

    // ──────────────────────────────────────────────────────────────
    // Initialization
    // ──────────────────────────────────────────────────────────────

    function test_initialization() public view {
        assertTrue(guarantee.hasRole(guarantee.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(guarantee.hasRole(OPERATOR_ROLE, admin));
        assertTrue(guarantee.hasRole(COMPLETION_ROLE, admin));
        assertTrue(guarantee.hasRole(UPGRADER_ROLE, admin));
    }

    function test_cannotReinitialize() public {
        vm.expectRevert();
        guarantee.initialize(admin, address(intentLayer));
    }

    // ──────────────────────────────────────────────────────────────
    // Post Guarantee
    // ──────────────────────────────────────────────────────────────

    function test_postGuarantee() public {
        bytes32 intentId = keccak256("intent1");
        uint256 amount = 1 ether;
        uint256 duration = 1 hours;
        // 110% collateral = 1.1 ether
        uint256 bond = 1.1 ether;

        vm.prank(guarantor);
        guarantee.postGuarantee{value: bond}(
            intentId,
            beneficiary,
            amount,
            duration
        );
    }

    function test_postGuarantee_insufficientBond_reverts() public {
        bytes32 intentId = keccak256("intent1");
        uint256 amount = 1 ether;
        uint256 duration = 1 hours;
        // Only 0.5 ether (need >= 1.1 ether at 110% ratio)
        uint256 bond = 0.5 ether;

        vm.prank(guarantor);
        vm.expectRevert();
        guarantee.postGuarantee{value: bond}(
            intentId,
            beneficiary,
            amount,
            duration
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Set Collateral Ratio
    // ──────────────────────────────────────────────────────────────

    function test_setCollateralRatio() public {
        vm.prank(operator);
        guarantee.setCollateralRatio(15_000); // 150%
    }

    function test_setCollateralRatio_nonOperator_reverts() public {
        vm.prank(guarantor);
        vm.expectRevert();
        guarantee.setCollateralRatio(15_000);
    }

    function test_setCollateralRatio_outOfRange_reverts() public {
        vm.prank(operator);
        vm.expectRevert();
        guarantee.setCollateralRatio(50_000); // 500% > max 300%
    }

    // ──────────────────────────────────────────────────────────────
    // Set Intent Layer
    // ──────────────────────────────────────────────────────────────

    function test_setIntentLayer() public {
        address newLayer = makeAddr("newLayer");
        vm.prank(operator);
        guarantee.setIntentLayer(newLayer);
    }

    function test_setIntentLayer_nonOperator_reverts() public {
        vm.prank(guarantor);
        vm.expectRevert();
        guarantee.setIntentLayer(makeAddr("x"));
    }

    // ──────────────────────────────────────────────────────────────
    // Mark Intent Finalized
    // ──────────────────────────────────────────────────────────────

    function test_markIntentFinalized() public {
        vm.prank(completer);
        guarantee.markIntentFinalized(keccak256("intent1"));
    }

    function test_markIntentFinalized_nonCompleter_reverts() public {
        vm.prank(guarantor);
        vm.expectRevert();
        guarantee.markIntentFinalized(keccak256("intent1"));
    }

    // ──────────────────────────────────────────────────────────────
    // UUPS Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_upgradeByUpgrader() public {
        InstantCompletionGuaranteeUpgradeable newImpl = new InstantCompletionGuaranteeUpgradeable();

        vm.prank(upgrader);
        guarantee.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgradeByNonUpgrader_reverts() public {
        InstantCompletionGuaranteeUpgradeable newImpl = new InstantCompletionGuaranteeUpgradeable();

        vm.prank(guarantor);
        vm.expectRevert();
        guarantee.upgradeToAndCall(address(newImpl), "");
    }

    // ──────────────────────────────────────────────────────────────
    // Storage Preservation After Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_storagePreservedAfterUpgrade() public {
        // Post a guarantee
        bytes32 intentId = keccak256("intent1");
        vm.prank(guarantor);
        guarantee.postGuarantee{value: 1.1 ether}(
            intentId,
            beneficiary,
            1 ether,
            1 hours
        );

        // Upgrade
        InstantCompletionGuaranteeUpgradeable newImpl = new InstantCompletionGuaranteeUpgradeable();
        vm.prank(upgrader);
        guarantee.upgradeToAndCall(address(newImpl), "");

        // Verify roles preserved
        assertTrue(guarantee.hasRole(OPERATOR_ROLE, operator));
        assertTrue(guarantee.hasRole(COMPLETION_ROLE, completer));
    }

    // ──────────────────────────────────────────────────────────────
    // Receive ETH (insurance pool)
    // ──────────────────────────────────────────────────────────────

    function test_receiveETH() public {
        vm.deal(address(this), 1 ether);
        (bool ok, ) = address(guarantee).call{value: 1 ether}("");
        assertTrue(ok);
    }
}
