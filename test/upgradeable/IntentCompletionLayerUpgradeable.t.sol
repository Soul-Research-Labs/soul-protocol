// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../../contracts/upgradeable/IntentCompletionLayerUpgradeable.sol";
import "../../contracts/interfaces/IProofVerifier.sol";

/**
 * @title MockIntentVerifier
 * @notice Minimal mock for IProofVerifier used by IntentCompletionLayerUpgradeable.
 */
contract MockIntentVerifier is IProofVerifier {
    bool public shouldPass = true;

    function setShouldPass(bool val) external {
        shouldPass = val;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external view override returns (bool) {
        return shouldPass;
    }
}

/**
 * @title IntentCompletionLayerUpgradeable Test
 * @notice Tests proxy init, solver registration, intent lifecycle,
 *         role enforcement, UUPS upgrade, and storage preservation.
 */
contract IntentCompletionLayerUpgradeableTest is Test {
    IntentCompletionLayerUpgradeable public layer;
    IntentCompletionLayerUpgradeable public implementation;
    MockIntentVerifier public verifier;
    ERC1967Proxy public proxy;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");
    address public emergency = makeAddr("emergency");
    address public upgrader = makeAddr("upgrader");
    address public solver = makeAddr("solver");
    address public intentUser = makeAddr("intentUser");

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    uint256 public constant MIN_SOLVER_STAKE = 1 ether;

    function setUp() public {
        // Deploy mock verifier
        verifier = new MockIntentVerifier();

        // Deploy implementation
        implementation = new IntentCompletionLayerUpgradeable();

        // Encode initializer
        bytes memory initData = abi.encodeCall(
            IntentCompletionLayerUpgradeable.initialize,
            (admin, address(verifier))
        );

        // Deploy proxy
        proxy = new ERC1967Proxy(address(implementation), initData);
        layer = IntentCompletionLayerUpgradeable(address(proxy));

        // Grant roles
        vm.startPrank(admin);
        layer.grantRole(OPERATOR_ROLE, operator);
        layer.grantRole(EMERGENCY_ROLE, emergency);
        layer.grantRole(UPGRADER_ROLE, upgrader);
        vm.stopPrank();

        // Fund actors
        vm.deal(solver, 100 ether);
        vm.deal(intentUser, 100 ether);

        // Enable supported chains
        vm.startPrank(operator);
        layer.setSupportedChain(1, true); // Ethereum
        layer.setSupportedChain(42161, true); // Arbitrum
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────────────────────
    // Initialization
    // ──────────────────────────────────────────────────────────────

    function test_initialization() public view {
        assertTrue(layer.hasRole(layer.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(layer.hasRole(OPERATOR_ROLE, admin));
        assertTrue(layer.hasRole(EMERGENCY_ROLE, admin));
        assertTrue(layer.hasRole(UPGRADER_ROLE, admin));
    }

    function test_cannotReinitialize() public {
        vm.expectRevert();
        layer.initialize(admin, address(verifier));
    }

    // ──────────────────────────────────────────────────────────────
    // Solver Registration
    // ──────────────────────────────────────────────────────────────

    function test_registerSolver() public {
        vm.prank(solver);
        layer.registerSolver{value: MIN_SOLVER_STAKE}();
    }

    function test_registerSolver_insufficientStake_reverts() public {
        vm.prank(solver);
        vm.expectRevert();
        layer.registerSolver{value: 0.5 ether}();
    }

    function test_registerSolver_duplicate_reverts() public {
        vm.startPrank(solver);
        layer.registerSolver{value: MIN_SOLVER_STAKE}();
        vm.expectRevert();
        layer.registerSolver{value: MIN_SOLVER_STAKE}();
        vm.stopPrank();
    }

    // ──────────────────────────────────────────────────────────────
    // Submit Intent
    // ──────────────────────────────────────────────────────────────

    function test_submitIntent() public {
        uint256 fee = 0.1 ether;
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(intentUser);
        layer.submitIntent{value: fee}(
            1, // sourceChainId
            42161, // destChainId
            keccak256("commitment"),
            keccak256("desiredState"),
            fee,
            deadline,
            keccak256("policy")
        );
    }

    function test_submitIntent_unsupportedChain_reverts() public {
        uint256 deadline = block.timestamp + 1 hours;

        vm.prank(intentUser);
        vm.expectRevert();
        layer.submitIntent{value: 0.1 ether}(
            1,
            99999, // unsupported
            keccak256("c"),
            keccak256("d"),
            0.1 ether,
            deadline,
            keccak256("p")
        );
    }

    function test_submitIntent_expiredDeadline_reverts() public {
        vm.prank(intentUser);
        vm.expectRevert();
        layer.submitIntent{value: 0.1 ether}(
            1,
            42161,
            keccak256("c"),
            keccak256("d"),
            0.1 ether,
            block.timestamp - 1, // past deadline
            keccak256("p")
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Pause / Unpause
    // ──────────────────────────────────────────────────────────────

    function test_emergencyCanPause() public {
        vm.prank(emergency);
        layer.pause();
        assertTrue(layer.paused());
    }

    function test_emergencyCanUnpause() public {
        vm.prank(emergency);
        layer.pause();

        vm.prank(emergency);
        layer.unpause();
        assertFalse(layer.paused());
    }

    function test_nonEmergencyCannotPause() public {
        vm.prank(solver);
        vm.expectRevert();
        layer.pause();
    }

    // ──────────────────────────────────────────────────────────────
    // Set Supported Chain
    // ──────────────────────────────────────────────────────────────

    function test_setSupportedChain() public {
        vm.prank(operator);
        layer.setSupportedChain(10, true); // Optimism
    }

    function test_setSupportedChain_nonOperator_reverts() public {
        vm.prank(solver);
        vm.expectRevert();
        layer.setSupportedChain(10, true);
    }

    // ──────────────────────────────────────────────────────────────
    // Set Intent Verifier
    // ──────────────────────────────────────────────────────────────

    function test_setIntentVerifier() public {
        MockIntentVerifier newVerifier = new MockIntentVerifier();

        vm.prank(operator);
        layer.setIntentVerifier(address(newVerifier));
    }

    function test_setIntentVerifier_nonOperator_reverts() public {
        vm.prank(solver);
        vm.expectRevert();
        layer.setIntentVerifier(address(verifier));
    }

    // ──────────────────────────────────────────────────────────────
    // UUPS Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_upgradeByUpgrader() public {
        IntentCompletionLayerUpgradeable newImpl = new IntentCompletionLayerUpgradeable();

        vm.prank(upgrader);
        layer.upgradeToAndCall(address(newImpl), "");
    }

    function test_upgradeByNonUpgrader_reverts() public {
        IntentCompletionLayerUpgradeable newImpl = new IntentCompletionLayerUpgradeable();

        vm.prank(solver);
        vm.expectRevert();
        layer.upgradeToAndCall(address(newImpl), "");
    }

    // ──────────────────────────────────────────────────────────────
    // Storage Preservation After Upgrade
    // ──────────────────────────────────────────────────────────────

    function test_storagePreservedAfterUpgrade() public {
        // Register solver before upgrade
        vm.prank(solver);
        layer.registerSolver{value: MIN_SOLVER_STAKE}();

        // Upgrade
        IntentCompletionLayerUpgradeable newImpl = new IntentCompletionLayerUpgradeable();
        vm.prank(upgrader);
        layer.upgradeToAndCall(address(newImpl), "");

        // Verify roles preserved
        assertTrue(layer.hasRole(OPERATOR_ROLE, operator));
        assertTrue(layer.hasRole(EMERGENCY_ROLE, emergency));
    }
}
