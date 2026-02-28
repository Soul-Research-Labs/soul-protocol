// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CrossChainProofHubV3Upgradeable} from "../../contracts/upgradeable/CrossChainProofHubV3Upgradeable.sol";
import {ZaseonAtomicSwapV2Upgradeable} from "../../contracts/upgradeable/ZaseonAtomicSwapV2Upgradeable.sol";
import {NullifierRegistryV3Upgradeable} from "../../contracts/upgradeable/NullifierRegistryV3Upgradeable.sol";
import {ConfidentialStateContainerV3Upgradeable} from "../../contracts/upgradeable/ConfidentialStateContainerV3Upgradeable.sol";

/**
 * @title StorageCollisionAndSecurityModuleTest
 * @notice Tests that:
 *   1. SecurityModule defaults are properly initialized through proxies
 *   2. Storage gaps are maintained correctly
 *   3. State survives upgrades without slot drift
 *   4. SecurityModule modifiers are functional through proxy
 *
 * @dev SecurityModule uses Solidity field initializers (e.g., `uint8 _securityFlags = 0x1B`).
 *      These only execute in the implementation constructor, NOT through a proxy.
 *      The `__initSecurityModule()` function must be called in `initialize()` to set defaults.
 */
contract StorageCollisionAndSecurityModuleTest is Test {
    address public admin;
    address public feeRecipient;

    CrossChainProofHubV3Upgradeable public hubProxy;
    ZaseonAtomicSwapV2Upgradeable public swapProxy;

    function setUp() public {
        admin = makeAddr("admin");
        feeRecipient = makeAddr("feeRecipient");
        vm.deal(admin, 100 ether);

        // Deploy CrossChainProofHubV3Upgradeable behind proxy
        CrossChainProofHubV3Upgradeable hubImpl = new CrossChainProofHubV3Upgradeable();
        bytes memory hubInit = abi.encodeWithSelector(
            CrossChainProofHubV3Upgradeable.initialize.selector,
            admin
        );
        ERC1967Proxy hubErc = new ERC1967Proxy(address(hubImpl), hubInit);
        hubProxy = CrossChainProofHubV3Upgradeable(payable(address(hubErc)));

        // Deploy ZaseonAtomicSwapV2Upgradeable behind proxy
        ZaseonAtomicSwapV2Upgradeable swapImpl = new ZaseonAtomicSwapV2Upgradeable();
        bytes memory swapInit = abi.encodeWithSelector(
            ZaseonAtomicSwapV2Upgradeable.initialize.selector,
            admin,
            feeRecipient
        );
        ERC1967Proxy swapErc = new ERC1967Proxy(address(swapImpl), swapInit);
        swapProxy = ZaseonAtomicSwapV2Upgradeable(payable(address(swapErc)));
    }

    /*//////////////////////////////////////////////////////////////
         SecurityModule Defaults Through Proxy — ProofHub
    //////////////////////////////////////////////////////////////*/

    function test_hub_securityFlags_initialized() public view {
        assertTrue(
            hubProxy.rateLimitingEnabled(),
            "Rate limiting should be enabled"
        );
        assertTrue(
            hubProxy.circuitBreakerEnabled(),
            "Circuit breaker should be enabled"
        );
        assertTrue(
            hubProxy.flashLoanGuardEnabled(),
            "Flash loan guard should be enabled"
        );
        assertTrue(
            hubProxy.withdrawalLimitsEnabled(),
            "Withdrawal limits should be enabled"
        );
        assertFalse(
            hubProxy.circuitBreakerTripped(),
            "Circuit breaker should NOT be tripped"
        );
    }

    function test_hub_rateLimitDefaults() public view {
        assertEq(
            hubProxy.rateLimitWindow(),
            1 hours,
            "Rate limit window should be 1 hour"
        );
        assertEq(
            hubProxy.maxActionsPerWindow(),
            50,
            "Max actions should be 50"
        );
    }

    function test_hub_circuitBreakerDefaults() public view {
        assertEq(
            hubProxy.volumeThreshold(),
            10_000_000 * 1e18,
            "Volume threshold should be 10M"
        );
        assertEq(
            hubProxy.circuitBreakerCooldown(),
            1 hours,
            "Cooldown should be 1 hour"
        );
    }

    function test_hub_flashLoanGuardDefaults() public view {
        assertEq(
            hubProxy.minBlocksForWithdrawal(),
            1,
            "Min blocks for withdrawal should be 1"
        );
    }

    function test_hub_withdrawalLimitDefaults() public view {
        assertEq(
            hubProxy.maxSingleWithdrawal(),
            100_000 * 1e18,
            "Max single withdrawal should be 100K"
        );
        assertEq(
            hubProxy.maxDailyWithdrawal(),
            1_000_000 * 1e18,
            "Max daily withdrawal should be 1M"
        );
        assertEq(
            hubProxy.accountMaxDailyWithdrawal(),
            100_000 * 1e18,
            "Account max daily should be 100K"
        );
    }

    /*//////////////////////////////////////////////////////////////
        SecurityModule Defaults Through Proxy — AtomicSwap
    //////////////////////////////////////////////////////////////*/

    function test_swap_securityFlags_initialized() public view {
        assertTrue(
            swapProxy.rateLimitingEnabled(),
            "Rate limiting should be enabled"
        );
        assertTrue(
            swapProxy.circuitBreakerEnabled(),
            "Circuit breaker should be enabled"
        );
        assertTrue(
            swapProxy.flashLoanGuardEnabled(),
            "Flash loan guard should be enabled"
        );
        assertTrue(
            swapProxy.withdrawalLimitsEnabled(),
            "Withdrawal limits should be enabled"
        );
        assertFalse(
            swapProxy.circuitBreakerTripped(),
            "Circuit breaker should NOT be tripped"
        );
    }

    function test_swap_rateLimitDefaults() public view {
        assertEq(
            swapProxy.rateLimitWindow(),
            1 hours,
            "Rate limit window should be 1 hour"
        );
        assertEq(
            swapProxy.maxActionsPerWindow(),
            50,
            "Max actions should be 50"
        );
    }

    function test_swap_withdrawalLimitDefaults() public view {
        assertEq(
            swapProxy.maxSingleWithdrawal(),
            100_000 * 1e18,
            "Max single withdrawal should be 100K"
        );
        assertEq(
            swapProxy.maxDailyWithdrawal(),
            1_000_000 * 1e18,
            "Max daily withdrawal should be 1M"
        );
    }

    /*//////////////////////////////////////////////////////////////
              Proxy Hub-Specific State Preservation
    //////////////////////////////////////////////////////////////*/

    function test_hub_proxyStatePreservesAfterUpgrade() public {
        // Verify initial state
        assertEq(hubProxy.contractVersion(), 1);
        assertEq(hubProxy.challengePeriod(), 1 hours);
        assertTrue(hubProxy.supportedChains(block.chainid));

        // Perform upgrade (deploy a new implementation, upgrade via UUPS)
        CrossChainProofHubV3Upgradeable newImpl = new CrossChainProofHubV3Upgradeable();
        vm.prank(admin);
        hubProxy.upgradeToAndCall(address(newImpl), "");

        // State must survive
        assertEq(hubProxy.contractVersion(), 2, "Version should bump to 2");
        assertEq(
            hubProxy.challengePeriod(),
            1 hours,
            "Challenge period must survive upgrade"
        );
        assertTrue(
            hubProxy.supportedChains(block.chainid),
            "Supported chain must survive"
        );

        // SecurityModule state must also survive
        assertTrue(
            hubProxy.rateLimitingEnabled(),
            "Rate limiting survives upgrade"
        );
        assertEq(
            hubProxy.rateLimitWindow(),
            1 hours,
            "Rate limit window survives upgrade"
        );
        assertEq(
            hubProxy.volumeThreshold(),
            10_000_000 * 1e18,
            "Volume threshold survives upgrade"
        );
    }

    function test_swap_proxyStatePreservesAfterUpgrade() public {
        // Verify initial state
        assertEq(swapProxy.contractVersion(), 1);
        assertEq(swapProxy.protocolFeeBps(), 10);
        assertEq(swapProxy.feeRecipient(), feeRecipient);

        // Upgrade
        ZaseonAtomicSwapV2Upgradeable newImpl = new ZaseonAtomicSwapV2Upgradeable();
        vm.prank(admin);
        swapProxy.upgradeToAndCall(address(newImpl), "");

        // State must survive
        assertEq(swapProxy.contractVersion(), 2, "Version should bump to 2");
        assertEq(swapProxy.protocolFeeBps(), 10, "Fee BPS must survive");
        assertEq(
            swapProxy.feeRecipient(),
            feeRecipient,
            "Fee recipient must survive"
        );

        // SecurityModule state must also survive
        assertTrue(
            swapProxy.rateLimitingEnabled(),
            "Rate limiting survives upgrade"
        );
        assertEq(
            swapProxy.maxSingleWithdrawal(),
            100_000 * 1e18,
            "Withdrawal limit survives"
        );
    }

    /*//////////////////////////////////////////////////////////////
          Implementation Cannot Be Re-initialized
    //////////////////////////////////////////////////////////////*/

    function test_hub_implementationCannotBeReinitialized() public {
        // Deploy raw implementation (not behind proxy)
        CrossChainProofHubV3Upgradeable impl = new CrossChainProofHubV3Upgradeable();

        // Should revert because constructor calls _disableInitializers()
        vm.expectRevert();
        impl.initialize(admin);
    }

    function test_swap_implementationCannotBeReinitialized() public {
        ZaseonAtomicSwapV2Upgradeable impl = new ZaseonAtomicSwapV2Upgradeable();

        vm.expectRevert();
        impl.initialize(admin, feeRecipient);
    }

    /*//////////////////////////////////////////////////////////////
         Proxy Cannot Be Double-Initialized
    //////////////////////////////////////////////////////////////*/

    function test_hub_proxyCannotDoubleInitialize() public {
        vm.expectRevert();
        hubProxy.initialize(address(0xdead));
    }

    function test_swap_proxyCannotDoubleInitialize() public {
        vm.expectRevert();
        swapProxy.initialize(address(0xdead), address(0xbeef));
    }

    /*//////////////////////////////////////////////////////////////
          Gap Size Validation (Storage Layout Safety)
    //////////////////////////////////////////////////////////////*/

    function test_hub_gapSlotAccessible() public view {
        // Read past all declared storage into the __gap region
        // If the gap was removed or undersized, this would read into
        // a different contract's storage
        bytes32 gapSlot = vm.load(
            address(hubProxy),
            bytes32(uint256(500)) // Far into storage — should be 0 if gap is intact
        );
        assertEq(gapSlot, bytes32(0), "Gap region should be zeroed");
    }

    /*//////////////////////////////////////////////////////////////
          NullifierRegistry Proxy Initialization
    //////////////////////////////////////////////////////////////*/

    function test_nullifier_proxyInitialization() public {
        NullifierRegistryV3Upgradeable impl = new NullifierRegistryV3Upgradeable();
        bytes memory initData = abi.encodeWithSelector(
            NullifierRegistryV3Upgradeable.initialize.selector,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        NullifierRegistryV3Upgradeable reg = NullifierRegistryV3Upgradeable(
            address(proxy)
        );

        assertTrue(
            reg.hasRole(reg.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role granted"
        );
        assertEq(reg.contractVersion(), 1, "Version should be 1");
    }

    function test_nullifier_proxyUpgradePreservesState() public {
        NullifierRegistryV3Upgradeable impl = new NullifierRegistryV3Upgradeable();
        bytes memory initData = abi.encodeWithSelector(
            NullifierRegistryV3Upgradeable.initialize.selector,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        NullifierRegistryV3Upgradeable reg = NullifierRegistryV3Upgradeable(
            address(proxy)
        );

        // Register a nullifier
        bytes32 registrarRole = keccak256("REGISTRAR_ROLE");
        vm.startPrank(admin);
        reg.grantRole(registrarRole, admin);
        reg.registerNullifier(bytes32(uint256(42)), bytes32(uint256(99)));
        vm.stopPrank();

        assertTrue(
            reg.isNullifierUsed(bytes32(uint256(42))),
            "Nullifier registered"
        );

        // Upgrade
        NullifierRegistryV3Upgradeable newImpl = new NullifierRegistryV3Upgradeable();
        vm.prank(admin);
        reg.upgradeToAndCall(address(newImpl), "");

        // State must survive
        assertEq(reg.contractVersion(), 2, "Version bumped");
        assertTrue(
            reg.isNullifierUsed(bytes32(uint256(42))),
            "Nullifier survives upgrade"
        );
    }

    /*//////////////////////////////////////////////////////////////
          ConfidentialStateContainer Proxy Tests
    //////////////////////////////////////////////////////////////*/

    function test_csc_proxyInitializationAndUpgrade() public {
        ConfidentialStateContainerV3Upgradeable impl = new ConfidentialStateContainerV3Upgradeable();
        address verifier = makeAddr("verifier");
        bytes memory initData = abi.encodeWithSelector(
            ConfidentialStateContainerV3Upgradeable.initialize.selector,
            admin,
            verifier
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        ConfidentialStateContainerV3Upgradeable csc = ConfidentialStateContainerV3Upgradeable(
                address(proxy)
            );

        assertTrue(csc.hasRole(csc.DEFAULT_ADMIN_ROLE(), admin), "Admin role");
        assertEq(csc.contractVersion(), 1, "Version 1");

        // Upgrade
        ConfidentialStateContainerV3Upgradeable newImpl = new ConfidentialStateContainerV3Upgradeable();
        vm.prank(admin);
        csc.upgradeToAndCall(address(newImpl), "");
        assertEq(csc.contractVersion(), 2, "Version bumped to 2");
    }

    /*//////////////////////////////////////////////////////////////
          EIP-1967 Implementation Slot Consistency
    //////////////////////////////////////////////////////////////*/

    function test_eip1967_implementationSlotIsSet() public view {
        // EIP-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
        bytes32 slot = bytes32(
            uint256(keccak256("eip1967.proxy.implementation")) - 1
        );
        bytes32 implAddr = vm.load(address(hubProxy), slot);
        assertTrue(implAddr != bytes32(0), "Implementation slot should be set");
    }

    /*//////////////////////////////////////////////////////////////
          Cross-Contract Storage Isolation
    //////////////////////////////////////////////////////////////*/

    function test_hub_storageDoesNotLeakToSwap() public {
        // Each proxy has independent storage; writing to hub must not affect swap
        vm.prank(admin);
        hubProxy.setChallengePeriod(2 hours);

        // Swap should still have its own independent state
        assertEq(
            swapProxy.protocolFeeBps(),
            10,
            "Swap state unaffected by hub write"
        );
        assertTrue(
            swapProxy.rateLimitingEnabled(),
            "Swap security flags unaffected"
        );
    }
}
