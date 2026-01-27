// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/crosschain/ArbitrumBridgeAdapter.sol";
import "../../contracts/crosschain/AztecBridgeAdapter.sol";

/**
 * @title SoulNewL2BridgeFuzz
 * @notice Fuzz tests for Arbitrum and Aztec bridge adapters
 * @dev Tests cross-domain messaging, proof relay, and security invariants
 *      Updated to focus on Arbitrum and Aztec after L2 consolidation
 *
 * Run with: forge test --match-contract SoulNewL2BridgeFuzz --fuzz-runs 10000
 */
contract SoulNewL2BridgeFuzz is Test {
    /*//////////////////////////////////////////////////////////////
                            CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 constant MIN_GAS_LIMIT = 100000;
    uint256 constant MAX_GAS_LIMIT = 30000000;

    // Chain IDs
    uint256 constant ARB_ONE = 42161;
    uint256 constant ARB_NOVA = 42170;

    /*//////////////////////////////////////////////////////////////
                              CONTRACTS
    //////////////////////////////////////////////////////////////*/

    ArbitrumBridgeAdapter public arbitrumL1Adapter;
    ArbitrumBridgeAdapter public arbitrumL2Adapter;
    AztecBridgeAdapter public aztecAdapter;

    address public admin = address(0x1);
    address public operator = address(0x2);
    address public relayer = address(0x3);
    address public user = address(0x4);
    address public mockMessenger = address(0x5);
    address public mockBridge = address(0x6);
    address public mockTarget = address(0x7);

    // Role constants
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        vm.startPrank(admin);

        // Deploy Arbitrum adapters
        arbitrumL1Adapter = new ArbitrumBridgeAdapter(admin);
        arbitrumL1Adapter.grantRole(OPERATOR_ROLE, operator);

        arbitrumL2Adapter = new ArbitrumBridgeAdapter(admin);

        // Deploy Aztec adapter (only takes admin address)
        aztecAdapter = new AztecBridgeAdapter(admin);
        aztecAdapter.grantRole(OPERATOR_ROLE, operator);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        ARBITRUM FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_ArbitrumChainIdConstants(uint256 chainId) public view {
        assertEq(arbitrumL1Adapter.ARB_ONE_CHAIN_ID(), ARB_ONE);
        assertEq(arbitrumL1Adapter.ARB_NOVA_CHAIN_ID(), ARB_NOVA);
    }

    function testFuzz_ArbitrumPauseUnpause(
        bool shouldPause,
        bool useL1
    ) public {
        ArbitrumBridgeAdapter adapter = useL1
            ? arbitrumL1Adapter
            : arbitrumL2Adapter;

        vm.startPrank(admin);
        adapter.grantRole(GUARDIAN_ROLE, admin);

        if (shouldPause) {
            adapter.pause();
            assertTrue(adapter.paused());
            adapter.unpause();
        }

        assertFalse(adapter.paused());
        vm.stopPrank();
    }

    function testFuzz_ArbitrumConfigureBridgeFee(uint256 fee) public {
        // Fee should be reasonable (0-100 = 0-1%, max allowed by contract)
        fee = bound(fee, 0, 100);

        vm.prank(admin);
        arbitrumL1Adapter.setBridgeFee(fee);

        assertEq(arbitrumL1Adapter.bridgeFee(), fee);
    }

    function testFuzz_ArbitrumConfigureTreasury(address treasuryAddress) public {
        vm.assume(treasuryAddress != address(0));

        vm.prank(admin);
        arbitrumL1Adapter.setTreasury(treasuryAddress);

        assertEq(arbitrumL1Adapter.treasury(), treasuryAddress);
    }

    function testFuzz_ArbitrumFastExitToggle(bool enable) public {
        vm.prank(admin);
        arbitrumL1Adapter.setFastExitEnabled(enable);

        assertEq(arbitrumL1Adapter.fastExitEnabled(), enable);
    }

    /*//////////////////////////////////////////////////////////////
                        AZTEC FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_AztecPauseUnpause(bool shouldPause) public {
        vm.startPrank(admin);
        aztecAdapter.grantRole(PAUSER_ROLE, admin);

        if (shouldPause) {
            aztecAdapter.pause();
            assertTrue(aztecAdapter.paused());
            aztecAdapter.unpause();
        }

        assertFalse(aztecAdapter.paused());
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    CROSS-ADAPTER INVARIANTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_AllAdaptersPauseIndependently(
        bool pauseArbitrumL1,
        bool pauseArbitrumL2,
        bool pauseAztec
    ) public {
        vm.startPrank(admin);

        // Grant pause roles
        arbitrumL1Adapter.grantRole(GUARDIAN_ROLE, admin);
        arbitrumL2Adapter.grantRole(GUARDIAN_ROLE, admin);
        aztecAdapter.grantRole(PAUSER_ROLE, admin);

        // Pause/unpause each adapter independently
        if (pauseArbitrumL1) arbitrumL1Adapter.pause();
        if (pauseArbitrumL2) arbitrumL2Adapter.pause();
        if (pauseAztec) aztecAdapter.pause();

        // Verify independent state
        assertEq(arbitrumL1Adapter.paused(), pauseArbitrumL1);
        assertEq(arbitrumL2Adapter.paused(), pauseArbitrumL2);
        assertEq(aztecAdapter.paused(), pauseAztec);

        vm.stopPrank();
    }

    function testFuzz_ConfigurationIntegrity(
        uint256 arbitrumFee,
        address arbitrumTreasury
    ) public {
        // Filter out zero addresses
        vm.assume(arbitrumTreasury != address(0));
        arbitrumFee = bound(arbitrumFee, 0, 100); // Max 1% fee (contract limit)

        // Configure adapters
        vm.startPrank(admin);
        arbitrumL1Adapter.setBridgeFee(arbitrumFee);
        arbitrumL1Adapter.setTreasury(arbitrumTreasury);
        vm.stopPrank();

        // Verify configurations
        assertEq(arbitrumL1Adapter.bridgeFee(), arbitrumFee);
        assertEq(arbitrumL1Adapter.treasury(), arbitrumTreasury);
    }

    /*//////////////////////////////////////////////////////////////
                        ACCESS CONTROL FUZZ
    //////////////////////////////////////////////////////////////*/

    function testFuzz_UnauthorizedCannotPause(address attacker) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != operator);
        vm.assume(attacker != relayer);

        vm.prank(attacker);
        vm.expectRevert();
        arbitrumL1Adapter.pause();
    }

    function testFuzz_UnauthorizedCannotConfigureFees(
        address attacker,
        uint256 fee
    ) public {
        vm.assume(attacker != admin);
        vm.assume(attacker != operator);

        vm.prank(attacker);
        vm.expectRevert();
        arbitrumL1Adapter.setBridgeFee(fee);
    }

    function testFuzz_RoleGrantRevoke(
        address grantee,
        bool grantThenRevoke
    ) public {
        vm.assume(grantee != address(0));
        vm.assume(grantee != admin);

        vm.startPrank(admin);

        // Grant role
        arbitrumL1Adapter.grantRole(OPERATOR_ROLE, grantee);
        assertTrue(arbitrumL1Adapter.hasRole(OPERATOR_ROLE, grantee));

        if (grantThenRevoke) {
            arbitrumL1Adapter.revokeRole(OPERATOR_ROLE, grantee);
            assertFalse(arbitrumL1Adapter.hasRole(OPERATOR_ROLE, grantee));
        }

        vm.stopPrank();
    }
}
