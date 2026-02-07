// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CrossChainSanctionsOracle} from "../../contracts/compliance/CrossChainSanctionsOracle.sol";

/**
 * @title CrossChainSanctionsOracleTest
 * @notice Comprehensive tests for the Cross-Chain Sanctions Oracle
 */
contract CrossChainSanctionsOracleTest is Test {
    CrossChainSanctionsOracle public oracle;

    address public admin = makeAddr("admin");
    address public providerA = makeAddr("providerA");
    address public providerB = makeAddr("providerB");
    address public providerC = makeAddr("providerC");
    address public suspectAddr = makeAddr("suspect");
    address public cleanAddr = makeAddr("clean");

    bytes32 public constant PROVIDER_ROLE =
        0xa523ebb80e7d3e9cd50c5f2c39f7eba5d0a66cdaad76bd8ad5e94f3f1bfe4803;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    function setUp() public {
        vm.startPrank(admin);
        oracle = new CrossChainSanctionsOracle(admin, 1);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializeCorrectly() public view {
        assertTrue(oracle.failOpen(), "Should default to fail-open");
        assertEq(oracle.sanctionsExpiry(), 90 days, "Default 90-day expiry");
        assertEq(oracle.quorumThreshold(), 1, "Default quorum = 1");
    }

    /*//////////////////////////////////////////////////////////////
                      PROVIDER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterProvider() public {
        vm.prank(admin);
        oracle.registerProvider(providerA, "Chainalysis", 100);

        (address addr, , uint256 weight, bool active, ) = oracle.providers(
            providerA
        );
        assertEq(addr, providerA);
        assertEq(weight, 100);
        assertTrue(active);
    }

    function test_RevertRegisterDuplicateProvider() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Chainalysis", 100);

        vm.expectRevert(
            abi.encodeWithSelector(
                CrossChainSanctionsOracle.ProviderAlreadyRegistered.selector
            )
        );
        oracle.registerProvider(providerA, "Duplicate", 50);
        vm.stopPrank();
    }

    function test_DeactivateProvider() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        oracle.deactivateProvider(providerA);
        vm.stopPrank();

        (, , , bool active, ) = oracle.providers(providerA);
        assertFalse(active, "Provider should be deactivated");
    }

    /*//////////////////////////////////////////////////////////////
                     SANCTIONS SCREENING
    //////////////////////////////////////////////////////////////*/

    function test_FlagAddress() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        vm.prank(providerA);
        oracle.flagAddress(suspectAddr, keccak256("OFAC"));

        assertTrue(
            oracle.isSanctioned(suspectAddr),
            "Address should be sanctioned"
        );
    }

    function test_UnflaggedAddressIsClean() public view {
        assertFalse(
            oracle.isSanctioned(cleanAddr),
            "Clean address should not be sanctioned"
        );
    }

    function test_QuorumRequiresMultipleProviders() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Chainalysis", 50);
        oracle.registerProvider(providerB, "Elliptic", 50);
        oracle.setQuorumThreshold(100); // Both must flag
        vm.stopPrank();

        // Only one provider flags
        vm.prank(providerA);
        oracle.flagAddress(suspectAddr, keccak256("OFAC"));

        assertFalse(
            oracle.isSanctioned(suspectAddr),
            "Single flag below quorum should not sanction"
        );

        // Second provider flags
        vm.prank(providerB);
        oracle.flagAddress(suspectAddr, keccak256("EU-SANCTIONS"));

        assertTrue(
            oracle.isSanctioned(suspectAddr),
            "Both flags should meet quorum"
        );
    }

    function test_ClearAddress() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        vm.prank(providerA);
        oracle.flagAddress(suspectAddr, keccak256("OFAC"));

        assertTrue(oracle.isSanctioned(suspectAddr));

        vm.prank(admin);
        oracle.clearAddress(suspectAddr);

        assertFalse(
            oracle.isSanctioned(suspectAddr),
            "Cleared address should not be sanctioned"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        SANCTIONS EXPIRY
    //////////////////////////////////////////////////////////////*/

    function test_SanctionsExpireAfterTimeout() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        vm.prank(providerA);
        oracle.flagAddress(suspectAddr, keccak256("OFAC"));

        assertTrue(oracle.isSanctioned(suspectAddr));

        // Advance past expiry
        vm.warp(block.timestamp + 91 days);

        assertFalse(
            oracle.isSanctioned(suspectAddr),
            "Sanctions should expire after 90 days"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        FAIL-OPEN / FAIL-CLOSED
    //////////////////////////////////////////////////////////////*/

    function test_FailOpenMode() public view {
        // With fail-open and no providers, should consider address clean
        assertFalse(oracle.isSanctioned(suspectAddr));
    }

    function test_FailClosedMode() public {
        vm.startPrank(admin);
        oracle.setFailOpen(false);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        // With fail-closed, unflagged address should still pass if no error
        assertFalse(oracle.isSanctioned(cleanAddr));
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH SCREENING
    //////////////////////////////////////////////////////////////*/

    function test_BatchScreen() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        vm.prank(providerA);
        oracle.flagAddress(suspectAddr, keccak256("OFAC"));

        address[] memory addrs = new address[](3);
        addrs[0] = cleanAddr;
        addrs[1] = suspectAddr;
        addrs[2] = makeAddr("another_clean");

        bool[] memory results = oracle.batchScreen(addrs);

        assertFalse(results[0], "Clean address should pass");
        assertTrue(results[1], "Suspect should be flagged");
        assertFalse(results[2], "Another clean should pass");
    }

    /*//////////////////////////////////////////////////////////////
                        STATUS QUERY
    //////////////////////////////////////////////////////////////*/

    function test_GetSanctionsStatus() public {
        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        vm.prank(providerA);
        oracle.flagAddress(suspectAddr, keccak256("OFAC"));

        (bool flagged, uint256 flagCount, uint256 lastUpdated) = oracle
            .getSanctionsStatus(suspectAddr);
        assertTrue(flagged, "Should be flagged");
        assertEq(flagCount, 1, "One provider flagged");
        assertEq(lastUpdated, block.timestamp, "Updated this block");
    }

    /*//////////////////////////////////////////////////////////////
                       ADMIN CONTROLS
    //////////////////////////////////////////////////////////////*/

    function test_SetQuorumThreshold() public {
        vm.prank(admin);
        oracle.setQuorumThreshold(200);
        assertEq(oracle.quorumThreshold(), 200);
    }

    function test_SetSanctionsExpiry() public {
        vm.prank(admin);
        oracle.setSanctionsExpiry(180 days);
        assertEq(oracle.sanctionsExpiry(), 180 days);
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_FlagAndScreenConsistent(address addr) public {
        vm.assume(addr != address(0));

        vm.startPrank(admin);
        oracle.registerProvider(providerA, "Provider", 100);
        vm.stopPrank();

        assertFalse(
            oracle.isSanctioned(addr),
            "Should be clean before flagging"
        );

        vm.prank(providerA);
        oracle.flagAddress(addr, keccak256("TEST"));

        assertTrue(
            oracle.isSanctioned(addr),
            "Should be sanctioned after flagging"
        );
    }
}
