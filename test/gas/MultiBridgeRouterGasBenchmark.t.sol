// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MultiBridgeRouter} from "../../contracts/bridge/MultiBridgeRouter.sol";
import {IMultiBridgeRouter} from "../../contracts/interfaces/IMultiBridgeRouter.sol";
import {IBridgeAdapter} from "../../contracts/crosschain/IBridgeAdapter.sol";

/// @dev Minimal mock bridge adapter implementing IBridgeAdapter for gas measurement
contract GasMockBridgeAdapter is IBridgeAdapter {
    function bridgeMessage(
        address,
        bytes calldata,
        address
    ) external payable override returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp));
    }

    function estimateFee(
        address,
        bytes calldata
    ) external pure override returns (uint256) {
        return 0.001 ether;
    }

    function isMessageVerified(bytes32) external pure override returns (bool) {
        return true;
    }
}

/**
 * @title MultiBridgeRouterGasBenchmark
 * @notice Gas benchmarks for MultiBridgeRouter operations
 *
 * TARGET BUDGETS:
 * - routeMessage (single bridge):  < 200,000 gas
 * - routeMessage (with failover):  < 300,000 gas
 * - verifyMessage:                 < 100,000 gas
 * - registerAdapter:               < 150,000 gas
 */
contract MultiBridgeRouterGasBenchmark is Test {
    MultiBridgeRouter public router;
    GasMockBridgeAdapter public nativeAdapter;
    GasMockBridgeAdapter public lzAdapter;
    GasMockBridgeAdapter public hyperlaneAdapter;

    address public admin = makeAddr("admin");
    uint256 public constant ARBITRUM = 42161;

    bytes32 public constant BRIDGE_ADMIN = keccak256("BRIDGE_ADMIN");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    function setUp() public {
        vm.startPrank(admin);

        router = new MultiBridgeRouter(admin);
        nativeAdapter = new GasMockBridgeAdapter();
        lzAdapter = new GasMockBridgeAdapter();
        hyperlaneAdapter = new GasMockBridgeAdapter();

        // Register three bridge adapters
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            address(nativeAdapter),
            95,
            1000 ether
        );
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            address(lzAdapter),
            80,
            500 ether
        );
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.HYPERLANE,
            address(hyperlaneAdapter),
            70,
            500 ether
        );

        // Add chain support
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            ARBITRUM
        );
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            ARBITRUM
        );
        router.addSupportedChain(
            IMultiBridgeRouter.BridgeType.HYPERLANE,
            ARBITRUM
        );

        // Set chain target for destination chain
        router.setChainTarget(ARBITRUM, makeAddr("arbitrumHub"));

        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: registerAdapter
    // ─────────────────────────────────────────────────────────────

    function test_gas_RegisterAdapter() public {
        GasMockBridgeAdapter newAdapter = new GasMockBridgeAdapter();

        vm.prank(admin);
        uint256 gasBefore = gasleft();
        router.registerAdapter(
            IMultiBridgeRouter.BridgeType.CHAINLINK_CCIP,
            address(newAdapter),
            85,
            800 ether
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("registerAdapter gas", gasUsed);
        assertLt(gasUsed, 150_000, "registerAdapter should be < 150k gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: routeMessage (single bridge, low value)
    // ─────────────────────────────────────────────────────────────

    function test_gas_RouteMessage_LowValue() public {
        bytes memory message = abi.encodePacked("gas-benchmark-payload");

        uint256 gasBefore = gasleft();
        router.routeMessage(ARBITRUM, message, 1 ether);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("routeMessage(lowValue) gas", gasUsed);
        assertLt(
            gasUsed,
            200_000,
            "routeMessage(lowValue) should be < 200k gas"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: routeMessage (high value — triggers multi-verification)
    // ─────────────────────────────────────────────────────────────

    function test_gas_RouteMessage_HighValue() public {
        bytes memory message = abi.encodePacked("high-value-payload");

        uint256 gasBefore = gasleft();
        router.routeMessage(ARBITRUM, message, 100 ether);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("routeMessage(highValue) gas", gasUsed);
        assertLt(
            gasUsed,
            300_000,
            "routeMessage(highValue) should be < 300k gas"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: verifyMessage
    // ─────────────────────────────────────────────────────────────

    function test_gas_VerifyMessage() public {
        bytes memory message = abi.encodePacked("verify-payload");
        bytes32 msgHash = router.routeMessage(ARBITRUM, message, 100 ether);

        vm.prank(admin);
        uint256 gasBefore = gasleft();
        router.verifyMessage(
            msgHash,
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            true
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("verifyMessage gas", gasUsed);
        assertLt(gasUsed, 100_000, "verifyMessage should be < 100k gas");
    }

    // ─────────────────────────────────────────────────────────────
    //  Benchmark: verifyMessage reaching consensus
    // ─────────────────────────────────────────────────────────────

    function test_gas_VerifyMessage_ReachConsensus() public {
        bytes memory message = abi.encodePacked("consensus-payload");
        bytes32 msgHash = router.routeMessage(ARBITRUM, message, 100 ether);

        vm.startPrank(admin);
        router.verifyMessage(
            msgHash,
            IMultiBridgeRouter.BridgeType.NATIVE_L2,
            true
        );

        uint256 gasBefore = gasleft();
        router.verifyMessage(
            msgHash,
            IMultiBridgeRouter.BridgeType.LAYERZERO,
            true
        );
        uint256 gasUsed = gasBefore - gasleft();
        vm.stopPrank();

        emit log_named_uint("verifyMessage(consensus) gas", gasUsed);
        assertLt(
            gasUsed,
            120_000,
            "verifyMessage(consensus) should be < 120k gas"
        );
    }
}
