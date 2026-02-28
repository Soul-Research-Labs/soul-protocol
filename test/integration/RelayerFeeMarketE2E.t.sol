// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DecentralizedRelayerRegistry} from "../../contracts/relayer/DecentralizedRelayerRegistry.sol";
import {RelayerFeeMarket} from "../../contracts/relayer/RelayerFeeMarket.sol";
import {IRelayerFeeMarket} from "../../contracts/interfaces/IRelayerFeeMarket.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Simple ERC20 mock for fee token
contract MockFeeToken is ERC20 {
    constructor() ERC20("Mock ZASEON", "mZASEON") {
        _mint(msg.sender, 1_000_000e18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title RelayerFeeMarketE2E
 * @notice E2E test for the relayer lifecycle:
 *         register relayer → submit relay request → claim → complete → collect fee
 *         + staking, slashing, fee market dynamics
 * @dev Validates the full relayer economic lifecycle end-to-end
 */
contract RelayerFeeMarketE2E is Test {
    DecentralizedRelayerRegistry public registry;
    RelayerFeeMarket public feeMarket;
    MockFeeToken public feeToken;

    address public admin = makeAddr("admin");
    address public relayer1 = makeAddr("relayer1");
    address public relayer2 = makeAddr("relayer2");
    address public requester = makeAddr("requester");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    bytes32 public ETH_CHAIN = keccak256("ethereum");
    bytes32 public ARB_CHAIN = keccak256("arbitrum");

    uint256 public constant MIN_STAKE = 10 ether;
    uint256 public constant ROUTE_BASE_FEE = 0.01 ether;

    function setUp() public {
        // Deploy registry
        vm.prank(admin);
        registry = new DecentralizedRelayerRegistry(admin);

        // Deploy fee token
        vm.prank(admin);
        feeToken = new MockFeeToken();

        // Deploy fee market
        vm.prank(admin);
        feeMarket = new RelayerFeeMarket(admin, address(feeToken));

        // Setup: grant relayer roles on fee market
        vm.startPrank(admin);
        feeMarket.grantRole(RELAYER_ROLE, relayer1);
        feeMarket.grantRole(RELAYER_ROLE, relayer2);

        // Initialize route: ETH → Arbitrum
        feeMarket.initializeRoute(ETH_CHAIN, ARB_CHAIN, ROUTE_BASE_FEE);
        vm.stopPrank();

        // Fund actors
        vm.deal(relayer1, 100 ether);
        vm.deal(relayer2, 100 ether);

        // Give requester fee tokens
        vm.prank(admin);
        feeToken.mint(requester, 100e18);
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Full relayer lifecycle (register → stake → relay → rewards)
    // ═════════════════════════════════════════════════════════════

    function test_E2E_FullRelayerLifecycle() public {
        // --- Phase 1: Register relayer with minimum stake ---
        vm.prank(relayer1);
        registry.register{value: MIN_STAKE}();

        (uint256 stake, , , bool isRegistered) = registry.relayers(relayer1);
        assertTrue(isRegistered, "Relayer should be registered");
        assertEq(stake, MIN_STAKE, "Stake should be MIN_STAKE");

        // --- Phase 2: Submit relay request ---
        uint256 maxFee = 0.05 ether;
        uint256 priorityFee = 0.005 ether;

        vm.startPrank(requester);
        feeToken.approve(address(feeMarket), maxFee);
        bytes32 requestId = feeMarket.submitRelayRequest(
            ETH_CHAIN,
            ARB_CHAIN,
            keccak256("proof-1"),
            maxFee,
            priorityFee,
            0 // default deadline
        );
        vm.stopPrank();

        // Verify request created
        (
            bytes32 storedRequestId,
            ,
            ,
            address requestRequester,
            uint256 storedMaxFee,
            ,
            ,
            ,
            ,
            IRelayerFeeMarket.RequestStatus requestStatus,
            ,
            ,

        ) = feeMarket.requests(requestId);
        assertEq(storedRequestId, requestId);
        assertEq(requestRequester, requester);
        assertEq(storedMaxFee, maxFee);
        assertEq(
            uint256(requestStatus),
            uint256(IRelayerFeeMarket.RequestStatus.PENDING)
        );

        // --- Phase 3: Relayer claims the request ---
        vm.prank(relayer1);
        feeMarket.claimRelayRequest(requestId);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            IRelayerFeeMarket.RequestStatus afterClaimStatus,
            address claimedBy,
            ,

        ) = feeMarket.requests(requestId);
        assertEq(
            uint256(afterClaimStatus),
            uint256(IRelayerFeeMarket.RequestStatus.CLAIMED)
        );
        assertEq(claimedBy, relayer1);

        // --- Phase 4: Relayer completes the relay ---
        uint256 relayerBalanceBefore = feeToken.balanceOf(relayer1);

        vm.prank(relayer1);
        feeMarket.completeRelay(requestId);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            IRelayerFeeMarket.RequestStatus finalStatus,
            ,
            ,
            uint256 effectiveFee
        ) = feeMarket.requests(requestId);
        assertEq(
            uint256(finalStatus),
            uint256(IRelayerFeeMarket.RequestStatus.COMPLETED)
        );
        assertGt(effectiveFee, 0, "Effective fee should be set");

        // Relayer should have received payout (minus protocol cut)
        uint256 relayerBalanceAfter = feeToken.balanceOf(relayer1);
        assertGt(
            relayerBalanceAfter,
            relayerBalanceBefore,
            "Relayer should receive fee"
        );

        // Requester refund (maxFee - effectiveFee)
        if (maxFee > effectiveFee) {
            assertGt(
                feeToken.balanceOf(requester),
                0,
                "Requester should get refund"
            );
        }

        // Protocol fees accumulated
        assertGt(
            feeMarket.protocolFees(),
            0,
            "Protocol fees should accumulate"
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Relayer staking and slashing
    // ═════════════════════════════════════════════════════════════

    function test_E2E_RelayerStakingAndSlashing() public {
        // Register
        vm.prank(relayer1);
        registry.register{value: 15 ether}();

        (uint256 stakeBefore, , , ) = registry.relayers(relayer1);
        assertEq(stakeBefore, 15 ether);

        // Slash 2 ETH for misbehavior
        vm.prank(admin);
        registry.slash(relayer1, 2 ether, admin);

        (uint256 stakeAfter, , , ) = registry.relayers(relayer1);
        assertEq(stakeAfter, 13 ether, "Stake reduced by slash amount");
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Relayer unbonding lifecycle
    // ═════════════════════════════════════════════════════════════

    function test_E2E_RelayerUnbonding() public {
        vm.prank(relayer1);
        registry.register{value: MIN_STAKE}();

        // Initiate unstake
        vm.prank(relayer1);
        registry.initiateUnstake();

        (, , uint256 unlockTime, ) = registry.relayers(relayer1);
        assertGt(unlockTime, block.timestamp, "Unlock should be in the future");

        // Cannot withdraw before unbonding period
        vm.prank(relayer1);
        vm.expectRevert();
        registry.withdrawStake();

        // Fast-forward past unbonding period (7 days)
        vm.warp(block.timestamp + 7 days + 1);

        // Withdraw
        uint256 balanceBefore = relayer1.balance;
        vm.prank(relayer1);
        registry.withdrawStake();

        assertEq(relayer1.balance, balanceBefore + MIN_STAKE, "Stake returned");
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Request cancellation and refund
    // ═════════════════════════════════════════════════════════════

    function test_E2E_RequestCancellationRefund() public {
        uint256 maxFee = 0.02 ether;
        uint256 balanceBefore = feeToken.balanceOf(requester);

        // Submit request
        vm.startPrank(requester);
        feeToken.approve(address(feeMarket), maxFee);
        bytes32 requestId = feeMarket.submitRelayRequest(
            ETH_CHAIN,
            ARB_CHAIN,
            keccak256("proof-cancel"),
            maxFee,
            0,
            0
        );

        // Cancel
        feeMarket.cancelRelayRequest(requestId);
        vm.stopPrank();

        // Full refund
        assertEq(
            feeToken.balanceOf(requester),
            balanceBefore,
            "Full refund on cancel"
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Request expiration
    // ═════════════════════════════════════════════════════════════

    function test_E2E_RequestExpiration() public {
        uint256 maxFee = 0.02 ether;

        vm.startPrank(requester);
        feeToken.approve(address(feeMarket), maxFee);
        bytes32 requestId = feeMarket.submitRelayRequest(
            ETH_CHAIN,
            ARB_CHAIN,
            keccak256("proof-expire"),
            maxFee,
            0,
            block.timestamp + 1 hours // 1 hour deadline
        );
        vm.stopPrank();

        // Fast-forward past deadline
        vm.warp(block.timestamp + 2 hours);

        // Anyone can expire
        feeMarket.expireRequest(requestId);

        (
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            ,
            IRelayerFeeMarket.RequestStatus status,
            ,
            ,

        ) = feeMarket.requests(requestId);
        assertEq(
            uint256(status),
            uint256(IRelayerFeeMarket.RequestStatus.EXPIRED)
        );
    }

    // ═════════════════════════════════════════════════════════════
    //  E2E: Insufficient stake registration blocked
    // ═════════════════════════════════════════════════════════════

    function test_E2E_InsufficientStakeBlocked() public {
        vm.prank(relayer2);
        vm.expectRevert();
        registry.register{value: 1 ether}(); // Below 10 ETH minimum
    }
}
