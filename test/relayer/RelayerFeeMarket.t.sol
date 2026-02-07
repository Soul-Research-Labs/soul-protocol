// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RelayerFeeMarket} from "../../contracts/relayer/RelayerFeeMarket.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @dev Mock ERC20 fee token for testing
contract MockFeeToken is ERC20 {
    constructor() ERC20("Soul Token", "SOUL") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/**
 * @title RelayerFeeMarketTest
 * @notice Comprehensive tests for the Relayer Fee Market
 */
contract RelayerFeeMarketTest is Test {
    RelayerFeeMarket public market;
    MockFeeToken public token;

    address public admin = makeAddr("admin");
    address public relayerA = makeAddr("relayerA");
    address public relayerB = makeAddr("relayerB");
    address public user = makeAddr("user");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    bytes32 public sourceChain = keccak256("ethereum");
    bytes32 public destChain = keccak256("arbitrum");

    function setUp() public {
        vm.startPrank(admin);

        token = new MockFeeToken();
        market = new RelayerFeeMarket(admin, address(token));

        // Grant roles
        market.grantRole(RELAYER_ROLE, relayerA);
        market.grantRole(RELAYER_ROLE, relayerB);
        market.grantRole(OPERATOR_ROLE, admin);

        // Initialize route
        market.initializeRoute(sourceChain, destChain, 0.001 ether);

        // Fund user with tokens
        token.transfer(user, 100 ether);

        vm.stopPrank();

        // User approves market
        vm.prank(user);
        token.approve(address(market), type(uint256).max);
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializeCorrectly() public view {
        assertEq(address(market.feeToken()), address(token));
        assertEq(market.protocolFeeBps(), 500); // 5%
        assertEq(market.totalRelaysCompleted(), 0);
    }

    function test_RouteInitialized() public view {
        uint256 baseFee = market.getBaseFee(sourceChain, destChain);
        assertEq(baseFee, 0.001 ether, "Base fee should be initialized");
    }

    /*//////////////////////////////////////////////////////////////
                       SUBMIT RELAY REQUEST
    //////////////////////////////////////////////////////////////*/

    function test_SubmitRelayRequest() public {
        bytes32 proofId = keccak256("proof1");

        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            proofId,
            0.01 ether,
            0.001 ether,
            0
        );

        assertTrue(requestId != bytes32(0), "Request ID should be generated");
        assertEq(
            token.balanceOf(address(market)),
            0.01 ether,
            "Max fee should be escrowed"
        );
    }

    function test_RevertSubmitInsufficientFee() public {
        bytes32 proofId = keccak256("proof2");

        // Try to submit with fee below base fee
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(RelayerFeeMarket.InsufficientFee.selector)
        );
        market.submitRelayRequest(
            sourceChain,
            destChain,
            proofId,
            0.0001 ether,
            0,
            0
        );
    }

    function test_RevertSubmitInactiveRoute() public {
        bytes32 proofId = keccak256("proof3");
        bytes32 unknownChain = keccak256("unknown");

        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(RelayerFeeMarket.RouteNotActive.selector)
        );
        market.submitRelayRequest(
            sourceChain,
            unknownChain,
            proofId,
            0.01 ether,
            0,
            0
        );
    }

    /*//////////////////////////////////////////////////////////////
                        CLAIM RELAY REQUEST
    //////////////////////////////////////////////////////////////*/

    function test_ClaimRelayRequest() public {
        // Submit
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof4"),
            0.01 ether,
            0.001 ether,
            0
        );

        // Claim
        vm.prank(relayerA);
        market.claimRelayRequest(requestId);

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
            RelayerFeeMarket.RequestStatus status,
            address claimedBy,
            ,

        ) = market.requests(requestId);
        assertEq(uint8(status), uint8(RelayerFeeMarket.RequestStatus.CLAIMED));
        assertEq(claimedBy, relayerA);
    }

    function test_RevertClaimNonRelayer() public {
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof5"),
            0.01 ether,
            0.001 ether,
            0
        );

        vm.prank(user); // not a relayer
        vm.expectRevert();
        market.claimRelayRequest(requestId);
    }

    /*//////////////////////////////////////////////////////////////
                        COMPLETE RELAY
    //////////////////////////////////////////////////////////////*/

    function test_CompleteRelay() public {
        // Submit
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof6"),
            0.01 ether,
            0.001 ether,
            0
        );

        // Claim
        vm.prank(relayerA);
        market.claimRelayRequest(requestId);

        uint256 relayerBefore = token.balanceOf(relayerA);
        uint256 userBefore = token.balanceOf(user);

        // Complete
        vm.prank(relayerA);
        market.completeRelay(requestId);

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
            RelayerFeeMarket.RequestStatus status,
            ,
            ,
            uint256 effectiveFee
        ) = market.requests(requestId);
        assertEq(
            uint8(status),
            uint8(RelayerFeeMarket.RequestStatus.COMPLETED)
        );
        assertTrue(effectiveFee > 0, "Effective fee should be set");
        assertEq(market.totalRelaysCompleted(), 1);

        // Relayer should have received payout (effective fee - protocol cut)
        uint256 relayerAfter = token.balanceOf(relayerA);
        assertTrue(
            relayerAfter > relayerBefore,
            "Relayer should receive payout"
        );

        // User should receive refund of (maxFee - effectiveFee)
        uint256 userAfter = token.balanceOf(user);
        uint256 refund = 0.01 ether - effectiveFee;
        assertEq(
            userAfter,
            userBefore + refund,
            "User should be refunded excess"
        );
    }

    function test_RevertCompleteByWrongRelayer() public {
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof7"),
            0.01 ether,
            0.001 ether,
            0
        );

        vm.prank(relayerA);
        market.claimRelayRequest(requestId);

        // Different relayer tries to complete
        vm.prank(relayerB);
        vm.expectRevert(
            abi.encodeWithSelector(RelayerFeeMarket.NotClaimedRelayer.selector)
        );
        market.completeRelay(requestId);
    }

    /*//////////////////////////////////////////////////////////////
                        CANCEL REQUEST
    //////////////////////////////////////////////////////////////*/

    function test_CancelRelayRequest() public {
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof8"),
            0.01 ether,
            0.001 ether,
            0
        );

        uint256 balanceBefore = token.balanceOf(user);

        vm.prank(user);
        market.cancelRelayRequest(requestId);

        assertEq(
            token.balanceOf(user),
            balanceBefore + 0.01 ether,
            "Full refund on cancel"
        );
    }

    function test_RevertCancelByNonRequester() public {
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof9"),
            0.01 ether,
            0.001 ether,
            0
        );

        vm.prank(relayerA);
        vm.expectRevert(
            abi.encodeWithSelector(RelayerFeeMarket.NotRequester.selector)
        );
        market.cancelRelayRequest(requestId);
    }

    /*//////////////////////////////////////////////////////////////
                        EXPIRY
    //////////////////////////////////////////////////////////////*/

    function test_ExpireRequest() public {
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof10"),
            0.01 ether,
            0.001 ether,
            0
        );

        // Advance past deadline
        vm.warp(block.timestamp + 5 hours);

        uint256 balanceBefore = token.balanceOf(user);

        market.expireRequest(requestId);

        assertEq(
            token.balanceOf(user),
            balanceBefore + 0.01 ether,
            "Full refund on expiry"
        );
    }

    function test_ExpireClaimedButTimedOut() public {
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof11"),
            0.01 ether,
            0.001 ether,
            0
        );

        vm.prank(relayerA);
        market.claimRelayRequest(requestId);

        // Advance past claim timeout (30 min)
        vm.warp(block.timestamp + 31 minutes);

        uint256 balanceBefore = token.balanceOf(user);
        market.expireRequest(requestId);

        assertEq(
            token.balanceOf(user),
            balanceBefore + 0.01 ether,
            "Refund on claim timeout"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        PROTOCOL FEES
    //////////////////////////////////////////////////////////////*/

    function test_ProtocolFeesAccumulate() public {
        // Submit + claim + complete a relay
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof12"),
            0.01 ether,
            0.001 ether,
            0
        );

        vm.prank(relayerA);
        market.claimRelayRequest(requestId);

        vm.prank(relayerA);
        market.completeRelay(requestId);

        assertTrue(
            market.protocolFees() > 0,
            "Protocol fees should accumulate"
        );
    }

    function test_WithdrawProtocolFees() public {
        // Complete a relay to generate fees
        vm.prank(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256("proof13"),
            0.01 ether,
            0.001 ether,
            0
        );
        vm.prank(relayerA);
        market.claimRelayRequest(requestId);
        vm.prank(relayerA);
        market.completeRelay(requestId);

        uint256 fees = market.protocolFees();
        address treasury = makeAddr("treasury");

        vm.prank(admin);
        market.withdrawProtocolFees(treasury);

        assertEq(
            token.balanceOf(treasury),
            fees,
            "Treasury should receive accumulated fees"
        );
        assertEq(market.protocolFees(), 0, "Protocol fees should be cleared");
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_SetProtocolFeeBps() public {
        vm.prank(admin);
        market.setProtocolFeeBps(250); // 2.5%
        assertEq(market.protocolFeeBps(), 250);
    }

    function test_RevertSetFeeBpsTooHigh() public {
        vm.prank(admin);
        vm.expectRevert("Max 10%");
        market.setProtocolFeeBps(1500);
    }

    /*//////////////////////////////////////////////////////////////
                          FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    function test_EstimateFee() public view {
        (uint256 totalFee, uint256 baseFee) = market.estimateFee(
            sourceChain,
            destChain,
            0.002 ether
        );
        assertEq(
            baseFee,
            0.001 ether,
            "Base fee should match initialized value"
        );
        assertEq(totalFee, 0.003 ether, "Total = base + priority");
    }

    /*//////////////////////////////////////////////////////////////
                           FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_SubmitAndCancelRefundsExactly(uint256 maxFee) public {
        uint256 baseFee = market.getBaseFee(sourceChain, destChain);
        vm.assume(maxFee >= baseFee && maxFee <= 10 ether);

        vm.startPrank(admin);
        token.mint(user, maxFee);
        vm.stopPrank();

        vm.startPrank(user);
        token.approve(address(market), maxFee);

        uint256 before = token.balanceOf(user);
        bytes32 requestId = market.submitRelayRequest(
            sourceChain,
            destChain,
            keccak256(abi.encodePacked("fuzz", maxFee)),
            maxFee,
            0,
            0
        );

        market.cancelRelayRequest(requestId);
        uint256 afterBal = token.balanceOf(user);

        assertEq(afterBal, before, "Cancel should refund exactly");
        vm.stopPrank();
    }
}
