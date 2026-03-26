// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {UniswapV3RebalanceAdapter} from "../../contracts/integrations/UniswapV3RebalanceAdapter.sol";
import {IRebalanceSwapAdapter} from "../../contracts/interfaces/IRebalanceSwapAdapter.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// ─── Mock Uniswap V3 Contracts ─────────────────────────────────────

contract MockSwapRouter {
    uint256 public lastAmountIn;
    uint256 public mockAmountOut;
    bool public shouldRevert;

    function setMockAmountOut(uint256 _amount) external {
        mockAmountOut = _amount;
    }

    function setShouldRevert(bool _shouldRevert) external {
        shouldRevert = _shouldRevert;
    }

    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(
        ExactInputSingleParams calldata params
    ) external payable returns (uint256 amountOut) {
        require(!shouldRevert, "MockRouter: forced revert");
        lastAmountIn = params.amountIn;

        // Transfer tokens from caller
        IERC20(params.tokenIn).transferFrom(
            msg.sender,
            address(this),
            params.amountIn
        );

        amountOut = mockAmountOut;
        require(amountOut >= params.amountOutMinimum, "Too little received");

        // Send output tokens to recipient
        IERC20(params.tokenOut).transfer(params.recipient, amountOut);

        return amountOut;
    }
}

contract MockUniswapFactory {
    mapping(bytes32 => address) public pools;

    function setPool(
        address tokenA,
        address tokenB,
        uint24 fee,
        address pool
    ) external {
        bytes32 key = keccak256(abi.encodePacked(tokenA, tokenB, fee));
        pools[key] = pool;
    }

    function getPool(
        address tokenA,
        address tokenB,
        uint24 fee
    ) external view returns (address) {
        bytes32 key = keccak256(abi.encodePacked(tokenA, tokenB, fee));
        return pools[key];
    }
}

contract MockQuoterV2 {
    function quoteExactInputSingle(
        address,
        address,
        uint24,
        uint256 amountIn,
        uint160
    ) external pure returns (uint256) {
        return amountIn;
    }
}

contract MockWETH {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "Insufficient WETH");
        balanceOf[msg.sender] -= amount;
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "ETH send failed");
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address, uint256) external returns (bool) {
        return true;
    }

    function allowance(address, address) external pure returns (uint256) {
        return type(uint256).max;
    }

    function totalSupply() external pure returns (uint256) {
        return 0;
    }

    receive() external payable {
        balanceOf[msg.sender] += msg.value;
    }
}

contract MockToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
}

// ─── Tests ──────────────────────────────────────────────────────

contract UniswapV3RebalanceAdapterTest is Test {
    UniswapV3RebalanceAdapter public adapter;
    MockSwapRouter public router;
    MockQuoterV2 public quoter;
    MockUniswapFactory public factory;
    MockWETH public weth;
    MockToken public usdc;
    MockToken public dai;

    address public admin = address(0xA1);
    address public operator = address(0xA2);
    address public vault = address(0xA3);
    address public unauthorized = address(0xA4);

    address public mockPool = address(0xBEEF);

    function setUp() public {
        router = new MockSwapRouter();
        quoter = new MockQuoterV2();
        factory = new MockUniswapFactory();
        weth = new MockWETH();
        usdc = new MockToken("USD Coin", "USDC");
        dai = new MockToken("Dai", "DAI");

        adapter = new UniswapV3RebalanceAdapter(
            admin,
            operator,
            address(router),
            address(quoter),
            address(factory),
            address(weth)
        );

        // Authorize the vault
        vm.prank(operator);
        adapter.setAuthorizedCaller(vault, true);

        // Set up factory pool
        factory.setPool(address(usdc), address(dai), 3000, mockPool);
        factory.setPool(address(usdc), address(weth), 3000, mockPool);
    }

    // ═══════════════════════════════════════════════════════════════
    // CONSTRUCTOR
    // ═══════════════════════════════════════════════════════════════

    function test_constructor_setsRoles() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(adapter.hasRole(adapter.OPERATOR_ROLE(), operator));
    }

    function test_constructor_setsImmutables() public view {
        assertEq(address(adapter.swapRouter()), address(router));
        assertEq(address(adapter.quoter()), address(quoter));
        assertEq(address(adapter.factory()), address(factory));
        assertEq(address(adapter.weth()), address(weth));
    }

    function test_constructor_revertsZeroAdmin() public {
        vm.expectRevert();
        new UniswapV3RebalanceAdapter(
            address(0),
            operator,
            address(router),
            address(quoter),
            address(factory),
            address(weth)
        );
    }

    function test_constructor_revertsZeroRouter() public {
        vm.expectRevert();
        new UniswapV3RebalanceAdapter(
            admin,
            operator,
            address(0),
            address(quoter),
            address(factory),
            address(weth)
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // AUTHORIZED CALLER
    // ═══════════════════════════════════════════════════════════════

    function test_setAuthorizedCaller_authorizes() public {
        address newVault = address(0xBB);
        vm.prank(operator);
        adapter.setAuthorizedCaller(newVault, true);
        assertTrue(adapter.authorizedCallers(newVault));
    }

    function test_setAuthorizedCaller_revokes() public {
        vm.prank(operator);
        adapter.setAuthorizedCaller(vault, false);
        assertFalse(adapter.authorizedCallers(vault));
    }

    function test_setAuthorizedCaller_revertsForNonOperator() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        adapter.setAuthorizedCaller(address(0xCC), true);
    }

    function test_setAuthorizedCaller_revertsZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setAuthorizedCaller(address(0), true);
    }

    function test_setAuthorizedCaller_emitsEvent() public {
        address newVault = address(0xDD);
        vm.prank(operator);
        vm.expectEmit(true, false, false, true);
        emit UniswapV3RebalanceAdapter.CallerAuthorized(newVault, true);
        adapter.setAuthorizedCaller(newVault, true);
    }

    // ═══════════════════════════════════════════════════════════════
    // FEE TIER OVERRIDES
    // ═══════════════════════════════════════════════════════════════

    function test_setFeeTierOverride_setsCorrectly() public {
        vm.prank(operator);
        adapter.setFeeTierOverride(address(usdc), address(dai), 500);

        // Verify via isSwapSupported (which uses _getFeeTier internally)
        factory.setPool(address(usdc), address(dai), 500, mockPool);
        assertTrue(adapter.isSwapSupported(address(usdc), address(dai)));
    }

    function test_setFeeTierOverride_orderIndependent() public {
        // Set override with tokenA, tokenB
        vm.prank(operator);
        adapter.setFeeTierOverride(address(usdc), address(dai), 500);

        // Factory has pool at fee=500
        factory.setPool(address(dai), address(usdc), 500, mockPool);
        assertTrue(adapter.isSwapSupported(address(dai), address(usdc)));
    }

    function test_setFeeTierOverride_revertsZeroTokenA() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setFeeTierOverride(address(0), address(dai), 500);
    }

    function test_setFeeTierOverride_revertsZeroTokenB() public {
        vm.prank(operator);
        vm.expectRevert();
        adapter.setFeeTierOverride(address(usdc), address(0), 500);
    }

    function test_setFeeTierOverride_revertsNonOperator() public {
        vm.prank(unauthorized);
        vm.expectRevert();
        adapter.setFeeTierOverride(address(usdc), address(dai), 500);
    }

    function test_setFeeTierOverride_emitsEvent() public {
        vm.prank(operator);
        vm.expectEmit(true, true, false, true);
        emit UniswapV3RebalanceAdapter.FeeTierOverrideSet(
            address(usdc),
            address(dai),
            500
        );
        adapter.setFeeTierOverride(address(usdc), address(dai), 500);
    }

    function test_defaultFeeTier_is3000() public view {
        assertEq(adapter.DEFAULT_FEE_TIER(), 3000);
    }

    // ═══════════════════════════════════════════════════════════════
    // isSwapSupported
    // ═══════════════════════════════════════════════════════════════

    function test_isSwapSupported_returnsTrueForKnownPool() public view {
        assertTrue(adapter.isSwapSupported(address(usdc), address(dai)));
    }

    function test_isSwapSupported_returnsFalseForUnknownPool() public view {
        assertFalse(adapter.isSwapSupported(address(usdc), address(0x999)));
    }

    function test_isSwapSupported_returnsFalseForSameToken() public view {
        assertFalse(adapter.isSwapSupported(address(usdc), address(usdc)));
    }

    // ═══════════════════════════════════════════════════════════════
    // getQuote
    // ═══════════════════════════════════════════════════════════════

    function test_getQuote_returnsZeroForOnChainQuoting() public view {
        // On-chain quoting is unavailable (QuoterV2 is non-view), returns 0
        uint256 quote = adapter.getQuote(address(usdc), address(dai), 1000e18);
        assertEq(quote, 0);
    }

    function test_getQuote_returnsZeroForNoPool() public view {
        uint256 quote = adapter.getQuote(
            address(usdc),
            address(0x999),
            1000e18
        );
        assertEq(quote, 0);
    }

    // ═══════════════════════════════════════════════════════════════
    // SWAP — ACCESS CONTROL
    // ═══════════════════════════════════════════════════════════════

    function test_swap_revertsForUnauthorizedCaller() public {
        vm.prank(unauthorized);
        vm.expectRevert(UniswapV3RebalanceAdapter.UnauthorizedCaller.selector);
        adapter.swap(
            address(usdc),
            address(dai),
            100e18,
            90e18,
            vault,
            block.timestamp + 1 hours
        );
    }

    function test_swap_revertsForZeroAmount() public {
        vm.prank(vault);
        vm.expectRevert(UniswapV3RebalanceAdapter.ZeroAmount.selector);
        adapter.swap(
            address(usdc),
            address(dai),
            0,
            0,
            vault,
            block.timestamp + 1 hours
        );
    }

    function test_swap_revertsForZeroRecipient() public {
        vm.prank(vault);
        vm.expectRevert(UniswapV3RebalanceAdapter.ZeroAddress.selector);
        adapter.swap(
            address(usdc),
            address(dai),
            100e18,
            90e18,
            address(0),
            block.timestamp + 1 hours
        );
    }

    function test_swap_revertsForExpiredDeadline() public {
        vm.prank(vault);
        vm.expectRevert(IRebalanceSwapAdapter.SwapDeadlineExpired.selector);
        adapter.swap(
            address(usdc),
            address(dai),
            100e18,
            90e18,
            vault,
            block.timestamp - 1
        );
    }

    function test_swap_revertsForSameToken() public {
        vm.prank(vault);
        vm.expectRevert(
            abi.encodeWithSelector(
                IRebalanceSwapAdapter.InvalidSwapPath.selector,
                address(usdc),
                address(usdc)
            )
        );
        adapter.swap(
            address(usdc),
            address(usdc),
            100e18,
            90e18,
            vault,
            block.timestamp + 1 hours
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // RECEIVE
    // ═══════════════════════════════════════════════════════════════

    function test_receiveETH() public {
        vm.deal(address(this), 1 ether);
        (bool sent, ) = address(adapter).call{value: 1 ether}("");
        assertTrue(sent);
    }

    // ═══════════════════════════════════════════════════════════════
    // MAX DEADLINE
    // ═══════════════════════════════════════════════════════════════

    function test_maxDeadlineExtension() public view {
        assertEq(adapter.MAX_DEADLINE_EXTENSION(), 1 hours);
    }
}
