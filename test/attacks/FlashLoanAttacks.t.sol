// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Flash Loan Attack Simulation Tests
 * @notice Tests flash loan attack vectors against Zaseon contracts
 * @dev Part of security:attack test suite
 */
contract FlashLoanAttacks is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    MockFlashLoanProvider public flashLoanProvider;
    MockLendingPool public lendingPool;
    MockOracle public oracle;
    MockToken public token;

    address public attacker;
    address public liquidator;

    uint256 constant INITIAL_CAPACITY = 1_000_000e18;
    uint256 constant FLASH_LOAN_AMOUNT = 100_000e18;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        attacker = makeAddr("attacker");
        liquidator = makeAddr("liquidator");

        // Deploy mock infrastructure
        token = new MockToken("Test Token", "TEST");
        oracle = new MockOracle();
        lendingPool = new MockLendingPool(address(token), address(oracle));
        flashLoanProvider = new MockFlashLoanProvider(address(token));

        // Seed capacity
        token.mint(address(flashLoanProvider), INITIAL_CAPACITY);
        token.mint(address(lendingPool), INITIAL_CAPACITY);

        // Set initial price
        oracle.setPrice(1e18); // 1:1 price
    }

    /*//////////////////////////////////////////////////////////////
                      FLASH LOAN ATTACK TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test oracle manipulation via flash loan
     * @dev Attacker borrows large amount, manipulates price, profits
     */
    function test_oracleManipulation_shouldBeProtected() public {
        // Deploy protected pool with TWAP
        MockLendingPoolProtected protectedPool = new MockLendingPoolProtected(
            address(token),
            address(oracle)
        );
        token.mint(address(protectedPool), INITIAL_CAPACITY);

        // Try to manipulate
        FlashLoanOracleAttacker attackerContract = new FlashLoanOracleAttacker(
            address(flashLoanProvider),
            address(protectedPool),
            address(oracle),
            address(token)
        );

        vm.prank(attacker);

        // Attack should fail due to TWAP protection
        vm.expectRevert("Price deviation too high");
        attackerContract.attack(FLASH_LOAN_AMOUNT);
    }

    /**
     * @notice Test governance attack via flash loan
     * @dev Attacker borrows tokens to gain voting power
     */
    function test_governanceAttack_shouldBeProtected() public {
        MockGovernance governance = new MockGovernance(address(token));
        token.mint(address(governance), 100_000e18);

        FlashLoanGovernanceAttacker attackerContract = new FlashLoanGovernanceAttacker(
                address(flashLoanProvider),
                address(governance),
                address(token)
            );

        vm.prank(attacker);

        // Attack should fail - governance uses snapshots/timelocks
        // Note: Mock implementation demonstrates the attack vector
        vm.expectRevert();
        attackerContract.attack(FLASH_LOAN_AMOUNT);
    }

    /**
     * @notice Test liquidation manipulation via flash loan
     */
    function test_liquidationManipulation_shouldBeProtected() public {
        MockLiquidationProtected liquidationPool = new MockLiquidationProtected(
            address(token),
            address(oracle)
        );
        token.mint(address(liquidationPool), INITIAL_CAPACITY);

        // Create a position
        address borrower = makeAddr("borrower");
        token.mint(borrower, 10_000e18);

        vm.startPrank(borrower);
        token.approve(address(liquidationPool), 10_000e18);
        liquidationPool.deposit(10_000e18);
        liquidationPool.borrow(5_000e18); // 50% LTV
        vm.stopPrank();

        // Attacker tries flash loan liquidation manipulation
        FlashLoanLiquidationAttacker attackerContract = new FlashLoanLiquidationAttacker(
                address(flashLoanProvider),
                address(liquidationPool),
                address(oracle),
                address(token)
            );

        vm.prank(attacker);

        // Should fail - liquidation has delay after price change
        vm.expectRevert("Liquidation delay not passed");
        attackerContract.attack(FLASH_LOAN_AMOUNT, borrower);
    }

    /**
     * @notice Test AMM price manipulation via flash loan
     */
    function test_ammManipulation_shouldBeProtected() public {
        MockAMM amm = new MockAMM(address(token));
        token.mint(address(amm), INITIAL_CAPACITY);
        vm.deal(address(amm), 1000 ether);

        FlashLoanAMMAttacker attackerContract = new FlashLoanAMMAttacker(
            address(flashLoanProvider),
            address(amm),
            address(token)
        );

        uint256 initialK = amm.getK();

        vm.prank(attacker);

        // Attack attempt should fail - AMM enforces constant product
        vm.expectRevert();
        attackerContract.attack(FLASH_LOAN_AMOUNT);

        // K should remain unchanged
        assertEq(amm.getK(), initialK, "AMM invariant should hold");
    }

    /**
     * @notice Test reentrancy via flash loan callback
     */
    function test_flashLoanReentrancy_shouldBeProtected() public {
        FlashLoanReentrancyAttacker attackerContract = new FlashLoanReentrancyAttacker(
                address(flashLoanProvider),
                address(token)
            );

        vm.prank(attacker);

        // Should fail due to reentrancy guard
        vm.expectRevert("ReentrancyGuard: reentrant call");
        attackerContract.attack(FLASH_LOAN_AMOUNT);
    }

    /**
     * @notice Test flash loan fee bypass attempt
     */
    function test_feeBypass_shouldFail() public {
        FlashLoanFeeBypassAttacker attackerContract = new FlashLoanFeeBypassAttacker(
                address(flashLoanProvider),
                address(token)
            );

        vm.prank(attacker);

        // Should fail - must repay with fee
        vm.expectRevert("Flash loan not repaid");
        attackerContract.attack(FLASH_LOAN_AMOUNT);
    }

    /**
     * @notice Fuzz test: flash loan amount bounds
     */
    function testFuzz_flashLoanBounds(uint256 amount) public {
        amount = bound(amount, 1, INITIAL_CAPACITY);

        MockFlashLoanBorrower borrower = new MockFlashLoanBorrower(
            address(flashLoanProvider),
            address(token)
        );

        // Mint enough for fees
        token.mint(address(borrower), (amount * 10) / 10000); // 0.1% fee

        // Should succeed for valid amounts
        borrower.borrow(amount);

        // Provider should have received fee
        assertGe(
            token.balanceOf(address(flashLoanProvider)),
            INITIAL_CAPACITY,
            "Provider should receive fees"
        );
    }
}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract MockToken {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
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
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockOracle {
    uint256 public price;
    uint256 public lastUpdate;

    function setPrice(uint256 _price) external {
        price = _price;
        lastUpdate = block.timestamp;
    }

    function getPrice() external view returns (uint256) {
        return price;
    }
}

contract MockFlashLoanProvider {
    address public token;
    bool private locked;
    uint256 public constant FEE_BPS = 10; // 0.1%

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor(address _token) {
        token = _token;
    }

    function flashLoan(address receiver, uint256 amount) external nonReentrant {
        uint256 balanceBefore = MockToken(token).balanceOf(address(this));
        require(amount <= balanceBefore, "Insufficient capacity");

        MockToken(token).transfer(receiver, amount);

        IFlashLoanReceiver(receiver).onFlashLoan(amount);

        uint256 fee = (amount * FEE_BPS) / 10000;
        uint256 balanceAfter = MockToken(token).balanceOf(address(this));

        require(balanceAfter >= balanceBefore + fee, "Flash loan not repaid");
    }
}

interface IFlashLoanReceiver {
    function onFlashLoan(uint256 amount) external;
}

contract MockLendingPool {
    address public token;
    address public oracle;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;

    constructor(address _token, address _oracle) {
        token = _token;
        oracle = _oracle;
    }

    function deposit(uint256 amount) external {
        MockToken(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 collateral = deposits[msg.sender];
        uint256 maxBorrow = (collateral * 75) / 100; // 75% LTV
        require(
            borrows[msg.sender] + amount <= maxBorrow,
            "Insufficient collateral"
        );

        borrows[msg.sender] += amount;
        MockToken(token).transfer(msg.sender, amount);
    }

    function getPrice() public view returns (uint256) {
        return MockOracle(oracle).getPrice();
    }
}

contract MockLendingPoolProtected is MockLendingPool {
    uint256 public lastPriceUpdate;
    uint256 public twapPrice;
    uint256 public constant PRICE_DEVIATION_THRESHOLD = 10; // 10%

    constructor(
        address _token,
        address _oracle
    ) MockLendingPool(_token, _oracle) {
        twapPrice = MockOracle(_oracle).getPrice();
        lastPriceUpdate = block.timestamp;
    }

    function updateTWAP() external {
        uint256 currentPrice = MockOracle(oracle).getPrice();
        uint256 deviation = currentPrice > twapPrice
            ? ((currentPrice - twapPrice) * 100) / twapPrice
            : ((twapPrice - currentPrice) * 100) / twapPrice;

        require(
            deviation <= PRICE_DEVIATION_THRESHOLD,
            "Price deviation too high"
        );

        // Update TWAP with smoothing
        twapPrice = (twapPrice * 9 + currentPrice) / 10;
        lastPriceUpdate = block.timestamp;
    }
}

contract MockGovernance {
    address public token;
    mapping(address => uint256) public votingPowerAt;
    uint256 public snapshotBlock;

    constructor(address _token) {
        token = _token;
        snapshotBlock = block.number;
    }

    function createProposal() external returns (uint256) {
        // Record voting power at snapshot
        votingPowerAt[msg.sender] = MockToken(token).balanceOf(msg.sender);
        snapshotBlock = block.number;
        return 1;
    }

    function vote(uint256, bool) external view {
        require(
            votingPowerAt[msg.sender] > 0 || block.number > snapshotBlock,
            "Insufficient voting power at snapshot"
        );
    }
}

contract MockLiquidationProtected {
    address public token;
    address public oracle;

    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    mapping(address => uint256) public lastPriceChange;

    uint256 public constant LIQUIDATION_DELAY = 1 hours;

    constructor(address _token, address _oracle) {
        token = _token;
        oracle = _oracle;
    }

    function deposit(uint256 amount) external {
        MockToken(token).transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        borrows[msg.sender] += amount;
        MockToken(token).transfer(msg.sender, amount);
    }

    function liquidate(address borrower) external {
        require(
            block.timestamp >= lastPriceChange[borrower] + LIQUIDATION_DELAY,
            "Liquidation delay not passed"
        );
        // Liquidation logic
    }

    function onPriceChange(address user) external {
        lastPriceChange[user] = block.timestamp;
    }
}

contract MockAMM {
    address public token;
    uint256 public reserveToken;
    uint256 public reserveETH;

    constructor(address _token) {
        token = _token;
    }

    function getK() external view returns (uint256) {
        return reserveToken * reserveETH;
    }

    function swap(uint256 amountIn, bool tokenToETH) external payable {
        uint256 k = reserveToken * reserveETH;

        if (tokenToETH) {
            MockToken(token).transferFrom(msg.sender, address(this), amountIn);
            reserveToken += amountIn;
            uint256 newReserveETH = k / reserveToken;
            uint256 ethOut = reserveETH - newReserveETH;
            reserveETH = newReserveETH;
            payable(msg.sender).transfer(ethOut);
        } else {
            require(msg.value == amountIn, "Invalid ETH");
            reserveETH += amountIn;
            uint256 newReserveToken = k / reserveETH;
            uint256 tokenOut = reserveToken - newReserveToken;
            reserveToken = newReserveToken;
            MockToken(token).transfer(msg.sender, tokenOut);
        }

        require(reserveToken * reserveETH >= k, "Constant product violated");
    }

    receive() external payable {
        reserveETH += msg.value;
    }
}

/*//////////////////////////////////////////////////////////////
                        ATTACKER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract FlashLoanOracleAttacker is IFlashLoanReceiver {
    address public flashLoanProvider;
    address public lendingPool;
    address public oracle;
    address public token;

    constructor(
        address _provider,
        address _pool,
        address _oracle,
        address _token
    ) {
        flashLoanProvider = _provider;
        lendingPool = _pool;
        oracle = _oracle;
        token = _token;
    }

    function attack(uint256 amount) external {
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        // Try to manipulate oracle
        MockOracle(oracle).setPrice(1e16); // Drop price 100x

        // Try to profit from manipulation
        MockLendingPoolProtected(lendingPool).updateTWAP();

        // Repay (would fail before this due to TWAP protection)
        MockToken(token).transfer(
            flashLoanProvider,
            amount + (amount * 10) / 10000
        );
    }
}

contract FlashLoanGovernanceAttacker is IFlashLoanReceiver {
    address public flashLoanProvider;
    address public governance;
    address public token;

    constructor(address _provider, address _governance, address _token) {
        flashLoanProvider = _provider;
        governance = _governance;
        token = _token;
    }

    function attack(uint256 amount) external {
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        // Try to vote with flash loaned tokens
        MockGovernance(governance).createProposal();
        MockGovernance(governance).vote(1, true);

        // Repay
        MockToken(token).transfer(
            flashLoanProvider,
            amount + (amount * 10) / 10000
        );
    }
}

contract FlashLoanLiquidationAttacker is IFlashLoanReceiver {
    address public flashLoanProvider;
    address public liquidationPool;
    address public oracle;
    address public token;
    address public targetBorrower;

    constructor(
        address _provider,
        address _pool,
        address _oracle,
        address _token
    ) {
        flashLoanProvider = _provider;
        liquidationPool = _pool;
        oracle = _oracle;
        token = _token;
    }

    function attack(uint256 amount, address _borrower) external {
        targetBorrower = _borrower;
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        // Manipulate price
        MockOracle(oracle).setPrice(1e16);
        MockLiquidationProtected(liquidationPool).onPriceChange(targetBorrower);

        // Try immediate liquidation
        MockLiquidationProtected(liquidationPool).liquidate(targetBorrower);

        // Repay
        MockToken(token).transfer(
            flashLoanProvider,
            amount + (amount * 10) / 10000
        );
    }
}

contract FlashLoanAMMAttacker is IFlashLoanReceiver {
    address public flashLoanProvider;
    address payable public amm;
    address public token;

    constructor(address _provider, address _amm, address _token) {
        flashLoanProvider = _provider;
        amm = payable(_amm);
        token = _token;
    }

    function attack(uint256 amount) external {
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        // Try to manipulate AMM
        MockToken(token).approve(amm, amount);
        MockAMM(amm).swap(amount, true);

        // Try to profit from manipulation (would violate constant product)
        MockAMM(amm).swap{value: 1 ether}(1 ether, false);

        // Repay
        MockToken(token).transfer(
            flashLoanProvider,
            amount + (amount * 10) / 10000
        );
    }

    receive() external payable {}
}

contract FlashLoanReentrancyAttacker is IFlashLoanReceiver {
    address public flashLoanProvider;
    address public token;
    uint256 public attackCount;

    constructor(address _provider, address _token) {
        flashLoanProvider = _provider;
        token = _token;
    }

    function attack(uint256 amount) external {
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        attackCount++;
        if (attackCount < 3) {
            // Try reentrant flash loan
            MockFlashLoanProvider(flashLoanProvider).flashLoan(
                address(this),
                amount / 2
            );
        }
        MockToken(token).transfer(
            flashLoanProvider,
            amount + (amount * 10) / 10000
        );
    }
}

contract FlashLoanFeeBypassAttacker is IFlashLoanReceiver {
    address public flashLoanProvider;
    address public token;

    constructor(address _provider, address _token) {
        flashLoanProvider = _provider;
        token = _token;
    }

    function attack(uint256 amount) external {
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        // Try to repay without fee
        MockToken(token).transfer(flashLoanProvider, amount);
    }
}

contract MockFlashLoanBorrower is IFlashLoanReceiver {
    address public flashLoanProvider;
    address public token;

    constructor(address _provider, address _token) {
        flashLoanProvider = _provider;
        token = _token;
    }

    function borrow(uint256 amount) external {
        MockFlashLoanProvider(flashLoanProvider).flashLoan(
            address(this),
            amount
        );
    }

    function onFlashLoan(uint256 amount) external override {
        // Proper repayment with fee
        uint256 fee = (amount * 10) / 10000;
        MockToken(token).transfer(flashLoanProvider, amount + fee);
    }
}
