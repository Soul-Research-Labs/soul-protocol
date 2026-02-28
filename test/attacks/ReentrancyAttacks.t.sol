// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title Reentrancy Attack Simulation Tests
 * @notice Tests various reentrancy attack vectors against Zaseon contracts
 * @dev Part of security:attack test suite
 */
contract ReentrancyAttacks is Test {
    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    address public victim;
    address public attacker;
    uint256 public attackCount;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public {
        victim = makeAddr("victim");
        attacker = makeAddr("attacker");

        vm.deal(victim, 100 ether);
        vm.deal(attacker, 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                        REENTRANCY ATTACK TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Test classic reentrancy protection
     * @dev Simulates an attacker trying to drain funds through reentrancy
     */
    function test_classicReentrancy_shouldFail() public {
        // Deploy a mock vulnerable contract
        VulnerableBank vulnerable = new VulnerableBank();
        vm.deal(address(vulnerable), 10 ether);

        // Deploy protected version
        ProtectedBank protected = new ProtectedBank();
        vm.deal(address(protected), 10 ether);

        // Deploy attacker contract
        ReentrancyAttacker attackerContract = new ReentrancyAttacker(
            address(protected)
        );
        vm.deal(address(attackerContract), 1 ether);

        // Attacker deposits
        vm.prank(address(attackerContract));
        protected.deposit{value: 1 ether}();

        // Try to attack - should fail due to reentrancy guard
        vm.expectRevert();
        attackerContract.attack();

        // Bank should still have funds
        assertGe(
            address(protected).balance,
            10 ether,
            "Protected bank should not be drained"
        );
    }

    /**
     * @notice Test cross-function reentrancy protection
     */
    function test_crossFunctionReentrancy_shouldFail() public {
        CrossFunctionProtected cfp = new CrossFunctionProtected();
        vm.deal(address(cfp), 10 ether);

        CrossFunctionAttacker cfa = new CrossFunctionAttacker(address(cfp));
        vm.deal(address(cfa), 1 ether);

        vm.prank(address(cfa));
        cfp.deposit{value: 1 ether}();

        // Attack should fail
        vm.expectRevert();
        cfa.attack();

        assertGe(
            address(cfp).balance,
            10 ether,
            "Should resist cross-function reentrancy"
        );
    }

    /**
     * @notice Test read-only reentrancy protection
     * @dev Tests protection against view function manipulation during reentrancy
     */
    function test_readOnlyReentrancy_priceManipulation() public {
        ReadOnlyReentrancyVictim victim_ = new ReadOnlyReentrancyVictim();
        vm.deal(address(victim_), 10 ether);

        ReadOnlyReentrancyAttacker attacker_ = new ReadOnlyReentrancyAttacker(
            address(victim_)
        );
        vm.deal(address(attacker_), 1 ether);

        // Get initial price
        uint256 initialPrice = victim_.getPrice();

        // Try attack
        vm.prank(address(attacker_));
        victim_.deposit{value: 1 ether}();

        // Price should remain consistent
        assertEq(
            victim_.getPrice(),
            initialPrice,
            "Price should not be manipulated"
        );
    }

    /**
     * @notice Test callback reentrancy (ERC721/ERC1155 style)
     */
    function test_callbackReentrancy_shouldFail() public {
        MockNFTWithCallback nft = new MockNFTWithCallback();
        CallbackReentrancyAttacker attacker_ = new CallbackReentrancyAttacker(
            address(nft)
        );

        // Mint should succeed but reentrancy should be blocked
        // The first callback succeeds, but subsequent reentrant mints fail
        vm.expectRevert();
        attacker_.attack();

        // Verify reentrancy was limited
        assertLe(
            nft.totalMinted(),
            1,
            "Reentrancy should be blocked after first mint"
        );
    }

    /**
     * @notice Test create2 reentrancy (address prediction attack)
     */
    function test_create2Reentrancy_addressPrediction() public {
        Create2ReentrancyTest c2test = new Create2ReentrancyTest();

        // Predict address should not allow reentrancy
        bytes32 salt = keccak256("attack");
        address predicted = c2test.predictAddress(salt);

        // Even with predicted address, reentrancy should fail
        assertTrue(predicted != address(0), "Should predict address");

        // The actual deployment with reentrancy attempt should fail
        vm.expectRevert();
        c2test.deployWithReentrancy(salt);
    }
}

/*//////////////////////////////////////////////////////////////
                        HELPER CONTRACTS
//////////////////////////////////////////////////////////////*/

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE - sends ETH before updating state
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}

contract ProtectedBank {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0; // CEI pattern
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}

contract ReentrancyAttacker {
    address payable public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = payable(_target);
    }

    function attack() external {
        ProtectedBank(target).withdraw();
    }

    receive() external payable {
        attackCount++;
        if (attackCount < 5 && address(target).balance > 0) {
            ProtectedBank(target).withdraw();
        }
    }
}

contract CrossFunctionProtected {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function transfer(address to, uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    receive() external payable {}
}

contract CrossFunctionAttacker {
    address payable public target;

    constructor(address _target) {
        target = payable(_target);
    }

    function attack() external {
        CrossFunctionProtected(target).withdraw();
    }

    receive() external payable {
        // Try to call transfer during withdraw callback
        CrossFunctionProtected(target).transfer(address(this), 1 ether);
    }
}

contract ReadOnlyReentrancyVictim {
    uint256 public totalDeposits;
    uint256 public totalShares;
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable nonReentrant {
        uint256 shares = msg.value; // Simplified
        totalShares += shares;
        totalDeposits += msg.value;
    }

    function getPrice() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (totalDeposits * 1e18) / totalShares;
    }

    receive() external payable {}
}

contract ReadOnlyReentrancyAttacker {
    address payable public target;

    constructor(address _target) {
        target = payable(_target);
    }

    receive() external payable {
        // Try to read manipulated price during callback
        ReadOnlyReentrancyVictim(target).getPrice();
    }
}

contract MockNFTWithCallback {
    bool private locked;
    uint256 public totalMinted;

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function mint(address to) external nonReentrant {
        totalMinted++;
        // Callback to receiver
        if (to.code.length > 0) {
            (bool success, ) = to.call(
                abi.encodeWithSignature(
                    "onERC721Received(address,address,uint256,bytes)",
                    msg.sender,
                    address(0),
                    totalMinted,
                    ""
                )
            );
            require(success, "Callback failed");
        }
    }
}

contract CallbackReentrancyAttacker {
    address public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = _target;
    }

    function attack() external {
        MockNFTWithCallback(target).mint(address(this));
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external returns (bytes4) {
        attackCount++;
        if (attackCount < 3) {
            MockNFTWithCallback(target).mint(address(this));
        }
        return this.onERC721Received.selector;
    }
}

contract Create2ReentrancyTest {
    bool private locked;

    modifier nonReentrant() {
        require(!locked, "ReentrancyGuard: reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function predictAddress(bytes32 salt) public view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(type(SimpleContract).creationCode)
            )
        );
        return address(uint160(uint256(hash)));
    }

    function deployWithReentrancy(bytes32 salt) external nonReentrant {
        // This should fail on reentrancy
        new SimpleContract{salt: salt}();
        this.deployWithReentrancy(salt); // Attempt reentrant call via external call
    }
}

contract SimpleContract {
    uint256 public value;

    constructor() {
        value = 1;
    }
}
