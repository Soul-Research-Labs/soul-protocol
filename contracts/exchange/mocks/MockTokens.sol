// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockERC20
 * @notice Mock ERC20 token for testing the PIL Private Exchange
 */
contract MockERC20 is ERC20, Ownable {
    uint8 private _decimals;

    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_
    ) ERC20(name_, symbol_) Ownable(msg.sender) {
        _decimals = decimals_;
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }
}

/**
 * @title MockUSDC
 * @notice Mock USDC token (6 decimals)
 */
contract MockUSDC is MockERC20 {
    constructor() MockERC20("USD Coin", "USDC", 6) {}
}

/**
 * @title MockWETH
 * @notice Mock Wrapped ETH token (18 decimals)
 */
contract MockWETH is MockERC20 {
    constructor() MockERC20("Wrapped Ether", "WETH", 18) {}

    function deposit() external payable {
        _mint(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        _burn(msg.sender, amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");
    }

    receive() external payable {
        _mint(msg.sender, msg.value);
    }
}

/**
 * @title MockWBTC
 * @notice Mock Wrapped Bitcoin token (8 decimals)
 */
contract MockWBTC is MockERC20 {
    constructor() MockERC20("Wrapped Bitcoin", "WBTC", 8) {}
}

/**
 * @title MockDAI
 * @notice Mock DAI Stablecoin (18 decimals)
 */
contract MockDAI is MockERC20 {
    constructor() MockERC20("Dai Stablecoin", "DAI", 18) {}
}

/**
 * @title MockSOUL
 * @notice Mock SOUL Token for Soul Network (18 decimals)
 */
contract MockSOUL is MockERC20 {
    constructor() MockERC20("Soul Network Token", "SOUL", 18) {}
}
