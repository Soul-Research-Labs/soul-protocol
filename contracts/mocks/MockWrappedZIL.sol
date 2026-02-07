// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedZIL
 * @notice Mock ERC-20 token representing wrapped ZIL for testing
 * @dev Uses 12 decimals to match Zilliqa's Qa denomination (1 ZIL = 1e12 Qa)
 */
contract MockWrappedZIL is ERC20, Ownable {
    constructor() ERC20("Wrapped ZIL", "wZIL") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return 12;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }

    function burnFrom(address account, uint256 amount) public {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }
}
