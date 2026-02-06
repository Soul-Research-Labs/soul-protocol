// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedPLASMA
 * @notice Mock wPLASMA ERC-20 token for testing the Plasma bridge adapter
 * @dev 8 decimals matching Plasma's satoplasma denomination (1 PLASMA = 1e8 satoplasma)
 */
contract MockWrappedPLASMA is ERC20, Ownable {
    constructor() ERC20("Wrapped PLASMA", "wPLASMA") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return 8;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) external {
        _spendAllowance(account, msg.sender, amount);
        _burn(account, amount);
    }
}
