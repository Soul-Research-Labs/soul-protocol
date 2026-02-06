// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockWrappedHASH
 * @notice Mock wHASH token for testing the Provenance bridge adapter
 * @dev Uses 9 decimals matching HASH's native nhash precision (1 HASH = 1e9 nhash)
 */
contract MockWrappedHASH is ERC20, Ownable {
    uint8 private constant _DECIMALS = 9;

    constructor() ERC20("Wrapped HASH", "wHASH") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return _DECIMALS;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address account, uint256 amount) external {
        _burn(account, amount);
    }
}
