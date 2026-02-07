// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockWrappedNEAR
/// @notice Mock wrapped NEAR token for testing bridge adapters
/// @dev Uses 24 decimals to match NEAR's yoctoNEAR denomination
contract MockWrappedNEAR is ERC20, Ownable {
    constructor() ERC20("Wrapped NEAR", "wNEAR") Ownable(msg.sender) {}

    function decimals() public pure override returns (uint8) {
        return 24;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    function burnFrom(address from, uint256 amount) external {
        _spendAllowance(from, msg.sender, amount);
        _burn(from, amount);
    }
}
