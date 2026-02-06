// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title MockWrappedSOL
 * @notice Mock ERC-20 token representing wrapped SOL (wSOL) for testing
 * @dev 9 decimals to match SOL's lamport granularity (1 SOL = 1,000,000,000 lamports)
 *      Includes mint/burn for bridge adapter integration testing
 */
contract MockWrappedSOL is ERC20, ERC20Burnable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    uint8 private constant WSOL_DECIMALS = 9;

    constructor(address admin) ERC20("Wrapped SOL", "wSOL") {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        // Pre-mint 10M wSOL to admin for testing
        _mint(admin, 10_000_000 * 10 ** WSOL_DECIMALS);
    }

    function decimals() public pure override returns (uint8) {
        return WSOL_DECIMALS;
    }

    /// @notice Mint wSOL (bridge adapter calls this on deposit completion)
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @notice Burn wSOL (bridge adapter calls this on withdrawal)
    function burn(uint256 amount) public override {
        super.burn(amount);
    }

    /// @notice Grant minter role to bridge adapter
    function grantMinter(address minter) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(MINTER_ROLE, minter);
    }
}
