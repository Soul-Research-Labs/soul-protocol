// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
contract TransparentUpgradeableProxy {
    constructor(address, address) {}
    function implementation() public view returns (address) { return address(0); }
    function admin() public view returns (address) { return address(0); }
    function upgradeTo(address) external {}
    function changeAdmin(address) external {}
    fallback() external payable {}
    receive() external payable {}
    function emergencyWithdrawETH(address payable, uint256) external {}
}
