// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

// STUB for coverage only
contract ArbitrumBridgeAdapter is AccessControl {
    constructor(address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    uint256 public constant ARB_ONE_CHAIN_ID = 42161;
    uint256 public constant ARB_NOVA_CHAIN_ID = 42170;
    
    uint256 public bridgeFee;
    address public treasury;
    bool public fastExitEnabled;
    bool public paused;

    function pause() external { paused = true; }
    function unpause() external { paused = false; }
    
    function setBridgeFee(uint256 fee) external { bridgeFee = fee; }
    function setTreasury(address t) external { treasury = t; }
    function setFastExitEnabled(bool e) external { fastExitEnabled = e; }

    function bridgeToArbitrum(address, uint256, bytes calldata) external payable {}
}
