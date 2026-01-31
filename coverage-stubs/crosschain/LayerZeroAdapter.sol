// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract LayerZeroAdapter is AccessControl, Pausable {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(uint32 => bytes32) public trustedRemotes;

    struct UlnConfig {
        uint64 confirmations;
        uint8 requiredDVNCount;
        uint8 optionalDVNCount;
        uint8 optionalDVNThreshold;
        address[] requiredDVNs;
        address[] optionalDVNs;
    }

    constructor(address, uint256, address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function sendMessage(uint16 chainId, bytes calldata payload) external payable {}
    function receiveMessage(uint16 chainId, bytes calldata payload) external {}
    function setUlnConfig(uint16 eid, UlnConfig calldata config) external {}
    function getUlnConfig(uint16 eid) external view returns (UlnConfig memory) {
        return UlnConfig(0, 0, 0, 0, new address[](0), new address[](0));
    }
    
    function setTrustedRemote(uint32 eid, bytes32 remote) external {
        trustedRemotes[eid] = remote;
    }

    function dvnConfirm(bytes32 messageId) external {}

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }
}
