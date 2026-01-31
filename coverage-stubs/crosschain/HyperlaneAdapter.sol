// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

// STUB for coverage only
contract HyperlaneAdapter is AccessControl, Pausable {
    struct ISMConfig {
        address ism;
        ISMType ismType;
        bool enabled;
        uint8 threshold;
        address[] validators;
    }

    enum ISMType { UNUSED, MULTISIG, ROUTING, AGGREGATION }

    struct MultisigConfig {
        uint8 threshold;
        bytes32 validatorsHash;
    }
    mapping(uint32 => ISMConfig) public ismConfigs;
    mapping(uint32 => MultisigConfig) public multisigParams; // Threshold and commitment
    mapping(uint32 => bytes32) public trustedSenders;

    constructor(address, uint32, address) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function setMultisigParams(uint32, address[] calldata, uint8) external {}
    function setTrustedSender(uint32, bytes32) external {}
    function setISMConfig(uint32, ISMConfig calldata) external {}
    function pause() external { _pause(); }
}
