// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TransparentUpgradeableProxy
/// @notice Minimal transparent proxy for upgradeable contracts
contract TransparentUpgradeableProxy {
    address public implementation;
    address public admin;

    constructor(address _implementation, address _admin) {
        implementation = _implementation;
        admin = _admin;
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "Not admin");
        implementation = newImplementation;
    }

    function changeAdmin(address newAdmin) external {
        require(msg.sender == admin, "Not admin");
        admin = newAdmin;
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "No implementation");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    receive() external payable {}
}
