// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title ICrossChainSanctionsOracle
 * @author ZASEON
 * @notice Interface for quorum-based multi-provider sanctions screening
 */
interface ICrossChainSanctionsOracle {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ScreeningProvider {
        address providerAddress;
        string name;
        uint256 weight;
        bool active;
        uint256 totalScreenings;
    }

    struct SanctionsEntry {
        bool flagged;
        uint256 flagCount;
        uint256 lastUpdated;
        bytes32 reason;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event ProviderRegistered(
        address indexed provider,
        string name,
        uint256 weight
    );
    event ProviderDeactivated(address indexed provider);
    event AddressFlagged(
        address indexed addr,
        address indexed provider,
        bytes32 reason
    );
    event AddressCleared(address indexed addr);
    event QuorumThresholdUpdated(uint256 newThreshold);

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ProviderAlreadyRegistered();
    error ProviderNotRegistered();
    error InvalidWeight();
    error InvalidThreshold();

    /*//////////////////////////////////////////////////////////////
                       SCREENING FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function isSanctioned(address addr) external view returns (bool sanctioned);

    function getSanctionsStatus(
        address addr
    )
        external
        view
        returns (bool flagged, uint256 flagCount, uint256 lastUpdated);

    function batchScreen(
        address[] calldata addrs
    ) external view returns (bool[] memory results);

    /*//////////////////////////////////////////////////////////////
                      PROVIDER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function flagAddress(address addr, bytes32 reason) external;

    function clearAddress(address addr) external;

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerProvider(
        address providerAddress,
        string calldata name,
        uint256 weight
    ) external;

    function deactivateProvider(address providerAddress) external;

    function setQuorumThreshold(uint256 _threshold) external;

    function setFailOpen(bool _failOpen) external;

    function setSanctionsExpiry(uint256 _expiry) external;
}
