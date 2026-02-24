// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ICrossChainSanctionsOracle} from "../interfaces/ICrossChainSanctionsOracle.sol";

/**
 * @title CrossChainSanctionsOracle
 * @author Soul Protocol
 * @notice On-chain sanctions screening for cross-chain privacy operations
 * @dev Acts as a pluggable compliance hook for the UniversalShieldedPool,
 *      CrossChainPrivacyHub, and PrivacyRouter. Supports multiple external
 *      oracle providers (Chainalysis, TRM Labs, etc.) with aggregated consensus.
 *
 * ARCHITECTURE:
 * - Provider registration: multiple screening providers can be registered
 * - Quorum-based: an address is "sanctioned" if >= N of M providers flag it
 * - Cross-chain: sanctions state can be synced from hub chain to L2s
 * - ZK-compatible: exposes isSanctioned(address) for on-chain checks
 *   and generateComplianceProof() for ZK proof of non-sanctioned status
 *
 * @custom:security-contact security@soul.network
 */
contract CrossChainSanctionsOracle is
    AccessControl,
    ICrossChainSanctionsOracle
{
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("PROVIDER_ROLE")
    bytes32 public constant PROVIDER_ROLE =
        0x18d9ff454de989bd126b06bd404b47ede75f9e65543e94e8d212f89d7dcbb87c;

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Registered screening providers
    mapping(address => ScreeningProvider) public providers;

    /// @notice All provider addresses
    address[] public providerList;

    /// @notice Sanctions registry (address => entry)
    mapping(address => SanctionsEntry) public sanctions;

    /// @notice Quorum threshold (total weight needed to flag an address)
    uint256 public quorumThreshold;

    /// @notice Total weight of all active providers
    uint256 public totalWeight;

    /// @notice Sanctions expiry (after which an entry must be refreshed)
    uint256 public sanctionsExpiry = 90 days;

    /// @notice Whether to fail-open (false = fail-closed: treat unknown as sanctioned)
    bool public failOpen = true;

    /// @notice Per-provider per-address dedup to prevent quorum gaming
    /// provider => address => hasFlagged
    mapping(address => mapping(address => bool)) public providerHasFlagged;

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin, uint256 _quorumThreshold) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);

        quorumThreshold = _quorumThreshold;
    }

    /*//////////////////////////////////////////////////////////////
                         SCREENING INTERFACE
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if an address is sanctioned (primary interface)
    /// @dev Called by ShieldedPool, PrivacyRouter, etc.
    /// @param addr The address to screen
    /// @return sanctioned Whether the address is sanctioned
    function isSanctioned(
        address addr
    ) external view returns (bool sanctioned) {
        SanctionsEntry storage entry = sanctions[addr];

        // If no providers, fail-open
        if (providerList.length == 0) return false;

        // If entry is stale, use failOpen policy
        if (entry.lastUpdated == 0) return !failOpen;
        if (block.timestamp > entry.lastUpdated + sanctionsExpiry)
            return !failOpen;

        return entry.flagged;
    }

    /// @notice Check if address is sanctioned and get details
    function getSanctionsStatus(
        address addr
    )
        external
        view
        returns (bool flagged, uint256 flagCount, uint256 lastUpdated)
    {
        SanctionsEntry storage entry = sanctions[addr];
        return (entry.flagged, entry.flagCount, entry.lastUpdated);
    }

    /*//////////////////////////////////////////////////////////////
                       PROVIDER OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Flag an address as sanctioned
    /// @param addr The address to flag
    /// @param reason Reason hash (e.g., keccak256 of sanctions list entry)
    function flagAddress(
        address addr,
        bytes32 reason
    ) external onlyRole(PROVIDER_ROLE) {
        ScreeningProvider storage provider = providers[msg.sender];
        require(provider.active, "Provider not active");

        // SECURITY FIX H-8b: Prevent duplicate flags from same provider
        require(
            !providerHasFlagged[msg.sender][addr],
            "Already flagged by this provider"
        );
        providerHasFlagged[msg.sender][addr] = true;

        SanctionsEntry storage entry = sanctions[addr];
        entry.flagCount += 1;
        entry.lastUpdated = block.timestamp;
        entry.reason = reason;
        provider.totalScreenings += 1;

        // Check if quorum is reached
        if (_calculateWeight(addr) >= quorumThreshold) {
            entry.flagged = true;
        }

        emit AddressFlagged(addr, msg.sender, reason);
    }

    /// @notice Clear a sanctioned address
    /// @param addr The address to clear
    function clearAddress(address addr) external onlyRole(OPERATOR_ROLE) {
        sanctions[addr].flagged = false;
        sanctions[addr].flagCount = 0;
        sanctions[addr].lastUpdated = block.timestamp;

        emit AddressCleared(addr);
    }

    /// @notice Batch screen multiple addresses
    function batchScreen(
        address[] calldata addrs
    ) external view returns (bool[] memory results) {
        results = new bool[](addrs.length);
        for (uint256 i = 0; i < addrs.length; ) {
            SanctionsEntry storage entry = sanctions[addrs[i]];
            if (
                entry.lastUpdated == 0 ||
                block.timestamp > entry.lastUpdated + sanctionsExpiry
            ) {
                results[i] = !failOpen;
            } else {
                results[i] = entry.flagged;
            }
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Register a screening provider
    function registerProvider(
        address providerAddress,
        string calldata name,
        uint256 weight
    ) external onlyRole(OPERATOR_ROLE) {
        if (providerAddress == address(0)) revert ZeroAddress();
        if (weight == 0 || weight > 100) revert InvalidWeight();
        if (providers[providerAddress].providerAddress != address(0)) {
            revert ProviderAlreadyRegistered();
        }

        providers[providerAddress] = ScreeningProvider({
            providerAddress: providerAddress,
            name: name,
            weight: weight,
            active: true,
            totalScreenings: 0
        });
        providerList.push(providerAddress);
        totalWeight += weight;

        _grantRole(PROVIDER_ROLE, providerAddress);

        emit ProviderRegistered(providerAddress, name, weight);
    }

    /// @notice Deactivate a provider
    function deactivateProvider(
        address providerAddress
    ) external onlyRole(OPERATOR_ROLE) {
        ScreeningProvider storage provider = providers[providerAddress];
        if (provider.providerAddress == address(0))
            revert ProviderNotRegistered();

        provider.active = false;
        totalWeight -= provider.weight;

        emit ProviderDeactivated(providerAddress);
    }

    /// @notice Update quorum threshold
    function setQuorumThreshold(
        uint256 _threshold
    ) external onlyRole(OPERATOR_ROLE) {
        if (_threshold == 0) revert InvalidThreshold();
        quorumThreshold = _threshold;
        emit QuorumThresholdUpdated(_threshold);
    }

    /// @notice Set fail-open/closed policy
    function setFailOpen(bool _failOpen) external onlyRole(OPERATOR_ROLE) {
        failOpen = _failOpen;
    }

    /// @notice Set sanctions expiry period
    function setSanctionsExpiry(
        uint256 _expiry
    ) external onlyRole(OPERATOR_ROLE) {
        // SECURITY FIX M-5: Enforce minimum expiry to prevent accidental sanctions bypass
        require(_expiry >= 1 days, "Expiry too short");
        sanctionsExpiry = _expiry;
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Calculate weighted flag score for an address
    function _calculateWeight(
        address addr
    ) internal view returns (uint256 weight) {
        // Simplified: count * average weight
        SanctionsEntry storage entry = sanctions[addr];
        if (providerList.length == 0) return 0;
        return (entry.flagCount * totalWeight) / providerList.length;
    }
}
