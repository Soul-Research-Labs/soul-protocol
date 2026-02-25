// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IUniversalChainAdapter} from "../interfaces/IUniversalChainAdapter.sol";
import {UniversalChainRegistry} from "../libraries/UniversalChainRegistry.sol";

/**
 * @title UniversalAdapterRegistry
 * @author Soul Protocol
 * @notice Central registry for all chain adapters across every blockchain ecosystem
 * @dev Manages the mapping of universal chain IDs to their adapter contracts,
 *      tracks supported proof systems, and facilitates cross-chain adapter discovery.
 *
 * This contract is deployed on a hub chain (e.g., Ethereum mainnet) and serves as
 * the canonical source of truth for which adapters are available across the network.
 *
 * ARCHITECTURE:
 *
 *   ┌──────────────────────────────────────────────────────────────────┐
 *   │                 Universal Adapter Registry (Hub)                 │
 *   ├──────────────────────────────────────────────────────────────────┤
 *   │                                                                  │
 *   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
 *   │  │  EVM Chain  │  │  Non-EVM    │  │  Privacy    │             │
 *   │  │  Adapters   │  │  Adapters   │  │  Adapters   │             │
 *   │  │             │  │             │  │             │             │
 *   │  │ • Ethereum  │  │ • Solana    │  │ • Aztec     │             │
 *   │  │ • Arbitrum  │  │ • Aptos     │  │ • Midnight  │             │
 *   │  │ • Optimism  │  │ • Sui       │  │ • Zcash     │             │
 *   │  │ • Base      │  │ • StarkNet  │  │ • Aleo      │             │
 *   │  │ • zkSync    │  │ • Cosmos    │  │             │             │
 *   │  │ • Scroll    │  │ • TON       │  │             │             │
 *   │  │ • Linea     │  │ • NEAR      │  │             │             │
 *   │  │ • Polygon   │  │ • Polkadot  │  │             │             │
 *   │  │             │  │ • Bitcoin   │  │             │             │
 *   │  └─────────────┘  └─────────────┘  └─────────────┘             │
 *   └──────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@soul.network
 */
contract UniversalAdapterRegistry is AccessControl, ReentrancyGuard, Pausable {
    using UniversalChainRegistry for *;

    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev keccak256("EMERGENCY_ROLE")
    bytes32 public constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice On-chain adapter entry (for EVM adapters deployed on this chain)
    struct EVMAdapterEntry {
        bytes32 universalChainId;
        address adapterContract;
        IUniversalChainAdapter.ChainVM vm;
        IUniversalChainAdapter.ChainLayer layer;
        IUniversalChainAdapter.ProofSystem proofSystem;
        string name;
        bool active;
        uint256 registeredAt;
        uint256 totalProofsRelayed;
    }

    /// @notice Off-chain adapter entry (for non-EVM chains where the adapter
    ///         is deployed natively — Solana, StarkNet, Aptos, etc.)
    struct ExternalAdapterEntry {
        bytes32 universalChainId;
        bytes adapterIdentifier; // Program ID, contract address in native format
        IUniversalChainAdapter.ChainVM vm;
        IUniversalChainAdapter.ChainLayer layer;
        IUniversalChainAdapter.ProofSystem proofSystem;
        string name;
        bool active;
        uint256 registeredAt;
        uint256 totalProofsRelayed;
    }

    /// @notice Route between two chains
    struct CrossChainRoute {
        bytes32 sourceChainId;
        bytes32 destChainId;
        bool active;
        uint256 totalRelays;
        uint256 lastRelayAt;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice EVM adapter registry (universalChainId => EVMAdapterEntry)
    mapping(bytes32 => EVMAdapterEntry) public evmAdapters;

    /// @notice External (non-EVM) adapter registry
    mapping(bytes32 => ExternalAdapterEntry) public externalAdapters;

    /// @notice All registered chain IDs
    bytes32[] public registeredChains;

    /// @notice Chain ID to index mapping for enumeration
    mapping(bytes32 => uint256) public chainIndex;

    /// @notice Whether a chain is registered
    mapping(bytes32 => bool) public isChainRegistered;

    /// @notice Cross-chain routes (sourceChainId => destChainId => route)
    mapping(bytes32 => mapping(bytes32 => CrossChainRoute)) public routes;

    /// @notice Supported proof systems per chain
    mapping(bytes32 => IUniversalChainAdapter.ProofSystem[])
        public chainProofSystems;

    /// @notice Total number of registered chains
    uint256 public totalChains;

    /// @notice Total number of active routes
    uint256 public totalActiveRoutes;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event EVMAdapterRegistered(
        bytes32 indexed universalChainId,
        address indexed adapterContract,
        IUniversalChainAdapter.ChainVM vm,
        string name
    );

    event ExternalAdapterRegistered(
        bytes32 indexed universalChainId,
        bytes adapterIdentifier,
        IUniversalChainAdapter.ChainVM vm,
        string name
    );

    event AdapterDeactivated(bytes32 indexed universalChainId);
    event AdapterActivated(bytes32 indexed universalChainId);

    event RouteCreated(
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId
    );

    event RouteDeactivated(
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId
    );

    event ProofRelayed(
        bytes32 indexed sourceChainId,
        bytes32 indexed destChainId,
        bytes32 indexed proofId
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ChainAlreadyRegistered(bytes32 chainId);
    error ChainNotRegistered(bytes32 chainId);
    error AdapterNotActive(bytes32 chainId);
    error RouteNotActive(bytes32 source, bytes32 dest);
    error RouteAlreadyExists(bytes32 source, bytes32 dest);
    error ZeroAddress();
    error EmptyIdentifier();
    error SelfRoute();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(EMERGENCY_ROLE, _admin);
    }

    /*//////////////////////////////////////////////////////////////
                    EVM ADAPTER REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Register an EVM-based chain adapter
    /// @param universalChainId The universal chain identifier
    /// @param adapterContract The deployed adapter contract address
    /// @param vm The VM type (should be EVM)
    /// @param layer The chain layer classification
    /// @param proofSystem The native proof system
    /// @param name Human-readable chain name
    function registerEVMAdapter(
        bytes32 universalChainId,
        address adapterContract,
        IUniversalChainAdapter.ChainVM vm,
        IUniversalChainAdapter.ChainLayer layer,
        IUniversalChainAdapter.ProofSystem proofSystem,
        string calldata name
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapterContract == address(0)) revert ZeroAddress();
        if (isChainRegistered[universalChainId])
            revert ChainAlreadyRegistered(universalChainId);

        evmAdapters[universalChainId] = EVMAdapterEntry({
            universalChainId: universalChainId,
            adapterContract: adapterContract,
            vm: vm,
            layer: layer,
            proofSystem: proofSystem,
            name: name,
            active: true,
            registeredAt: block.timestamp,
            totalProofsRelayed: 0
        });

        _registerChain(universalChainId);

        emit EVMAdapterRegistered(universalChainId, adapterContract, vm, name);
    }

    /// @notice Register a non-EVM chain adapter (Solana, StarkNet, Aptos, etc.)
    /// @param universalChainId The universal chain identifier
    /// @param adapterIdentifier The native adapter address/program ID
    /// @param vm The VM type
    /// @param layer The chain layer classification
    /// @param proofSystem The native proof system
    /// @param name Human-readable chain name
    function registerExternalAdapter(
        bytes32 universalChainId,
        bytes calldata adapterIdentifier,
        IUniversalChainAdapter.ChainVM vm,
        IUniversalChainAdapter.ChainLayer layer,
        IUniversalChainAdapter.ProofSystem proofSystem,
        string calldata name
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapterIdentifier.length == 0) revert EmptyIdentifier();
        if (isChainRegistered[universalChainId])
            revert ChainAlreadyRegistered(universalChainId);

        externalAdapters[universalChainId] = ExternalAdapterEntry({
            universalChainId: universalChainId,
            adapterIdentifier: adapterIdentifier,
            vm: vm,
            layer: layer,
            proofSystem: proofSystem,
            name: name,
            active: true,
            registeredAt: block.timestamp,
            totalProofsRelayed: 0
        });

        _registerChain(universalChainId);

        emit ExternalAdapterRegistered(
            universalChainId,
            adapterIdentifier,
            vm,
            name
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ROUTE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Create a cross-chain route between two chains
    /// @param sourceChainId The source chain universal ID
    /// @param destChainId The destination chain universal ID
    function createRoute(
        bytes32 sourceChainId,
        bytes32 destChainId
    ) external onlyRole(OPERATOR_ROLE) {
        if (!isChainRegistered[sourceChainId])
            revert ChainNotRegistered(sourceChainId);
        if (!isChainRegistered[destChainId])
            revert ChainNotRegistered(destChainId);
        if (sourceChainId == destChainId) revert SelfRoute();

        if (routes[sourceChainId][destChainId].active) {
            revert RouteAlreadyExists(sourceChainId, destChainId);
        }

        routes[sourceChainId][destChainId] = CrossChainRoute({
            sourceChainId: sourceChainId,
            destChainId: destChainId,
            active: true,
            totalRelays: 0,
            lastRelayAt: 0
        });

        unchecked {
            ++totalActiveRoutes;
        }

        emit RouteCreated(sourceChainId, destChainId);
    }

    /// @notice Create bidirectional route between two chains
    function createBidirectionalRoute(
        bytes32 chainA,
        bytes32 chainB
    ) external onlyRole(OPERATOR_ROLE) {
        if (!isChainRegistered[chainA]) revert ChainNotRegistered(chainA);
        if (!isChainRegistered[chainB]) revert ChainNotRegistered(chainB);
        if (chainA == chainB) revert SelfRoute();

        if (!routes[chainA][chainB].active) {
            routes[chainA][chainB] = CrossChainRoute({
                sourceChainId: chainA,
                destChainId: chainB,
                active: true,
                totalRelays: 0,
                lastRelayAt: 0
            });
            unchecked {
                ++totalActiveRoutes;
            }
            emit RouteCreated(chainA, chainB);
        }

        if (!routes[chainB][chainA].active) {
            routes[chainB][chainA] = CrossChainRoute({
                sourceChainId: chainB,
                destChainId: chainA,
                active: true,
                totalRelays: 0,
                lastRelayAt: 0
            });
            unchecked {
                ++totalActiveRoutes;
            }
            emit RouteCreated(chainB, chainA);
        }
    }

    /// @notice Deactivate a route
    function deactivateRoute(
        bytes32 sourceChainId,
        bytes32 destChainId
    ) external onlyRole(OPERATOR_ROLE) {
        if (!routes[sourceChainId][destChainId].active) {
            revert RouteNotActive(sourceChainId, destChainId);
        }

        routes[sourceChainId][destChainId].active = false;

        unchecked {
            --totalActiveRoutes;
        }

        emit RouteDeactivated(sourceChainId, destChainId);
    }

    /*//////////////////////////////////////////////////////////////
                       ADAPTER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Deactivate a chain adapter
    function deactivateAdapter(
        bytes32 universalChainId
    ) external onlyRole(OPERATOR_ROLE) {
        if (!isChainRegistered[universalChainId])
            revert ChainNotRegistered(universalChainId);

        // Try EVM first
        if (evmAdapters[universalChainId].adapterContract != address(0)) {
            evmAdapters[universalChainId].active = false;
        } else {
            externalAdapters[universalChainId].active = false;
        }

        emit AdapterDeactivated(universalChainId);
    }

    /// @notice Activate a chain adapter
    function activateAdapter(
        bytes32 universalChainId
    ) external onlyRole(OPERATOR_ROLE) {
        if (!isChainRegistered[universalChainId])
            revert ChainNotRegistered(universalChainId);

        if (evmAdapters[universalChainId].adapterContract != address(0)) {
            evmAdapters[universalChainId].active = true;
        } else {
            externalAdapters[universalChainId].active = true;
        }

        emit AdapterActivated(universalChainId);
    }

    /// @notice Record a proof relay between chains (called by relayer)
    function recordProofRelay(
        bytes32 sourceChainId,
        bytes32 destChainId,
        bytes32 proofId
    ) external onlyRole(OPERATOR_ROLE) nonReentrant {
        if (!routes[sourceChainId][destChainId].active) {
            revert RouteNotActive(sourceChainId, destChainId);
        }

        routes[sourceChainId][destChainId].totalRelays += 1;
        routes[sourceChainId][destChainId].lastRelayAt = block.timestamp;

        // Update adapter stats
        if (evmAdapters[sourceChainId].adapterContract != address(0)) {
            evmAdapters[sourceChainId].totalProofsRelayed += 1;
        } else {
            externalAdapters[sourceChainId].totalProofsRelayed += 1;
        }

        emit ProofRelayed(sourceChainId, destChainId, proofId);
    }

    /*//////////////////////////////////////////////////////////////
                          EMERGENCY
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Get all registered chain IDs
    function getRegisteredChains() external view returns (bytes32[] memory) {
        return registeredChains;
    }

    /// @notice Check if a route is active between two chains
    function isRouteActive(
        bytes32 sourceChainId,
        bytes32 destChainId
    ) external view returns (bool) {
        return routes[sourceChainId][destChainId].active;
    }

    /// @notice Get the EVM adapter address for a chain
    function getEVMAdapterAddress(
        bytes32 universalChainId
    ) external view returns (address) {
        return evmAdapters[universalChainId].adapterContract;
    }

    /// @notice Get the external adapter identifier for a chain
    function getExternalAdapterIdentifier(
        bytes32 universalChainId
    ) external view returns (bytes memory) {
        return externalAdapters[universalChainId].adapterIdentifier;
    }

    /// @notice Check if an adapter is active
    function isAdapterActive(
        bytes32 universalChainId
    ) external view returns (bool) {
        if (evmAdapters[universalChainId].adapterContract != address(0)) {
            return evmAdapters[universalChainId].active;
        }
        return externalAdapters[universalChainId].active;
    }

    /// @notice Get the VM type for a chain
    function getChainVM(
        bytes32 universalChainId
    ) external view returns (IUniversalChainAdapter.ChainVM) {
        if (evmAdapters[universalChainId].adapterContract != address(0)) {
            return evmAdapters[universalChainId].vm;
        }
        return externalAdapters[universalChainId].vm;
    }

    /// @notice Get route statistics
    function getRouteStats(
        bytes32 sourceChainId,
        bytes32 destChainId
    ) external view returns (uint256 totalRelays, uint256 lastRelayAt) {
        CrossChainRoute storage route = routes[sourceChainId][destChainId];
        return (route.totalRelays, route.lastRelayAt);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerChain(bytes32 universalChainId) internal {
        isChainRegistered[universalChainId] = true;
        chainIndex[universalChainId] = registeredChains.length;
        registeredChains.push(universalChainId);

        unchecked {
            ++totalChains;
        }
    }
}
