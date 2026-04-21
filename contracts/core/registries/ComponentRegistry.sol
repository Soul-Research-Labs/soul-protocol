// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ComponentRegistry
 * @author ZASEON
 * @notice Generic, key-addressable registry of protocol component addresses.
 *         Replaces the 40+ purpose-built setters and ~800-line `wireAll()` currently in
 *         {ZaseonProtocolHub}, allowing the hub to become a thin dispatcher.
 *
 * @dev Each slot is identified by a `bytes32` key (typically the keccak256 of the component
 *      name, e.g. `keccak256("verifierRegistry")`). This removes the need to fork the hub
 *      when new components are added, and reduces wireAll complexity from O(N) conditionals
 *      to a single batch call.
 *
 *      Migration plan (non-breaking): the existing hub can instantiate a ComponentRegistry
 *      and use it as the canonical source of addresses in a follow-up PR. Legacy typed getters
 *      on the hub can be re-implemented as thin wrappers over {get}.
 *
 *      Canonical key constants are provided for the most common components so callers do
 *      not have to rehash strings on the hot path.
 */
contract ComponentRegistry is AccessControl {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant REGISTRY_ADMIN_ROLE =
        keccak256("REGISTRY_ADMIN_ROLE");

    /*//////////////////////////////////////////////////////////////
                         CANONICAL COMPONENT KEYS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant KEY_VERIFIER_REGISTRY =
        keccak256("verifierRegistry");
    bytes32 public constant KEY_UNIVERSAL_VERIFIER =
        keccak256("universalVerifier");
    bytes32 public constant KEY_MULTI_PROVER = keccak256("multiProver");
    bytes32 public constant KEY_STEALTH_ADDRESS_REGISTRY =
        keccak256("stealthAddressRegistry");
    bytes32 public constant KEY_PRIVATE_RELAYER_NETWORK =
        keccak256("privateRelayerNetwork");
    bytes32 public constant KEY_VIEW_KEY_REGISTRY =
        keccak256("viewKeyRegistry");
    bytes32 public constant KEY_SHIELDED_POOL = keccak256("shieldedPool");
    bytes32 public constant KEY_NULLIFIER_MANAGER =
        keccak256("nullifierManager");
    bytes32 public constant KEY_COMPLIANCE_ORACLE =
        keccak256("complianceOracle");
    bytes32 public constant KEY_PROOF_TRANSLATOR = keccak256("proofTranslator");
    bytes32 public constant KEY_PRIVACY_ROUTER = keccak256("privacyRouter");
    bytes32 public constant KEY_RELAY_PROOF_VALIDATOR =
        keccak256("relayProofValidator");
    bytes32 public constant KEY_RELAY_WATCHTOWER = keccak256("relayWatchtower");
    bytes32 public constant KEY_RELAY_CIRCUIT_BREAKER =
        keccak256("relayCircuitBreaker");
    bytes32 public constant KEY_ZK_BOUND_STATE_LOCKS =
        keccak256("zkBoundStateLocks");
    bytes32 public constant KEY_PROOF_CARRYING_CONTAINER =
        keccak256("proofCarryingContainer");
    bytes32 public constant KEY_CROSS_DOMAIN_NULLIFIER_ALGEBRA =
        keccak256("crossDomainNullifierAlgebra");
    bytes32 public constant KEY_POLICY_BOUND_PROOFS =
        keccak256("policyBoundProofs");
    bytes32 public constant KEY_TIMELOCK = keccak256("timelock");
    bytes32 public constant KEY_UPGRADE_TIMELOCK = keccak256("upgradeTimelock");

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(bytes32 => address) private _components;

    /// @notice Enumerable list of keys that have been set (insertion order, no removals).
    bytes32[] public keys;
    mapping(bytes32 => bool) private _keyExists;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ComponentSet(
        bytes32 indexed key,
        address indexed previous,
        address indexed current
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error LengthMismatch(uint256 keysLen, uint256 addrsLen);
    error EmptyBatch();

    constructor(address admin) {
        if (admin == address(0)) revert ZeroAddress();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REGISTRY_ADMIN_ROLE, admin);
    }

    /*//////////////////////////////////////////////////////////////
                            WRITE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Set a component address for `key`. Zero address resets/unsets a component.
    /// @dev Follows the hub's existing semantic: setting address(0) leaves the prior value
    ///      for that key unchanged, mirroring `wireAll` skip-zero-address behavior.
    function set(
        bytes32 key,
        address addr
    ) public onlyRole(REGISTRY_ADMIN_ROLE) {
        if (addr == address(0)) {
            // No-op on zero address to mirror hub wireAll() semantics.
            return;
        }
        address prev = _components[key];
        _components[key] = addr;
        if (!_keyExists[key]) {
            _keyExists[key] = true;
            keys.push(key);
        }
        emit ComponentSet(key, prev, addr);
    }

    /// @notice Batch-set multiple components in a single call.
    function setBatch(
        bytes32[] calldata _keys,
        address[] calldata addrs
    ) external onlyRole(REGISTRY_ADMIN_ROLE) {
        uint256 n = _keys.length;
        if (n == 0) revert EmptyBatch();
        if (n != addrs.length) revert LengthMismatch(n, addrs.length);
        for (uint256 i; i < n; ) {
            set(_keys[i], addrs[i]);
            unchecked {
                ++i;
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                             VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Return the address at `key`, or zero if unset.
    function get(bytes32 key) external view returns (address) {
        return _components[key];
    }

    /// @notice Return true if `key` has ever been set.
    function has(bytes32 key) external view returns (bool) {
        return _keyExists[key];
    }

    /// @notice Return the count of distinct keys ever set.
    function keyCount() external view returns (uint256) {
        return keys.length;
    }
}
