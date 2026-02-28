// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IRelayerAdapter.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title SelfRelayAdapter
 * @author ZASEON
 * @notice Allows users to relay their own cross-chain messages directly without
 *         a third-party relayer, eliminating censorship risk and relayer dependency.
 *
 * @dev Implements IRelayerAdapter so it can be plugged into the same infrastructure
 *      as GelatoRelayAdapter or any future relayer adapter. The user pays gas directly
 *      and the adapter forwards the call to the target contract.
 *
 *      Key features:
 *      - No relayer fee (user pays gas directly)
 *      - Censorship resistant (no intermediary can block messages)
 *      - Nonce-based replay protection per sender
 *      - Gas limit enforcement for safety
 *      - Integration with RelayerHealthMonitor for stats tracking
 *      - Pausable for emergency scenarios
 *
 * @custom:security-contact security@zaseonprotocol.io
 */
contract SelfRelayAdapter is
    IRelayerAdapter,
    AccessControl,
    ReentrancyGuard,
    Pausable
{
    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Maximum gas limit a self-relay call can specify (10M)
    uint256 public constant MAX_GAS_LIMIT = 10_000_000;

    /// @notice Minimum gas limit to prevent griefing with too-low gas
    uint256 public constant MIN_GAS_LIMIT = 21_000;

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Per-sender nonce for replay protection
    mapping(address => uint256) public nonces;

    /// @notice Optional RelayerHealthMonitor for tracking self-relay stats
    address public healthMonitor;

    /// @notice Total number of self-relayed messages
    uint256 public totalRelayed;

    /// @notice Total number of failed self-relayed messages
    uint256 public totalFailed;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SelfRelayed(
        bytes32 indexed taskId,
        address indexed sender,
        address indexed target,
        uint256 nonce,
        bool success
    );

    event HealthMonitorUpdated(
        address indexed oldMonitor,
        address indexed newMonitor
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidTarget();
    error GasLimitTooLow(uint256 provided, uint256 minimum);
    error GasLimitTooHigh(uint256 provided, uint256 maximum);
    error CallFailed(bytes32 taskId, bytes returnData);

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Deploy the SelfRelayAdapter
     * @param _admin Address that receives DEFAULT_ADMIN_ROLE and PAUSER_ROLE
     * @param _healthMonitor Optional RelayerHealthMonitor address (address(0) to skip)
     */
    constructor(address _admin, address _healthMonitor) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);
        healthMonitor = _healthMonitor;
    }

    /*//////////////////////////////////////////////////////////////
                           CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Relay a message directly from the caller to the target contract
     * @dev The caller pays gas and the call is forwarded with the specified gas limit.
     *      A unique taskId is generated from the sender, nonce, and target for tracking.
     *      Any value sent is forwarded to the target.
     * @param target The destination contract to call
     * @param payload The calldata to forward to the target
     * @param gasLimit The gas limit for the forwarded call
     * @return taskId Unique identifier for tracking this relay
     */
    function relayMessage(
        address target,
        bytes calldata payload,
        uint256 gasLimit
    )
        external
        payable
        override
        nonReentrant
        whenNotPaused
        returns (bytes32 taskId)
    {
        if (target == address(0)) revert InvalidTarget();
        if (gasLimit < MIN_GAS_LIMIT)
            revert GasLimitTooLow(gasLimit, MIN_GAS_LIMIT);
        if (gasLimit > MAX_GAS_LIMIT)
            revert GasLimitTooHigh(gasLimit, MAX_GAS_LIMIT);

        uint256 currentNonce = nonces[msg.sender]++;

        // Generate deterministic task ID
        taskId = keccak256(
            abi.encode(msg.sender, currentNonce, target, block.chainid)
        );

        // Forward call to target
        (bool success, bytes memory returnData) = target.call{
            value: msg.value,
            gas: gasLimit
        }(payload);

        if (success) {
            unchecked {
                ++totalRelayed;
            }
        } else {
            unchecked {
                ++totalFailed;
            }
        }

        emit SelfRelayed(taskId, msg.sender, target, currentNonce, success);

        // Report to health monitor if configured
        if (healthMonitor != address(0)) {
            _reportToMonitor(msg.sender, success);
        }

        if (!success) {
            revert CallFailed(taskId, returnData);
        }

        return taskId;
    }

    /**
     * @notice Get the fee for self-relaying (always zero — user pays gas directly)
     * @return fee Always returns 0
     */
    function getFee(
        uint256 /* gasLimit */
    ) external pure override returns (uint256) {
        return 0;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get the current nonce for a sender
     * @param sender The address to check
     * @return The current nonce (next task will use this nonce)
     */
    function getNonce(address sender) external view returns (uint256) {
        return nonces[sender];
    }

    /**
     * @notice Get relay statistics
     * @return _totalRelayed Total successful relays
     * @return _totalFailed Total failed relays
     */
    function getStats()
        external
        view
        returns (uint256 _totalRelayed, uint256 _totalFailed)
    {
        return (totalRelayed, totalFailed);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Update the health monitor address
     * @param _healthMonitor New health monitor address (address(0) to disable)
     */
    function setHealthMonitor(
        address _healthMonitor
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        address old = healthMonitor;
        healthMonitor = _healthMonitor;
        emit HealthMonitorUpdated(old, _healthMonitor);
    }

    /**
     * @notice Pause the adapter (emergency only)
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the adapter
     */
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Report relay result to the health monitor.
     *      Uses a low-level call to avoid reverting if the monitor is misconfigured.
     */
    function _reportToMonitor(address relayer, bool success) internal {
        // Best-effort reporting — don't revert if monitor call fails
        if (success) {
            // recordSuccess(address, uint256) — latency = 0 for self-relay (instant)
            (bool ok, ) = healthMonitor.call(
                abi.encodeWithSignature(
                    "recordSuccess(address,uint256)",
                    relayer,
                    0
                )
            );
            // Silence unused variable warning
            ok;
        } else {
            (bool ok, ) = healthMonitor.call(
                abi.encodeWithSignature("reportFailure(address)", relayer)
            );
            ok;
        }
    }
}
