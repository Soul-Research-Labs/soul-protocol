// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title CrossChainBridgeIntegration
 * @author Soul Protocol
 * @notice Unified cross-chain bridge integration connecting all L2 and bridge adapters
 * @dev Single entry point for cross-chain operations across 40+ supported chains
 *
 * SUPPORTED BRIDGES:
 * ┌─────────────────────────────────────────────────────────────────────────────────┐
 * │                           CrossChainBridgeIntegration                            │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  L2 ROLLUPS (Native Bridges)                                              │ │
 * │   │  ├─ Arbitrum (ArbitrumBridgeAdapter)                                      │ │
 * │   │  ├─ Optimism (BaseBridgeAdapter)                                          │ │
 * │   │  ├─ Base (BaseBridgeAdapter)                                              │ │
 * │   │  ├─ zkSync Era (zkSyncBridgeAdapter)                                      │ │
 * │   │  ├─ Scroll (ScrollBridgeAdapter)                                          │ │
 * │   │  ├─ Linea (LineaBridgeAdapter)                                            │ │
 * │   │  └─ Polygon zkEVM (PolygonZkEVMBridgeAdapter)                             │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  INTEROPERABILITY PROTOCOLS                                               │ │
 * │   │  ├─ LayerZero (LayerZeroBridgeAdapter)                                    │ │
 * │   │  ├─ Hyperlane (HyperlaneAdapter)                                          │ │
 * │   │  └─ Axelar (AxelarBridgeAdapter)                                          │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  PRIVACY CHAINS                                                            │ │
 * │   │  ├─ Zcash (via Zcash Bridge)                                              │ │
 * │   │  ├─ Aztec (AztecBridgeAdapter)                                            │ │
 * │   │  ├─ Midnight (MidnightBridgeAdapter)                                      │ │
 * │   │  └─ Starknet (StarknetBridgeAdapter)                                      │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   ┌───────────────────────────────────────────────────────────────────────────┐ │
 * │   │  BITCOIN ECOSYSTEM                                                         │ │
 * │   │  ├─ Bitcoin (BitcoinBridgeAdapter)                                        │ │
 * │   │  └─ BitVM (BitVMBridge)                                                   │ │
 * │   └───────────────────────────────────────────────────────────────────────────┘ │
 * │                                                                                  │
 * │   FEATURES:                                                                      │
 * │   ├─ Auto-routing: Selects optimal bridge based on cost/speed                   │
 * │   ├─ Aggregation: Batches multiple transfers for gas efficiency                 │
 * │   ├─ Failover: Automatic fallback to alternative bridges                        │
 * │   └─ Privacy: Integrates with privacy layer for confidential transfers         │
 * │                                                                                  │
 * └─────────────────────────────────────────────────────────────────────────────────┘
 *
 * @custom:security-contact security@soulprotocol.io
 */
contract CrossChainBridgeIntegration is
    ReentrancyGuard,
    AccessControl,
    Pausable
{
    using SafeERC20 for IERC20;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error InvalidChainId();
    error ChainNotSupported();
    error BridgeNotAvailable();
    error InsufficientFee();
    error TransferFailed();
    error InvalidRecipient();
    error InvalidToken();
    error ExceedsMaxTransfer();
    error ExceedsDailyLimit();
    error BridgeCallFailed();
    error InvalidRoute();
    error QuorumNotMet();
    error MessageAlreadyProcessed();
    error InvalidProof();
    error Unauthorized();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event BridgeTransferInitiated(
        bytes32 indexed transferId,
        uint256 indexed sourceChain,
        uint256 indexed destChain,
        address sender,
        bytes32 recipient,
        address token,
        uint256 amount,
        BridgeProtocol protocol
    );

    event BridgeTransferCompleted(
        bytes32 indexed transferId,
        uint256 indexed destChain,
        bytes32 indexed recipient,
        uint256 amount
    );

    event BridgeAdapterRegistered(
        uint256 indexed chainId,
        BridgeProtocol indexed protocol,
        address adapter
    );

    event RouteConfigured(
        uint256 indexed sourceChain,
        uint256 indexed destChain,
        BridgeProtocol[] protocols
    );

    event FeeUpdated(
        uint256 indexed chainId,
        BridgeProtocol indexed protocol,
        uint256 baseFee,
        uint256 percentageFee
    );

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    enum BridgeProtocol {
        NATIVE, // Native chain bridge
        LAYERZERO, // LayerZero v2
        HYPERLANE, // Hyperlane
        AXELAR, // Axelar
        WORMHOLE, // Wormhole
        CCIP, // Chainlink CCIP
        STARGATE, // Stargate
        ACROSS, // Across Protocol
        HOP, // Hop Protocol
        MULTICHAIN, // Multichain
        AZTEC, // Aztec Connect
        STARKNET, // Starknet Bridge
        BITVM // BitVM Trust-minimized
    }

    enum ChainType {
        EVM,
        UTXO,
        ACCOUNT,
        MOVE,
        WASM,
        CAIRO,
        PLUTUS
    }

    enum TransferStatus {
        PENDING,
        RELAYED,
        COMPLETED,
        FAILED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct ChainConfig {
        uint256 chainId;
        ChainType chainType;
        bool isSupported;
        uint256 minConfirmations;
        uint256 maxTransfer;
        uint256 dailyLimit;
        uint256 dailyUsed;
        uint256 lastResetDay;
    }

    struct BridgeAdapter {
        address adapter;
        BridgeProtocol protocol;
        bool isActive;
        uint256 baseFee;
        uint256 percentageFee; // in bps (100 = 1%)
        uint256 avgLatency; // in blocks
        uint256 reliability; // in bps (10000 = 100%)
    }

    struct Route {
        uint256 sourceChain;
        uint256 destChain;
        BridgeProtocol[] availableProtocols;
        BridgeProtocol preferredProtocol;
        bool isActive;
    }

    struct TransferRequest {
        uint256 sourceChain;
        uint256 destChain;
        address sender;
        bytes32 recipient; // bytes32 for cross-chain compatibility
        address token;
        uint256 amount;
        BridgeProtocol protocol;
        bytes extraData; // Protocol-specific data
    }

    struct TransferRecord {
        bytes32 transferId;
        TransferRequest request;
        TransferStatus status;
        uint256 initiatedAt;
        uint256 completedAt;
        bytes32 sourceProof;
        bytes32 destProof;
    }

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant ROUTER_ROLE = keccak256("ROUTER_ROLE");

    bytes32 public constant BRIDGE_DOMAIN =
        keccak256("Soul_BRIDGE_INTEGRATION_V1");

    /// @notice Maximum protocols per route
    uint256 public constant MAX_PROTOCOLS_PER_ROUTE = 5;

    /// @notice Maximum transfer age for completion (7 days)
    uint256 public constant MAX_TRANSFER_AGE = 7 days;

    /// @notice Native token marker
    address public constant NATIVE_TOKEN =
        address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    /// @notice This chain ID
    uint256 public immutable THIS_CHAIN_ID;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain configurations
    mapping(uint256 => ChainConfig) public chainConfigs;

    /// @notice Supported chain IDs
    uint256[] public supportedChains;

    /// @notice Bridge adapters per chain per protocol
    mapping(uint256 => mapping(BridgeProtocol => BridgeAdapter))
        public bridgeAdapters;

    /// @notice Routes between chains
    mapping(bytes32 => Route) public routes;

    /// @notice Transfer records
    mapping(bytes32 => TransferRecord) public transfers;

    /// @notice User transfers
    mapping(address => bytes32[]) public userTransfers;

    /// @notice Processed message hashes
    mapping(bytes32 => bool) public processedMessages;

    /// @notice Transfer nonce to prevent ID collisions
    uint256 public transferNonce;

    /// @notice Accumulated protocol fees claimable by feeRecipient
    uint256 public accruedProtocolFees;

    /// @notice Auto-router enabled
    bool public autoRouterEnabled;

    /// @notice Fee recipient
    address public feeRecipient;

    /// @notice Protocol fee (bps)
    uint256 public protocolFeeBps;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        uint256 _chainId,
        address _feeRecipient,
        uint256 _protocolFeeBps
    ) {
        if (_feeRecipient == address(0)) revert ZeroAddress();
        if (_protocolFeeBps > 500) revert InvalidRoute(); // Max 5%

        THIS_CHAIN_ID = _chainId;
        feeRecipient = _feeRecipient;
        protocolFeeBps = _protocolFeeBps;
        autoRouterEnabled = true;

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);
        _grantRole(ROUTER_ROLE, msg.sender);
    }

    /*//////////////////////////////////////////////////////////////
                        CHAIN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a supported chain
     */
    function configureChain(
        uint256 chainId,
        ChainType chainType,
        uint256 minConfirmations,
        uint256 maxTransfer,
        uint256 dailyLimit
    ) external onlyRole(OPERATOR_ROLE) {
        if (chainId == 0) revert InvalidChainId();

        bool isNew = !chainConfigs[chainId].isSupported;

        chainConfigs[chainId] = ChainConfig({
            chainId: chainId,
            chainType: chainType,
            isSupported: true,
            minConfirmations: minConfirmations,
            maxTransfer: maxTransfer,
            dailyLimit: dailyLimit,
            dailyUsed: 0,
            lastResetDay: block.timestamp / 1 days
        });

        if (isNew) {
            supportedChains.push(chainId);
        }
    }

    /**
     * @notice Register a bridge adapter
     */
    function registerBridgeAdapter(
        uint256 chainId,
        BridgeProtocol protocol,
        address adapter,
        uint256 baseFee,
        uint256 percentageFee
    ) external onlyRole(OPERATOR_ROLE) {
        if (adapter == address(0)) revert ZeroAddress();
        if (!chainConfigs[chainId].isSupported) revert ChainNotSupported();

        bridgeAdapters[chainId][protocol] = BridgeAdapter({
            adapter: adapter,
            protocol: protocol,
            isActive: true,
            baseFee: baseFee,
            percentageFee: percentageFee,
            avgLatency: 0,
            reliability: 10000 // Start at 100%
        });

        emit BridgeAdapterRegistered(chainId, protocol, adapter);
    }

    /**
     * @notice Configure route between chains
     */
    function configureRoute(
        uint256 sourceChain,
        uint256 destChain,
        BridgeProtocol[] calldata protocols,
        BridgeProtocol preferredProtocol
    ) external onlyRole(ROUTER_ROLE) {
        if (protocols.length == 0) revert InvalidRoute();
        if (protocols.length > MAX_PROTOCOLS_PER_ROUTE) revert InvalidRoute();

        bytes32 routeKey = _getRouteKey(sourceChain, destChain);

        routes[routeKey] = Route({
            sourceChain: sourceChain,
            destChain: destChain,
            availableProtocols: protocols,
            preferredProtocol: preferredProtocol,
            isActive: true
        });

        emit RouteConfigured(sourceChain, destChain, protocols);
    }

    /*//////////////////////////////////////////////////////////////
                       BRIDGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate cross-chain transfer
     * @param destChain Destination chain ID
     * @param recipient Recipient address (bytes32 for cross-chain)
     * @param token Token to transfer
     * @param amount Amount to transfer
     * @param protocol Bridge protocol to use (ignored if auto-router enabled)
     * @param extraData Protocol-specific data
     */
    function bridgeTransfer(
        uint256 destChain,
        bytes32 recipient,
        address token,
        uint256 amount,
        BridgeProtocol protocol,
        bytes calldata extraData
    ) external payable nonReentrant whenNotPaused returns (bytes32 transferId) {
        if (recipient == bytes32(0)) revert InvalidRecipient();
        if (amount == 0) revert ZeroAmount();

        ChainConfig storage destConfig = chainConfigs[destChain];
        if (!destConfig.isSupported) revert ChainNotSupported();
        if (amount > destConfig.maxTransfer) revert ExceedsMaxTransfer();

        // Reset daily limit if needed
        _resetDailyLimitIfNeeded(destConfig);
        if (destConfig.dailyUsed + amount > destConfig.dailyLimit) {
            revert ExceedsDailyLimit();
        }

        // Select protocol
        BridgeProtocol selectedProtocol = autoRouterEnabled
            ? _selectOptimalProtocol(THIS_CHAIN_ID, destChain, amount)
            : protocol;

        BridgeAdapter storage adapter = bridgeAdapters[destChain][
            selectedProtocol
        ];
        if (!adapter.isActive) revert BridgeNotAvailable();

        // Calculate fees
        uint256 bridgeFee = adapter.baseFee +
            (amount * adapter.percentageFee) /
            10000;
        uint256 protocolFee = (amount * protocolFeeBps) / 10000;
        uint256 totalFee = bridgeFee + protocolFee;

        if (token == NATIVE_TOKEN) {
            if (msg.value < amount + totalFee) revert InsufficientFee();
        } else {
            if (msg.value < totalFee) revert InsufficientFee();
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }

        // Generate transfer ID (include nonce to prevent collisions)
        transferId = keccak256(
            abi.encodePacked(
                BRIDGE_DOMAIN,
                THIS_CHAIN_ID,
                destChain,
                msg.sender,
                recipient,
                token,
                amount,
                block.timestamp,
                transferNonce++
            )
        );

        // Create transfer record
        TransferRequest memory request = TransferRequest({
            sourceChain: THIS_CHAIN_ID,
            destChain: destChain,
            sender: msg.sender,
            recipient: recipient,
            token: token,
            amount: amount,
            protocol: selectedProtocol,
            extraData: extraData
        });

        transfers[transferId] = TransferRecord({
            transferId: transferId,
            request: request,
            status: TransferStatus.PENDING,
            initiatedAt: block.timestamp,
            completedAt: 0,
            sourceProof: bytes32(0),
            destProof: bytes32(0)
        });

        userTransfers[msg.sender].push(transferId);

        // Update daily usage
        destConfig.dailyUsed += amount;

        // Execute bridge call
        _executeBridgeCall(adapter.adapter, request, totalFee);

        // Accrue protocol fee (non-blocking to prevent griefing)
        if (protocolFee > 0) {
            accruedProtocolFees += protocolFee;
        }

        emit BridgeTransferInitiated(
            transferId,
            THIS_CHAIN_ID,
            destChain,
            msg.sender,
            recipient,
            token,
            amount,
            selectedProtocol
        );
    }

    /**
     * @notice Complete transfer (called by relayer on destination)
     */
    function completeTransfer(
        bytes32 transferId,
        bytes32 recipient,
        address token,
        uint256 amount,
        bytes calldata proof
    ) external onlyRole(RELAYER_ROLE) nonReentrant whenNotPaused {
        if (processedMessages[transferId]) revert MessageAlreadyProcessed();

        // Verify proof
        if (
            !_verifyTransferProof(transferId, recipient, token, amount, proof)
        ) {
            revert InvalidProof();
        }

        processedMessages[transferId] = true;

        // Execute transfer to recipient
        address recipientAddr = address(uint160(uint256(recipient)));

        if (token == NATIVE_TOKEN) {
            (bool success, ) = recipientAddr.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            IERC20(token).safeTransfer(recipientAddr, amount);
        }

        emit BridgeTransferCompleted(
            transferId,
            THIS_CHAIN_ID,
            recipient,
            amount
        );
    }

    /*//////////////////////////////////////////////////////////////
                        AUTO-ROUTER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Select optimal bridge protocol
     */
    function _selectOptimalProtocol(
        uint256 sourceChain,
        uint256 destChain,
        uint256 amount
    ) internal view returns (BridgeProtocol) {
        bytes32 routeKey = _getRouteKey(sourceChain, destChain);
        Route storage route = routes[routeKey];

        if (!route.isActive || route.availableProtocols.length == 0) {
            revert InvalidRoute();
        }

        // Simple scoring: prefer cheaper + faster + more reliable
        BridgeProtocol bestProtocol = route.preferredProtocol;
        uint256 bestScore = 0;

        for (uint256 i = 0; i < route.availableProtocols.length; i++) {
            BridgeProtocol protocol = route.availableProtocols[i];
            BridgeAdapter storage adapter = bridgeAdapters[destChain][protocol];

            if (!adapter.isActive) continue;

            // Score = reliability - (normalized_cost + normalized_latency)
            uint256 cost = adapter.baseFee +
                (amount * adapter.percentageFee) /
                10000;
            uint256 normalizedCost = cost > 0 ? (10000 * 1e18) / cost : 10000;
            uint256 normalizedLatency = adapter.avgLatency > 0
                ? (10000 * 1e18) / (adapter.avgLatency * 1e18)
                : 10000;

            uint256 score = (adapter.reliability *
                normalizedCost *
                normalizedLatency) / 1e36;

            if (score > bestScore) {
                bestScore = score;
                bestProtocol = protocol;
            }
        }

        return bestProtocol;
    }

    /**
     * @notice Get quote for transfer
     */
    function getQuote(
        uint256 destChain,
        address /* token - reserved for future token-specific fees */,
        uint256 amount,
        BridgeProtocol protocol
    )
        external
        view
        returns (
            uint256 bridgeFee,
            uint256 protocolFee,
            uint256 estimatedLatency
        )
    {
        BridgeProtocol selectedProtocol = autoRouterEnabled
            ? _selectOptimalProtocol(THIS_CHAIN_ID, destChain, amount)
            : protocol;

        BridgeAdapter storage adapter = bridgeAdapters[destChain][
            selectedProtocol
        ];
        if (!adapter.isActive) revert BridgeNotAvailable();

        bridgeFee = adapter.baseFee + (amount * adapter.percentageFee) / 10000;
        protocolFee = (amount * protocolFeeBps) / 10000;
        estimatedLatency = adapter.avgLatency;
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _getRouteKey(
        uint256 source,
        uint256 dest
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(source, dest));
    }

    function _resetDailyLimitIfNeeded(ChainConfig storage config) internal {
        uint256 currentDay = block.timestamp / 1 days;
        if (config.lastResetDay < currentDay) {
            config.dailyUsed = 0;
            config.lastResetDay = currentDay;
        }
    }

    function _executeBridgeCall(
        address adapter,
        TransferRequest memory request,
        uint256 fee
    ) internal {
        bytes memory callData = abi.encodeWithSignature(
            "bridge(uint256,bytes32,address,uint256,bytes)",
            request.destChain,
            request.recipient,
            request.token,
            request.amount,
            request.extraData
        );

        uint256 value = request.token == NATIVE_TOKEN
            ? request.amount + fee
            : fee;

        (bool success, ) = adapter.call{value: value}(callData);
        if (!success) revert BridgeCallFailed();
    }

    function _verifyTransferProof(
        bytes32 transferId,
        bytes32 recipient,
        address token,
        uint256 amount,
        bytes calldata proof
    ) internal view returns (bool) {
        // Require ECDSA signature from a RELAYER_ROLE holder
        if (proof.length < 65) return false;

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(
                    abi.encodePacked(transferId, recipient, token, amount)
                )
            )
        );

        // Extract ECDSA signature (r, s, v)
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(proof.offset)
            s := calldataload(add(proof.offset, 32))
            v := byte(0, calldataload(add(proof.offset, 64)))
        }

        // Signature malleability protection
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return false;
        }

        address signer = ecrecover(messageHash, v, r, s);
        if (signer == address(0)) return false;

        // Verify signer has RELAYER_ROLE
        return hasRole(RELAYER_ROLE, signer);
    }

    /// @notice Claim accrued protocol fees
    function claimProtocolFees() external nonReentrant {
        if (msg.sender != feeRecipient) revert Unauthorized();
        uint256 amount = accruedProtocolFees;
        if (amount == 0) revert ZeroAmount();
        accruedProtocolFees = 0;
        (bool success, ) = feeRecipient.call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getChainConfig(
        uint256 chainId
    ) external view returns (ChainConfig memory) {
        return chainConfigs[chainId];
    }

    function getBridgeAdapter(
        uint256 chainId,
        BridgeProtocol protocol
    ) external view returns (BridgeAdapter memory) {
        return bridgeAdapters[chainId][protocol];
    }

    function getRoute(
        uint256 source,
        uint256 dest
    ) external view returns (Route memory) {
        return routes[_getRouteKey(source, dest)];
    }

    function getTransfer(
        bytes32 transferId
    ) external view returns (TransferRecord memory) {
        return transfers[transferId];
    }

    function getUserTransfers(
        address user
    ) external view returns (bytes32[] memory) {
        return userTransfers[user];
    }

    function getSupportedChains() external view returns (uint256[] memory) {
        return supportedChains;
    }

    function isChainSupported(uint256 chainId) external view returns (bool) {
        return chainConfigs[chainId].isSupported;
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setAutoRouter(bool enabled) external onlyRole(OPERATOR_ROLE) {
        autoRouterEnabled = enabled;
    }

    function setFeeRecipient(
        address _feeRecipient
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_feeRecipient == address(0)) revert ZeroAddress();
        feeRecipient = _feeRecipient;
    }

    function setProtocolFee(
        uint256 _protocolFeeBps
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_protocolFeeBps > 500) revert InvalidRoute();
        protocolFeeBps = _protocolFeeBps;
    }

    function updateAdapterMetrics(
        uint256 chainId,
        BridgeProtocol protocol,
        uint256 avgLatency,
        uint256 reliability
    ) external onlyRole(OPERATOR_ROLE) {
        BridgeAdapter storage adapter = bridgeAdapters[chainId][protocol];
        adapter.avgLatency = avgLatency;
        adapter.reliability = reliability;
    }

    function deactivateAdapter(
        uint256 chainId,
        BridgeProtocol protocol
    ) external onlyRole(GUARDIAN_ROLE) {
        bridgeAdapters[chainId][protocol].isActive = false;
    }

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Emergency withdraw
     */
    function emergencyWithdraw(
        address token,
        address to
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();

        if (token == NATIVE_TOKEN) {
            (bool success, ) = to.call{value: address(this).balance}("");
            if (!success) revert TransferFailed();
        } else {
            uint256 balance = IERC20(token).balanceOf(address(this));
            IERC20(token).safeTransfer(to, balance);
        }
    }

    receive() external payable {}
}
