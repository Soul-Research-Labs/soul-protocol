# ADR-012: Bridge Plugin Architecture (IBridgeAdapter)

## Status

Accepted

## Date

2026-03-01

## Context

ZASEON supports 12 bridge protocols across 7 L2 networks. Each bridge has different:

1. **Messaging semantics**: Native messaging vs third-party relayers
2. **Finality models**: Optimistic (7-day challenge) vs ZK (proof-based)
3. **Fee structures**: Gas-based vs token-based vs subscription
4. **Security models**: L1 finality vs validator sets vs multi-sig

A unified routing layer must abstract these differences while preserving protocol-specific capabilities.

## Decision

Define a minimal **`IBridgeAdapter`** interface that all bridge adapters implement, enabling the `MultiBridgeRouter` to route messages polymorphically.

### IBridgeAdapter interface

```solidity
interface IBridgeAdapter {
    function bridgeMessage(
        uint256 dstChainId,
        address receiver,
        bytes calldata message
    ) external payable returns (bytes32 messageId);

    function estimateFee(
        uint256 dstChainId,
        bytes calldata message
    ) external view returns (uint256 nativeFee);

    function isMessageVerified(
        bytes32 messageId
    ) external view returns (bool);
}
```

### Design principles

1. **Minimal interface**: Only 3 functions — send, quote, verify. Adapter-specific features accessed directly
2. **Chain ID addressing**: Use EVM chain IDs (not protocol-specific identifiers like LayerZero EIDs)
3. **Native fee payments**: `msg.value` for bridge fees, no token approvals needed
4. **Message ID tracking**: All adapters return a `bytes32` message ID for status tracking

### Adapter classification

| Type        | Adapters                                        | Trust model          |
| ----------- | ----------------------------------------------- | -------------------- |
| Native L2   | Arbitrum, Optimism, Base, zkSync, Scroll, Linea | L1 settlement        |
| Third-party | LayerZero, Hyperlane, Wormhole, Axelar, CCIP    | Validator/oracle set |
| Privacy     | Aztec                                           | Shielded execution   |

### Internal chain ID mapping

Adapters translate between EVM chain IDs and protocol-specific identifiers:

- LayerZero: chain ID → endpoint ID (uint32)
- Hyperlane: chain ID → domain (uint32)
- Wormhole: chain ID → Wormhole chain ID (uint16)

### Rationale

- **Polymorphism**: `MultiBridgeRouter` treats all adapters uniformly
- **Extensibility**: New bridges added by deploying new adapter + registering in router
- **Minimal coupling**: Router doesn't depend on any specific bridge protocol
- **Composability**: Adapters can be paused, replaced, or upgraded independently

## Consequences

- All 9 bridge adapters implement `IBridgeAdapter`
- Adapter-specific features (e.g., LayerZero DVN config) accessed via adapter-specific interfaces
- `MultiBridgeRouter` manages adapter registry and routing configuration
- Testing: Each adapter has unit tests + an `IBridgeAdapter` compatibility test suite
- Gas overhead: ~3k for the `IBridgeAdapter` abstraction layer per message
