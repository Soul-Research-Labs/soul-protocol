# Bridge Adapter Comparison Matrix

> **Overview of all 11 bridge adapters implementing `IBridgeAdapter` in ZASEON**

---

## Interface: IBridgeAdapter

All adapters implement the core `IBridgeAdapter` interface:

```solidity
interface IBridgeAdapter {
    function bridgeMessage(address targetAddress, bytes calldata payload, address refundAddress)
        external payable returns (bytes32 messageId);
    function estimateFee(address targetAddress, bytes calldata payload)
        external view returns (uint256 nativeFee);
    function isMessageVerified(bytes32 messageId)
        external view returns (bool verified);
}
```

---

## Comparison Matrix

| Adapter                   | Network           | Type                 | Finality                | Security Model             | Unique Features                                    |
| ------------------------- | ----------------- | -------------------- | ----------------------- | -------------------------- | -------------------------------------------------- |
| **ArbitrumBridgeAdapter** | Arbitrum One/Nova | Native L2            | ~7 days (fraud proof)   | Optimistic rollup          | Retryable tickets, fast exits, LP liquidity        |
| **OptimismBridgeAdapter** | Optimism          | Native L2 (OP Stack) | ~7 days (fraud proof)   | Optimistic rollup          | L2 output proposals, HTLC escrow, privacy deposits |
| **BaseBridgeAdapter**     | Base              | Native L2 (OP Stack) | ~7 days (fraud proof)   | Optimistic rollup          | Shared OP Stack messaging                          |
| **zkSyncBridgeAdapter**   | zkSync Era        | Native L2            | ~1 hour (ZK proof)      | ZK rollup (Diamond Proxy)  | ZK proof finality, L2 log inclusion proofs         |
| **ScrollBridgeAdapter**   | Scroll            | Native L2            | ~1 hour (ZK proof)      | ZK rollup                  | Batch ZK proof verification                        |
| **LineaBridgeAdapter**    | Linea             | Native L2            | ~1 hour (ZK proof)      | ZK rollup (MessageService) | Linea MessageService API                           |
| **AztecBridgeAdapter**    | Aztec             | Privacy L2           | ~10 min (ZK proof)      | ZK rollup (shielded)       | Shielded deposits, nullifier tracking, DeFi bridge |
| **EthereumL1Bridge**      | Ethereum L1       | Native L1            | Immediate (L1 finality) | L1 consensus               | Deposit/withdrawal, direct L1 messaging            |
| **LayerZeroAdapter**      | 120+ chains       | Interop protocol     | Varies by chain         | DVN + executor             | Ultra-light nodes, OApp V2, configurable security  |
| **HyperlaneAdapter**      | 50+ chains        | Interop protocol     | Varies by ISM           | Modular ISM                | Configurable per-domain ISM, quorum validation     |
| **NativeL2BridgeWrapper** | Any L2            | Wrapper              | Inherits wrapped        | Inherits wrapped           | Unified IBridgeAdapter for any native bridge       |

---

## Detailed Capabilities

### Access Control Roles

| Adapter    | OPERATOR | GUARDIAN | EXECUTOR | RELAYER | TREASURY | PAUSER |
| ---------- | -------- | -------- | -------- | ------- | -------- | ------ |
| Arbitrum   | ✅       | ✅       | ✅       | —       | —        | —      |
| Optimism   | ✅       | ✅       | —        | ✅      | ✅       | —      |
| Base       | ✅       | ✅       | —        | —       | —        | —      |
| zkSync     | ✅       | ✅       | ✅       | —       | —        | —      |
| Scroll     | ✅       | ✅       | ✅       | —       | —        | —      |
| Linea      | ✅       | ✅       | —        | —       | —        | —      |
| Aztec      | ✅       | ✅       | —        | ✅      | —        | ✅     |
| EthereumL1 | ✅       | ✅       | —        | —       | —        | —      |
| LayerZero  | ✅       | ✅       | —        | —       | —        | —      |
| Hyperlane  | ✅       | ✅       | —        | ✅      | —        | —      |

### Feature Support

| Feature               | Arb | OP  | Base | zkSync | Scroll | Linea | Aztec | L1  | LZ  | Hyp |
| --------------------- | --- | --- | ---- | ------ | ------ | ----- | ----- | --- | --- | --- |
| Pause/Unpause         | ✅  | ✅  | ✅   | ✅     | ✅     | ✅    | ✅    | ✅  | ✅  | ✅  |
| Token Mapping         | ✅  | —   | —    | ✅     | ✅     | —     | —     | —   | —   | —   |
| Fast Exit             | ✅  | —   | —    | —      | —      | —     | —     | —   | —   | —   |
| LP Liquidity          | ✅  | —   | —    | —      | —      | —     | —     | —   | —   | —   |
| HTLC Escrow           | —   | ✅  | —    | —      | —      | —     | —     | —   | —   | —   |
| Privacy Deposits      | —   | ✅  | —    | —      | —      | —     | ✅    | —   | —   | —   |
| Nullifier Tracking    | —   | —   | —    | —      | —      | —     | ✅    | —   | —   | —   |
| Fee Treasury          | ✅  | ✅  | —    | ✅     | ✅     | —     | —     | —   | —   | —   |
| Configurable Security | —   | —   | —    | —      | —      | —     | —     | —   | ✅  | ✅  |
| Multi-Chain (50+)     | —   | —   | —    | —      | —      | —     | —     | —   | ✅  | ✅  |

### Finality Times

| Adapter   | Optimistic Exit | ZK Proven | Fast Path     |
| --------- | --------------- | --------- | ------------- |
| Arbitrum  | 7 days          | —         | LP-backed     |
| Optimism  | 7 days          | —         | —             |
| Base      | 7 days          | —         | —             |
| zkSync    | —               | ~1 hour   | —             |
| Scroll    | —               | ~1 hour   | —             |
| Linea     | —               | ~1 hour   | —             |
| Aztec     | —               | ~10 min   | —             |
| LayerZero | —               | —         | Minutes (DVN) |
| Hyperlane | —               | —         | Minutes (ISM) |

---

## When to Use Each Adapter

| Use Case                         | Recommended Adapter                          |
| -------------------------------- | -------------------------------------------- |
| **ETH L1 ↔ Arbitrum**            | ArbitrumBridgeAdapter (native, cheapest)     |
| **ETH L1 ↔ Optimism/Base**       | OptimismBridgeAdapter / BaseBridgeAdapter    |
| **ETH L1 ↔ zkSync/Scroll/Linea** | Native ZK bridge adapters (fastest finality) |
| **Shielded cross-chain**         | AztecBridgeAdapter (native privacy)          |
| **Multi-chain hub-and-spoke**    | LayerZeroAdapter (broadest reach)            |
| **Custom security requirements** | HyperlaneAdapter (modular ISM)               |
| **Fallover / redundancy**        | MultiBridgeRouter auto-selects from multiple |

---

## Certora Verification

All adapters have formal verification specs:

| Adapter                 | Spec File              | Conf File                      |
| ----------------------- | ---------------------- | ------------------------------ |
| Arbitrum                | `ArbitrumBridge.spec`  | `verify_arbitrum_bridge.conf`  |
| Optimism                | `OptimismBridge.spec`  | `verify_optimism_bridge.conf`  |
| zkSync                  | `zkSyncBridge.spec`    | `verify_zksync_bridge.conf`    |
| Scroll                  | `ScrollBridge.spec`    | `verify_scroll_bridge.conf`    |
| Aztec                   | `BridgeAdapters.spec`  | `verify_aztec_bridge.conf`     |
| Hyperlane               | `HyperlaneBridge.spec` | `verify_hyperlane_bridge.conf` |
| Linea                   | `LineaBridge.spec`     | `verify_linea_bridge.conf`     |
| Base                    | `BaseBridge.spec`      | `verify_base_bridge.conf`      |
| Shared (IBridgeAdapter) | `BridgeAdapters.spec`  | —                              |

See `certora/specs/` and `certora/conf/` for full specifications.
