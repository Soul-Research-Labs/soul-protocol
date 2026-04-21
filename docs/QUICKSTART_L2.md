# Quickstart — Add a new L2 bridge adapter (10 min)

This guide walks through adding a new L2 to ZASEON by implementing the
`IBridgeAdapter` interface. Target: PR-ready adapter in ~10 minutes.

## 1. Copy the template

```bash
cp -r templates/BridgeAdapter contracts/crosschain/MyL2BridgeAdapter.sol
mv contracts/crosschain/MyL2BridgeAdapter.sol/BridgeAdapter.sol.template \
   contracts/crosschain/MyL2BridgeAdapter.sol
```

Or use the scaffold generator:

```bash
npm run scaffold:adapter -- --name MyL2
```

## 2. Implement three methods

Every adapter must implement [`IBridgeAdapter`](../contracts/crosschain/IBridgeAdapter.sol):

```solidity
function bridgeMessage(
    uint64 destChainId,
    bytes32 recipient,
    bytes calldata payload
) external payable returns (bytes32 messageId);

function estimateFee(
    uint64 destChainId,
    bytes calldata payload
) external view returns (uint256);

function isMessageVerified(bytes32 messageId) external view returns (bool);
```

### Native L2 bridges (Optimism/Arbitrum-style)

Wrap the native bridge contract and forward. See
[`contracts/crosschain/OptimismBridgeAdapter.sol`](../contracts/crosschain/OptimismBridgeAdapter.sol)
for a reference.

### Generic messengers (LayerZero/Hyperlane-style)

Implement `_lzReceive` / `handle` callbacks and track `isMessageVerified` via
an internal map updated by the callback.

## 3. Register with `MultiBridgeRouter`

Add your adapter to the bridge registry:

```solidity
router.registerAdapter(
    keccak256("MyL2"),                       // adapter ID
    address(myL2Adapter),                    // deployed adapter
    IMultiBridgeRouter.BridgeTier.Standard,  // tier
    true                                     // isActive
);
```

## 4. Add tests

Copy [`templates/BridgeAdapter/BridgeAdapter.t.sol.template`](../templates/BridgeAdapter/BridgeAdapter.t.sol.template)
to `test/crosschain/MyL2BridgeAdapter.t.sol`. At minimum cover:

- `test_bridgeMessage_emitsEvent`
- `test_bridgeMessage_refundsExcessFee`
- `test_estimateFee_matchesNativeBridge`
- `test_replayProtection_rejectsDuplicateMessageId`
- `testFuzz_bridgeMessage_payloadSize(uint16 size)`

## 5. Add CI matrix entry

Open `.github/workflows/ci.yml` and add your adapter to the bridge test matrix:

```yaml
bridges: [arbitrum, optimism, base, zksync, scroll, linea, myL2]
```

## 6. Update deploy script

Add a phase block inside
[`scripts/deploy/DeployL2Bridges.s.sol`](../scripts/deploy/DeployL2Bridges.s.sol)
that deploys your adapter and wires it into the hub.

## Checklist before PR

- [ ] Adapter implements all three `IBridgeAdapter` functions
- [ ] Replay protection via unique `messageId`
- [ ] Fees are refunded on overpayment
- [ ] ≥ 5 unit tests, ≥ 1 fuzz test
- [ ] Registered in `MultiBridgeRouter`
- [ ] Deploy script updated
- [ ] `docs/BRIDGE_COMPARISON_MATRIX.md` row added

## References

- [BRIDGE_INTEGRATION.md](./BRIDGE_INTEGRATION.md) — deep-dive on the adapter pattern
- [BRIDGE_SECURITY_FRAMEWORK.md](./BRIDGE_SECURITY_FRAMEWORK.md) — threat model
- [L2_INTEROPERABILITY.md](./L2_INTEROPERABILITY.md) — cross-L2 design
