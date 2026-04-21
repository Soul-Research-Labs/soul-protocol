# BridgeAdapter template

Scaffold for a new `IBridgeAdapter` implementation.

## Files

- `BridgeAdapter.sol.template` — adapter skeleton with replay protection, fee refund, and callback entry point
- `BridgeAdapter.t.sol.template` — unit + fuzz tests

## Usage

```bash
NAME=MyL2
sed "s/__ADAPTER_NAME__/$NAME/g" BridgeAdapter.sol.template \
  > ../../contracts/crosschain/${NAME}BridgeAdapter.sol
sed "s/__ADAPTER_NAME__/$NAME/g" BridgeAdapter.t.sol.template \
  > ../../test/crosschain/${NAME}BridgeAdapter.t.sol
```

Then fill in `CHAIN_ID_L2`, `_sendNative`, and `estimateFee` to match the
target L2's native bridge. See [docs/QUICKSTART_L2.md](../../docs/QUICKSTART_L2.md).
