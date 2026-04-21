# Verifier V3 — Consumer Migration Guide

This guide is the consumer-side companion to [ADR-013](adr/ADR-013-verifier-v3.md).
It shows **exactly** how to port an existing contract from a per-circuit adapter
call to the unified `ZaseonVerifierRouter` without changing proof semantics.

Target audience: authors of the six production consumers currently
still wired to legacy adapters — `ConfidentialStateContainerV3`,
`ZKBoundStateLocks`, `IntentCompletionLayer`, `CrossChainProofHubV3`,
`UnifiedNullifierManager`, and `DelayedClaimVault`.

## 1. Pick your `circuitId`

The registry keys circuits by `bytes32`, not an enum. Pick a stable
string; suggested convention is `"<circuit_name>:v<major>"`. Examples:

```solidity
bytes32 constant PRIVATE_TRANSFER_V1 = keccak256("private_transfer:v1");
bytes32 constant STATE_UNLOCK_V1     = keccak256("state_unlock:v1");
bytes32 constant NULLIFIER_V2        = keccak256("nullifier:v2");
```

Rotating a vkey means picking a **new** id (`…:v2`) and deploying a new
adapter + re-registering — the registry refuses to overwrite an existing
entry (see `CircuitAlreadyRegistered`).

## 2. Decide whether you need context binding

Context binding means: the **last** public input of every proof is
required to equal

```solidity
contextTag = keccak(DOMAIN_TAG || chainId || registry || circuitId || vkeyHash || callerCtx) mod BN254_R
```

Turn it on (`requiresContextBinding = true`) when the circuit is
vulnerable to cross-chain / cross-deployment replay — which is almost
always the case for anything spending or unlocking state. You’ll need to
include the matching public input in your Noir circuit:

```noir
fn main(..., context_tag: pub Field) {
    // circuit body … the tag is constrained only by being pub, so the
    // verifier is what enforces chain/deployment binding.
}
```

If the circuit doesn’t spend state (e.g. a stateless range-proof used
for compliance reporting), you can leave `requiresContextBinding = false`.

## 3. Register the circuit (one-time, via timelock)

```solidity
registry.registerCircuit(
    IZaseonVerifierRegistryV3.RegistrationRequest({
        circuitId:              PRIVATE_TRANSFER_V1,
        verifier:               address(groth16VerifierBN254),
        adapter:                address(privateTransferAdapter),
        acirHash:               0x…,   // keccak of compiled ACIR
        vkeyHash:               0x…,   // keccak of the vkey
        gasCap:                 450_000,
        minPublicInputs:        6,
        maxPublicInputs:        6,
        consensusMode:          false,
        requiresContextBinding: true
    })
);
```

Store the circuit id in an immutable on the consumer.

## 4. Replace your verification call

### Before (legacy)

```solidity
import {PrivateTransferAdapter} from "contracts/verifiers/adapters/PrivateTransferAdapter.sol";

contract ConfidentialStateContainerV3 {
    PrivateTransferAdapter public adapter;

    function _verify(bytes calldata proof, uint256[] calldata pis) internal view {
        require(adapter.verifyProof(proof, pis), "invalid proof");
    }
}
```

### After (V3)

```solidity
import {IZaseonVerifierRouter} from "contracts/interfaces/IZaseonVerifierRouter.sol";

contract ConfidentialStateContainerV3 {
    IZaseonVerifierRouter public immutable router;
    bytes32 public immutable circuitId; // e.g. PRIVATE_TRANSFER_V1

    constructor(address router_, bytes32 circuitId_) {
        router = IZaseonVerifierRouter(router_);
        circuitId = circuitId_;
    }

    function _verify(bytes calldata proof, uint256[] calldata pis) internal view {
        router.verify(circuitId, proof, pis, _callerCtx());
    }

    function _callerCtx() internal view returns (bytes32) {
        return keccak256(abi.encode(address(this), msg.sender));
    }
}
```

Notes:

- `router.verify` **reverts** on failure with a typed error; you no
  longer check a bool return.
- `callerCtx` is free-form. A common choice is
  `keccak(address(this), msg.sender)` — binds the proof both to the
  contract being entered and to the caller/relayer that submitted it.
  Whatever you choose, it must match what the circuit received as the
  final public input.

## 5. Batch path (optional, for relayers)

When a relayer submits several proofs in one tx:

```solidity
IZaseonVerifierRouter.Request[] memory reqs =
    new IZaseonVerifierRouter.Request[](n);
for (uint256 i; i < n; ++i) {
    reqs[i] = IZaseonVerifierRouter.Request({
        circuitId:    circuitIds[i],
        proof:        proofs[i],
        publicInputs: pis[i],
        callerCtx:    keccak256(abi.encode(address(this), relayers[i]))
    });
}
router.verifyBatch(reqs);
```

The router deduplicates `(circuitId, keccak(proof))` within the call.

## 6. Compact calldata path

If you control the submitter, use `CompactProof` to halve/quarter the
calldata bill:

```solidity
bytes memory blob = CompactProof.encode(
    circuitId, pis, proof, callerCtx
);
router.verifyCompact(blob);
```

## 7. Deployment wiring

Add the router address to your existing deploy script’s consumer
constructors and to `WireRemainingComponents.s.sol` via a new
`hub.setVerifierRouter(router)` call. No bytecode change is required in
consumers already upgraded via UUPS — just a `initializeV3(router, id)`
migration function if you prefer that to a fresh deploy.

## 8. Checklist

- [ ] `circuitId` chosen and documented
- [ ] Circuit registered via timelock
- [ ] Consumer constructor takes `(router, circuitId)`
- [ ] Legacy adapter import removed
- [ ] `callerCtx` computed identically on-chain and inside the Noir circuit
- [ ] Tests updated to deploy the router + registry in setUp
- [ ] Deployment script updated to pass the router address
- [ ] `IntegrationTest` verifies a real proof end-to-end through the router

## 9. Deprecated adapters

The following adapter subclasses are **deprecated** and slated for removal
after consumer migration completes. Do not use them in new integrations:

- `PolicyVerifierAdapter`
- `PrivateTransferAdapter`
- `CommitmentAdapter`
- `StateTransferAdapter`
- `ComplianceAdapter`
- `SwapProofAdapter`
- `BalanceProofAdapter`
- `NullifierAdapter`
- `PedersenCommitmentAdapter`
- `CrossChainAdapter`
- `AggregatorAdapter`

They remain in-tree (and compilable) for the duration of the migration window.
