/**
 * ZASEON Relayer - Contract ABIs
 *
 * Minimal ABI fragments for cross-chain relay operations.
 */

/** ProofRelayed event from ZaseonCrossChainRelay */
export const PROOF_RELAYED_EVENT = {
  type: "event",
  name: "ProofRelayed",
  inputs: [
    { name: "proofId", type: "bytes32", indexed: true },
    { name: "sourceChainId", type: "uint64", indexed: false },
    { name: "destChainId", type: "uint64", indexed: false },
    { name: "commitment", type: "bytes32", indexed: false },
    { name: "messageId", type: "bytes32", indexed: false },
  ],
} as const;

/** submitProof on CrossChainProofHubV3 */
export const SUBMIT_PROOF_ABI = [
  {
    type: "function",
    name: "submitProof",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "publicInputs", type: "bytes" },
      { name: "commitment", type: "bytes32" },
      { name: "sourceChainId", type: "uint64" },
      { name: "destChainId", type: "uint64" },
    ],
    outputs: [{ name: "proofId", type: "bytes32" }],
    stateMutability: "payable",
  },
] as const;

/** receiveRelayedProof on ZaseonCrossChainRelay (destination) */
export const RECEIVE_RELAYED_PROOF_ABI = [
  {
    type: "function",
    name: "receiveRelayedProof",
    inputs: [
      { name: "_sourceChainId", type: "uint256" },
      { name: "payload", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

/** ProofDataEmitted event from CrossChainProofHubV3 */
export const PROOF_DATA_EMITTED_EVENT = {
  type: "event",
  name: "ProofDataEmitted",
  inputs: [
    { name: "proofId", type: "bytes32", indexed: true },
    { name: "proof", type: "bytes", indexed: false },
    { name: "publicInputs", type: "bytes", indexed: false },
  ],
} as const;

/** Full ABI fragments for watching relay events */
export const RELAY_WATCH_ABI = [
  PROOF_RELAYED_EVENT,
  PROOF_DATA_EMITTED_EVENT,
] as const;
