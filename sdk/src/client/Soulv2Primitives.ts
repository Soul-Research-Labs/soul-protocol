import {
  PublicClient,
  WalletClient,
  getContract,
  decodeEventLog,
  Hex,
  zeroHash,
  TransactionReceipt,
  Log,
  Abi,
} from "viem";
import { ViemContract, DecodedEventArgs } from "../types/contracts";

/** Parsed event log with fragment name */
export interface ParsedEventLog extends Log {
  eventName?: string;
  args?: DecodedEventArgs;
}

const PC3_ABI = [
  {
    name: "containers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "encryptedPayload", type: "bytes" },
          { name: "stateCommitment", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          {
            name: "proofs",
            type: "tuple",
            components: [
              { name: "validityProof", type: "bytes" },
              { name: "policyProof", type: "bytes" },
              { name: "nullifierProof", type: "bytes" },
              { name: "proofHash", type: "bytes32" },
              { name: "proofTimestamp", type: "uint256" },
              { name: "proofExpiry", type: "uint256" },
            ],
          },
          { name: "policyHash", type: "bytes32" },
          { name: "chainId", type: "uint64" },
          { name: "createdAt", type: "uint64" },
          { name: "version", type: "uint32" },
          { name: "isVerified", type: "bool" },
          { name: "isConsumed", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "consumedNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "supportedPolicies",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "totalContainers",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "totalVerified",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "getContainerIds",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "offset", type: "uint256" },
      { name: "limit", type: "uint256" },
    ],
    outputs: [{ type: "bytes32[]" }],
  },
  {
    name: "createContainer",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "encryptedPayload", type: "bytes" },
      { name: "stateCommitment", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "validityProof", type: "bytes" },
      { name: "policyProof", type: "bytes" },
      { name: "nullifierProof", type: "bytes" },
      { name: "proofExpiry", type: "uint256" },
      { name: "policyHash", type: "bytes32" },
    ],
    outputs: [{ name: "containerId", type: "bytes32" }],
  },
  {
    name: "verifyContainer",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "containerId", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "batchVerifyContainers",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "containerIds", type: "bytes32[]" }],
    outputs: [{ type: "bool[]" }],
  },
  {
    name: "consumeContainer",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "containerId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "exportContainer",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "containerId", type: "bytes32" },
      { name: "targetChainId", type: "uint64" },
    ],
    outputs: [{ type: "bytes" }],
  },
  {
    name: "importContainer",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "exportedData", type: "bytes" },
      { name: "crossChainProof", type: "bytes" },
    ],
    outputs: [{ name: "containerId", type: "bytes32" }],
  },
  {
    name: "addSupportedPolicy",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "policyHash", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "ContainerCreated",
    type: "event",
    inputs: [
      { name: "containerId", type: "bytes32", indexed: true },
      { name: "stateCommitment", type: "bytes32", indexed: true },
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "policyHash", type: "bytes32" },
    ],
  },
  {
    name: "ContainerVerified",
    type: "event",
    inputs: [
      { name: "containerId", type: "bytes32", indexed: true },
      { name: "success", type: "bool" },
    ],
  },
  {
    name: "ContainerConsumed",
    type: "event",
    inputs: [
      { name: "containerId", type: "bytes32", indexed: true },
      { name: "nullifier", type: "bytes32", indexed: true },
    ],
  },
  {
    name: "ContainerExported",
    type: "event",
    inputs: [
      { name: "containerId", type: "bytes32", indexed: true },
      { name: "targetChainId", type: "uint64", indexed: true },
    ],
  },
  {
    name: "ContainerImported",
    type: "event",
    inputs: [
      { name: "containerId", type: "bytes32", indexed: true },
      { name: "sourceChainId", type: "uint64", indexed: true },
    ],
  },
] as const;

const PBP_ABI = [
  {
    name: "policies",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "policyId", type: "bytes32" },
          { name: "policyHash", type: "bytes32" },
          { name: "name", type: "string" },
          { name: "description", type: "string" },
          { name: "requiresIdentity", type: "bool" },
          { name: "requiresJurisdiction", type: "bool" },
          { name: "requiresAmount", type: "bool" },
          { name: "requiresCounterparty", type: "bool" },
          { name: "minAmount", type: "uint256" },
          { name: "maxAmount", type: "uint256" },
          { name: "allowedAssets", type: "bytes32[]" },
          { name: "blockedCountries", type: "bytes32[]" },
          { name: "createdAt", type: "uint64" },
          { name: "expiresAt", type: "uint64" },
          { name: "isActive", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "verificationKeys",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "vkHash", type: "bytes32" },
          { name: "policyHash", type: "bytes32" },
          { name: "domainSeparator", type: "bytes32" },
          { name: "isActive", type: "bool" },
          { name: "registeredAt", type: "uint64" },
        ],
      },
    ],
  },
  {
    name: "totalPolicies",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "totalVerifications",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "getPolicyIds",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "offset", type: "uint256" },
      { name: "limit", type: "uint256" },
    ],
    outputs: [{ type: "bytes32[]" }],
  },
  {
    name: "getVkHashes",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "offset", type: "uint256" },
      { name: "limit", type: "uint256" },
    ],
    outputs: [{ type: "bytes32[]" }],
  },
  {
    name: "registerPolicy",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "name", type: "string" },
      { name: "description", type: "string" },
      { name: "requiresIdentity", type: "bool" },
      { name: "requiresJurisdiction", type: "bool" },
      { name: "requiresAmount", type: "bool" },
      { name: "requiresCounterparty", type: "bool" },
      { name: "minAmount", type: "uint256" },
      { name: "maxAmount", type: "uint256" },
      { name: "allowedAssets", type: "bytes32[]" },
      { name: "blockedCountries", type: "bytes32[]" },
      { name: "expiresAt", type: "uint64" },
    ],
    outputs: [{ name: "policyId", type: "bytes32" }],
  },
  {
    name: "bindVerificationKey",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "vkHash", type: "bytes32" },
      { name: "policyHash", type: "bytes32" },
    ],
    outputs: [{ name: "domainSeparator", type: "bytes32" }],
  },
  {
    name: "verifyBoundProof",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "proof", type: "bytes" },
      { name: "policyHash", type: "bytes32" },
      { name: "domainSeparator", type: "bytes32" },
      { name: "publicInputs", type: "bytes32[]" },
      { name: "expiresAt", type: "uint64" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "batchCheckPolicies",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "policyHashes", type: "bytes32[]" }],
    outputs: [{ type: "bool[]" }],
  },
  {
    name: "PolicyRegistered",
    type: "event",
    inputs: [
      { name: "policyId", type: "bytes32", indexed: true },
      { name: "policyHash", type: "bytes32", indexed: true },
      { name: "name", type: "string" },
    ],
  },
  {
    name: "VerificationKeyBound",
    type: "event",
    inputs: [
      { name: "vkHash", type: "bytes32", indexed: true },
      { name: "policyHash", type: "bytes32", indexed: true },
      { name: "domainSeparator", type: "bytes32" },
    ],
  },
  {
    name: "BoundProofVerified",
    type: "event",
    inputs: [
      { name: "policyHash", type: "bytes32", indexed: true },
      { name: "domainSeparator", type: "bytes32", indexed: true },
      { name: "success", type: "bool" },
    ],
  },
] as const;

const EASC_ABI = [
  {
    name: "backends",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "backendId", type: "bytes32" },
          { name: "backendType", type: "uint8" },
          { name: "name", type: "string" },
          { name: "attestationKey", type: "bytes32" },
          { name: "configHash", type: "bytes32" },
          { name: "registeredAt", type: "uint64" },
          { name: "lastAttestation", type: "uint64" },
          { name: "isActive", type: "bool" },
          { name: "trustScore", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "getCommitment",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "commitmentId", type: "bytes32" },
          { name: "stateHash", type: "bytes32" },
          { name: "transitionHash", type: "bytes32" },
          { name: "nullifier", type: "bytes32" },
          { name: "attestedBackends", type: "bytes32[]" },
          { name: "creator", type: "address" },
          { name: "createdAt", type: "uint64" },
          { name: "attestationCount", type: "uint32" },
          { name: "isFinalized", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "consumedNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "totalCommitments",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "totalAttestations",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "getActiveBackends",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "bytes32[]" }],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }, { type: "uint256" }, { type: "uint256" }],
  },
  {
    name: "registerBackend",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "backendType", type: "uint8" },
      { name: "name", type: "string" },
      { name: "attestationKey", type: "bytes32" },
      { name: "configHash", type: "bytes32" },
      { name: "initialTrustScore", type: "uint256" },
    ],
    outputs: [{ name: "backendId", type: "bytes32" }],
  },
  {
    name: "createCommitment",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "stateHash", type: "bytes32" },
      { name: "transitionHash", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "requiredAttestations", type: "uint32" },
    ],
    outputs: [{ name: "commitmentId", type: "bytes32" }],
  },
  {
    name: "attestCommitment",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "commitmentId", type: "bytes32" },
      { name: "backendId", type: "bytes32" },
      { name: "attestationProof", type: "bytes" },
      { name: "executionHash", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "batchCheckCommitments",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "commitmentIds", type: "bytes32[]" }],
    outputs: [{ type: "bool[]" }],
  },
  {
    name: "updateTrustScore",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "backendId", type: "bytes32" },
      { name: "newScore", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "deactivateBackend",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "backendId", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "BackendRegistered",
    type: "event",
    inputs: [
      { name: "backendId", type: "bytes32", indexed: true },
      { name: "backendType", type: "uint8" },
      { name: "name", type: "string" },
    ],
  },
  {
    name: "CommitmentCreated",
    type: "event",
    inputs: [
      { name: "commitmentId", type: "bytes32", indexed: true },
      { name: "stateHash", type: "bytes32", indexed: true },
      { name: "nullifier", type: "bytes32" },
    ],
  },
  {
    name: "CommitmentAttested",
    type: "event",
    inputs: [
      { name: "commitmentId", type: "bytes32", indexed: true },
      { name: "backendId", type: "bytes32", indexed: true },
    ],
  },
  {
    name: "CommitmentFinalized",
    type: "event",
    inputs: [{ name: "commitmentId", type: "bytes32", indexed: true }],
  },
] as const;

const CDNA_ABI = [
  {
    name: "domains",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "domainId", type: "bytes32" },
          { name: "chainId", type: "uint64" },
          { name: "appId", type: "bytes32" },
          { name: "epochStart", type: "uint64" },
          { name: "epochEnd", type: "uint64" },
          { name: "domainSeparator", type: "bytes32" },
          { name: "isActive", type: "bool" },
          { name: "registeredAt", type: "uint64" },
        ],
      },
    ],
  },
  {
    name: "nullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "nullifier", type: "bytes32" },
          { name: "domainId", type: "bytes32" },
          { name: "commitmentHash", type: "bytes32" },
          { name: "transitionId", type: "bytes32" },
          { name: "parentNullifier", type: "bytes32" },
          { name: "childNullifiers", type: "bytes32[]" },
          { name: "registrar", type: "address" },
          { name: "registeredAt", type: "uint64" },
          { name: "epochId", type: "uint64" },
          { name: "isConsumed", type: "bool" },
        ],
      },
    ],
  },
  {
    name: "nullifierExists",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "totalDomains",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "totalNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "currentEpoch",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint64" }],
  },
  {
    name: "getActiveDomains",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "bytes32[]" }],
  },
  {
    name: "getStats",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint64" },
    ],
  },
  {
    name: "registerDomain",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "chainId", type: "uint64" },
      { name: "appId", type: "bytes32" },
      { name: "epochStart", type: "uint64" },
      { name: "epochEnd", type: "uint64" },
    ],
    outputs: [{ name: "domainId", type: "bytes32" }],
  },
  {
    name: "registerNullifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "domainId", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "commitmentHash", type: "bytes32" },
      { name: "transitionId", type: "bytes32" },
      { name: "registrationProof", type: "bytes" },
    ],
    outputs: [{ name: "nullifierHash", type: "bytes32" }],
  },
  {
    name: "registerDerivedNullifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "parentNullifier", type: "bytes32" },
      { name: "childNullifier", type: "bytes32" },
      { name: "targetDomainId", type: "bytes32" },
      { name: "derivationProof", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "consumeNullifier",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "nullifier", type: "bytes32" }],
    outputs: [],
  },
  {
    name: "batchCheckNullifiers",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "nullifierList", type: "bytes32[]" }],
    outputs: [{ type: "bool[]" }],
  },
  {
    name: "batchConsumeNullifiers",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [{ name: "nullifierList", type: "bytes32[]" }],
    outputs: [],
  },
  {
    name: "verifyCrossDomainProof",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "sourceNullifier", type: "bytes32" },
      { name: "targetNullifier", type: "bytes32" },
      { name: "sourceDomainId", type: "bytes32" },
      { name: "targetDomainId", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    name: "finalizeEpoch",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "DomainRegistered",
    type: "event",
    inputs: [
      { name: "domainId", type: "bytes32", indexed: true },
      { name: "chainId", type: "uint64", indexed: true },
      { name: "appId", type: "bytes32" },
    ],
  },
  {
    name: "NullifierRegistered",
    type: "event",
    inputs: [
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "domainId", type: "bytes32", indexed: true },
      { name: "commitmentHash", type: "bytes32" },
    ],
  },
  {
    name: "DerivedNullifierRegistered",
    type: "event",
    inputs: [
      { name: "parentNullifier", type: "bytes32", indexed: true },
      { name: "childNullifier", type: "bytes32", indexed: true },
      { name: "targetDomainId", type: "bytes32", indexed: true },
    ],
  },
  {
    name: "NullifierConsumed",
    type: "event",
    inputs: [
      { name: "nullifier", type: "bytes32", indexed: true },
      { name: "domainId", type: "bytes32", indexed: true },
    ],
  },
  {
    name: "EpochFinalized",
    type: "event",
    inputs: [
      { name: "epochId", type: "uint64", indexed: true },
      { name: "merkleRoot", type: "bytes32" },
    ],
  },
] as const;

const ORCHESTRATOR_ABI = [
  {
    name: "pc3",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    name: "pbp",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    name: "easc",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    name: "cdna",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
  {
    name: "isPrimitiveActive",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    name: "getSystemStatus",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [
      {
        type: "tuple",
        components: [
          { name: "pc3Active", type: "bool" },
          { name: "pbpActive", type: "bool" },
          { name: "eascActive", type: "bool" },
          { name: "cdnaActive", type: "bool" },
          { name: "paused", type: "bool" },
          { name: "lastUpdate", type: "uint256" },
        ],
      },
    ],
  },
  {
    name: "totalOperations",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "successfulOperations",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    name: "executePrivateTransfer",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "containerId", type: "bytes32" },
      { name: "policyId", type: "bytes32" },
      { name: "stateCommitment", type: "bytes32" },
      { name: "nullifier", type: "bytes32" },
      { name: "proof", type: "bytes" },
    ],
    outputs: [
      { type: "bool" },
      { name: "operationId", type: "bytes32" },
      { name: "message", type: "string" },
    ],
  },
  {
    name: "updatePrimitive",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "primitiveId", type: "bytes32" },
      { name: "newAddress", type: "address" },
    ],
    outputs: [],
  },
  {
    name: "setPrimitiveActive",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "primitiveId", type: "bytes32" },
      { name: "active", type: "bool" },
    ],
    outputs: [],
  },
  {
    name: "pause",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "unpause",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
  {
    name: "OperationExecuted",
    type: "event",
    inputs: [
      { name: "operationId", type: "bytes32", indexed: true },
      { name: "user", type: "address", indexed: true },
      { name: "success", type: "bool" },
      { name: "message", type: "string" },
    ],
  },
  {
    name: "PrimitiveUpdated",
    type: "event",
    inputs: [
      { name: "primitiveId", type: "bytes32", indexed: true },
      { name: "oldAddress", type: "address" },
      { name: "newAddress", type: "address" },
    ],
  },
  {
    name: "PrimitiveStatusChanged",
    type: "event",
    inputs: [
      { name: "primitiveId", type: "bytes32", indexed: true },
      { name: "active", type: "bool" },
    ],
  },
] as const;

/*//////////////////////////////////////////////////////////////
                        SHARED TYPES
//////////////////////////////////////////////////////////////*/

export interface TransactionOptions {
  gasLimit?: bigint;
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
}

export interface ProofBundle {
  validityProof: string;
  policyProof: string;
  nullifierProof: string;
  proofHash: string;
  proofTimestamp: bigint;
  proofExpiry: bigint;
}

/*//////////////////////////////////////////////////////////////
              PROOF CARRYING CONTAINER (PC³) CLIENT
//////////////////////////////////////////////////////////////*/

export interface Container {
  encryptedPayload: Hex;
  stateCommitment: Hex;
  nullifier: Hex;
  proofs: ProofBundle;
  policyHash: Hex;
  chainId: bigint;
  createdAt: bigint;
  version: number;
  isVerified: boolean;
  isConsumed: boolean;
}

export interface ContainerCreationParams {
  encryptedPayload: Hex;
  stateCommitment: Hex;
  nullifier: Hex;
  validityProof: Hex;
  policyProof: Hex;
  nullifierProof: Hex;
  proofExpiry: number;
  policyHash: Hex;
}

export interface VerificationResult {
  validityValid: boolean;
  policyValid: boolean;
  nullifierValid: boolean;
  notExpired: boolean;
  notConsumed: boolean;
  failureReason: string;
}

/**
 * Client for ProofCarryingContainer (PC³) contract
 * Self-authenticating confidential containers with embedded proofs
 */
export class ProofCarryingContainerClient {
  public contract: ViemContract;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    abi?: Abi,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: abi || PC3_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  /**
   * Create a new self-authenticating container
   */
  async createContainer(
    params: ContainerCreationParams,
    options?: TransactionOptions,
  ): Promise<{ txHash: Hex; containerId: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.createContainer(
      [
        params.encryptedPayload,
        params.stateCommitment,
        params.nullifier,
        params.validityProof,
        params.policyProof,
        params.nullifierProof,
        BigInt(params.proofExpiry),
        params.policyHash,
      ],
      options || {},
    );

    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract containerId from event
    let containerId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PC3_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "ContainerCreated") {
          containerId = (decoded.args as DecodedEventArgs).containerId as Hex;
          break;
        }
      } catch {}
    }

    return { txHash: receipt.transactionHash, containerId };
  }

  /**
   * Verify a container's embedded proofs
   */
  async verifyContainer(
    containerId: Hex,
    options?: TransactionOptions,
  ): Promise<boolean> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.verifyContainer(
      [containerId],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return true;
  }

  /**
   * Batch verify multiple containers
   */
  async batchVerifyContainers(
    containerIds: Hex[],
    options?: TransactionOptions,
  ): Promise<boolean[]> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    // Simulate to get return value
    const { result } = await this.publicClient.simulateContract({
      address: this.contract.address,
      abi: this.contract.abi,
      functionName: "batchVerifyContainers",
      args: [containerIds],
      ...options,
    } as Parameters<typeof this.publicClient.simulateContract>[0]);

    const hash = await this.contract.write.batchVerifyContainers(
      [containerIds],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });

    return result as boolean[];
  }

  /**
   * Consume a container (marks nullifier as used)
   */
  async consumeContainer(
    containerId: Hex,
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.consumeContainer(
      [containerId],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Export container for cross-chain transfer
   */
  async exportContainer(
    containerId: Hex,
    targetChainId: bigint,
    options?: TransactionOptions,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.exportContainer(
      [containerId, targetChainId],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });
    return receipt.transactionHash;
  }

  /**
   * Get container by ID
   */
  async getContainer(containerId: Hex): Promise<Container | null> {
    try {
      const container = await this.contract.read.containers([containerId]);
      if (!container || container.stateCommitment === zeroHash) {
        return null;
      }
      return container as Container;
    } catch {
      return null;
    }
  }

  /**
   * Get paginated list of container IDs
   */
  async getContainerIds(offset: number, limit: number): Promise<Hex[]> {
    const ids = await this.contract.read.getContainerIds([
      BigInt(offset),
      BigInt(limit),
    ]);
    return ids as Hex[];
  }

  /**
   * Check if a nullifier has been consumed
   */
  async isNullifierConsumed(nullifier: Hex): Promise<boolean> {
    return await this.contract.read.consumedNullifiers([nullifier]);
  }

  /**
   * Get total containers created
   */
  async getTotalContainers(): Promise<bigint> {
    return await this.contract.read.totalContainers();
  }
}

/*//////////////////////////////////////////////////////////////
              POLICY BOUND PROOFS (PBP) CLIENT
//////////////////////////////////////////////////////////////*/

export interface DisclosurePolicy {
  policyId: Hex;
  policyHash: Hex;
  name: string;
  description: string;
  requiresIdentity: boolean;
  requiresJurisdiction: boolean;
  requiresAmount: boolean;
  requiresCounterparty: boolean;
  minAmount: bigint;
  maxAmount: bigint;
  allowedAssets: Hex[];
  blockedCountries: Hex[];
  createdAt: bigint;
  expiresAt: bigint;
  isActive: boolean;
}

export interface PolicyCreationParams {
  name: string;
  description: string;
  requiresIdentity: boolean;
  requiresJurisdiction: boolean;
  requiresAmount: boolean;
  requiresCounterparty: boolean;
  minAmount: bigint;
  maxAmount: bigint;
  allowedAssets: Hex[];
  blockedCountries: Hex[];
  expiresAt: number;
}

export interface BoundProofParams {
  proof: Hex;
  policyHash: Hex;
  domainSeparator: Hex;
  publicInputs: Hex[];
  expiresAt: number;
}

/**
 * Client for PolicyBoundProofs (PBP) contract
 * Proofs cryptographically scoped by disclosure policy
 */
export class PolicyBoundProofsClient {
  public contract: ViemContract;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    abi?: Abi,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: abi || PBP_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  /**
   * Register a new disclosure policy
   */
  async registerPolicy(
    params: PolicyCreationParams,
    options?: TransactionOptions,
  ): Promise<{ txHash: Hex; policyId: Hex; policyHash: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerPolicy(
      [
        params.name,
        params.description,
        params.requiresIdentity,
        params.requiresJurisdiction,
        params.requiresAmount,
        params.requiresCounterparty,
        params.minAmount,
        params.maxAmount,
        params.allowedAssets,
        params.blockedCountries,
        BigInt(params.expiresAt),
      ],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let policyId: Hex = zeroHash;
    let policyHash: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PBP_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "PolicyRegistered") {
          const eventArgs = decoded.args as DecodedEventArgs;
          policyId = eventArgs.policyId as Hex;
          policyHash = eventArgs.policyHash as Hex;
          break;
        }
      } catch {}
    }

    return {
      txHash: receipt.transactionHash,
      policyId,
      policyHash,
    };
  }

  /**
   * Bind a verification key to a policy
   */
  async bindVerificationKey(
    vkHash: Hex,
    policyHash: Hex,
    options?: TransactionOptions,
  ): Promise<Hex> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.bindVerificationKey(
      [vkHash, policyHash],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let domainSeparator: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: PBP_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "VerificationKeyBound") {
          domainSeparator = (decoded.args as DecodedEventArgs)
            .domainSeparator as Hex;
          break;
        }
      } catch {}
    }
    return domainSeparator;
  }

  /**
   * Verify a policy-bound proof
   */
  async verifyBoundProof(
    params: BoundProofParams,
    options?: TransactionOptions,
  ): Promise<boolean> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.verifyBoundProof(
      [
        params.proof,
        params.policyHash,
        params.domainSeparator,
        params.publicInputs,
        BigInt(params.expiresAt),
      ],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return true;
  }

  /**
   * Check if multiple policies exist and are active
   */
  async batchCheckPolicies(policyHashes: Hex[]): Promise<boolean[]> {
    return await this.contract.read.batchCheckPolicies([policyHashes]);
  }

  /**
   * Get policy by ID
   */
  async getPolicy(policyId: Hex): Promise<DisclosurePolicy | null> {
    try {
      const policy = await this.contract.read.policies([policyId]);
      if (!policy || policy.policyHash === zeroHash) {
        return null;
      }
      return policy as DisclosurePolicy;
    } catch {
      return null;
    }
  }

  /**
   * Get paginated policy IDs
   */
  async getPolicyIds(offset: number, limit: number): Promise<Hex[]> {
    return await this.contract.read.getPolicyIds([
      BigInt(offset),
      BigInt(limit),
    ]);
  }

  /**
   * Get paginated verification key hashes
   */
  async getVkHashes(offset: number, limit: number): Promise<Hex[]> {
    return await this.contract.read.getVkHashes([
      BigInt(offset),
      BigInt(limit),
    ]);
  }
}

/*//////////////////////////////////////////////////////////////
     EXECUTION AGNOSTIC STATE COMMITMENTS (EASC) CLIENT
//////////////////////////////////////////////////////////////*/

export enum BackendType {
  ZkVM = 0,
  TEE = 1,
  Native = 2,
}

export interface ExecutionBackend {
  backendId: Hex;
  backendType: BackendType;
  name: string;
  attestationKey: Hex;
  configHash: Hex;
  registeredAt: bigint;
  lastAttestation: bigint;
  isActive: boolean;
  trustScore: bigint;
}

export interface BackendRegistrationParams {
  backendType: BackendType;
  name: string;
  attestationKey: Hex;
  configHash: Hex;
  initialTrustScore: number;
}

export interface CommitmentParams {
  stateHash: Hex;
  transitionHash: Hex;
  nullifier: Hex;
  requiredAttestations: number;
}

export interface AttestationParams {
  commitmentId: Hex;
  backendId: Hex;
  attestationProof: Hex;
  executionHash: Hex;
}

export interface CommitmentStats {
  totalCommitments: bigint;
  totalAttestations: bigint;
  activeBackends: bigint;
}

/**
 * Client for ExecutionAgnosticStateCommitments (EASC) contract
 * Backend-independent state commitments with multi-attestation
 */
export class ExecutionAgnosticStateCommitmentsClient {
  public contract: ViemContract;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    abi?: Abi,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: abi || EASC_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  /**
   * Register a new execution backend
   */
  async registerBackend(
    params: BackendRegistrationParams,
    options?: TransactionOptions,
  ): Promise<{ txHash: Hex; backendId: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerBackend(
      [
        params.backendType,
        params.name,
        params.attestationKey,
        params.configHash,
        BigInt(params.initialTrustScore),
      ],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let backendId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: EASC_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "BackendRegistered") {
          backendId = (decoded.args as DecodedEventArgs).backendId as Hex;
          break;
        }
      } catch {}
    }
    return { txHash: receipt.transactionHash, backendId };
  }

  /**
   * Create a new execution-agnostic commitment
   */
  async createCommitment(
    params: CommitmentParams,
    options?: TransactionOptions,
  ): Promise<{ txHash: Hex; commitmentId: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.createCommitment(
      [
        params.stateHash,
        params.transitionHash,
        params.nullifier,
        params.requiredAttestations,
      ],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let commitmentId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: EASC_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "CommitmentCreated") {
          commitmentId = (decoded.args as DecodedEventArgs).commitmentId as Hex;
          break;
        }
      } catch {}
    }
    return { txHash: receipt.transactionHash, commitmentId };
  }

  /**
   * Attest a commitment from a backend
   */
  async attestCommitment(
    params: AttestationParams,
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.attestCommitment(
      [
        params.commitmentId,
        params.backendId,
        params.attestationProof,
        params.executionHash,
      ],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Batch check if commitments are finalized
   */
  async batchCheckCommitments(commitmentIds: Hex[]): Promise<boolean[]> {
    return await this.contract.read.batchCheckCommitments([commitmentIds]);
  }

  /**
   * Get backend by ID
   */
  async getBackend(backendId: Hex): Promise<ExecutionBackend | null> {
    try {
      const backend = await this.contract.read.backends([backendId]);
      if (!backend || backend.backendId === zeroHash) {
        return null;
      }
      return backend as ExecutionBackend;
    } catch {
      return null;
    }
  }

  /**
   * Get active backend IDs
   */
  async getActiveBackends(): Promise<Hex[]> {
    return await this.contract.read.getActiveBackends();
  }

  /**
   * Get contract stats
   */
  async getStats(): Promise<CommitmentStats> {
    const [total, attestations, backends] = await this.contract.read.getStats();
    return {
      totalCommitments: total,
      totalAttestations: attestations,
      activeBackends: backends,
    };
  }
}

/*//////////////////////////////////////////////////////////////
       CROSS DOMAIN NULLIFIER ALGEBRA (CDNA) CLIENT
//////////////////////////////////////////////////////////////*/

export interface Domain {
  domainId: Hex;
  chainId: bigint;
  appId: Hex;
  epochStart: bigint;
  epochEnd: bigint;
  domainSeparator: Hex;
  isActive: boolean;
  registeredAt: bigint;
}

export interface DomainNullifier {
  nullifier: Hex;
  domainId: Hex;
  commitmentHash: Hex;
  transitionId: Hex;
  parentNullifier: Hex;
  childNullifiers: Hex[];
  registrar: Hex;
  registeredAt: bigint;
  epochId: bigint;
  isConsumed: boolean;
}

export interface DomainRegistrationParams {
  chainId: bigint;
  appId: Hex;
  epochStart: number;
  epochEnd: number;
}

export interface NullifierRegistrationParams {
  domainId: Hex;
  nullifier: Hex;
  commitmentHash: Hex;
  transitionId: Hex;
  registrationProof: Hex;
}

export interface DerivedNullifierParams {
  parentNullifier: Hex;
  childNullifier: Hex;
  targetDomainId: Hex;
  derivationProof: Hex;
}

export interface NullifierStats {
  totalDomains: bigint;
  totalNullifiers: bigint;
  totalConsumed: bigint;
  currentEpoch: bigint;
}

/**
 * Client for CrossDomainNullifierAlgebra (CDNA) contract
 * Domain-separated nullifiers with cross-chain double-spend prevention
 */
export class CrossDomainNullifierAlgebraClient {
  public contract: ViemContract;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    abi?: Abi,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: abi || CDNA_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  /**
   * Register a new domain for nullifier separation
   */
  async registerDomain(
    params: DomainRegistrationParams,
    options?: TransactionOptions,
  ): Promise<{ txHash: Hex; domainId: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerDomain(
      [
        params.chainId,
        params.appId,
        BigInt(params.epochStart),
        BigInt(params.epochEnd),
      ],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    let domainId: Hex = zeroHash;
    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: CDNA_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "DomainRegistered") {
          domainId = (decoded.args as DecodedEventArgs).domainId as Hex;
          break;
        }
      } catch {}
    }
    return { txHash: receipt.transactionHash, domainId };
  }

  /**
   * Register a nullifier in a domain
   */
  async registerNullifier(
    params: NullifierRegistrationParams,
    options?: TransactionOptions,
  ): Promise<{ txHash: Hex; nullifier: Hex }> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerNullifier(
      [
        params.domainId,
        params.nullifier,
        params.commitmentHash,
        params.transitionId,
        params.registrationProof,
      ],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    return { txHash: receipt.transactionHash, nullifier: params.nullifier };
  }

  /**
   * Register a derived nullifier from a parent
   */
  async registerDerivedNullifier(
    params: DerivedNullifierParams,
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.registerDerivedNullifier(
      [
        params.parentNullifier,
        params.childNullifier,
        params.targetDomainId,
        params.derivationProof,
      ],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Consume a nullifier (mark as spent)
   */
  async consumeNullifier(
    nullifier: Hex,
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.consumeNullifier(
      [nullifier],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Batch check if nullifiers exist
   */
  async batchCheckNullifiers(nullifiers: Hex[]): Promise<boolean[]> {
    return await this.contract.read.batchCheckNullifiers([nullifiers]);
  }

  /**
   * Batch consume multiple nullifiers
   */
  async batchConsumeNullifiers(
    nullifiers: Hex[],
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.batchConsumeNullifiers(
      [nullifiers],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Verify cross-domain nullifier proof
   */
  async verifyCrossDomainProof(
    sourceNullifier: Hex,
    targetNullifier: Hex,
    sourceDomainId: Hex,
    targetDomainId: Hex,
    proof: Hex,
    options?: TransactionOptions,
  ): Promise<boolean> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.verifyCrossDomainProof(
      [sourceNullifier, targetNullifier, sourceDomainId, targetDomainId, proof],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
    return true;
  }

  /**
   * Get domain by ID
   */
  async getDomain(domainId: Hex): Promise<Domain | null> {
    try {
      const domain = await this.contract.read.domains([domainId]);
      if (!domain || domain.domainId === zeroHash) {
        return null;
      }
      return domain as Domain;
    } catch {
      return null;
    }
  }

  /**
   * Get nullifier data
   */
  async getNullifier(nullifier: Hex): Promise<DomainNullifier | null> {
    try {
      const data = await this.contract.read.nullifiers([nullifier]);
      if (!data || data.nullifier === zeroHash) {
        return null;
      }
      return data as DomainNullifier;
    } catch {
      return null;
    }
  }

  /**
   * Check if nullifier exists
   */
  async nullifierExists(nullifier: Hex): Promise<boolean> {
    return await this.contract.read.nullifierExists([nullifier]);
  }

  /**
   * Get active domain IDs
   */
  async getActiveDomains(): Promise<Hex[]> {
    return await this.contract.read.getActiveDomains();
  }

  /**
   * Get contract stats
   */
  async getStats(): Promise<NullifierStats> {
    const [domains, nullifiers, consumed, epoch] =
      await this.contract.read.getStats();
    return {
      totalDomains: domains,
      totalNullifiers: nullifiers,
      totalConsumed: consumed,
      currentEpoch: epoch,
    };
  }

  /**
   * Finalize current epoch
   */
  async finalizeEpoch(options?: TransactionOptions): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.finalizeEpoch([], options || {});
    await this.publicClient.waitForTransactionReceipt({ hash });
  }
}

/*//////////////////////////////////////////////////////////////
                   Soulv2 ORCHESTRATOR CLIENT
//////////////////////////////////////////////////////////////*/

export interface OperationParams {
  containerId: Hex;
  policyId: Hex;
  stateCommitment: Hex;
  nullifier: Hex;
  proof: Hex;
}

export interface OperationResult {
  success: boolean;
  operationId: Hex;
  message: string;
}

export interface SystemStatus {
  pc3Active: boolean;
  pbpActive: boolean;
  eascActive: boolean;
  cdnaActive: boolean;
  paused: boolean;
  lastUpdate: bigint;
}

/**
 * Client for Soulv2Orchestrator contract
 * Coordinates operations across all Soul v2 primitives
 */
export class Soulv2OrchestratorClient {
  public contract: ViemContract;
  private publicClient: PublicClient;
  private walletClient?: WalletClient;

  constructor(
    contractAddress: Hex,
    publicClient: PublicClient,
    walletClient?: WalletClient,
    abi?: Abi,
  ) {
    this.publicClient = publicClient;
    this.walletClient = walletClient;
    this.contract = getContract({
      address: contractAddress,
      abi: abi || ORCHESTRATOR_ABI,
      client: { public: publicClient, wallet: walletClient },
    }) as unknown as ViemContract;
  }

  /**
   * Execute a coordinated private transfer across primitives
   */
  async executePrivateTransfer(
    params: OperationParams,
    options?: TransactionOptions,
  ): Promise<OperationResult> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");

    const hash = await this.contract.write.executePrivateTransfer(
      [
        params.containerId,
        params.policyId,
        params.stateCommitment,
        params.nullifier,
        params.proof,
      ],
      options || {},
    );
    const receipt = await this.publicClient.waitForTransactionReceipt({ hash });

    // Extract result from event
    let success = false;
    let operationId: Hex = zeroHash;
    let message = "";

    for (const log of receipt.logs) {
      try {
        const decoded = decodeEventLog({
          abi: ORCHESTRATOR_ABI,
          data: log.data,
          topics: log.topics,
        });
        if (decoded.eventName === "OperationExecuted") {
          const eventArgs = decoded.args as DecodedEventArgs;
          success = eventArgs.success as boolean;
          operationId = eventArgs.operationId as Hex;
          message = eventArgs.message as string;
          break;
        }
      } catch {}
    }

    return {
      success,
      operationId,
      message,
    };
  }

  /**
   * Get system status
   */
  async getSystemStatus(): Promise<SystemStatus> {
    const status = await this.contract.read.getSystemStatus();
    return {
      pc3Active: status.pc3Active,
      pbpActive: status.pbpActive,
      eascActive: status.eascActive,
      cdnaActive: status.cdnaActive,
      paused: status.paused,
      lastUpdate: status.lastUpdate,
    };
  }

  /**
   * Get primitive addresses
   */
  async getPrimitiveAddresses(): Promise<{
    pc3: Hex;
    pbp: Hex;
    easc: Hex;
    cdna: Hex;
  }> {
    const [pc3, pbp, easc, cdna] = await Promise.all([
      this.contract.read.pc3(),
      this.contract.read.pbp(),
      this.contract.read.easc(),
      this.contract.read.cdna(),
    ]);
    return {
      pc3: pc3 as Hex,
      pbp: pbp as Hex,
      easc: easc as Hex,
      cdna: cdna as Hex,
    };
  }

  /**
   * Get operation statistics
   */
  async getStats(): Promise<{ total: bigint; successful: bigint }> {
    const [total, successful] = await Promise.all([
      this.contract.read.totalOperations(),
      this.contract.read.successfulOperations(),
    ]);
    return { total, successful };
  }

  /**
   * Check if a primitive is active
   */
  async isPrimitiveActive(primitiveId: Hex): Promise<boolean> {
    return await this.contract.read.isPrimitiveActive([primitiveId]);
  }

  /**
   * Update primitive address (admin only)
   */
  async updatePrimitive(
    primitiveId: Hex,
    newAddress: Hex,
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.updatePrimitive(
      [primitiveId, newAddress],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Set primitive active status (admin only)
   */
  async setPrimitiveActive(
    primitiveId: Hex,
    active: boolean,
    options?: TransactionOptions,
  ): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.setPrimitiveActive(
      [primitiveId, active],
      options || {},
    );
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Pause the orchestrator (admin only)
   */
  async pause(options?: TransactionOptions): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.pause([], options || {});
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Unpause the orchestrator (admin only)
   */
  async unpause(options?: TransactionOptions): Promise<void> {
    if (!this.walletClient)
      throw new Error("Wallet client required for write operations");
    const hash = await this.contract.write.unpause([], options || {});
    await this.publicClient.waitForTransactionReceipt({ hash });
  }

  /**
   * Subscribe to operation events
   */
  onOperationExecuted(
    callback: (
      operationId: Hex,
      user: Hex,
      success: boolean,
      message: string,
    ) => void,
  ): ReturnType<PublicClient["watchContractEvent"]> {
    return this.publicClient.watchContractEvent({
      address: this.contract.address,
      abi: ORCHESTRATOR_ABI,
      eventName: "OperationExecuted",
      onLogs: (logs) => {
        for (const log of logs) {
          const args = (log as unknown as { args: DecodedEventArgs }).args;
          callback(
            args.operationId as Hex,
            args.user as Hex,
            args.success as boolean,
            args.message as string,
          );
        }
      },
    });
  }
}

/*//////////////////////////////////////////////////////////////
                     UNIFIED CLIENT FACTORY
//////////////////////////////////////////////////////////////*/

export interface Soulv2Config {
  proofCarryingContainer?: Hex;
  policyBoundProofs?: Hex;
  executionAgnosticStateCommitments?: Hex;
  crossDomainNullifierAlgebra?: Hex;
  orchestrator?: Hex;
}

/**
 * Factory for creating Soul v2 primitive clients
 */
export class Soulv2ClientFactory {
  constructor(
    private config: Soulv2Config,
    private publicClient: PublicClient,
    private walletClient?: WalletClient,
  ) {}

  /**
   * Create ProofCarryingContainer client
   */
  proofCarryingContainer(): ProofCarryingContainerClient {
    if (!this.config.proofCarryingContainer) {
      throw new Error("ProofCarryingContainer address not configured");
    }
    return new ProofCarryingContainerClient(
      this.config.proofCarryingContainer as Hex,
      this.publicClient,
      this.walletClient,
    );
  }

  /**
   * Create PolicyBoundProofs client
   */
  policyBoundProofs(): PolicyBoundProofsClient {
    if (!this.config.policyBoundProofs) {
      throw new Error("PolicyBoundProofs address not configured");
    }
    return new PolicyBoundProofsClient(
      this.config.policyBoundProofs as Hex,
      this.publicClient,
      this.walletClient,
    );
  }

  /**
   * Create ExecutionAgnosticStateCommitments client
   */
  executionAgnosticStateCommitments(): ExecutionAgnosticStateCommitmentsClient {
    if (!this.config.executionAgnosticStateCommitments) {
      throw new Error(
        "ExecutionAgnosticStateCommitments address not configured",
      );
    }
    return new ExecutionAgnosticStateCommitmentsClient(
      this.config.executionAgnosticStateCommitments as Hex,
      this.publicClient,
      this.walletClient,
    );
  }

  /**
   * Create CrossDomainNullifierAlgebra client
   */
  crossDomainNullifierAlgebra(): CrossDomainNullifierAlgebraClient {
    if (!this.config.crossDomainNullifierAlgebra) {
      throw new Error("CrossDomainNullifierAlgebra address not configured");
    }
    return new CrossDomainNullifierAlgebraClient(
      this.config.crossDomainNullifierAlgebra as Hex,
      this.publicClient,
      this.walletClient,
    );
  }

  /**
   * Create Soulv2Orchestrator client
   */
  orchestrator(): Soulv2OrchestratorClient {
    if (!this.config.orchestrator) {
      throw new Error("Orchestrator address not configured");
    }
    return new Soulv2OrchestratorClient(
      this.config.orchestrator as Hex,
      this.publicClient,
      this.walletClient,
    );
  }

  /**
   * Alias for proofCarryingContainer
   */
  getPC3(): ProofCarryingContainerClient {
    return this.proofCarryingContainer();
  }

  /**
   * Alias for policyBoundProofs
   */
  getPBP(): PolicyBoundProofsClient {
    return this.policyBoundProofs();
  }

  /**
   * Alias for executionAgnosticStateCommitments
   */
  getEASC(): ExecutionAgnosticStateCommitmentsClient {
    return this.executionAgnosticStateCommitments();
  }

  /**
   * Alias for crossDomainNullifierAlgebra
   */
  getCDNA(): CrossDomainNullifierAlgebraClient {
    return this.crossDomainNullifierAlgebra();
  }

  /**
   * Alias for orchestrator
   */
  getOrchestrator(): Soulv2OrchestratorClient {
    return this.orchestrator();
  }

  /**
   * Get the public client
   */
  getPublicClient(): PublicClient {
    return this.publicClient;
  }

  /**
   * Get the wallet client
   */
  getWalletClient(): WalletClient | undefined {
    return this.walletClient;
  }

  /**
   * Get the provider (PublicClient for viem)
   */
  getProvider(): PublicClient {
    return this.publicClient;
  }

  /**
   * Estimate gas for a method.
   *
   * Uses the public client's gas estimation when a contract address and ABI
   * are available, otherwise returns a conservative default.
   */
  async estimateGas(
    method: string,
    params: Record<string, unknown>[],
  ): Promise<bigint> {
    try {
      // Use the public client to estimate gas via eth_estimateGas
      const gasEstimate = await this.publicClient.estimateGas({
        account: params[0]?.from as Hex | undefined,
        to: params[0]?.to as Hex | undefined,
        data: params[0]?.data as Hex | undefined,
        value: params[0]?.value as bigint | undefined,
      });
      // Add 20% buffer for safety
      return (gasEstimate * 120n) / 100n;
    } catch {
      // Conservative fallback if estimation fails
      console.warn(
        `Gas estimation failed for ${method}, using conservative default`,
      );
      return 500_000n;
    }
  }

  /**
   * Create all clients at once
   */
  all(): {
    pc3: ProofCarryingContainerClient;
    pbp: PolicyBoundProofsClient;
    easc: ExecutionAgnosticStateCommitmentsClient;
    cdna: CrossDomainNullifierAlgebraClient;
    orchestrator: Soulv2OrchestratorClient;
  } {
    return {
      pc3: this.proofCarryingContainer(),
      pbp: this.policyBoundProofs(),
      easc: this.executionAgnosticStateCommitments(),
      cdna: this.crossDomainNullifierAlgebra(),
      orchestrator: this.orchestrator(),
    };
  }
}
