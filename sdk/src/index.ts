import { PILSDK } from "./client/PILSDK";
import { CryptoModule } from "./utils/crypto";
import ProofTranslator, {
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,
} from "./proof-translator/ProofTranslator";
import {
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,
} from "./proof-translator/adapters/ChainAdapter";

// PIL v2 Primitives
import {
  ProofCarryingContainerClient,
  PolicyBoundProofsClient,
  ExecutionAgnosticStateCommitmentsClient,
  CrossDomainNullifierAlgebraClient,
  PILv2ClientFactory,
  // Types
  Container,
  ContainerCreationParams,
  VerificationResult,
  DisclosurePolicy,
  PolicyCreationParams,
  BoundProofParams,
  BackendType,
  ExecutionBackend,
  BackendRegistrationParams,
  CommitmentParams,
  AttestationParams,
  CommitmentStats,
  Domain,
  DomainNullifier,
  DomainRegistrationParams,
  NullifierRegistrationParams,
  DerivedNullifierParams,
  NullifierStats,
  PILv2Config,
  TransactionOptions,
  ProofBundle,
} from "./client/PILv2Primitives";

export {
  // Core SDK
  PILSDK,
  CryptoModule,

  // Proof Translator
  ProofTranslator,
  parseSnarkjsProof,
  parseGnarkProof,
  parseArkworksProof,
  toSolidityBN254,
  toBytesBN254,
  toBytesBLS12381,
  translateForChain,
  createVerifyCalldata,
  createBatchProofData,
  CURVE_PARAMS,
  CHAIN_CONFIGS,

  // Chain Adapters
  EVMChainAdapter,
  EVMBLS12381Adapter,
  CosmosChainAdapter,
  SubstrateChainAdapter,
  createChainAdapter,
  MultiChainProofManager,

  // PIL v2 Primitives
  ProofCarryingContainerClient,
  PolicyBoundProofsClient,
  ExecutionAgnosticStateCommitmentsClient,
  CrossDomainNullifierAlgebraClient,
  PILv2ClientFactory,

  // PIL v2 Types
  Container,
  ContainerCreationParams,
  VerificationResult,
  DisclosurePolicy,
  PolicyCreationParams,
  BoundProofParams,
  BackendType,
  ExecutionBackend,
  BackendRegistrationParams,
  CommitmentParams,
  AttestationParams,
  CommitmentStats,
  Domain,
  DomainNullifier,
  DomainRegistrationParams,
  NullifierRegistrationParams,
  DerivedNullifierParams,
  NullifierStats,
  PILv2Config,
  TransactionOptions,
  ProofBundle,
};
