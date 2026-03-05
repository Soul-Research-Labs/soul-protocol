/**
 * ZASEON Testnet Deployment Script (Hardhat)
 *
 * Deploys the core ZASEON protocol contracts to any configured testnet.
 * Used by deploy-all-testnets.sh for multi-chain orchestration.
 *
 * Usage:
 *   npx hardhat run scripts/deploy/deploy-testnet.ts --network arbitrumSepolia
 *   npx hardhat run scripts/deploy/deploy-testnet.ts --network optimismSepolia
 *
 * Required env vars:
 *   PRIVATE_KEY — deployer wallet private key
 *
 * Optional env vars:
 *   VERIFY_CONTRACTS=true — verify on block explorers after deploy
 */

import hre from "hardhat";
import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

interface DeployedContracts {
  [name: string]: string;
}

async function main() {
  const network = await hre.network.connect();
  const viem = network.viem;
  const [deployer] = await viem.getWalletClients();
  const publicClient = await viem.getPublicClient();
  const chainId = await publicClient.getChainId();

  console.log("=== ZASEON Testnet Deployment ===");
  console.log(`Network:  ${hre.network.name}`);
  console.log(`Chain ID: ${chainId}`);
  console.log(`Deployer: ${deployer.account.address}`);
  console.log("");

  const deployed: DeployedContracts = {};

  // Phase 1: Security Layer
  console.log("Phase 1: Deploying Security Layer...");

  const verifier = await viem.deployContract("OptimisticRelayVerifier", [
    deployer.account.address,
  ]);
  deployed.optimisticRelayVerifier = verifier.address;
  console.log(`  OptimisticRelayVerifier: ${verifier.address}`);

  const rateLimiter = await viem.deployContract("RelayRateLimiter", [
    deployer.account.address,
  ]);
  deployed.relayRateLimiter = rateLimiter.address;
  console.log(`  RelayRateLimiter: ${rateLimiter.address}`);

  const watchtower = await viem.deployContract("RelayWatchtower", [
    deployer.account.address,
  ]);
  deployed.relayWatchtower = watchtower.address;
  console.log(`  RelayWatchtower: ${watchtower.address}`);

  // Phase 2: Core Protocol
  console.log("Phase 2: Deploying Core Protocol...");

  const zoneManager = await viem.deployContract("PrivacyZoneManager", [
    deployer.account.address,
    true, // testMode = true for testnets
  ]);
  deployed.privacyZoneManager = zoneManager.address;
  console.log(`  PrivacyZoneManager: ${zoneManager.address}`);

  const relay = await viem.deployContract("ZaseonCrossChainRelay", [
    verifier.address,
    1, // BridgeType.LAYERZERO
  ]);
  deployed.zaseonCrossChainRelay = relay.address;
  console.log(`  ZaseonCrossChainRelay: ${relay.address}`);

  // Phase 3: Relayer Infrastructure
  console.log("Phase 3: Deploying Relayer Infrastructure...");

  const relayerRegistry = await viem.deployContract(
    "DecentralizedRelayerRegistry",
    [deployer.account.address],
  );
  deployed.decentralizedRelayerRegistry = relayerRegistry.address;
  console.log(`  DecentralizedRelayerRegistry: ${relayerRegistry.address}`);

  const fraudProof = await viem.deployContract("RelayFraudProof", [
    verifier.address,
    deployer.account.address,
  ]);
  deployed.relayFraudProof = fraudProof.address;
  console.log(`  RelayFraudProof: ${fraudProof.address}`);

  // Phase 4: Verifier + Proof Hub
  console.log("Phase 4: Deploying Verifier & Proof Hub...");

  const verifierRegistry = await viem.deployContract("VerifierRegistryV2", [
    deployer.account.address,
  ]);
  deployed.verifierRegistry = verifierRegistry.address;
  console.log(`  VerifierRegistryV2: ${verifierRegistry.address}`);

  const proofHub = await viem.deployContract("CrossChainProofHubV3", [
    deployer.account.address,
  ]);
  deployed.crossChainProofHub = proofHub.address;
  console.log(`  CrossChainProofHubV3: ${proofHub.address}`);

  // Phase 5: Privacy Primitives
  console.log("Phase 5: Deploying Privacy Primitives...");

  const nullifierRegistry = await viem.deployContract("NullifierRegistryV3", [
    deployer.account.address,
  ]);
  deployed.nullifierRegistry = nullifierRegistry.address;
  console.log(`  NullifierRegistryV3: ${nullifierRegistry.address}`);

  const pcc = await viem.deployContract("ProofCarryingContainer", [
    verifierRegistry.address,
  ]);
  deployed.proofCarryingContainer = pcc.address;
  console.log(`  ProofCarryingContainer: ${pcc.address}`);

  // Phase 6: Hub Deployment + Wiring
  console.log("Phase 6: Deploying ZaseonProtocolHub...");

  const hub = await viem.deployContract("ZaseonProtocolHub");
  deployed.zaseonProtocolHub = hub.address;
  console.log(`  ZaseonProtocolHub: ${hub.address}`);

  // Phase 7: Post-deploy Wiring
  console.log("Phase 7: Wiring components...");

  // Grant RESOLVER_ROLE on OptimisticRelayVerifier to RelayFraudProof
  const RESOLVER_ROLE = await verifier.read.RESOLVER_ROLE();
  await verifier.write.grantRole([RESOLVER_ROLE, fraudProof.address]);
  console.log("  Granted RESOLVER_ROLE to RelayFraudProof");

  // Configure watchtower
  await watchtower.write.setTargetContracts([
    relay.address,
    rateLimiter.address,
  ]);
  console.log("  Configured RelayWatchtower targets");

  // Wire Hub with available components (zero-address fields are skipped)
  const zeroAddr = "0x0000000000000000000000000000000000000000" as const;
  await hub.write.wireAll([
    {
      _verifierRegistry: verifierRegistry.address,
      _universalVerifier: zeroAddr,
      _crossChainMessageRelay: relay.address,
      _crossChainPrivacyHub: zeroAddr,
      _stealthAddressRegistry: zeroAddr,
      _privateRelayerNetwork: relayerRegistry.address,
      _viewKeyRegistry: zeroAddr,
      _shieldedPool: zeroAddr,
      _nullifierManager: nullifierRegistry.address,
      _complianceOracle: zeroAddr,
      _proofTranslator: zeroAddr,
      _privacyRouter: zeroAddr,
      _relayProofValidator: zeroAddr,
      _zkBoundStateLocks: zeroAddr,
      _proofCarryingContainer: pcc.address,
      _crossDomainNullifierAlgebra: zeroAddr,
      _policyBoundProofs: zeroAddr,
      _multiProver: zeroAddr,
      _relayWatchtower: watchtower.address,
      _intentCompletionLayer: zeroAddr,
      _instantCompletionGuarantee: zeroAddr,
      _dynamicRoutingOrchestrator: zeroAddr,
      _crossChainLiquidityVault: zeroAddr,
    },
  ]);
  console.log("  Hub wireAll() completed");

  // Save deployment
  const deploymentDir = join(__dirname, "..", "..", "deployments");
  mkdirSync(deploymentDir, { recursive: true });

  const deploymentData = {
    network: hre.network.name,
    chainId,
    deployer: deployer.account.address,
    timestamp: new Date().toISOString(),
    contracts: deployed,
  };

  const filename = `${hre.network.name}-${chainId}.json`;
  const filepath = join(deploymentDir, filename);
  writeFileSync(filepath, JSON.stringify(deploymentData, null, 2));
  console.log("");
  console.log(`Deployment saved to: deployments/${filename}`);

  // Summary
  console.log("");
  console.log("=== Deployment Summary ===");
  console.log(`Contracts deployed: ${Object.keys(deployed).length}`);
  for (const [name, address] of Object.entries(deployed)) {
    console.log(`  ${name}: ${address}`);
  }

  console.log("");
  console.log("Next steps:");
  console.log("  1. Verify contracts on block explorer");
  console.log("  2. Run ConfigureCrossChain.s.sol to link L2 peers");
  console.log("  3. Fund relayer and register in DecentralizedRelayerRegistry");
  console.log(
    "  4. Run ConfirmRoleSeparation.s.sol to enable proof submission",
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
