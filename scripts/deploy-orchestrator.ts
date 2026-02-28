import hre from "hardhat";
import fs from "fs";
import path from "path";
import { formatEther, parseEther, type Address, keccak256, toHex } from "viem";

/**
 * ZASEON Full Deployment Orchestrator
 *
 * Deploys ALL Zaseon contracts and wires them together in correct dependency order.
 * Includes: Verifier infrastructure, Core contracts, Privacy modules, Security,
 * Primitives, Governance, and full hub wiring via ZaseonProtocolHub.wireAll().
 *
 * Usage:
 *   npx hardhat run scripts/deploy-orchestrator.ts --network <network>
 */

const DEPLOYMENT_LOG_DIR = "./deployments";

// Role hashes (precomputed to match on-chain)
const REGISTRAR_ROLE = keccak256(toHex("REGISTRAR_ROLE"));
const BRIDGE_ROLE = keccak256(toHex("BRIDGE_ROLE"));
const OPERATOR_ROLE = keccak256(toHex("OPERATOR_ROLE"));
const REGISTRY_ADMIN_ROLE = keccak256(toHex("REGISTRY_ADMIN_ROLE"));

interface DeploymentRecord {
  network: string;
  chainId: number;
  deployer: string;
  timestamp: string;
  contracts: Record<string, string>;
  wiring: Record<string, string>;
}

async function main() {
  console.log("\n" + "=".repeat(80));
  console.log("ZASEON PROTOCOL — FULL DEPLOYMENT ORCHESTRATOR");
  console.log("=".repeat(80) + "\n");

  const { viem } = await hre.network.connect();
  const publicClient = await viem.getPublicClient();
  const [deployer] = await viem.getWalletClients();

  const balance = await publicClient.getBalance({
    address: deployer.account.address,
  });
  const chainId = await publicClient.getChainId();

  console.log("Deployer:", deployer.account.address);
  console.log("Balance:", formatEther(balance), "ETH");
  console.log("Network:", hre.network.name);
  console.log("Chain ID:", chainId);
  console.log("");

  if (balance < parseEther("0.1")) {
    console.error(
      "Insufficient balance. Need at least 0.1 ETH for full deployment.",
    );
    process.exit(1);
  }

  const deployed: DeploymentRecord = {
    network: hre.network.name,
    chainId,
    deployer: deployer.account.address,
    timestamp: new Date().toISOString(),
    contracts: {},
    wiring: {},
  };

  try {
    // ================================================================
    // PHASE 1: Verifier Infrastructure
    // ================================================================
    console.log("PHASE 1: Verifier Infrastructure\n");

    // 1a. Deploy MockProofVerifier (testnet) or use real verifiers
    console.log("  [1] MockProofVerifier...");
    const mockVerifier = await viem.deployContract("MockProofVerifier");
    await mockVerifier.write.setVerificationResult([true]);
    deployed.contracts.mockVerifier = mockVerifier.address;
    console.log("      =>", mockVerifier.address);

    // 1b. Deploy Groth16VerifierBN254
    console.log("  [2] Groth16VerifierBN254...");
    const groth16 = await viem.deployContract("Groth16VerifierBN254");
    deployed.contracts.groth16Verifier = groth16.address;
    console.log("      =>", groth16.address);

    // 1c. Deploy VerifierRegistryV2
    console.log("  [3] VerifierRegistryV2...");
    const verifierRegistry = await viem.deployContract("VerifierRegistryV2");
    deployed.contracts.verifierRegistry = verifierRegistry.address;
    console.log("      =>", verifierRegistry.address);

    // 1d. Deploy ZaseonUniversalVerifier
    console.log("  [4] ZaseonUniversalVerifier...");
    const universalVerifier = await viem.deployContract(
      "ZaseonUniversalVerifier",
    );
    deployed.contracts.universalVerifier = universalVerifier.address;
    console.log("      =>", universalVerifier.address);

    // ================================================================
    // PHASE 2: Core Contracts
    // ================================================================
    console.log("\nPHASE 2: Core Contracts\n");

    // 2a. NullifierRegistryV3
    console.log("  [5] NullifierRegistryV3...");
    const nullifierRegistry = await viem.deployContract("NullifierRegistryV3");
    deployed.contracts.nullifierRegistry = nullifierRegistry.address;
    console.log("      =>", nullifierRegistry.address);

    // 2b. ConfidentialStateContainerV3
    console.log("  [6] ConfidentialStateContainerV3...");
    const stateContainer = await viem.deployContract(
      "ConfidentialStateContainerV3",
      [mockVerifier.address],
    );
    deployed.contracts.stateContainer = stateContainer.address;
    console.log("      =>", stateContainer.address);

    // 2c. PrivacyRouter
    console.log("  [7] PrivacyRouter...");
    const privacyRouter = await viem.deployContract("PrivacyRouter");
    deployed.contracts.privacyRouter = privacyRouter.address;
    console.log("      =>", privacyRouter.address);

    // 2d. CrossChainProofHubV3
    console.log("  [8] CrossChainProofHubV3...");
    const proofHub = await viem.deployContract("CrossChainProofHubV3");
    deployed.contracts.proofHub = proofHub.address;
    console.log("      =>", proofHub.address);

    // ================================================================
    // PHASE 3: Privacy Modules
    // ================================================================
    console.log("\nPHASE 3: Privacy Modules\n");

    // 3a. StealthAddressRegistry
    console.log("  [9] StealthAddressRegistry...");
    const stealthRegistry = await viem.deployContract("StealthAddressRegistry");
    deployed.contracts.stealthAddressRegistry = stealthRegistry.address;
    console.log("      =>", stealthRegistry.address);

    // 3b. ShieldedPool
    console.log("  [10] ShieldedPool...");
    const shieldedPool = await viem.deployContract("ShieldedPool", [
      mockVerifier.address,
    ]);
    deployed.contracts.shieldedPool = shieldedPool.address;
    console.log("       =>", shieldedPool.address);

    // 3c. BatchAccumulator
    console.log("  [11] BatchAccumulator...");
    const batchAccumulator = await viem.deployContract("BatchAccumulator", [
      mockVerifier.address,
    ]);
    deployed.contracts.batchAccumulator = batchAccumulator.address;
    console.log("       =>", batchAccumulator.address);

    // 3d. ZaseonAtomicSwapV2
    console.log("  [12] ZaseonAtomicSwapV2...");
    const atomicSwap = await viem.deployContract("ZaseonAtomicSwapV2", [
      deployer.account.address,
    ]);
    deployed.contracts.atomicSwap = atomicSwap.address;
    console.log("       =>", atomicSwap.address);

    // ================================================================
    // PHASE 4: Zaseon v2 Primitives
    // ================================================================
    console.log("\nPHASE 4: Zaseon v2 Primitives\n");

    // 4a. ZKBoundStateLocks
    console.log("  [13] ZKBoundStateLocks...");
    const zkSlocks = await viem.deployContract("ZKBoundStateLocks", [
      mockVerifier.address,
    ]);
    deployed.contracts.zkBoundStateLocks = zkSlocks.address;
    console.log("       =>", zkSlocks.address);

    // 4b. ProofCarryingContainer (PC3)
    console.log("  [14] ProofCarryingContainer...");
    const pc3 = await viem.deployContract("ProofCarryingContainer");
    deployed.contracts.proofCarryingContainer = pc3.address;
    console.log("       =>", pc3.address);

    // 4c. CrossDomainNullifierAlgebra (CDNA)
    console.log("  [15] CrossDomainNullifierAlgebra...");
    const cdna = await viem.deployContract("CrossDomainNullifierAlgebra");
    deployed.contracts.crossDomainNullifierAlgebra = cdna.address;
    console.log("       =>", cdna.address);

    // 4d. PolicyBoundProofs (PBP)
    console.log("  [16] PolicyBoundProofs...");
    const pbp = await viem.deployContract("PolicyBoundProofs");
    deployed.contracts.policyBoundProofs = pbp.address;
    console.log("       =>", pbp.address);

    // ================================================================
    // PHASE 5: Security Infrastructure
    // ================================================================
    console.log("\nPHASE 5: Security Infrastructure\n");

    // 5a. BridgeProofValidator
    console.log("  [17] BridgeProofValidator...");
    const bridgeValidator = await viem.deployContract("BridgeProofValidator");
    deployed.contracts.relayProofValidator = bridgeValidator.address;
    console.log("       =>", bridgeValidator.address);

    // 5b. EmergencyRecovery
    console.log("  [18] EmergencyRecovery...");
    const emergencyRecovery = await viem.deployContract("EmergencyRecovery");
    deployed.contracts.emergencyRecovery = emergencyRecovery.address;
    console.log("       =>", emergencyRecovery.address);

    // ================================================================
    // PHASE 6: ZaseonProtocolHub (Central Registry)
    // ================================================================
    console.log("\nPHASE 6: ZaseonProtocolHub\n");

    console.log("  [19] ZaseonProtocolHub...");
    const hub = await viem.deployContract("ZaseonProtocolHub");
    deployed.contracts.zaseonProtocolHub = hub.address;
    console.log("       =>", hub.address);

    // ================================================================
    // PHASE 7: WIRING — Connect all contracts
    // ================================================================
    console.log("\nPHASE 7: WIRING\n");

    // 7a. Wire ZaseonProtocolHub via wireAll()
    console.log("  [W1] Hub wireAll()...");
    await hub.write.wireAll([
      {
        _verifierRegistry: verifierRegistry.address,
        _universalVerifier: universalVerifier.address,
        _crossChainMessageRelay: proofHub.address,
        _crossChainPrivacyHub: proofHub.address,
        _stealthAddressRegistry: stealthRegistry.address,
        _privateRelayerNetwork:
          "0x0000000000000000000000000000000000000000" as Address,
        _viewKeyRegistry:
          "0x0000000000000000000000000000000000000000" as Address,
        _shieldedPool: shieldedPool.address,
        _nullifierManager: nullifierRegistry.address,
        _complianceOracle:
          "0x0000000000000000000000000000000000000000" as Address,
        _proofTranslator:
          "0x0000000000000000000000000000000000000000" as Address,
        _privacyRouter: privacyRouter.address,
        _relayProofValidator: bridgeValidator.address,
        _zkBoundStateLocks: zkSlocks.address,
        _proofCarryingContainer: pc3.address,
        _crossDomainNullifierAlgebra: cdna.address,
        _policyBoundProofs: pbp.address,
      },
    ]);
    deployed.wiring.hubWireAll = "complete";
    console.log("       => Hub fully wired");

    // 7b. Grant REGISTRAR_ROLE to ZKBoundStateLocks on NullifierRegistryV3
    console.log("  [W2] Grant REGISTRAR_ROLE to ZKBoundStateLocks...");
    await nullifierRegistry.write.grantRole([REGISTRAR_ROLE, zkSlocks.address]);
    deployed.wiring.zkSlocksRegistrar = "granted";
    console.log("       => ZKBoundStateLocks can register nullifiers");

    // 7c. Set nullifierRegistry on ZKBoundStateLocks
    console.log("  [W3] Wire ZKBoundStateLocks -> NullifierRegistryV3...");
    await zkSlocks.write.setNullifierRegistry([nullifierRegistry.address]);
    deployed.wiring.zkSlocksNullifierRegistry = nullifierRegistry.address;
    console.log(
      "       => ZKBoundStateLocks propagates nullifiers to registry",
    );

    // 7d. Grant REGISTRAR_ROLE to BatchAccumulator on NullifierRegistryV3
    console.log("  [W4] Grant REGISTRAR_ROLE to BatchAccumulator...");
    await nullifierRegistry.write.grantRole([
      REGISTRAR_ROLE,
      batchAccumulator.address,
    ]);
    deployed.wiring.batchAccumulatorRegistrar = "granted";
    console.log("       => BatchAccumulator can register nullifiers");

    // 7e. Wire VerifierRegistryV2 proof type mappings for CrossChainProofHubV3 compatibility
    console.log("  [W5] Map proof types on VerifierRegistryV2...");
    const proofTypeMappings = [
      { name: "state_transfer", circuitType: 0 },
      { name: "cross_chain_proof", circuitType: 1 },
      { name: "nullifier", circuitType: 2 },
      { name: "merkle_proof", circuitType: 3 },
      { name: "policy", circuitType: 4 },
      { name: "compliance_proof", circuitType: 5 },
      { name: "container", circuitType: 6 },
      { name: "cross_domain_nullifier", circuitType: 7 },
      { name: "balance_proof", circuitType: 11 },
      { name: "private_transfer", circuitType: 12 },
      { name: "ring_signature", circuitType: 14 },
    ];
    const proofTypeHashes = proofTypeMappings.map((m) =>
      keccak256(toHex(m.name)),
    );
    const circuitTypes = proofTypeMappings.map((m) => m.circuitType);
    await verifierRegistry.write.batchSetProofTypeMappings([
      proofTypeHashes,
      circuitTypes,
    ]);
    deployed.wiring.proofTypeMappings = `${proofTypeMappings.length} types mapped`;
    console.log(`       => ${proofTypeMappings.length} proof types mapped`);

    // 7f. Set verifier registry on ProofHub
    console.log("  [W6] Wire ProofHub -> VerifierRegistryV2...");
    await proofHub.write.setVerifierRegistry([verifierRegistry.address]);
    deployed.wiring.proofHubRegistry = verifierRegistry.address;
    console.log(
      "       => ProofHub uses VerifierRegistryV2 for fallback verification",
    );

    // ================================================================
    // PHASE 8: Verification
    // ================================================================
    console.log("\nPHASE 8: Verification\n");

    const isConfigured = await hub.read.isFullyConfigured();
    console.log(`  Hub isFullyConfigured: ${isConfigured ? "YES" : "NO"}`);
    if (!isConfigured) {
      console.warn("  WARNING: Hub is not fully configured. Check wiring.");
    }

    // ================================================================
    // Save Deployment
    // ================================================================
    console.log("\n" + "=".repeat(80));
    console.log("DEPLOYMENT COMPLETE");
    console.log("=".repeat(80) + "\n");

    if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
      fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
    }

    const filename = `${hre.network.name}-${chainId}.json`;
    const filepath = path.join(DEPLOYMENT_LOG_DIR, filename);
    fs.writeFileSync(filepath, JSON.stringify(deployed, null, 2));
    console.log(`Deployment saved to: ${filepath}`);

    console.log("\nDeployed Contracts:");
    console.log("-".repeat(60));
    for (const [name, address] of Object.entries(deployed.contracts)) {
      console.log(`  ${name.padEnd(35)} ${address}`);
    }
    console.log("-".repeat(60));

    console.log("\nWiring Status:");
    console.log("-".repeat(60));
    for (const [key, value] of Object.entries(deployed.wiring)) {
      console.log(`  ${key.padEnd(35)} ${value}`);
    }
    console.log("-".repeat(60));
    console.log(`\nTotal contracts: ${Object.keys(deployed.contracts).length}`);
    console.log(`Total wiring ops: ${Object.keys(deployed.wiring).length}`);
  } catch (error) {
    console.error("\nDeployment failed:", error);

    // Save partial deployment for debugging
    if (Object.keys(deployed.contracts).length > 0) {
      const failFile = path.join(
        DEPLOYMENT_LOG_DIR,
        `FAILED-${hre.network.name}-${chainId}-${Date.now()}.json`,
      );
      if (!fs.existsSync(DEPLOYMENT_LOG_DIR)) {
        fs.mkdirSync(DEPLOYMENT_LOG_DIR, { recursive: true });
      }
      fs.writeFileSync(failFile, JSON.stringify(deployed, null, 2));
      console.error(`Partial deployment saved to: ${failFile}`);
    }
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
