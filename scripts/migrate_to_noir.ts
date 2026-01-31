import { ethers } from "hardhat";

async function main() {
  console.log("Starting Noir Verifier Migration...");

  // Addresses of already deployed generated verifiers
  const deployedVerifiers = {
    stateTransfer: "0x...",
    crossChain: "0x...",
    policy: "0x...",
    commitment: "0x...",
    nullifier: "0x...",
    privateTransfer: "0x...",
    compliance: "0x...",
    balance: "0x...",
    swap: "0x...",
    ringSig: "0x...",
    privateOrder: "0x..."
  };

  const [deployer] = await ethers.getSigners();
  console.log("Deploying with address:", deployer.address);

  // 1. Deploy Adapters
  console.log("Deploying Adapters...");
  
  const adapters = [];
  
  const adapterConfigs = [
    { name: "StateTransferAdapter", vk: deployedVerifiers.stateTransfer },
    { name: "CrossChainAdapter", vk: deployedVerifiers.crossChain },
    { name: "PolicyVerifierAdapter", vk: deployedVerifiers.policy },
    { name: "CommitmentAdapter", vk: deployedVerifiers.commitment },
    { name: "NullifierAdapter", vk: deployedVerifiers.nullifier },
    { name: "PrivateTransferAdapter", vk: deployedVerifiers.privateTransfer },
    { name: "ComplianceAdapter", vk: deployedVerifiers.compliance },
    { name: "BalanceProofAdapter", vk: deployedVerifiers.balance },
    { name: "SwapProofAdapter", vk: deployedVerifiers.swap },
    { name: "RingSignatureAdapter", vk: deployedVerifiers.ringSig },
    { name: "PrivateOrderAdapter", vk: deployedVerifiers.privateOrder }
  ];

  for (const config of adapterConfigs) {
    const Factory = await ethers.getContractFactory(config.name);
    const adapter = await Factory.deploy(config.vk);
    await adapter.deployed();
    console.log(`${config.name} deployed to:`, adapter.address);
    adapters.push({ name: config.name, address: adapter.address });
  }

  // 2. Register in VerifierRegistry
  const registryAddress = "0x..."; // Soul Registry Address
  const Registry = await ethers.getContractAt("VerifierRegistry", registryAddress);

  const PROOF_TYPES = {
    STATE_TRANSITION: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("STATE_TRANSITION_PROOF")),
    CROSS_DOMAIN: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("CROSS_DOMAIN_PROOF")),
    POLICY: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("POLICY_PROOF")),
    COMMITMENT: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("STATE_COMMITMENT_PROOF")),
    NULLIFIER: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("NULLIFIER_PROOF")),
    PRIVATE_TRANSFER: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("PRIVATE_TRANSFER_PROOF")),
    COMPLIANCE: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("COMPLIANCE_PROOF")),
    BALANCE: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("BALANCE_PROOF")),
    SWAP: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("SWAP_PROOF")),
    RING_SIGNATURE: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("RING_SIGNATURE_PROOF")),
    PRIVATE_ORDER: ethers.utils.keccak256(ethers.utils.toUtf8Bytes("PRIVATE_ORDER_PROOF"))
  };

  console.log("Registering new versions in Registry...");

  await Registry.registerVerifierVersion(PROOF_TYPES.STATE_TRANSITION, adapters[0].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.CROSS_DOMAIN, adapters[1].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.POLICY, adapters[2].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.COMMITMENT, adapters[3].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.NULLIFIER, adapters[4].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.PRIVATE_TRANSFER, adapters[5].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.COMPLIANCE, adapters[6].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.BALANCE, adapters[7].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.SWAP, adapters[8].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.RING_SIGNATURE, adapters[9].address);
  await Registry.registerVerifierVersion(PROOF_TYPES.PRIVATE_ORDER, adapters[10].address);

  // 3. Link UniversalVerifier to Registry for dynamic routing
  const universalVerifierAddress = "0x..."; // Soul Universal Verifier Address
  const UniversalVerifier = await ethers.getContractAt("SoulUniversalVerifier", universalVerifierAddress);
  
  console.log("Linking UniversalVerifier to Registry...");
  await UniversalVerifier.setVerifierRegistry(Registry.address);

  // 4. Link VerifierHub and CrossChainProofHubV3 for full protocol alignment
  const hubAddress = "0x..."; // Soul VerifierHub Address
  const bridgeAddress = "0x..."; // Soul CrossChainProofHubV3 Address
  
  const Hub = await ethers.getContractAt("VerifierHub", hubAddress);
  const Bridge = await ethers.getContractAt("CrossChainProofHubV3", bridgeAddress);

  console.log("Linking VerifierHub to Registry...");
  await Hub.setVerifierRegistry(Registry.address);

  console.log("Linking CrossChainProofHubV3 to Registry...");
  await Bridge.setVerifierRegistry(Registry.address);

  console.log("Migration complete. Full protocol alignment enabled.");
  console.log("Run switch script to perform Canary cutover.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
