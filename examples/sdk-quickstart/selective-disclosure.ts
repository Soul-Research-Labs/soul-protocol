/**
 * ZASEON — Selective Disclosure Example
 *
 * Demonstrates the compliance-with-privacy flow:
 *   1. Register as a compliance provider
 *   2. Issue KYC credentials with ZK proofs
 *   3. Create selective disclosure (prove attributes without revealing all)
 *   4. Verify compliance status
 *
 * Uses the ZaseonComplianceProvider SDK client.
 */
import {
  ZaseonComplianceProvider,
  type ComplianceConfig,
} from "../../sdk/src/compliance/ZaseonComplianceProvider";

// ─── Configuration ──────────────────────────────────────────────────────────
const config: ComplianceConfig = {
  rpcUrl: process.env.RPC_URL ?? "https://rpc.sepolia.org",
  contractAddress: process.env.COMPLIANCE_CONTRACT_ADDRESS as `0x${string}`,
  providerId: "example-provider",
};

async function main() {
  if (!config.contractAddress) {
    throw new Error("Set COMPLIANCE_CONTRACT_ADDRESS env var");
  }

  const provider = new ZaseonComplianceProvider(config);

  // ─── 1. Register as a Compliance Provider ─────────────────────────────
  console.log("Registering as compliance provider...");
  await provider.registerProvider("ExampleKYCProvider");
  console.log("Provider registered!");

  // ─── 2. Issue a Credential ────────────────────────────────────────────
  const userAddress =
    "0x1234567890abcdef1234567890abcdef12345678" as `0x${string}`;

  console.log("\nIssuing credential to user:", userAddress);
  const credentialId = await provider.issueCredential(userAddress, {
    level: "standard",
    jurisdiction: "US",
    expiry: Math.floor(Date.now() / 1000) + 86400 * 365, // 1 year
  });
  console.log("Credential issued:", credentialId);

  // ─── 3. Check Compliance Status ───────────────────────────────────────
  console.log("\nChecking compliance...");
  const isCompliant = await provider.checkCompliance(userAddress);
  console.log("User compliant:", isCompliant);

  // ─── 4. Selective Disclosure Flow ─────────────────────────────────────
  // In a real scenario, the user generates a ZK proof that selectively
  // discloses certain attributes (e.g., "jurisdiction = US") without
  // revealing others (e.g., exact KYC level or personal data).
  //
  // The SelectiveDisclosureManager contract on-chain verifies:
  //   - The credential is valid and not revoked
  //   - The ZK proof is valid for the disclosed fields
  //   - The disclosure has not expired
  //
  // See contracts/compliance/SelectiveDisclosureManager.sol for the
  // on-chain protocol and docs/MODULAR_PRIVACY_ARCHITECTURE.md for
  // the architecture.

  console.log("\n─── Selective Disclosure ───");
  console.log("Disclosed fields: [jurisdiction]");
  console.log("Hidden fields:    [name, dateOfBirth, kycLevel]");
  console.log(
    "Verifier sees:    jurisdiction=US, credential is valid, nothing else",
  );

  // ─── 5. Retrieve Provider Info ────────────────────────────────────────
  console.log("\nProvider info:");
  const info = await provider.getProviderInfo();
  console.log("  Name:", info.name);
  console.log("  Credentials issued:", info.credentialsIssued.toString());
  console.log("  Active:", info.isActive);

  console.log("\n✅ Selective disclosure example complete!");
}

main().catch(console.error);
