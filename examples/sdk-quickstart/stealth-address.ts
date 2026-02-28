/**
 * ZASEON — Stealth Address Example
 *
 * Demonstrates the full stealth address lifecycle:
 *   1. Generate a stealth meta-address keypair (spending + viewing keys)
 *   2. Register the meta-address on-chain
 *   3. Sender computes a stealth address and announces payment
 *   4. Receiver scans announcements to discover payments
 */
import StealthAddressClient, {
  StealthScheme,
} from "../../sdk/src/privacy/StealthAddressClient";
import { createPublicClient, createWalletClient, http } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// --- Configuration -----------------------------------------------------------
const REGISTRY_ADDRESS = process.env.STEALTH_REGISTRY as `0x${string}`;
const RECEIVER_KEY = process.env.RECEIVER_PRIVATE_KEY as `0x${string}`;
const SENDER_KEY = process.env.SENDER_PRIVATE_KEY as `0x${string}`;
const RPC_URL = process.env.RPC_URL ?? "https://rpc.sepolia.org";

async function main() {
  if (!REGISTRY_ADDRESS) throw new Error("Set STEALTH_REGISTRY env var");
  if (!RECEIVER_KEY) throw new Error("Set RECEIVER_PRIVATE_KEY env var");
  if (!SENDER_KEY) throw new Error("Set SENDER_PRIVATE_KEY env var");

  const transport = http(RPC_URL);

  // --- Receiver setup --------------------------------------------------------
  const receiverAccount = privateKeyToAccount(RECEIVER_KEY);
  const receiverWallet = createWalletClient({
    chain: sepolia,
    transport,
    account: receiverAccount,
  });
  const publicClient = createPublicClient({ chain: sepolia, transport });

  // Constructor: (contractAddress, publicClient, walletClient?)
  const receiverClient = new StealthAddressClient(
    REGISTRY_ADDRESS,
    publicClient as any,
    receiverWallet as any,
  );

  // 1. Generate meta-address keypair (spending + viewing keys)
  console.log("1. Generating stealth meta-address keypair...");
  const keys = StealthAddressClient.generateMetaAddress(
    StealthScheme.SECP256K1,
  );
  console.log("   spending pub:", keys.spendingPubKey.slice(0, 20) + "...");
  console.log("   viewing pub: ", keys.viewingPubKey.slice(0, 20) + "...");

  // 2. Register meta-address on-chain
  console.log("\n2. Registering stealth meta-address...");
  const { stealthId, txHash: regTx } = await receiverClient.registerMetaAddress(
    keys.spendingPubKey,
    keys.viewingPubKey,
    StealthScheme.SECP256K1,
  );
  console.log("   stealth ID:", stealthId);
  console.log("   register tx:", regTx);

  // --- Sender setup ----------------------------------------------------------
  const senderAccount = privateKeyToAccount(SENDER_KEY);
  const senderWallet = createWalletClient({
    chain: sepolia,
    transport,
    account: senderAccount,
  });

  const senderClient = new StealthAddressClient(
    REGISTRY_ADDRESS,
    publicClient as any,
    senderWallet as any,
  );

  // 3. Compute a one-time stealth address for the receiver
  console.log("\n3. Computing stealth address from stealth ID...");
  const stealth = await senderClient.computeStealthAddress(stealthId);
  console.log("   stealth address:", stealth.stealthAddress);
  console.log(
    "   ephemeral pub:  ",
    stealth.ephemeralPubKey.slice(0, 20) + "...",
  );

  // 4. Announce the payment on-chain
  console.log("\n4. Announcing payment...");
  const announceTx = await senderClient.announcePayment(
    stealth.stealthAddress,
    stealth.ephemeralPubKey,
    stealth.viewTag,
  );
  console.log("   announce tx:", announceTx);

  // 5. Receiver scans announcements
  console.log("\n5. Scanning announcements as receiver...");
  const payments = await receiverClient.scanAnnouncements(
    keys.viewingPrivKey,
    keys.spendingPubKey,
    0n, // fromBlock
  );
  console.log(`   Found ${payments.length} payment(s)`);
  for (const p of payments) {
    console.log(
      "   -",
      p.address,
      "ephemeral:",
      p.ephemeralPubKey.slice(0, 20) + "...",
    );
  }

  console.log("\n✅ Full stealth address lifecycle complete.");
}

main().catch(console.error);
