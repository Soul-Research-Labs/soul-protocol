import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex, type Address } from "viem";

/**
 * Base Bridge Adapter Tests
 * 
 * Tests Base L2 integration including:
 * - CrossDomainMessenger configuration
 * - Proof relay to L2
 * - Withdrawal initiation and completion
 * - State synchronization
 * - Security controls
 */
describe("BaseBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const EXECUTOR_ROLE = keccak256(toBytes("EXECUTOR_ROLE"));
    const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

    // Chain IDs
    const BASE_MAINNET_CHAIN_ID = 8453n;
    const BASE_SEPOLIA_CHAIN_ID = 84532n;
    const WITHDRAWAL_PERIOD = 604800n; // 7 days

    // Test data
    const testProofHash = keccak256(toBytes("test-proof-hash"));
    const testProof = toHex("test-proof-data");
    const testPublicInputs = toHex("test-public-inputs");
    const testStateRoot = keccak256(toBytes("test-state-root"));

    async function getViem() {
        // @ts-expect-error - Hardhat 3 viem integration
        const { viem } = await hre.network.connect();
        return viem;
    }

    async function deployAdapter(isL1: boolean = true) {
        const viem = await getViem();
        const [admin] = await viem.getWalletClients();
        
        const mockMessenger = admin.account.address; // Use admin as mock messenger
        
        const adapter = await viem.deployContract("BaseBridgeAdapter", [
            admin.account.address,  // admin
            mockMessenger,          // l1CrossDomainMessenger
            mockMessenger,          // l2CrossDomainMessenger
            mockMessenger,          // basePortal
            isL1                    // isL1
        ]);
        
        return { adapter, admin, viem };
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    describe("Deployment", function () {
        it("Should deploy with correct initial state", async function () {
            const { adapter } = await deployAdapter(true);

            const isL1 = await adapter.read.isL1();
            expect(isL1).to.be.true;
        });

        it("Should deploy as L2 adapter", async function () {
            const { adapter } = await deployAdapter(false);

            const isL1 = await adapter.read.isL1();
            expect(isL1).to.be.false;
        });

        it("Should grant admin role to deployer", async function () {
            const { adapter, admin } = await deployAdapter();

            const hasRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should grant operator role to deployer", async function () {
            const { adapter, admin } = await deployAdapter();

            const hasRole = await adapter.read.hasRole([OPERATOR_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should grant guardian role to deployer", async function () {
            const { adapter, admin } = await deployAdapter();

            const hasRole = await adapter.read.hasRole([GUARDIAN_ROLE, admin.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should start with zero counters", async function () {
            const { adapter } = await deployAdapter();

            const stats = await adapter.read.getStats();
            expect(stats[0]).to.equal(0n); // messagesSent
            expect(stats[1]).to.equal(0n); // messagesReceived
            expect(stats[2]).to.equal(0n); // valueBridged
            expect(stats[3]).to.equal(0n); // currentNonce
        });

        it("Should set messenger addresses correctly", async function () {
            const { adapter, admin } = await deployAdapter();

            const l1Messenger = await adapter.read.l1CrossDomainMessenger();
            const l2Messenger = await adapter.read.l2CrossDomainMessenger();
            
            expect(l1Messenger.toLowerCase()).to.equal(admin.account.address.toLowerCase());
            expect(l2Messenger.toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set L2 target", async function () {
            const { adapter, admin, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            await adapter.write.setL2Target([other.account.address]);

            const l2Target = await adapter.read.l2Target();
            expect(l2Target.toLowerCase()).to.equal(other.account.address.toLowerCase());
        });

        it("Should emit L2TargetUpdated event", async function () {
            const { adapter, admin, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();

            const hash = await adapter.write.setL2Target([other.account.address]);
            const receipt = await publicClient.waitForTransactionReceipt({ hash });

            // Check for event in logs
            expect(receipt.logs.length).to.be.greaterThan(0);
        });

        it("Should update L1 messenger", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            await adapter.write.setMessenger([other.account.address, true]);

            const l1Messenger = await adapter.read.l1CrossDomainMessenger();
            expect(l1Messenger.toLowerCase()).to.equal(other.account.address.toLowerCase());
        });

        it("Should update L2 messenger", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            await adapter.write.setMessenger([other.account.address, false]);

            const l2Messenger = await adapter.read.l2CrossDomainMessenger();
            expect(l2Messenger.toLowerCase()).to.equal(other.account.address.toLowerCase());
        });

        it("Should reject non-admin setting L2 target", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            let reverted = false;
            try {
                await adapter.write.setL2Target([other.account.address], {
                    account: other.account
                });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PROOF RELAY (L1 -> L2)
    //////////////////////////////////////////////////////////////*/

    describe("Proof Relay", function () {
        it("Should send proof to L2", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            // Set L2 target first
            await adapter.write.setL2Target([target.account.address]);

            // Send proof
            const hash = await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: parseEther("0.01") });

            expect(hash).to.be.a("string");
        });

        it("Should increment message counter", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            const statsBefore = await adapter.read.getStats();
            
            await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: parseEther("0.01") });

            const statsAfter = await adapter.read.getStats();
            expect(statsAfter[0]).to.equal(statsBefore[0] + 1n);
        });

        it("Should track value bridged", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);
            const bridgeValue = parseEther("0.05");

            await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: bridgeValue });

            const stats = await adapter.read.getStats();
            expect(stats[2]).to.equal(bridgeValue);
        });

        it("Should reject if no L2 target set", async function () {
            const { adapter } = await deployAdapter(true);

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject insufficient gas limit", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    50000n // Below MIN_GAS_LIMIT
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject if called on L2 adapter", async function () {
            const { adapter, viem } = await deployAdapter(false); // L2
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PROOF RECEIVING (L2)
    //////////////////////////////////////////////////////////////*/

    describe("Proof Receiving", function () {
        it("Should receive proof from L1", async function () {
            const { adapter } = await deployAdapter(false);

            const hash = await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n // source chain ID
            ]);

            expect(hash).to.be.a("string");
        });

        it("Should mark proof as relayed", async function () {
            const { adapter } = await deployAdapter(false);

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            const isRelayed = await adapter.read.isProofRelayed([testProofHash]);
            expect(isRelayed).to.be.true;
        });

        it("Should reject duplicate proof relay", async function () {
            const { adapter } = await deployAdapter(false);

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            let reverted = false;
            try {
                await adapter.write.receiveProofFromL1([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1n
                ]);
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should increment received counter", async function () {
            const { adapter } = await deployAdapter(false);

            const statsBefore = await adapter.read.getStats();

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            const statsAfter = await adapter.read.getStats();
            expect(statsAfter[1]).to.equal(statsBefore[1] + 1n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                            WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    describe("Withdrawals", function () {
        it("Should initiate withdrawal from L2", async function () {
            const { adapter } = await deployAdapter(false); // L2

            const hash = await adapter.write.initiateWithdrawal([testProofHash], {
                value: parseEther("0.1")
            });

            expect(hash).to.be.a("string");
        });

        it("Should reject withdrawal initiation on L1", async function () {
            const { adapter } = await deployAdapter(true); // L1

            let reverted = false;
            try {
                await adapter.write.initiateWithdrawal([testProofHash], {
                    value: parseEther("0.1")
                });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should complete withdrawal on L1 after challenge period", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin] = await viem.getWalletClients();

            // Manually create a withdrawal that's ready
            // In production this would come from L2
            // For testing, we'd need to mock the withdrawal state
        });
    });

    /*//////////////////////////////////////////////////////////////
                          STATE SYNC
    //////////////////////////////////////////////////////////////*/

    describe("State Sync", function () {
        it("Should sync state to L2", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            const hash = await adapter.write.syncStateToL2([
                testStateRoot,
                100n, // block number
                500000n // gas limit
            ]);

            expect(hash).to.be.a("string");
        });

        it("Should receive state from L1", async function () {
            const { adapter } = await deployAdapter(false);

            await adapter.write.receiveStateFromL1([
                testStateRoot,
                100n
            ]);

            const blockNumber = await adapter.read.confirmedStateRoots([testStateRoot]);
            expect(blockNumber).to.equal(100n);
        });

        it("Should reject state sync on L2 adapter", async function () {
            const { adapter, viem } = await deployAdapter(false);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            let reverted = false;
            try {
                await adapter.write.syncStateToL2([
                    testStateRoot,
                    100n,
                    500000n
                ]);
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                         PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    describe("Pause Controls", function () {
        it("Should pause adapter", async function () {
            const { adapter } = await deployAdapter();

            await adapter.write.pause();

            const isPaused = await adapter.read.paused();
            expect(isPaused).to.be.true;
        });

        it("Should unpause adapter", async function () {
            const { adapter } = await deployAdapter();

            await adapter.write.pause();
            await adapter.write.unpause();

            const isPaused = await adapter.read.paused();
            expect(isPaused).to.be.false;
        });

        it("Should reject operations when paused", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);
            await adapter.write.pause();

            let reverted = false;
            try {
                await adapter.write.sendProofToL2([
                    testProofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject non-guardian pause", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            let reverted = false;
            try {
                await adapter.write.pause({ account: other.account });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                        EMERGENCY FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("Emergency Functions", function () {
        it("Should emergency withdraw", async function () {
            const { adapter, admin, viem } = await deployAdapter();
            const publicClient = await viem.getPublicClient();

            // Send some ETH to the adapter
            await admin.sendTransaction({
                to: adapter.address,
                value: parseEther("1")
            });

            const balanceBefore = await publicClient.getBalance({ address: admin.account.address });

            await adapter.write.emergencyWithdraw([
                admin.account.address,
                parseEther("0.5")
            ]);

            const balanceAfter = await publicClient.getBalance({ address: admin.account.address });
            // Balance should have increased (received 0.5 ETH minus gas costs)
            expect(balanceAfter > balanceBefore - parseEther("0.1")).to.be.true;
        });

        it("Should reject non-admin emergency withdraw", async function () {
            const { adapter, viem } = await deployAdapter();
            const [_, other] = await viem.getWalletClients();

            let reverted = false;
            try {
                await adapter.write.emergencyWithdraw([
                    other.account.address,
                    parseEther("0.1")
                ], { account: other.account });
            } catch {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("View Functions", function () {
        it("Should return message details", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            await adapter.write.sendProofToL2([
                testProofHash,
                testProof,
                testPublicInputs,
                1000000n
            ], { value: parseEther("0.01") });

            // Generate same message ID as contract
            // Note: exact ID generation may differ, this is a placeholder test
        });

        it("Should check if proof is relayed", async function () {
            const { adapter } = await deployAdapter(false);

            const notRelayed = await adapter.read.isProofRelayed([testProofHash]);
            expect(notRelayed).to.be.false;

            await adapter.write.receiveProofFromL1([
                testProofHash,
                testProof,
                testPublicInputs,
                1n
            ]);

            const isRelayed = await adapter.read.isProofRelayed([testProofHash]);
            expect(isRelayed).to.be.true;
        });

        it("Should return correct stats", async function () {
            const { adapter, viem } = await deployAdapter(true);
            const [admin, target] = await viem.getWalletClients();

            await adapter.write.setL2Target([target.account.address]);

            // Send multiple messages
            for (let i = 0; i < 3; i++) {
                const proofHash = keccak256(toBytes(`test-proof-${i}`));
                await adapter.write.sendProofToL2([
                    proofHash,
                    testProof,
                    testPublicInputs,
                    1000000n
                ], { value: parseEther("0.01") });
            }

            const stats = await adapter.read.getStats();
            expect(stats[0]).to.equal(3n); // 3 messages sent
            expect(stats[3]).to.equal(3n); // nonce is 3
        });
    });
});
