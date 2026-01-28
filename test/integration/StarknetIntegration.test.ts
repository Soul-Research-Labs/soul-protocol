import { expect } from "chai";
import hre from "hardhat";
import { keccak256, toBytes, padHex, parseEther } from "viem";

/**
 * Starknet Integration Tests
 * 
 * End-to-end tests for the complete Starknet interoperability stack:
 * - Full bridge lifecycle (deposit → L2 processing → withdrawal)
 * - Cross-domain nullifier synchronization
 * - State sync and verification
 * - Multi-component interaction
 */
describe("Starknet Integration", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const SEQUENCER_ROLE = keccak256(toBytes("SEQUENCER_ROLE"));
    const VERIFIER_ROLE = keccak256(toBytes("VERIFIER_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const PROVER_ROLE = keccak256(toBytes("PROVER_ROLE"));
    const BRIDGE_ROLE = keccak256(toBytes("BRIDGE_ROLE"));
    const NULLIFIER_REGISTRAR_ROLE = keccak256(toBytes("NULLIFIER_REGISTRAR_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

    // Test constants
    const STARK_PRIME = 0x800000000000011000000000000000000000000000000000000000000000001n;

    // Helper to get viem
    async function getViem() {
        const { viem } = await hre.network.connect();
        return viem;
    }

    /*//////////////////////////////////////////////////////////////
                       FULL BRIDGE LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    describe("Full Bridge Lifecycle", function () {
        it("Should complete L1→L2 message lifecycle", async function () {
            const viem = await getViem();
            const [admin, operator, sequencer, user] = await viem.getWalletClients();

            // Deploy bridge adapter
            const bridge = await viem.deployContract("StarknetBridgeAdapter", [admin.account.address]);
            await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await bridge.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);

            // Configure Starknet core
            const mockStarknet = await viem.deployContract("contracts/mocks/MockStarknetMessaging.sol:MockStarknetMessaging");
            const mockCore = mockStarknet.address;
            await bridge.write.configure([mockCore, mockCore, 1n], { account: operator.account });

            // Step 1: User sends message to L2
            const toAddress = 12345n;
            const selector = 67890n;
            const payload = [100n, 200n];
            const fee = parseEther("0.01");

            const tx = await bridge.write.sendMessageToL2(
                [toAddress, selector, payload],
                { value: fee, account: user.account }
            );
            expect(tx).to.not.be.null;

            // Verify message was queued
            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // totalL1ToL2Messages
        });

        it.skip("Should complete L2→L1 message lifecycle", async function () {
            const viem = await getViem();
            const [admin, operator, sequencer] = await viem.getWalletClients();

            const bridge = await viem.deployContract("StarknetBridgeAdapter", [admin.account.address]);
            await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await bridge.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);

            const mockStarknet = await viem.deployContract("contracts/mocks/MockStarknetMessaging.sol:MockStarknetMessaging");
            const mockCore = mockStarknet.address;
            await bridge.write.configure([mockCore, mockCore, 1n], { account: operator.account });

            // Sequencer relays message from L2
            const fromAddress = 54321n;
            const payload = [500n, 600n];
            const starknetTxHash = keccak256(toBytes("starknet_tx"));

            const tx = await bridge.write.receiveMessageFromL2(
                [fromAddress, payload, starknetTxHash],
                { account: sequencer.account }
            );
            expect(tx).to.not.be.null;

            // Verify stats
            const stats = await bridge.read.getBridgeStats();
            expect(stats[1]).to.equal(1n); // totalL2ToL1Messages
        });
    });

    /*//////////////////////////////////////////////////////////////
                    CROSS-DOMAIN NULLIFIER SYNC
    //////////////////////////////////////////////////////////////*/

    describe.skip("Cross-Domain Nullifier Sync", function () {
        it("Should synchronize nullifier from L1 to L2", async function () {
            const viem = await getViem();
            const [admin, operator, registrar] = await viem.getWalletClients();

            const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");
            await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

            // Register domain
            const domainId = keccak256(toBytes("starknet_domain"));
            await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

            // Register nullifier
            const nullifierHash = keccak256(toBytes("private_transaction"));
            const commitment = keccak256(toBytes("commitment_hash"));

            await nullifier.write.registerNullifierFromL1(
                [nullifierHash, commitment, domainId],
                { account: registrar.account }
            );

            // Verify L2 nullifier was derived
            const l2Nullifier = await nullifier.read.getL2Nullifier([nullifierHash]);
            expect(l2Nullifier).to.not.equal(0n);
            expect(l2Nullifier).to.be.lessThan(STARK_PRIME);
        });

        it("Should prevent double-spend across domains", async function () {
            const viem = await getViem();
            const [admin, operator, registrar] = await viem.getWalletClients();

            const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");
            await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

            // Register domain
            const domainId = keccak256(toBytes("double_spend_domain"));
            await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

            // Register nullifier
            const nullifierHash = keccak256(toBytes("unique_nullifier"));
            const commitment = keccak256(toBytes("commitment"));

            await nullifier.write.registerNullifierFromL1(
                [nullifierHash, commitment, domainId],
                { account: registrar.account }
            );

            // Attempt double registration should fail
            let failed = false;
            try {
                await nullifier.write.registerNullifierFromL1(
                    [nullifierHash, commitment, domainId],
                    { account: registrar.account }
                );
            } catch {
                failed = true;
            }
            expect(failed).to.be.true;
        });

        it("Should track Merkle root updates", async function () {
            const viem = await getViem();
            const [admin, operator, registrar] = await viem.getWalletClients();

            const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");
            await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

            // Register domain
            const domainId = keccak256(toBytes("merkle_domain"));
            await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

            const initialRoot = await nullifier.read.getMerkleRoot();

            // Register multiple nullifiers
            for (let i = 0; i < 5; i++) {
                await nullifier.write.registerNullifierFromL1(
                    [keccak256(toBytes(`nullifier_${i}`)), keccak256(toBytes(`commitment_${i}`)), domainId],
                    { account: registrar.account }
                );
            }

            const finalRoot = await nullifier.read.getMerkleRoot();
            const count = await nullifier.read.totalNullifiers();

            expect(finalRoot).to.not.equal(initialRoot);
            expect(count).to.equal(5n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                         STATE SYNC INTEGRATION
    //////////////////////////////////////////////////////////////*/

    describe.skip("State Sync Integration", function () {
        it("Should sync state across multiple blocks", async function () {
            const viem = await getViem();
            const [admin, operator, sequencer, verifier] = await viem.getWalletClients();

            const stateSync = await viem.deployContract("StarknetStateSync");
            await stateSync.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await stateSync.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);
            await stateSync.write.grantRole([VERIFIER_ROLE, verifier.account.address]);

            const mockCore = "0x1234567890123456789012345678901234567890";
            await stateSync.write.setStarknetCore([mockCore], { account: operator.account });

            // Cache multiple blocks
            const blocks = [100n, 101n, 102n];

            for (const blockNumber of blocks) {
                await stateSync.write.cacheBlockHeader([
                    blockNumber,
                    keccak256(toBytes(`block_${blockNumber}`)),
                    keccak256(toBytes(`parent_${blockNumber}`)),
                    keccak256(toBytes(`state_${blockNumber}`)),
                    keccak256(toBytes(`tx_${blockNumber}`)),
                    keccak256(toBytes(`receipts_${blockNumber}`)),
                    keccak256(toBytes("sequencer")),
                    BigInt(Math.floor(Date.now() / 1000)),
                    1000000000n
                ], { account: sequencer.account });
            }

            // Verify latest block tracking
            const latestBlock = await stateSync.read.latestBlockNumber();
            expect(latestBlock).to.equal(102n);

            // Mark blocks as proven
            for (const blockNumber of blocks) {
                await stateSync.write.markBlockProven([
                    blockNumber,
                    toBytes("proof_sufficient_length")
                ], { account: verifier.account });
            }

            // Create checkpoint
            await stateSync.write.createCheckpoint([102n], { account: operator.account });
            const checkpointIndex = await stateSync.read.latestCheckpointIndex();
            expect(checkpointIndex).to.equal(1n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                    STARK PROOF INTEGRATION
    //////////////////////////////////////////////////////////////*/

    describe.skip("STARK Proof Integration", function () {
        it("Should complete full proof lifecycle", async function () {
            const viem = await getViem();
            const [admin, operator, prover, verifier, user] = await viem.getWalletClients();

            const proofVerifier = await viem.deployContract("StarknetProofVerifier");
            await proofVerifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await proofVerifier.write.grantRole([PROVER_ROLE, prover.account.address]);
            await proofVerifier.write.grantRole([VERIFIER_ROLE, verifier.account.address]);

            // Register program with valid security config
            // Security: 45 * log2(8) = 135 >= 128
            const programHash = keccak256(toBytes("integration_test_program"));
            const config = {
                domainSize: BigInt(1 << 16),
                blowupFactor: 8n,
                numQueries: 45n,
                foldingFactor: 2n,
                lastLayerDegBound: 64n,
                numLayers: 10n
            };
            await proofVerifier.write.registerProgram([programHash, config], { account: operator.account });

            // Submit proof
            const tx = await proofVerifier.write.submitProof([
                programHash,
                1, // CAIRO_1
                keccak256(toBytes("trace")),
                keccak256(toBytes("constraint")),
                keccak256(toBytes("composition")),
                [keccak256(toBytes("fri_0")), keccak256(toBytes("fri_1"))],
                [1n, 2n, 3n]
            ], { account: user.account });

            expect(tx).to.not.be.null;

            const stats = await proofVerifier.read.getStats();
            expect(stats[0]).to.equal(1n); // totalProofs
        });
    });

    /*//////////////////////////////////////////////////////////////
                     MULTI-COMPONENT INTEGRATION
    //////////////////////////////////////////////////////////////*/

    describe.skip("Multi-Component Integration", function () {
        it("Should coordinate bridge and nullifier operations", async function () {
            const viem = await getViem();
            const [admin, operator, sequencer, registrar, user] = await viem.getWalletClients();

            // Deploy both contracts
            const bridge = await viem.deployContract("StarknetBridgeAdapter", [admin.account.address]);
            const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

            // Configure bridge
            await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await bridge.write.grantRole([SEQUENCER_ROLE, sequencer.account.address]);
            const mockStarknet = await viem.deployContract("contracts/mocks/MockStarknetMessaging.sol:MockStarknetMessaging");
            const mockCore = mockStarknet.address;
            await bridge.write.configureStarkNetCore([mockCore], { account: operator.account });

            // Configure nullifier
            await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);

            const domainId = keccak256(toBytes("coordinated_domain"));
            await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

            // User creates nullifier and sends bridge message
            const nullifierHash = keccak256(toBytes("transfer_nullifier"));
            await nullifier.write.registerNullifierFromL1(
                [nullifierHash, keccak256(toBytes("commitment")), domainId],
                { account: registrar.account }
            );

            // Send bridge message
            await bridge.write.sendMessageToL2(
                [12345n, 67890n, [100n]],
                { value: parseEther("0.01"), account: user.account }
            );

            // Verify both operations succeeded
            const bridgeStats = await bridge.read.getBridgeStats();
            const nullifierCount = await nullifier.read.totalNullifiers();

            expect(bridgeStats[0]).to.equal(1n); // totalL1ToL2Messages
            expect(nullifierCount).to.equal(1n);
        });

        it("Should handle concurrent operations", async function () {
            const viem = await getViem();
            const [admin, operator, registrar, user1, user2] = await viem.getWalletClients();

            const bridge = await viem.deployContract("StarknetBridgeAdapter", [admin.account.address]);
            const nullifier = await viem.deployContract("CrossDomainNullifierStarknet");

            // Configure
            await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            const mockStarknet = await viem.deployContract("contracts/mocks/MockStarknetMessaging.sol:MockStarknetMessaging");
            const mockCore = mockStarknet.address;
            await bridge.write.configureStarkNetCore([mockCore], { account: operator.account });

            await nullifier.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await nullifier.write.grantRole([NULLIFIER_REGISTRAR_ROLE, registrar.account.address]);
            const domainId = keccak256(toBytes("concurrent_domain"));
            await nullifier.write.registerDomain([domainId, 0, 12345n], { account: operator.account });

            // Execute concurrent operations
            const operations = [];
            for (let i = 0; i < 5; i++) {
                operations.push(
                    nullifier.write.registerNullifierFromL1(
                        [keccak256(toBytes(`concurrent_null_${i}`)), keccak256(toBytes(`comm_${i}`)), domainId],
                        { account: registrar.account }
                    )
                );
                operations.push(
                    bridge.write.sendMessageToL2(
                        [BigInt(i + 1), 12345n, [BigInt(i)]],
                        { value: parseEther("0.01"), account: user1.account }
                    )
                );
            }

            await Promise.all(operations);

            // Verify counts
            expect(await nullifier.read.totalNullifiers()).to.equal(5n);
            expect((await bridge.read.getBridgeStats())[0]).to.equal(5n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                          ERROR HANDLING
    //////////////////////////////////////////////////////////////*/

    describe("Error Handling", function () {
        it("Should handle paused contracts", async function () {
            const viem = await getViem();
            const [admin, operator, guardian, user] = await viem.getWalletClients();

            const bridge = await viem.deployContract("StarknetBridgeAdapter", [admin.account.address]);
            await bridge.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await bridge.write.grantRole([GUARDIAN_ROLE, guardian.account.address]);

            const mockStarknet = await viem.deployContract("contracts/mocks/MockStarknetMessaging.sol:MockStarknetMessaging");
            const mockCore = mockStarknet.address;
            await bridge.write.configure([mockCore, mockCore, 1n], { account: operator.account });

            // Pause the bridge
            await bridge.write.pause([], { account: guardian.account });

            // Attempt to send message (should fail)
            let failed = false;
            try {
                await bridge.write.sendMessageToL2(
                    [12345n, 67890n, [100n]],
                    { value: parseEther("0.01"), account: user.account }
                );
            } catch {
                failed = true;
            }
            expect(failed).to.be.true;

            // Unpause
            await bridge.write.unpause([], { account: guardian.account });

            // Now should work
            const tx = await bridge.write.sendMessageToL2(
                [12345n, 67890n, [100n]],
                { value: parseEther("0.01"), account: user.account }
            );
            expect(tx).to.not.be.null;
        });
    });
});
