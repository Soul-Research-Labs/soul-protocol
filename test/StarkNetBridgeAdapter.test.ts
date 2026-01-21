import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex, encodePacked } from "viem";

/**
 * StarkNet Bridge Adapter Tests
 * 
 * Tests StarkNet L2 integration including:
 * - L1 ↔ L2 messaging
 * - STARK proof verification
 * - Cairo contract registry
 * - Token bridging
 * - State updates
 */
describe("StarkNetBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const SEQUENCER_ROLE = keccak256(toBytes("SEQUENCER_ROLE"));
    const VERIFIER_ROLE = keccak256(toBytes("VERIFIER_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

    // Message status enum
    const MessageStatus = {
        PENDING: 0,
        SENT: 1,
        CONSUMED: 2,
        CANCELLED: 3,
        FAILED: 4
    };

    // Proof status enum
    const ProofStatus = {
        UNVERIFIED: 0,
        PENDING_VERIFICATION: 1,
        VERIFIED: 2,
        REJECTED: 3
    };

    // Cairo version enum
    const CairoVersion = {
        CAIRO_0: 0,
        CAIRO_1: 1,
        CAIRO_2: 2
    };

    // Test data
    const testStarkNetCore = "0x1234567890123456789012345678901234567890";
    const testL2Address = 12345678901234567890n;
    const testSelector = 987654321n; // Entry point selector
    const testPayload = [1n, 2n, 3n, 4n, 5n];
    const testProgramHash = keccak256(toBytes("cairo-program-v1"));
    const testOutputHash = keccak256(toBytes("program-output"));
    const testClassHash = 111222333444555n;
    const testL1Token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // USDC
    const testL2Token = 999888777666555n;
    const testProof = padHex("0x1234567890abcdef", { size: 64 });

    // Helper to get viem
    async function getViem() {
        const { viem } = await hre.network.connect();
        return viem;
    }

    /*//////////////////////////////////////////////////////////////
                              DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    describe("Deployment", function () {
        it("Should deploy with correct initial state", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const bridgeFeeBps = await bridge.read.bridgeFeeBps();
            const minMessageFee = await bridge.read.minMessageFee();
            const messageTimeout = await bridge.read.messageTimeout();

            expect(bridgeFeeBps).to.equal(10n); // 0.1%
            expect(minMessageFee).to.equal(parseEther("0.001"));
            expect(messageTimeout).to.equal(7n * 24n * 60n * 60n); // 7 days
        });

        it("Should grant admin role to deployer", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const hasAdminRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
            expect(hasAdminRole).to.be.true;
        });

        it("Should start with zero counters", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(0n); // totalL1ToL2Messages
            expect(stats[1]).to.equal(0n); // totalL2ToL1Messages
            expect(stats[2]).to.equal(0n); // totalProofs
            expect(stats[3]).to.equal(0n); // totalContracts
            expect(stats[4]).to.equal(0n); // totalBridgeOperations
            expect(stats[5]).to.equal(0n); // accumulatedFees
        });

        it("Should have no latest state initially", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const state = await bridge.read.getLatestState();
            expect(state[0]).to.equal(padHex("0x00", { size: 32 })); // stateRoot
            expect(state[1]).to.equal(0n); // blockNumber
        });
    });

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should configure StarkNet Core", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.configureStarkNetCore([testStarkNetCore]);

            const core = await bridge.read.starknetCore();
            expect(core.toLowerCase()).to.equal(testStarkNetCore.toLowerCase());
        });

        it("Should reject zero address for StarkNet Core", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.configureStarkNetCore([
                    "0x0000000000000000000000000000000000000000"
                ]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should set token mapping", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setTokenMapping([testL1Token, testL2Token]);

            const l2Token = await bridge.read.l1ToL2TokenMap([testL1Token]);
            const l1Token = await bridge.read.l2ToL1TokenMap([testL2Token]);

            expect(l2Token).to.equal(testL2Token);
            expect(l1Token.toLowerCase()).to.equal(testL1Token.toLowerCase());
        });

        it("Should set bridge fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setBridgeFee([50n]); // 0.5%

            const fee = await bridge.read.bridgeFeeBps();
            expect(fee).to.equal(50n);
        });

        it("Should reject fee above 1%", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.setBridgeFee([150n]); // 1.5%
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should set minimum message fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setMinMessageFee([parseEther("0.01")]);

            const fee = await bridge.read.minMessageFee();
            expect(fee).to.equal(parseEther("0.01"));
        });
    });

    /*//////////////////////////////////////////////////////////////
                       L1 TO L2 MESSAGING
    //////////////////////////////////////////////////////////////*/

    describe("L1 to L2 Messaging", function () {
        it("Should send message to L2", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("0.01") });

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // totalL1ToL2Messages
        });

        it("Should collect message fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("0.05") });

            const stats = await bridge.read.getBridgeStats();
            expect(stats[5]).to.equal(parseEther("0.05")); // accumulatedFees
        });

        it("Should reject message with insufficient fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.sendMessageToL2([
                    testL2Address,
                    testSelector,
                    testPayload
                ], { value: parseEther("0.0001") }); // Below minimum
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject message to zero address", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.sendMessageToL2([
                    0n, // Zero address
                    testSelector,
                    testPayload
                ], { value: parseEther("0.01") });
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject message with zero selector", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.sendMessageToL2([
                    testL2Address,
                    0n, // Zero selector
                    testPayload
                ], { value: parseEther("0.01") });
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should increment nonce for sender", async function () {
            const viem = await getViem();
            const [sender] = await viem.getWalletClients();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            // Send first message
            await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("0.01") });

            // Send second message
            await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("0.01") });

            const nonce = await bridge.read.messageNonces([sender.account.address]);
            expect(nonce).to.equal(2n);
        });

        it("Should confirm message as sent by sequencer", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            // Grant sequencer role
            await bridge.write.grantRole([SEQUENCER_ROLE, admin.account.address]);

            // Send message
            const hash = await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("0.01") });

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const messageHash = receipt.logs[0].topics[1];

            // Confirm as sent
            await bridge.write.confirmL1ToL2MessageSent([messageHash]);

            const message = await bridge.read.getL1ToL2Message([messageHash]);
            expect(message.status).to.equal(MessageStatus.SENT);
        });
    });

    /*//////////////////////////////////////////////////////////////
                       STARK PROOF VERIFICATION
    //////////////////////////////////////////////////////////////*/

    describe("STARK Proof Verification", function () {
        it("Should submit STARK proof", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const friCommitments = [
                keccak256(toBytes("fri-layer-1")),
                keccak256(toBytes("fri-layer-2"))
            ];

            await bridge.write.submitSTARKProof([
                testProgramHash,
                testOutputHash,
                123456789n,
                friCommitments,
                CairoVersion.CAIRO_1
            ]);

            const stats = await bridge.read.getBridgeStats();
            expect(stats[2]).to.equal(1n); // totalProofs
        });

        it("Should verify STARK proof", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            // Grant verifier role
            await bridge.write.grantRole([VERIFIER_ROLE, admin.account.address]);

            // Submit proof
            const friCommitments = [
                keccak256(toBytes("fri-layer-1")),
                keccak256(toBytes("fri-layer-2"))
            ];

            const hash = await bridge.write.submitSTARKProof([
                testProgramHash,
                testOutputHash,
                123456789n,
                friCommitments,
                CairoVersion.CAIRO_2
            ]);

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const proofId = receipt.logs[0].topics[1];

            // Verify
            const decommitments = [
                keccak256(toBytes("decommit-1")),
                keccak256(toBytes("decommit-2"))
            ];

            await bridge.write.verifySTARKProof([proofId, decommitments]);

            const proof = await bridge.read.getSTARKProof([proofId]);
            expect(proof.status).to.equal(ProofStatus.VERIFIED);
        });

        it("Should mark program as verified after proof verification", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.grantRole([VERIFIER_ROLE, admin.account.address]);

            const friCommitments = [keccak256(toBytes("fri-layer-1"))];

            const hash = await bridge.write.submitSTARKProof([
                testProgramHash,
                testOutputHash,
                123456789n,
                friCommitments,
                CairoVersion.CAIRO_1
            ]);

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const proofId = receipt.logs[0].topics[1];

            await bridge.write.verifySTARKProof([proofId, [keccak256(toBytes("decommit"))]]);

            const isVerified = await bridge.read.isProgramVerified([testProgramHash]);
            expect(isVerified).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                       CAIRO CONTRACT REGISTRY
    //////////////////////////////////////////////////////////////*/

    describe("Cairo Contract Registry", function () {
        it("Should register Cairo contract", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.registerCairoContract([
                testClassHash,
                testL2Address,
                testProgramHash,
                CairoVersion.CAIRO_1
            ]);

            const stats = await bridge.read.getBridgeStats();
            expect(stats[3]).to.equal(1n); // totalContracts
        });

        it("Should verify Cairo contract", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.grantRole([VERIFIER_ROLE, admin.account.address]);

            const hash = await bridge.write.registerCairoContract([
                testClassHash,
                testL2Address,
                testProgramHash,
                CairoVersion.CAIRO_2
            ]);

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const contractId = receipt.logs[0].topics[1];

            await bridge.write.verifyCairoContract([contractId]);

            const cairo = await bridge.read.getCairoContract([contractId]);
            expect(cairo.verified).to.be.true;
        });

        it("Should store correct Cairo version", async function () {
            const viem = await getViem();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const hash = await bridge.write.registerCairoContract([
                testClassHash,
                testL2Address,
                testProgramHash,
                CairoVersion.CAIRO_0
            ]);

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const contractId = receipt.logs[0].topics[1];

            const cairo = await bridge.read.getCairoContract([contractId]);
            expect(cairo.version).to.equal(CairoVersion.CAIRO_0);
        });
    });

    /*//////////////////////////////////////////////////////////////
                       BRIDGE OPERATIONS
    //////////////////////////////////////////////////////////////*/

    describe("Bridge Operations", function () {
        it("Should deposit tokens to L2", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            // Set token mapping first
            await bridge.write.setTokenMapping([testL1Token, testL2Token]);

            await bridge.write.depositToL2([
                testL1Token,
                parseEther("100"),
                testL2Address
            ], { value: parseEther("0.01") });

            const stats = await bridge.read.getBridgeStats();
            expect(stats[4]).to.equal(1n); // totalBridgeOperations
        });

        it("Should collect deposit fee", async function () {
            const viem = await getViem();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setTokenMapping([testL1Token, testL2Token]);

            const hash = await bridge.write.depositToL2([
                testL1Token,
                parseEther("1000"),
                testL2Address
            ], { value: parseEther("0.01") });

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const operationId = receipt.logs[0].topics[1];

            const operation = await bridge.read.getBridgeOperation([operationId]);
            // Fee = 0.1% of 1000 = 1, so amount = 999
            expect(operation.amount).to.equal(parseEther("999"));
        });

        it("Should reject deposit with zero amount", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setTokenMapping([testL1Token, testL2Token]);

            let reverted = false;
            try {
                await bridge.write.depositToL2([
                    testL1Token,
                    0n,
                    testL2Address
                ], { value: parseEther("0.01") });
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject deposit without token mapping", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.depositToL2([
                    testL1Token, // No mapping set
                    parseEther("100"),
                    testL2Address
                ], { value: parseEther("0.01") });
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should withdraw tokens from L2", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setTokenMapping([testL1Token, testL2Token]);

            const operationId = keccak256(toBytes("withdrawal-1"));

            await bridge.write.withdrawFromL2([
                operationId,
                testL2Token,
                parseEther("50"),
                admin.account.address,
                testProof
            ]);

            const stats = await bridge.read.getBridgeStats();
            expect(stats[4]).to.equal(1n); // totalBridgeOperations
        });
    });

    /*//////////////////////////////////////////////////////////////
                          STATE UPDATES
    //////////////////////////////////////////////////////////////*/

    describe("State Updates", function () {
        it("Should submit state update", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.grantRole([SEQUENCER_ROLE, admin.account.address]);

            const blockHash = keccak256(toBytes("block-hash"));
            const stateRoot = keccak256(toBytes("state-root"));
            const parentStateRoot = keccak256(toBytes("parent-state-root"));

            await bridge.write.submitStateUpdate([
                12345n,
                blockHash,
                stateRoot,
                parentStateRoot,
                [testL2Address]
            ]);

            // State should not be verified yet
            const state = await bridge.read.getLatestState();
            expect(state[1]).to.equal(0n);
        });

        it("Should verify state update", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.grantRole([SEQUENCER_ROLE, admin.account.address]);
            await bridge.write.grantRole([VERIFIER_ROLE, admin.account.address]);

            const blockNumber = 99999n;
            const blockHash = keccak256(toBytes("block-hash"));
            const stateRoot = keccak256(toBytes("state-root"));
            const parentStateRoot = keccak256(toBytes("parent-state-root"));

            const hash = await bridge.write.submitStateUpdate([
                blockNumber,
                blockHash,
                stateRoot,
                parentStateRoot,
                [testL2Address]
            ]);

            await publicClient.waitForTransactionReceipt({ hash });

            // Compute updateId the same way the contract does using encodePacked
            const computedUpdateId = keccak256(
                encodePacked(
                    ["uint256", "bytes32", "bytes32"],
                    [blockNumber, blockHash, stateRoot]
                )
            );

            await bridge.write.verifyStateUpdate([computedUpdateId, testProof]);

            const state = await bridge.read.getLatestState();
            expect(state[0]).to.equal(stateRoot);
            expect(state[1]).to.equal(blockNumber);
        });
    });

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("Admin Functions", function () {
        it("Should set message timeout", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const newTimeout = 14n * 24n * 60n * 60n; // 14 days
            await bridge.write.setMessageTimeout([newTimeout]);

            expect(await bridge.read.messageTimeout()).to.equal(newTimeout);
        });

        it("Should reject timeout too short", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.setMessageTimeout([3600n]); // 1 hour
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should pause the bridge", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.pause();

            expect(await bridge.read.paused()).to.be.true;
        });

        it("Should unpause the bridge", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.pause();
            await bridge.write.unpause();

            expect(await bridge.read.paused()).to.be.false;
        });

        it("Should withdraw accumulated fees", async function () {
            const viem = await getViem();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            // Send message to accumulate fees
            await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("1") });

            const recipient = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF";
            const balanceBefore = await publicClient.getBalance({ address: recipient });

            await bridge.write.withdrawFees([recipient]);

            const balanceAfter = await publicClient.getBalance({ address: recipient });
            expect(balanceAfter > balanceBefore).to.be.true;

            const stats = await bridge.read.getBridgeStats();
            expect(stats[5]).to.equal(0n); // fees reset
        });
    });

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("View Functions", function () {
        it("Should return bridge statistics", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const stats = await bridge.read.getBridgeStats();
            expect(stats.length).to.equal(6);
        });

        it("Should check if program is verified", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const isVerified = await bridge.read.isProgramVerified([testProgramHash]);
            expect(isVerified).to.be.false;
        });

        it("Should check if message is consumed", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            const messageHash = keccak256(toBytes("some-message"));
            const isConsumed = await bridge.read.isMessageConsumed([messageHash]);
            expect(isConsumed).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Integration Tests", function () {
        it("Should complete full L1 to L2 message flow", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const publicClient = await viem.getPublicClient();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.grantRole([SEQUENCER_ROLE, admin.account.address]);

            // 1. Send message
            const hash = await bridge.write.sendMessageToL2([
                testL2Address,
                testSelector,
                testPayload
            ], { value: parseEther("0.02") });

            const receipt = await publicClient.waitForTransactionReceipt({ hash });
            const messageHash = receipt.logs[0].topics[1];

            // 2. Verify pending status
            let message = await bridge.read.getL1ToL2Message([messageHash]);
            expect(message.status).to.equal(MessageStatus.PENDING);

            // 3. Confirm sent by sequencer
            await bridge.write.confirmL1ToL2MessageSent([messageHash]);

            // 4. Verify sent status
            message = await bridge.read.getL1ToL2Message([messageHash]);
            expect(message.status).to.equal(MessageStatus.SENT);
        });

        it("Should handle multiple Cairo versions", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            // Register contracts with different Cairo versions
            await bridge.write.registerCairoContract([
                testClassHash,
                testL2Address,
                testProgramHash,
                CairoVersion.CAIRO_0
            ]);

            await bridge.write.registerCairoContract([
                testClassHash + 1n,
                testL2Address + 1n,
                keccak256(toBytes("program-2")),
                CairoVersion.CAIRO_1
            ]);

            await bridge.write.registerCairoContract([
                testClassHash + 2n,
                testL2Address + 2n,
                keccak256(toBytes("program-3")),
                CairoVersion.CAIRO_2
            ]);

            const stats = await bridge.read.getBridgeStats();
            expect(stats[3]).to.equal(3n); // totalContracts
        });

        it("Should handle concurrent bridge operations", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("StarkNetBridgeAdapter");

            await bridge.write.setTokenMapping([testL1Token, testL2Token]);

            // Multiple deposits
            for (let i = 0; i < 3; i++) {
                await bridge.write.depositToL2([
                    testL1Token,
                    parseEther(String((i + 1) * 100)),
                    testL2Address + BigInt(i)
                ], { value: parseEther("0.01") });
            }

            const stats = await bridge.read.getBridgeStats();
            expect(stats[4]).to.equal(3n); // totalBridgeOperations
        });
    });
});
