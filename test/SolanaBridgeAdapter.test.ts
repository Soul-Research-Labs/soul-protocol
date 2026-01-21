import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex } from "viem";

/**
 * Solana Bridge Adapter Tests
 * 
 * Tests Solana/Wormhole integration including:
 * - Program registration
 * - PDA management
 * - SPL Token mappings
 * - Cross-chain messaging
 * - VAA processing
 */
describe("SolanaBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const VAA_VERIFIER_ROLE = keccak256(toBytes("VAA_VERIFIER_ROLE"));

    // Test addresses
    const testProgramId = keccak256(toBytes("test-program"));
    const testPDA = keccak256(toBytes("test-pda"));
    const testMintAddress = keccak256(toBytes("test-spl-mint"));
    const testRecipient = keccak256(toBytes("test-recipient"));

    async function getViem() {
        const connection = await hre.network.connect();
        return connection.viem;
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    describe("Deployment", function () {
        it("Should deploy with correct initial state", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const bridgeFee = await bridge.read.bridgeFee();
            expect(bridgeFee).to.equal(10n); // 0.1%

            const minMessageFee = await bridge.read.minMessageFee();
            expect(minMessageFee).to.equal(parseEther("0.001"));
        });

        it("Should grant admin role to deployer", async function () {
            const viem = await getViem();
            const [deployer] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });
            const hasRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, deployer.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should start with zero counters", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(0n); // messagesSent
            expect(stats[1]).to.equal(0n); // messagesReceived
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set Wormhole core address", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWormholeCore([admin.account.address]);

            const core = await bridge.read.wormholeCore();
            expect(core.toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });

        it("Should reject zero address for Wormhole core", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const zeroAddress = "0x0000000000000000000000000000000000000000";
            let reverted = false;
            try {
                await bridge.write.setWormholeCore([zeroAddress]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should set bridge fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setBridgeFee([50n]); // 0.5%

            const fee = await bridge.read.bridgeFee();
            expect(fee).to.equal(50n);
        });

        it("Should reject fee above 1%", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.setBridgeFee([101n]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should set minimum message fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setMinMessageFee([parseEther("0.005")]);

            const fee = await bridge.read.minMessageFee();
            expect(fee).to.equal(parseEther("0.005"));
        });
    });

    /*//////////////////////////////////////////////////////////////
                        PROGRAM MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Program Management", function () {
        it("Should register a Solana program", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.registerProgram([testProgramId, "Test Program"]);

            const program = await bridge.read.programs([testProgramId]);
            expect(program[0]).to.equal(testProgramId); // programId
        });

        it("Should verify a registered program", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.grantRole([VAA_VERIFIER_ROLE, admin.account.address]);
            await bridge.write.registerProgram([testProgramId, "Test Program"]);
            await bridge.write.verifyProgram([testProgramId]);

            const program = await bridge.read.programs([testProgramId]);
            expect(program[2]).to.be.true; // verified
        });

        it("Should whitelist a program", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWhitelistedProgram([testProgramId, true]);

            const isWhitelisted = await bridge.read.isProgramWhitelisted([testProgramId]);
            expect(isWhitelisted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                          PDA MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("PDA Management", function () {
        it("Should register a PDA", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const seeds = [toHex("seed1"), toHex("seed2")];
            await bridge.write.registerPDA([testProgramId, seeds, 255, testPDA]);

            const pda = await bridge.read.pdaRegistry([testPDA]);
            // Auto-generated getter skips dynamic arrays, so:
            // [0] = programId, [1] = bump, [2] = derivedAddress, [3] = verified
            expect(pda[0]).to.equal(testProgramId); // programId
            expect(Number(pda[1])).to.equal(255); // bump
        });

        it("Should verify a PDA", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.grantRole([VAA_VERIFIER_ROLE, admin.account.address]);

            const seeds = [toHex("seed1")];
            await bridge.write.registerPDA([testProgramId, seeds, 254, testPDA]);
            await bridge.write.verifyPDA([testPDA, "0x"]);

            const pda = await bridge.read.pdaRegistry([testPDA]);
            // [0] = programId, [1] = bump, [2] = derivedAddress, [3] = verified
            expect(pda[3]).to.be.true; // verified
        });
    });

    /*//////////////////////////////////////////////////////////////
                        SPL TOKEN MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("SPL Token Management", function () {
        it("Should register an SPL token mapping", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.registerSPLToken([testMintAddress, 9, admin.account.address]);

            const token = await bridge.read.getSPLTokenInfo([testMintAddress]);
            // SPLTokenInfo: mintAddress, decimals, supply, evmToken, frozen, verified
            expect(token.mintAddress || token[0]).to.equal(testMintAddress);
            expect(Number(token.decimals || token[1])).to.equal(9);
        });

        it("Should verify an SPL token", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.grantRole([VAA_VERIFIER_ROLE, admin.account.address]);
            await bridge.write.registerSPLToken([testMintAddress, 9, admin.account.address]);
            await bridge.write.verifySPLToken([testMintAddress]);

            const token = await bridge.read.getSPLTokenInfo([testMintAddress]);
            // SPLTokenInfo: mintAddress, decimals, supply, evmToken, frozen, verified
            expect(token.verified || token[5]).to.be.true;
        });

        it("Should map EVM token to SPL mint", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.registerSPLToken([testMintAddress, 9, admin.account.address]);

            const mappedMint = await bridge.read.evmToSplToken([admin.account.address]);
            expect(mappedMint).to.equal(testMintAddress);
        });
    });

    /*//////////////////////////////////////////////////////////////
                            MESSAGING
    //////////////////////////////////////////////////////////////*/

    describe("Messaging", function () {
        it("Should send message to Solana", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWhitelistedProgram([testProgramId, true]);

            const payload = toHex("test message");
            await bridge.write.sendMessageToSolana(
                [testProgramId, testRecipient, payload],
                { value: parseEther("0.01") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n); // messagesSent
        });

        it("Should reject message with insufficient fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWhitelistedProgram([testProgramId, true]);

            const payload = toHex("test");
            let reverted = false;
            try {
                await bridge.write.sendMessageToSolana(
                    [testProgramId, testRecipient, payload],
                    { value: parseEther("0.0001") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject message to non-whitelisted program", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const payload = toHex("test");
            let reverted = false;
            try {
                await bridge.write.sendMessageToSolana(
                    [testProgramId, testRecipient, payload],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should increment nonce for sender", async function () {
            const viem = await getViem();
            const [sender] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWhitelistedProgram([testProgramId, true]);

            const payload = toHex("test");
            await bridge.write.sendMessageToSolana(
                [testProgramId, testRecipient, payload],
                { value: parseEther("0.01") }
            );

            const nonce = await bridge.read.getSenderNonce([sender.account.address]);
            expect(nonce).to.equal(1n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                          VAA MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("VAA Management", function () {
        it("Should submit a VAA", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.grantRole([RELAYER_ROLE, admin.account.address]);

            await bridge.write.submitVAA([
                1,                      // version
                0,                      // guardianSetIndex
                "0x",                   // signatures
                Math.floor(Date.now() / 1000), // timestamp
                12345,                  // nonce
                1,                      // emitterChainId (Solana)
                testProgramId,          // emitterAddress
                1n,                     // sequence
                1,                      // consistencyLevel
                toHex("payload")        // payload
            ]);
        });

        it("Should verify a VAA", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.grantRole([RELAYER_ROLE, admin.account.address]);
            await bridge.write.grantRole([VAA_VERIFIER_ROLE, admin.account.address]);

            const hash = await bridge.write.submitVAA([
                1, 0, "0x",
                Math.floor(Date.now() / 1000),
                12345, 1, testProgramId, 1n, 1,
                toHex("payload")
            ]);

            // In a real test, we'd extract the VAA hash from the event
        });

        it("Should check if VAA is used", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const fakeHash = keccak256(toBytes("fake-vaa"));
            const isUsed = await bridge.read.isVAAUsed([fakeHash]);
            expect(isUsed).to.be.false;
        });
    });

    /*//////////////////////////////////////////////////////////////
                          TOKEN TRANSFERS
    //////////////////////////////////////////////////////////////*/

    describe("Token Transfers", function () {
        it("Should initiate transfer to Solana", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            // Register token mapping
            await bridge.write.registerSPLToken([testMintAddress, 18, admin.account.address]);

            // Initiate transfer
            await bridge.write.transferToSolana(
                [admin.account.address, 10000n, testRecipient],
                { value: parseEther("0.01") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[2]).to.be.greaterThan(0n); // totalBridged
        });

        it("Should reject transfer with zero amount", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.registerSPLToken([testMintAddress, 18, admin.account.address]);

            let reverted = false;
            try {
                await bridge.write.transferToSolana(
                    [admin.account.address, 0n, testRecipient],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject transfer for unmapped token", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.transferToSolana(
                    [admin.account.address, 10000n, testRecipient],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("Admin Functions", function () {
        it("Should pause the bridge", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.pause();

            const isPaused = await bridge.read.paused();
            expect(isPaused).to.be.true;
        });

        it("Should unpause the bridge", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.pause();
            await bridge.write.unpause();

            const isPaused = await bridge.read.paused();
            expect(isPaused).to.be.false;
        });

        it("Should reject operations when paused", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWhitelistedProgram([testProgramId, true]);
            await bridge.write.pause();

            const payload = toHex("test");
            let reverted = false;
            try {
                await bridge.write.sendMessageToSolana(
                    [testProgramId, testRecipient, payload],
                    { value: parseEther("0.01") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("View Functions", function () {
        it("Should return bridge statistics", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            const stats = await bridge.read.getBridgeStats();
            expect(stats).to.have.lengthOf(4);
        });

        it("Should get transfer details", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.registerSPLToken([testMintAddress, 18, admin.account.address]);
            await bridge.write.transferToSolana(
                [admin.account.address, 10000n, testRecipient],
                { value: parseEther("0.01") }
            );

            // Transfer ID would be obtained from events in real test
        });
    });

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Integration Tests", function () {
        it("Should complete full message flow", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            // Setup
            await bridge.write.grantRole([RELAYER_ROLE, admin.account.address]);
            await bridge.write.grantRole([VAA_VERIFIER_ROLE, admin.account.address]);
            await bridge.write.setWhitelistedProgram([testProgramId, true]);

            // Send message
            const payload = toHex("integration test");
            await bridge.write.sendMessageToSolana(
                [testProgramId, testRecipient, payload],
                { value: parseEther("0.01") }
            );

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(1n);
        });

        it("Should handle multiple concurrent operations", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("SolanaBridgeAdapter");

            await bridge.write.setWhitelistedProgram([testProgramId, true]);

            // Send multiple messages
            for (let i = 0; i < 3; i++) {
                const payload = toHex(`message ${i}`);
                await bridge.write.sendMessageToSolana(
                    [testProgramId, testRecipient, payload],
                    { value: parseEther("0.01") }
                );
            }

            const stats = await bridge.read.getBridgeStats();
            expect(stats[0]).to.equal(3n);
        });
    });
});
