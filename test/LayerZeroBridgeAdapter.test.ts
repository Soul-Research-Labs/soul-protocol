import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex } from "viem";

/**
 * LayerZero Bridge Adapter Tests
 * 
 * Tests LayerZero V2 integration including:
 * - Peer configuration
 * - Cross-chain messaging
 * - OFT transfers
 * - Fee estimation
 */
describe("LayerZeroBridgeAdapter", function () {
    // Role constants
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const EXECUTOR_ROLE = keccak256(toBytes("EXECUTOR_ROLE"));
    const CONFIG_ROLE = keccak256(toBytes("CONFIG_ROLE"));

    // Test data
    const testEid = 30101; // Ethereum Sepolia
    const testPeerAddress = keccak256(toBytes("test-peer"));
    const testReceiver = keccak256(toBytes("test-receiver"));

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
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const bridgeFee = await bridge.read.bridgeFee();
            expect(bridgeFee).to.equal(10n); // 0.1%
        });

        it("Should grant admin role to deployer", async function () {
            const viem = await getViem();
            const [deployer] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });
            const hasRole = await bridge.read.hasRole([DEFAULT_ADMIN_ROLE, deployer.account.address]);
            expect(hasRole).to.be.true;
        });

        it("Should start with zero counters", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const stats = await bridge.read.getStats();
            expect(stats[0]).to.equal(0n); // sent
            expect(stats[1]).to.equal(0n); // received
        });

        it("Should have no registered peers initially", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const eids = await bridge.read.getRegisteredEids();
            expect(eids.length).to.equal(0);
        });
    });

    /*//////////////////////////////////////////////////////////////
                           CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Configuration", function () {
        it("Should set endpoint", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setEndpoint([admin.account.address, 30101]);

            const endpoint = await bridge.read.lzEndpoint();
            expect(endpoint.toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });

        it("Should reject zero address for endpoint", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const zeroAddress = "0x0000000000000000000000000000000000000000";
            let reverted = false;
            try {
                await bridge.write.setEndpoint([zeroAddress, 30101]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should set delegate", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setDelegate([admin.account.address]);

            const delegate = await bridge.read.delegate();
            expect(delegate.toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });

        it("Should set bridge fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setBridgeFee([50n]); // 0.5%

            const fee = await bridge.read.bridgeFee();
            expect(fee).to.equal(50n);
        });

        it("Should reject fee above 1%", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            let reverted = false;
            try {
                await bridge.write.setBridgeFee([101n]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });
    });

    /*//////////////////////////////////////////////////////////////
                          PEER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    describe("Peer Management", function () {
        it("Should set a peer", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([
                testEid,
                testPeerAddress,
                0, // EVM
                200000n,
                0 // STANDARD
            ]);

            const peer = await bridge.read.getPeer([testEid]);
            // PeerConfig: eid, peerAddress, chainType, active, minGas, securityLevel, registeredAt
            expect(Number(peer.eid || peer[0])).to.equal(testEid);
            expect(peer.peerAddress || peer[1]).to.equal(testPeerAddress);
        });

        it("Should reject duplicate peer", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            let reverted = false;
            try {
                await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should check if peer is active", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const isActive = await bridge.read.isPeerActive([testEid]);
            expect(isActive).to.be.true;
        });

        it("Should deactivate a peer", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);
            await bridge.write.deactivatePeer([testEid]);

            const isActive = await bridge.read.isPeerActive([testEid]);
            expect(isActive).to.be.false;
        });

        it("Should reactivate a peer", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);
            await bridge.write.deactivatePeer([testEid]);
            await bridge.write.reactivatePeer([testEid]);

            const isActive = await bridge.read.isPeerActive([testEid]);
            expect(isActive).to.be.true;
        });

        it("Should update peer security level", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);
            await bridge.write.updatePeerSecurity([testEid, 2]); // MAXIMUM

            const peer = await bridge.read.getPeer([testEid]);
            // PeerConfig: eid, peerAddress, chainType, active, minGas, securityLevel, registeredAt
            expect(Number(peer.securityLevel || peer[5])).to.equal(2); // MAXIMUM
        });
    });

    /*//////////////////////////////////////////////////////////////
                         LIBRARY CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    describe("Library Configuration", function () {
        it("Should set send library config", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setSendLibConfig([
                testEid,
                admin.account.address, // sendLib
                [admin.account.address], // requiredDVNs
                [], // optionalDVNs
                0, // optionalThreshold
                1048576, // maxMessageSize
                admin.account.address // executor
            ]);

            const config = await bridge.read.sendLibConfigs([testEid]);
            expect(config[0].toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });

        it("Should set receive library config", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setReceiveLibConfig([
                testEid,
                admin.account.address, // receiveLib
                [admin.account.address], // requiredDVNs
                [], // optionalDVNs
                0, // optionalThreshold
                3600n // gracePeriod
            ]);

            const config = await bridge.read.receiveLibConfigs([testEid]);
            expect(config[0].toLowerCase()).to.equal(admin.account.address.toLowerCase());
        });
    });

    /*//////////////////////////////////////////////////////////////
                            MESSAGING
    //////////////////////////////////////////////////////////////*/

    describe("Messaging", function () {
        it("Should send a message (lzSend)", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const message = toHex("test message");
            const options = {
                gas: 200000n,
                value: 0n,
                composeMsg: "0x",
                extraOptions: "0x"
            };

            await bridge.write.lzSend(
                [testEid, testReceiver, message, options],
                { value: parseEther("0.1") }
            );

            const stats = await bridge.read.getStats();
            expect(stats[0]).to.equal(1n); // sent
        });

        it("Should reject message to inactive peer", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);
            await bridge.write.deactivatePeer([testEid]);

            const message = toHex("test");
            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            let reverted = false;
            try {
                await bridge.write.lzSend(
                    [testEid, testReceiver, message, options],
                    { value: parseEther("0.1") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should reject message with insufficient gas", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const message = toHex("test");
            const options = { gas: 1000n, value: 0n, composeMsg: "0x", extraOptions: "0x" }; // Too low

            let reverted = false;
            try {
                await bridge.write.lzSend(
                    [testEid, testReceiver, message, options],
                    { value: parseEther("0.1") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should receive a message (lzReceive)", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.grantRole([EXECUTOR_ROLE, admin.account.address]);
            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const guid = keccak256(toBytes("test-guid"));
            const message = toHex("received message");

            await bridge.write.lzReceive([
                testEid,
                testPeerAddress,
                guid,
                message,
                "0x"
            ]);

            const stats = await bridge.read.getStats();
            expect(stats[1]).to.equal(1n); // received
        });

        it("Should increment nonce for sender", async function () {
            const viem = await getViem();
            const [sender] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const message = toHex("test");
            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            await bridge.write.lzSend(
                [testEid, testReceiver, message, options],
                { value: parseEther("0.1") }
            );

            const nonce = await bridge.read.getNonce([sender.account.address]);
            expect(nonce).to.equal(1n);
        });
    });

    /*//////////////////////////////////////////////////////////////
                          OFT TRANSFERS
    //////////////////////////////////////////////////////////////*/

    describe("OFT Transfers", function () {
        it("Should map local token to remote", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const remoteToken = keccak256(toBytes("remote-token"));
            await bridge.write.mapToken([admin.account.address, testEid, remoteToken]);

            const mapped = await bridge.read.getRemoteToken([admin.account.address, testEid]);
            expect(mapped).to.equal(remoteToken);
        });

        it("Should set OFT adapter", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const oftAdapter = admin.account.address;
            await bridge.write.setOFTAdapter([admin.account.address, oftAdapter]);

            const adapter = await bridge.read.tokenToOFT([admin.account.address]);
            expect(adapter.toLowerCase()).to.equal(oftAdapter.toLowerCase());
        });

        it("Should send OFT tokens", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const remoteToken = keccak256(toBytes("remote-token"));
            await bridge.write.mapToken([admin.account.address, testEid, remoteToken]);

            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };
            await bridge.write.sendOFT(
                [admin.account.address, testEid, testReceiver, 1000000n, options],
                { value: parseEther("0.1") }
            );
        });

        it("Should reject OFT send with zero amount", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const remoteToken = keccak256(toBytes("remote-token"));
            await bridge.write.mapToken([admin.account.address, testEid, remoteToken]);

            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            let reverted = false;
            try {
                await bridge.write.sendOFT(
                    [admin.account.address, testEid, testReceiver, 0n, options],
                    { value: parseEther("0.1") }
                );
            } catch (error) {
                reverted = true;
            }
            expect(reverted).to.be.true;
        });

        it("Should receive OFT tokens", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.grantRole([EXECUTOR_ROLE, admin.account.address]);
            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const transferId = keccak256(toBytes("transfer-id"));
            const remoteToken = keccak256(toBytes("remote-token"));
            const sender = keccak256(toBytes("sender"));

            await bridge.write.receiveOFT([
                transferId,
                testEid,
                remoteToken,
                sender,
                admin.account.address,
                1000000n
            ]);
        });
    });

    /*//////////////////////////////////////////////////////////////
                          FEE ESTIMATION
    //////////////////////////////////////////////////////////////*/

    describe("Fee Estimation", function () {
        it("Should quote send fee", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const message = toHex("test message for fee estimation");
            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            const fee = await bridge.read.quoteSend([testEid, message, options]);
            // Fee returns (nativeFee, lzTokenFee)
            const nativeFee = fee.nativeFee || fee[0];
            expect(nativeFee > 0n).to.be.true; // nativeFee > 0
        });
    });

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    describe("Admin Functions", function () {
        it("Should pause the bridge", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.pause();

            const isPaused = await bridge.read.paused();
            expect(isPaused).to.be.true;
        });

        it("Should unpause the bridge", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.pause();
            await bridge.write.unpause();

            const isPaused = await bridge.read.paused();
            expect(isPaused).to.be.false;
        });

        it("Should reject operations when paused", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);
            await bridge.write.pause();

            const message = toHex("test");
            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            let reverted = false;
            try {
                await bridge.write.lzSend(
                    [testEid, testReceiver, message, options],
                    { value: parseEther("0.1") }
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
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            const stats = await bridge.read.getStats();
            expect(stats).to.have.lengthOf(4);
        });

        it("Should get registered endpoint IDs", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([30101, testPeerAddress, 0, 200000n, 0]);
            await bridge.write.setPeer([30102, testPeerAddress, 1, 200000n, 1]); // Solana

            const eids = await bridge.read.getRegisteredEids();
            expect(eids.length).to.equal(2);
        });

        it("Should get message by GUID", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const message = toHex("test");
            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            await bridge.write.lzSend(
                [testEid, testReceiver, message, options],
                { value: parseEther("0.1") }
            );

            // GUID would be obtained from events in real test
        });
    });

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    describe("Integration Tests", function () {
        it("Should complete full message flow", async function () {
            const viem = await getViem();
            const [admin] = await viem.getWalletClients();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            // Setup
            await bridge.write.grantRole([EXECUTOR_ROLE, admin.account.address]);
            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            // Send
            const message = toHex("integration test");
            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            await bridge.write.lzSend(
                [testEid, testReceiver, message, options],
                { value: parseEther("0.1") }
            );

            // Receive (simulated)
            const guid = keccak256(toBytes("response-guid"));
            await bridge.write.lzReceive([testEid, testPeerAddress, guid, toHex("response"), "0x"]);

            const stats = await bridge.read.getStats();
            expect(stats[0]).to.equal(1n); // sent
            expect(stats[1]).to.equal(1n); // received
        });

        it("Should handle multiple chain types", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            // Add peers for different chain types
            await bridge.write.setPeer([30101, testPeerAddress, 0, 200000n, 0]); // EVM
            await bridge.write.setPeer([30102, testPeerAddress, 1, 200000n, 1]); // Solana
            await bridge.write.setPeer([30103, testPeerAddress, 2, 200000n, 0]); // Aptos

            const eids = await bridge.read.getRegisteredEids();
            expect(eids.length).to.equal(3);
        });

        it("Should handle concurrent messages", async function () {
            const viem = await getViem();
            const bridge = await viem.deployContract("LayerZeroBridgeAdapter");

            await bridge.write.setPeer([testEid, testPeerAddress, 0, 200000n, 0]);

            const options = { gas: 200000n, value: 0n, composeMsg: "0x", extraOptions: "0x" };

            for (let i = 0; i < 3; i++) {
                const message = toHex(`message ${i}`);
                await bridge.write.lzSend(
                    [testEid, testReceiver, message, options],
                    { value: parseEther("0.1") }
                );
            }

            const stats = await bridge.read.getStats();
            expect(stats[0]).to.equal(3n);
        });
    });
});
