import { expect } from "chai";
import hre from "hardhat";
import { parseEther, keccak256, toBytes, toHex, padHex, type Address } from "viem";

/**
 * L2 Bridge Adapters Test Suite
 * 
 * Comprehensive tests for all L2 bridge adapters:
 * - ScrollBridgeAdapter
 * - LineaBridgeAdapter  
 * - PolygonZkEVMBridgeAdapter
 * - zkSyncBridgeAdapter
 * - ArbitrumBridgeAdapter
 * 
 * Run: npx hardhat test test/L2BridgeAdapters.test.ts
 */
describe("L2 Bridge Adapters", function () {
    // Role constants
    const BRIDGE_OPERATOR_ROLE = keccak256(toBytes("BRIDGE_OPERATOR_ROLE"));
    const PAUSER_ROLE = keccak256(toBytes("PAUSER_ROLE"));
    const RELAYER_ROLE = keccak256(toBytes("RELAYER_ROLE"));
    const GUARDIAN_ROLE = keccak256(toBytes("GUARDIAN_ROLE"));
    const OPERATOR_ROLE = keccak256(toBytes("OPERATOR_ROLE"));
    const DEFAULT_ADMIN_ROLE = padHex("0x00", { size: 32 });

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

    // ============================================
    // SCROLL BRIDGE ADAPTER TESTS
    // ============================================

    describe("ScrollBridgeAdapter", function () {
        
        async function deployScrollAdapter() {
            const viem = await getViem();
            const [admin, operator, relayer, user] = await viem.getWalletClients();
            
            const adapter = await viem.deployContract("ScrollBridgeAdapter", [
                admin.account.address,   // scrollMessenger
                admin.account.address,   // gatewayRouter
                admin.account.address,   // rollupContract
                admin.account.address    // admin
            ]);
            
            // Grant roles
            await adapter.write.grantRole([BRIDGE_OPERATOR_ROLE, operator.account.address]);
            await adapter.write.grantRole([RELAYER_ROLE, relayer.account.address]);
            
            return { adapter, admin, operator, relayer, user, viem };
        }

        describe("Deployment", function () {
            it("Should deploy with correct configuration", async function () {
                const { adapter, admin } = await deployScrollAdapter();

                const hasAdminRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
                expect(hasAdminRole).to.be.true;
            });

            it("Should have correct chain ID constants", async function () {
                const { adapter } = await deployScrollAdapter();

                const mainnetChainId = await adapter.read.SCROLL_MAINNET_CHAIN_ID();
                const sepoliaChainId = await adapter.read.SCROLL_SEPOLIA_CHAIN_ID();
                
                expect(mainnetChainId).to.equal(534352n);
                expect(sepoliaChainId).to.equal(534351n);
            });

            it("Should have finality blocks set to 1 (ZK proof finality)", async function () {
                const { adapter } = await deployScrollAdapter();

                const finalityBlocks = await adapter.read.FINALITY_BLOCKS();
                expect(finalityBlocks).to.equal(1n);
            });
        });

        describe("Bridge Configuration", function () {
            it("Should set Soul Hub L2 address", async function () {
                const { adapter, admin, user } = await deployScrollAdapter();

                // Admin can set Soul Hub L2
                await adapter.write.setPilHubL2([user.account.address]);

                const pilHub = await adapter.read.pilHubL2();
                expect(pilHub.toLowerCase()).to.equal(user.account.address.toLowerCase());
            });

            it("Should set proof registry", async function () {
                const { adapter, admin, user } = await deployScrollAdapter();

                // Admin can set proof registry
                await adapter.write.setProofRegistry([user.account.address]);

                const registry = await adapter.read.proofRegistry();
                expect(registry.toLowerCase()).to.equal(user.account.address.toLowerCase());
            });
        });

        describe("Emergency Controls", function () {
            it("Should pause and unpause", async function () {
                const { adapter, admin, viem } = await deployScrollAdapter();

                await adapter.write.grantRole([PAUSER_ROLE, admin.account.address]);
                await adapter.write.pause();
                
                const paused = await adapter.read.paused();
                expect(paused).to.be.true;

                await adapter.write.unpause();
                const unpaused = await adapter.read.paused();
                expect(unpaused).to.be.false;
            });
        });
    });

    // ============================================
    // LINEA BRIDGE ADAPTER TESTS
    // ============================================

    describe("LineaBridgeAdapter", function () {
        
        async function deployLineaAdapter() {
            const viem = await getViem();
            const [admin, operator, relayer, user] = await viem.getWalletClients();
            
            const adapter = await viem.deployContract("LineaBridgeAdapter", [
                admin.account.address,   // messageService
                admin.account.address,   // tokenBridge
                admin.account.address,   // rollup
                admin.account.address    // admin
            ]);
            
            // Grant roles
            await adapter.write.grantRole([BRIDGE_OPERATOR_ROLE, operator.account.address]);
            await adapter.write.grantRole([RELAYER_ROLE, relayer.account.address]);
            
            return { adapter, admin, operator, relayer, user, viem };
        }

        describe("Deployment", function () {
            it("Should deploy with correct configuration", async function () {
                const { adapter, admin } = await deployLineaAdapter();

                const hasAdminRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
                expect(hasAdminRole).to.be.true;
            });

            it("Should have correct chain ID constants", async function () {
                const { adapter } = await deployLineaAdapter();

                const mainnetChainId = await adapter.read.LINEA_MAINNET_CHAIN_ID();
                const testnetChainId = await adapter.read.LINEA_TESTNET_CHAIN_ID();
                
                expect(mainnetChainId).to.equal(59144n);
                expect(testnetChainId).to.equal(59140n);
            });
        });

        describe("Bridge Configuration", function () {
            it("Should set Soul Hub L2 address", async function () {
                const { adapter, admin, user } = await deployLineaAdapter();

                // Admin can set Soul Hub L2
                await adapter.write.setPilHubL2([user.account.address]);

                const pilHub = await adapter.read.pilHubL2();
                expect(pilHub.toLowerCase()).to.equal(user.account.address.toLowerCase());
            });
        });

        describe("Emergency Controls", function () {
            it("Should pause and unpause", async function () {
                const { adapter, admin } = await deployLineaAdapter();

                await adapter.write.grantRole([PAUSER_ROLE, admin.account.address]);
                await adapter.write.pause();
                
                const paused = await adapter.read.paused();
                expect(paused).to.be.true;

                await adapter.write.unpause();
                const unpaused = await adapter.read.paused();
                expect(unpaused).to.be.false;
            });
        });
    });

    // ============================================
    // POLYGON ZKEVM BRIDGE ADAPTER TESTS
    // ============================================

    describe("PolygonZkEVMBridgeAdapter", function () {
        
        async function deployPolygonZkEVMAdapter() {
            const viem = await getViem();
            const [admin, operator, relayer, user] = await viem.getWalletClients();
            
            const adapter = await viem.deployContract("PolygonZkEVMBridgeAdapter", [
                admin.account.address,   // bridge
                admin.account.address,   // globalExitRootManager
                admin.account.address,   // polygonZkEVM
                0,                        // networkId (L1)
                admin.account.address    // admin
            ]);
            
            // Grant roles
            await adapter.write.grantRole([BRIDGE_OPERATOR_ROLE, operator.account.address]);
            await adapter.write.grantRole([RELAYER_ROLE, relayer.account.address]);
            
            return { adapter, admin, operator, relayer, user, viem };
        }

        describe("Deployment", function () {
            it("Should deploy with correct configuration", async function () {
                const { adapter, admin } = await deployPolygonZkEVMAdapter();

                const hasAdminRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
                expect(hasAdminRole).to.be.true;
            });

            it("Should have correct chain ID constants", async function () {
                const { adapter } = await deployPolygonZkEVMAdapter();

                const mainnetChainId = await adapter.read.POLYGON_ZKEVM_MAINNET();
                const testnetChainId = await adapter.read.POLYGON_ZKEVM_TESTNET();
                
                expect(mainnetChainId).to.equal(1101n);
                expect(testnetChainId).to.equal(1442n);
            });

            it("Should have correct network IDs", async function () {
                const { adapter } = await deployPolygonZkEVMAdapter();

                const mainnetNetworkId = await adapter.read.NETWORK_ID_MAINNET();
                const zkevmNetworkId = await adapter.read.NETWORK_ID_ZKEVM();
                expect(Number(mainnetNetworkId)).to.equal(0);
                expect(Number(zkevmNetworkId)).to.equal(1);
            });
        });

        describe("Bridge Configuration", function () {
            it("Should set Soul Hub L2 address", async function () {
                const { adapter, admin, user } = await deployPolygonZkEVMAdapter();

                // Admin can set Soul Hub L2
                await adapter.write.setPilHubL2([user.account.address]);

                const pilHub = await adapter.read.pilHubL2();
                expect(pilHub.toLowerCase()).to.equal(user.account.address.toLowerCase());
            });
        });

        describe("Emergency Controls", function () {
            it("Should pause and unpause", async function () {
                const { adapter, admin } = await deployPolygonZkEVMAdapter();

                await adapter.write.grantRole([PAUSER_ROLE, admin.account.address]);
                await adapter.write.pause();
                
                const paused = await adapter.read.paused();
                expect(paused).to.be.true;

                await adapter.write.unpause();
                const unpaused = await adapter.read.paused();
                expect(unpaused).to.be.false;
            });
        });
    });

    // ============================================
    // ZKSYNC BRIDGE ADAPTER TESTS
    // ============================================

    describe("zkSyncBridgeAdapter", function () {
        
        async function deployZkSyncAdapter() {
            const viem = await getViem();
            const [admin, operator, relayer, user] = await viem.getWalletClients();
            
            const adapter = await viem.deployContract("zkSyncBridgeAdapter", [
                admin.account.address,   // admin
                admin.account.address    // zkSyncDiamond
            ]);
            
            // Grant roles
            await adapter.write.grantRole([OPERATOR_ROLE, operator.account.address]);
            await adapter.write.grantRole([GUARDIAN_ROLE, relayer.account.address]);
            
            return { adapter, admin, operator, relayer, user, viem };
        }

        describe("Deployment", function () {
            it("Should deploy with correct configuration", async function () {
                const { adapter, admin } = await deployZkSyncAdapter();

                const hasAdminRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
                expect(hasAdminRole).to.be.true;
            });

            it("Should have correct chain ID constant", async function () {
                const { adapter } = await deployZkSyncAdapter();

                const chainId = await adapter.read.ZKSYNC_CHAIN_ID();
                expect(chainId).to.equal(324n);
            });
        });

        describe("Emergency Controls", function () {
            it("Should pause and unpause", async function () {
                const { adapter } = await deployZkSyncAdapter();

                await adapter.write.pause();
                
                const paused = await adapter.read.paused();
                expect(paused).to.be.true;

                await adapter.write.unpause();
                const unpaused = await adapter.read.paused();
                expect(unpaused).to.be.false;
            });
        });
    });

    // ============================================
    // ARBITRUM BRIDGE ADAPTER TESTS
    // ============================================

    describe("ArbitrumBridgeAdapter", function () {
        
        async function deployArbitrumAdapter() {
            const viem = await getViem();
            const [admin, operator, relayer, user] = await viem.getWalletClients();
            
            // ArbitrumBridgeAdapter only takes admin address
            const adapter = await viem.deployContract("ArbitrumBridgeAdapter", [
                admin.account.address   // admin
            ]);
            
            // Roles are granted in constructor already
            return { adapter, admin, operator, relayer, user, viem };
        }

        describe("Deployment", function () {
            it("Should grant admin role to deployer", async function () {
                const { adapter, admin } = await deployArbitrumAdapter();

                const hasRole = await adapter.read.hasRole([DEFAULT_ADMIN_ROLE, admin.account.address]);
                expect(hasRole).to.be.true;
            });

            it("Should have correct chain ID constants", async function () {
                const { adapter } = await deployArbitrumAdapter();

                const arbOneChainId = await adapter.read.ARB_ONE_CHAIN_ID();
                const arbNovaChainId = await adapter.read.ARB_NOVA_CHAIN_ID();
                
                expect(arbOneChainId).to.equal(42161n);
                expect(arbNovaChainId).to.equal(42170n);
            });

            it("Should have correct challenge period", async function () {
                const { adapter } = await deployArbitrumAdapter();

                const challengePeriod = await adapter.read.CHALLENGE_PERIOD();
                expect(challengePeriod).to.equal(604800n); // 7 days in seconds
            });
        });

        describe("Rollup Configuration", function () {
            it("Should configure Arbitrum One rollup", async function () {
                const { adapter, admin, user } = await deployArbitrumAdapter();

                // Configure rollup (admin has OPERATOR_ROLE from constructor)
                await adapter.write.configureRollup([
                    42161n,                    // chainId (Arbitrum One)
                    user.account.address,      // inbox
                    user.account.address,      // outbox  
                    user.account.address,      // bridge
                    user.account.address,      // rollup
                    0                          // rollupType (ARB_ONE)
                ]);

                // rollupConfigs returns [chainId, inbox, outbox, bridge, rollup, rollupType, active]
                const config = await adapter.read.rollupConfigs([42161n]);
                // active is the 7th element (index 6) in the returned tuple
                expect(config[6]).to.be.true;
            });
        });

        describe("Emergency Controls", function () {
            it("Should pause and unpause", async function () {
                const { adapter } = await deployArbitrumAdapter();

                await adapter.write.pause();
                
                const paused = await adapter.read.paused();
                expect(paused).to.be.true;

                await adapter.write.unpause();
                const unpaused = await adapter.read.paused();
                expect(unpaused).to.be.false;
            });
        });
    });
});
