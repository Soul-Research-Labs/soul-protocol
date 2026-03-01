// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {NullifierRegistryV3} from "../../contracts/core/NullifierRegistryV3.sol";
import {CrossChainProofHubV3} from "../../contracts/bridge/CrossChainProofHubV3.sol";

/**
 * @title ZASEON Cross-Chain Configuration Script
 * @notice Links L1 Sepolia and L2 testnet deployments after initial deploys
 *
 * This script should be run AFTER:
 *   1. DeployMainnet.s.sol (or L1 testnet deploy) is complete on Sepolia
 *   2. DeployL2Testnet.s.sol is complete on each target L2 testnet
 *
 * It connects the L1 proof hub with L2 bridge adapters and syncs nullifier
 * registries across chains.
 *
 * Environment Variables:
 *   DEPLOYER_PRIVATE_KEY     - Must have admin role on target contracts
 *   PROOF_HUB_ADDRESS        - CrossChainProofHubV3 on Sepolia
 *   NULLIFIER_REGISTRY       - NullifierRegistryV3 on current chain
 *
 *   # Peer L2 bridge adapter addresses (set per-chain)
 *   ARBITRUM_SEPOLIA_ADAPTER - Bridge adapter on Arbitrum Sepolia
 *   BASE_SEPOLIA_ADAPTER     - Bridge adapter on Base Sepolia
 *   OPTIMISM_SEPOLIA_ADAPTER - Bridge adapter on Optimism Sepolia
 *   SCROLL_SEPOLIA_ADAPTER   - Bridge adapter on Scroll Sepolia
 *   LINEA_SEPOLIA_ADAPTER    - Bridge adapter on Linea Sepolia
 *   ZKSYNC_SEPOLIA_ADAPTER   - Bridge adapter on zkSync Sepolia
 *   POLYGON_ZKEVM_ADAPTER    - Bridge adapter on Polygon zkEVM Cardona
 *   STARKNET_ADAPTER         - Bridge adapter for Starknet Goerli
 *   MANTLE_TESTNET_ADAPTER   - Bridge adapter on Mantle Testnet
 *   BLAST_SEPOLIA_ADAPTER    - Bridge adapter on Blast Sepolia
 *   TAIKO_HEKLA_ADAPTER      - Bridge adapter on Taiko Hekla
 *   MODE_TESTNET_ADAPTER     - Bridge adapter on Mode Testnet
 *   MANTA_TESTNET_ADAPTER    - Bridge adapter on Manta Testnet
 *
 * Usage (run on Sepolia L1):
 *   forge script scripts/deploy/ConfigureCrossChain.s.sol \
 *     --rpc-url $SEPOLIA_RPC_URL \
 *     --broadcast -vvv
 */
contract ConfigureCrossChain is Script {
    // L2 testnet chain IDs
    uint256 constant ARBITRUM_SEPOLIA = 421614;
    uint256 constant BASE_SEPOLIA = 84532;
    uint256 constant OPTIMISM_SEPOLIA = 11155420;
    uint256 constant SCROLL_SEPOLIA = 534351;
    uint256 constant LINEA_SEPOLIA = 59141;
    uint256 constant ZKSYNC_SEPOLIA = 300;
    uint256 constant POLYGON_ZKEVM_CARDONA = 2442;
    uint256 constant STARKNET_GOERLI = 1263227476; // SN_GOERLI
    uint256 constant MANTLE_TESTNET = 5001;
    uint256 constant BLAST_SEPOLIA = 168587773;
    uint256 constant TAIKO_HEKLA = 167009;
    uint256 constant MODE_TESTNET = 919;
    uint256 constant MANTA_TESTNET = 3441006;
    uint256 constant L1_SEPOLIA = 11155111;

    function run() external {
        uint256 deployerPK = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);

        console.log("=== Cross-Chain Configuration ===");
        console.log("Chain ID:", block.chainid);
        console.log("Deployer:", deployer);

        if (block.chainid == L1_SEPOLIA) {
            _configureL1(deployerPK);
        } else {
            _configureL2(deployerPK);
        }
    }

    /// @notice Configure L1 Sepolia proof hub with L2 peer chains
    function _configureL1(uint256 deployerPK) internal {
        address proofHubAddr = vm.envAddress("PROOF_HUB_ADDRESS");
        CrossChainProofHubV3 proofHub = CrossChainProofHubV3(
            payable(proofHubAddr)
        );

        console.log("Configuring L1 ProofHub:", proofHubAddr);

        vm.startBroadcast(deployerPK);

        // Register all L2 testnet chains
        uint256[12] memory chains = [
            ARBITRUM_SEPOLIA,
            BASE_SEPOLIA,
            OPTIMISM_SEPOLIA,
            SCROLL_SEPOLIA,
            LINEA_SEPOLIA,
            ZKSYNC_SEPOLIA,
            POLYGON_ZKEVM_CARDONA,
            MANTLE_TESTNET,
            BLAST_SEPOLIA,
            TAIKO_HEKLA,
            MODE_TESTNET,
            MANTA_TESTNET
        ];

        string[12] memory names = [
            "Arbitrum Sepolia",
            "Base Sepolia",
            "Optimism Sepolia",
            "Scroll Sepolia",
            "Linea Sepolia",
            "zkSync Sepolia",
            "Polygon zkEVM Cardona",
            "Mantle Testnet",
            "Blast Sepolia",
            "Taiko Hekla",
            "Mode Testnet",
            "Manta Testnet"
        ];

        for (uint256 i; i < chains.length; i++) {
            // addSupportedChain is idempotent — will skip if already added
            try proofHub.addSupportedChain(chains[i]) {
                console.log(string.concat("  Added chain: ", names[i]));
            } catch {
                console.log(string.concat("  Already registered: ", names[i]));
            }
        }

        vm.stopBroadcast();
        console.log("L1 configuration complete");
    }

    /// @notice Configure L2 nullifier registry with peer chain domains
    function _configureL2(uint256 deployerPK) internal {
        address registryAddr = vm.envAddress("NULLIFIER_REGISTRY");
        NullifierRegistryV3 registry = NullifierRegistryV3(registryAddr);

        console.log("Configuring L2 NullifierRegistry:", registryAddr);

        vm.startBroadcast(deployerPK);

        // Register L1 + all L2 peer chains as nullifier sync domains
        uint256[13] memory peers = [
            L1_SEPOLIA,
            ARBITRUM_SEPOLIA,
            BASE_SEPOLIA,
            OPTIMISM_SEPOLIA,
            SCROLL_SEPOLIA,
            LINEA_SEPOLIA,
            ZKSYNC_SEPOLIA,
            POLYGON_ZKEVM_CARDONA,
            MANTLE_TESTNET,
            BLAST_SEPOLIA,
            TAIKO_HEKLA,
            MODE_TESTNET,
            MANTA_TESTNET
        ];

        for (uint256 i; i < peers.length; i++) {
            if (peers[i] != block.chainid) {
                try registry.registerDomain(bytes32(peers[i])) {
                    console.log(
                        string.concat(
                            "  Registered domain: ",
                            vm.toString(peers[i])
                        )
                    );
                } catch {
                    console.log(
                        string.concat(
                            "  Domain already registered: ",
                            vm.toString(peers[i])
                        )
                    );
                }
            }
        }

        vm.stopBroadcast();
        console.log("L2 configuration complete");
        _logNextSteps();
    }

    function _logNextSteps() internal pure {
        console.log("");
        console.log("=== Next Steps ===");
        console.log("1. Fund relayer wallets on each L2 testnet");
        console.log("2. Submit a test proof via SDK:");
        console.log(
            "     npx zaseon-cli submit-proof --network arbitrum-sepolia"
        );
        console.log("3. Verify cross-chain nullifier sync:");
        console.log("     npx zaseon-cli check-nullifier --all-chains");
        console.log("4. Run e2e integration test suite:");
        console.log(
            "     npx hardhat test test/integration/ --network arbitrum-sepolia"
        );
    }
}
