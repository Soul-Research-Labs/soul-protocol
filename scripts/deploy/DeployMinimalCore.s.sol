// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../contracts/privacy/PrivacyZoneManager.sol";
import "../../contracts/crosschain/SoulCrossChainRelay.sol";
import "../../contracts/security/OptimisticBridgeVerifier.sol";
import "../../contracts/security/BridgeRateLimiter.sol";
import "../../contracts/security/BridgeWatchtower.sol";
import "../../contracts/security/BridgeFraudProof.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";

/**
 * @title DeployMinimalCore
 * @notice Deploys the minimal core set of Soul Protocol contracts.
 *
 * Usage (dry-run):
 *   forge script scripts/deploy/DeployMinimalCore.s.sol \
 *     --rpc-url $BASE_SEPOLIA_RPC_URL -vvv
 *
 * Usage (broadcast):
 *   forge script scripts/deploy/DeployMinimalCore.s.sol \
 *     --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast -vvv
 */
contract DeployMinimalCore is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deployer:", deployer);
        console.log("Chain ID:", block.chainid);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Security Layer (needed as proofHub for relay)
        OptimisticBridgeVerifier verifier = new OptimisticBridgeVerifier(
            deployer
        );
        BridgeRateLimiter limiter = new BridgeRateLimiter(deployer);
        BridgeWatchtower watchtower = new BridgeWatchtower(deployer);

        // 2. Deploy Core Protocol
        // testMode=true for testnet deployment (relaxed constraints)
        PrivacyZoneManager zoneManager = new PrivacyZoneManager(deployer, true);

        // proofHub = verifier address, BridgeType.LAYERZERO for L2 testnets
        SoulCrossChainRelay relay = new SoulCrossChainRelay(
            address(verifier),
            SoulCrossChainRelay.BridgeType.LAYERZERO
        );

        // 3. Deploy Enhancements
        DecentralizedRelayerRegistry registry = new DecentralizedRelayerRegistry(
                deployer
            );
        BridgeFraudProof fraudProof = new BridgeFraudProof(
            address(verifier),
            deployer
        );

        // 4. Configuration / Wiring
        verifier.grantRole(verifier.RESOLVER_ROLE(), address(fraudProof));
        watchtower.setTargetContracts(address(relay), address(limiter));

        vm.stopBroadcast();

        // 5. Output addresses
        console.log("");
        console.log("=== Deployed Minimal Core ===");
        console.log("PrivacyZoneManager:           ", address(zoneManager));
        console.log("SoulCrossChainRelay:          ", address(relay));
        console.log("OptimisticBridgeVerifier:     ", address(verifier));
        console.log("BridgeRateLimiter:            ", address(limiter));
        console.log("BridgeWatchtower:             ", address(watchtower));
        console.log("DecentralizedRelayerRegistry: ", address(registry));
        console.log("BridgeFraudProof:             ", address(fraudProof));
        console.log("");
        console.log("Next steps:");
        console.log("  1. Verify contracts on BaseScan");
        console.log("  2. Fund relayer addresses with testnet ETH");
        console.log("  3. Configure cross-chain peer chains");
        console.log("");
        console.log("SECURITY REMINDER:");
        console.log("  If deploying ProofCarryingContainer separately, call");
        console.log("  lockVerificationMode() via multisig to permanently");
        console.log("  enable real ZK proof verification (irreversible).");
    }
}
