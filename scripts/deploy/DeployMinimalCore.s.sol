// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../../contracts/privacy/PrivacyZoneManager.sol";
import "../../contracts/crosschain/ZaseonCrossChainRelay.sol";
import "../../contracts/security/OptimisticRelayVerifier.sol";
import "../../contracts/security/RelayRateLimiter.sol";
import "../../contracts/security/RelayWatchtower.sol";
import "../../contracts/security/RelayFraudProof.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";

/**
 * @title DeployMinimalCore
 * @notice Deploys the minimal core set of ZASEON contracts.
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
        OptimisticRelayVerifier verifier = new OptimisticRelayVerifier(
            deployer
        );
        RelayRateLimiter limiter = new RelayRateLimiter(deployer);
        RelayWatchtower watchtower = new RelayWatchtower(deployer);

        // 2. Deploy Core Protocol
        // testMode=true for testnet deployment (relaxed constraints)
        PrivacyZoneManager zoneManager = new PrivacyZoneManager(deployer, true);

        // proofHub = verifier address, BridgeType.LAYERZERO for L2 testnets
        ZaseonCrossChainRelay relay = new ZaseonCrossChainRelay(
            address(verifier),
            ZaseonCrossChainRelay.BridgeType.LAYERZERO
        );

        // 3. Deploy Enhancements
        DecentralizedRelayerRegistry registry = new DecentralizedRelayerRegistry(
                deployer
            );
        RelayFraudProof fraudProof = new RelayFraudProof(
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
        console.log("ZaseonCrossChainRelay:          ", address(relay));
        console.log("OptimisticRelayVerifier:     ", address(verifier));
        console.log("RelayRateLimiter:            ", address(limiter));
        console.log("RelayWatchtower:             ", address(watchtower));
        console.log("DecentralizedRelayerRegistry: ", address(registry));
        console.log("RelayFraudProof:             ", address(fraudProof));
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
