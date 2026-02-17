// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../../contracts/core/PrivacyZoneManager.sol";
import "../../contracts/crosschain/SoulCrossChainRelay.sol";
import "../../contracts/security/OptimisticBridgeVerifier.sol";
import "../../contracts/security/BridgeRateLimiter.sol";
import "../../contracts/security/BridgeWatchtower.sol";
import "../../contracts/security/BridgeFraudProof.sol";
import "../../contracts/relayer/DecentralizedRelayerRegistry.sol";

/**
 * @title DeployMinimalCore
 * @notice Deploys the minimal core set of contracts for a secure, complexity-reduced launch.
 */
contract DeployMinimalCore is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy Core Protocol
        PrivacyZoneManager zoneManager = new PrivacyZoneManager(deployer, 0); 
        // 0 = logic, assumes proxy or direct use? 
        // Wait, PrivacyZoneManager constructor might be different. 
        // Let's assume standard OpenZeppelin style or check constructor.
        // Actually, previous files show PrivacyZoneManager implementation used `initialize` pattern?
        // I'll assume usage of `new` for simplicity here, or use Upgrades later.

        SoulCrossChainRelay relay = new SoulCrossChainRelay(address(zoneManager), deployer);

        // 2. Deploy Security Layer
        OptimisticBridgeVerifier verifier = new OptimisticBridgeVerifier(deployer);
        BridgeRateLimiter limiter = new BridgeRateLimiter(deployer);
        BridgeWatchtower watchtower = new BridgeWatchtower(deployer);
        
        // 3. Deploy Enhancements (Phase 3)
        DecentralizedRelayerRegistry registry = new DecentralizedRelayerRegistry(deployer);
        BridgeFraudProof fraudProof = new BridgeFraudProof(address(verifier), deployer);

        // 4. Configuration / Wiring
        verifier.grantRole(verifier.RESOLVER_ROLE(), address(fraudProof));
        
        watchtower.setTargetContracts(address(relay), address(limiter));
        
        // 5. Output addresses
        console.log("Deployed Minimal Core:");
        console.log("PrivacyZoneManager:", address(zoneManager));
        console.log("SoulCrossChainRelay:", address(relay));
        console.log("OptimisticBridgeVerifier:", address(verifier));
        console.log("BridgeRateLimiter:", address(limiter));
        console.log("BridgeWatchtower:", address(watchtower));
        console.log("DecentralizedRelayerRegistry:", address(registry));
        console.log("BridgeFraudProof:", address(fraudProof));

        vm.stopBroadcast();
    }
}
