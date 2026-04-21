// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {VerifierRegistryV3} from "../../contracts/verifiers/VerifierRegistryV3.sol";
import {ZaseonVerifierRouter} from "../../contracts/verifiers/ZaseonVerifierRouter.sol";

/**
 * @title DeployVerifierV3
 * @author ZASEON
 * @notice Deploys the V3 verifier stack: `VerifierRegistryV3` +
 *         `ZaseonVerifierRouter`. Circuit registration is performed
 *         by a separate governance-queued transaction via the timelock.
 *
 * Env vars:
 *   PRIVATE_KEY        Deployer key.
 *   ADMIN              DEFAULT_ADMIN_ROLE holder on both contracts
 *                      (governance multisig).
 *   TIMELOCK           ZaseonUpgradeTimelock address; receives
 *                      REGISTRY_ADMIN_ROLE on the registry.
 *   GUARDIAN           Emergency guardian (pause-only).
 *   TRANSIENT_STORAGE_OK (optional) "true" or "false" — router uses
 *                      EIP-1153 if "true"; persistent-map fallback if
 *                      "false". Default: "true" on Cancun chains
 *                      (Arbitrum/Optimism/Base/Linea), "false" on
 *                      chains that haven't shipped Cancun yet.
 *
 * Usage (dry-run):
 *   forge script scripts/deploy/DeployVerifierV3.s.sol --rpc-url $RPC
 * Usage (broadcast):
 *   forge script scripts/deploy/DeployVerifierV3.s.sol \
 *     --rpc-url $RPC --broadcast -vvv
 */
contract DeployVerifierV3 is Script {
    function run()
        external
        returns (VerifierRegistryV3 registry, ZaseonVerifierRouter router)
    {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN");
        address timelock = vm.envOr("TIMELOCK", address(0));
        address guardian = vm.envOr("GUARDIAN", admin);
        bool transientOk = _transientOkForChain(block.chainid);

        console.log("Deployer :", vm.addr(pk));
        console.log("Admin    :", admin);
        console.log("Timelock :", timelock);
        console.log("Guardian :", guardian);
        console.log("ChainId  :", block.chainid);
        console.log("TSTORE ok:", transientOk);

        vm.startBroadcast(pk);

        registry = new VerifierRegistryV3(admin, timelock, guardian);
        router = new ZaseonVerifierRouter(
            address(registry),
            admin,
            guardian,
            transientOk
        );

        vm.stopBroadcast();

        console.log("Registry :", address(registry));
        console.log("Router   :", address(router));
    }

    /**
     * @dev Per-chain TSTORE availability table. Conservative defaults:
     *      returns `false` on chains that had not shipped Cancun/EIP-1153
     *      as of the 2026-Q1 baseline. Override with env var
     *      `TRANSIENT_STORAGE_OK` if your chain has upgraded.
     */
    function _transientOkForChain(
        uint256 chainId
    ) internal view returns (bool) {
        // Env override wins.
        try vm.envBool("TRANSIENT_STORAGE_OK") returns (bool v) {
            return v;
        } catch {}

        // Mainnets + L2s known to support EIP-1153.
        if (chainId == 1) return true; // Ethereum
        if (chainId == 10) return true; // Optimism
        if (chainId == 42161) return true; // Arbitrum One
        if (chainId == 8453) return true; // Base
        if (chainId == 59144) return true; // Linea
        if (chainId == 31337) return true; // Anvil
        if (chainId == 11155111) return true; // Sepolia

        // Chains that may not yet have Cancun as of baseline:
        if (chainId == 324) return false; // zkSync Era
        if (chainId == 534352) return false; // Scroll

        // Default: conservative.
        return false;
    }
}
