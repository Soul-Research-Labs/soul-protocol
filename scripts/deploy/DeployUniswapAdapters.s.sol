// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {UniswapV3RebalanceAdapter} from "../../contracts/integrations/UniswapV3RebalanceAdapter.sol";

/**
 * @title DeployUniswapAdapters
 * @notice Deploys UniswapV3RebalanceAdapter on a target L2 and configures it for the vault.
 *
 * @dev Deploys the adapter with chain-specific Uniswap V3 addresses, authorizes the vault,
 *      and optionally sets fee tier overrides for specific token pairs.
 *
 * Environment Variables:
 *   DEPLOYER_PRIVATE_KEY    - Deployer EOA private key
 *   MULTISIG_ADMIN          - Gnosis Safe admin on the L2
 *   VAULT_ADDRESS            - CrossChainLiquidityVault address on this chain
 *   UNISWAP_ROUTER          - Uniswap V3 SwapRouter address
 *   UNISWAP_QUOTER          - Uniswap V3 QuoterV2 address
 *   UNISWAP_FACTORY         - Uniswap V3 Factory address
 *   WETH_ADDRESS             - WETH contract address
 *
 * Optional:
 *   FEE_OVERRIDE_TOKEN_A    - Token A for fee tier override
 *   FEE_OVERRIDE_TOKEN_B    - Token B for fee tier override
 *   FEE_OVERRIDE_TIER       - Fee tier (100, 500, 3000, 10000)
 *
 * Usage:
 *   DEPLOYER_PRIVATE_KEY=0x... \
 *   MULTISIG_ADMIN=0x...       \
 *   VAULT_ADDRESS=0x...        \
 *   UNISWAP_ROUTER=0x...      \
 *   UNISWAP_QUOTER=0x...      \
 *   UNISWAP_FACTORY=0x...     \
 *   WETH_ADDRESS=0x...         \
 *   forge script scripts/deploy/DeployUniswapAdapters.s.sol \
 *     --rpc-url $RPC_URL --broadcast --verify
 */
contract DeployUniswapAdapters is Script {
    function run() external {
        uint256 deployerPK = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPK);
        address admin = vm.envAddress("MULTISIG_ADMIN");
        address vault = vm.envAddress("VAULT_ADDRESS");
        address router = vm.envAddress("UNISWAP_ROUTER");
        address quoter = vm.envAddress("UNISWAP_QUOTER");
        address factory = vm.envAddress("UNISWAP_FACTORY");
        address weth = vm.envAddress("WETH_ADDRESS");

        require(admin != address(0), "MULTISIG_ADMIN not set");
        require(vault != address(0), "VAULT_ADDRESS not set");
        require(router != address(0), "UNISWAP_ROUTER not set");
        require(quoter != address(0), "UNISWAP_QUOTER not set");
        require(factory != address(0), "UNISWAP_FACTORY not set");
        require(weth != address(0), "WETH_ADDRESS not set");

        console.log("=== Deploy UniswapV3RebalanceAdapter ===");
        console.log("Chain ID:       ", block.chainid);
        console.log("Deployer:       ", deployer);
        console.log("Admin:          ", admin);
        console.log("Vault:          ", vault);
        console.log("Uniswap Router: ", router);
        console.log("Uniswap Quoter: ", quoter);
        console.log("Uniswap Factory:", factory);
        console.log("WETH:           ", weth);

        vm.startBroadcast(deployerPK);

        // Deploy adapter with deployer as initial operator
        UniswapV3RebalanceAdapter adapter = new UniswapV3RebalanceAdapter(
            deployer, // admin (will transfer to multisig)
            deployer, // operator (will transfer to multisig)
            router,
            quoter,
            factory,
            weth
        );
        console.log("Adapter deployed:", address(adapter));

        // Authorize the vault to call swap()
        adapter.setAuthorizedCaller(vault, true);
        console.log("Vault authorized for swaps");

        // Optional: set fee tier override for a specific token pair
        address feeTokenA = _envOr("FEE_OVERRIDE_TOKEN_A");
        address feeTokenB = _envOr("FEE_OVERRIDE_TOKEN_B");
        if (feeTokenA != address(0) && feeTokenB != address(0)) {
            uint24 feeTier = uint24(
                vm.envOr("FEE_OVERRIDE_TIER", uint256(500))
            );
            adapter.setFeeTierOverride(feeTokenA, feeTokenB, feeTier);
            console.log("Fee tier override set:");
            console.log("  Token A:", feeTokenA);
            console.log("  Token B:", feeTokenB);
            console.log("  Fee tier:", uint256(feeTier));
        }

        // Transfer admin + operator roles to multisig
        adapter.grantRole(adapter.DEFAULT_ADMIN_ROLE(), admin);
        adapter.grantRole(adapter.OPERATOR_ROLE(), admin);

        // Revoke deployer roles
        adapter.revokeRole(adapter.OPERATOR_ROLE(), deployer);
        adapter.revokeRole(adapter.DEFAULT_ADMIN_ROLE(), deployer);
        console.log("Roles transferred to multisig:", admin);

        vm.stopBroadcast();

        console.log("\n=== Deployment Complete ===");
        console.log("Adapter:  ", address(adapter));
        console.log("Vault:    ", vault);
        console.log("Chain ID: ", block.chainid);
        console.log(
            "\nNext step: Call vault.setRebalanceAdapter(",
            address(adapter),
            ") via WireRemainingComponents or directly"
        );
    }

    /// @dev Read an address from env, returning address(0) if not set.
    function _envOr(string memory key) internal view returns (address) {
        try vm.envAddress(key) returns (address val) {
            return val;
        } catch {
            return address(0);
        }
    }
}
