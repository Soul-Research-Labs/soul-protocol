// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IUniversalChainAdapter} from "../interfaces/IUniversalChainAdapter.sol";

/**
 * @title UniversalChainRegistry
 * @author Soul Protocol
 * @notice Library for universal chain identification across all blockchain ecosystems
 * @dev Provides deterministic chain IDs that work across EVM, Solana, StarkNet, Move, and privacy chains
 *
 * DESIGN:
 * EVM chains use keccak256("SOUL_CHAIN" || chainId) for deterministic universal IDs.
 * Non-EVM chains use keccak256("SOUL_CHAIN" || chainName) since they don't share EVM's chainId scheme.
 * This ensures collision-free identification across all ecosystems.
 *
 * GAS OPTIMIZATIONS:
 * - All constants are pre-computed at compile time
 * - No runtime keccak256 calls for known chains
 */
library UniversalChainRegistry {
    /*//////////////////////////////////////////////////////////////
                             EVM L1 CHAINS
    //////////////////////////////////////////////////////////////*/

    /// @dev sha256("SOUL_CHAIN_ETHEREUM_1")
    bytes32 internal constant ETHEREUM_MAINNET =
        0x6c42dc772e9847aeb2f8cd5abe126847b466ee9eba8e79f171db96881cbc077e;

    /*//////////////////////////////////////////////////////////////
                             EVM L2 CHAINS
    //////////////////////////////////////////////////////////////*/

    /// @dev sha256("SOUL_CHAIN_ARBITRUM_42161")
    bytes32 internal constant ARBITRUM_ONE =
        0x8b4761d1f1507ea95c40a012681d51bb6df647a419e12d0857536cafc194346d;

    /// @dev sha256("SOUL_CHAIN_OPTIMISM_10")
    bytes32 internal constant OPTIMISM =
        0x786bb3dfa05a768db1292a1e0fd3d48a4fd1674c0de1542ccdcc3e4b1c5bf3c8;

    /// @dev sha256("SOUL_CHAIN_BASE_8453")
    bytes32 internal constant BASE =
        0x03300c3d2bd1faf9434500755c973c9849040b8c177e4968baadea1f1efefc48;

    /// @dev sha256("SOUL_CHAIN_ZKSYNC_324")
    bytes32 internal constant ZKSYNC_ERA =
        0x852342e5961eb3d1b0316caf60206a0cd35e101d5d8b82b4c0dd9e88cca00f12;

    /// @dev sha256("SOUL_CHAIN_SCROLL_534352")
    bytes32 internal constant SCROLL =
        0xe549b543a8278de9f949001ee2977b24a05128e0086eb9b725fa3d2e8d7e60ba;

    /// @dev sha256("SOUL_CHAIN_LINEA_59144")
    bytes32 internal constant LINEA =
        0x5b96aeb7d662f01e4b0ba35b75b6e7196746c6d71a03cb9a38c6cd2dcd356d7a;

    /// @dev sha256("SOUL_CHAIN_POLYGON_ZKEVM_1101")
    bytes32 internal constant POLYGON_ZKEVM =
        0xd08e36ff4b1dbc1d9b38b883a5f915d317184798e7fec4d8efcba32b536b7cb1;

    /*//////////////////////////////////////////////////////////////
                         NON-EVM PUBLIC L1 CHAINS
    //////////////////////////////////////////////////////////////*/

    /// @dev sha256("SOUL_CHAIN_SOLANA")
    bytes32 internal constant SOLANA =
        0x15b6a644f9c6a79c7b5e0583dd75f9576b5ed076aa007b4b6a45d7e23b267ab8;

    /// @dev sha256("SOUL_CHAIN_APTOS")
    bytes32 internal constant APTOS =
        0x095f5672ea7907c1418a10c6f10a11633fc6dd9bf52c84222fcd73738e354dcb;

    /// @dev sha256("SOUL_CHAIN_SUI")
    bytes32 internal constant SUI =
        0xa10deca24ecbda9bfbe1ac451b97ce8fa16f65ac27179c42d0f76b334d99a292;

    /// @dev sha256("SOUL_CHAIN_STARKNET")
    bytes32 internal constant STARKNET =
        0x60b3030e41a9b25a876934220e815f780f4e3df0d9b234b242d8bed8aeb4154c;

    /// @dev sha256("SOUL_CHAIN_NEAR")
    bytes32 internal constant NEAR =
        0xab820431fb4457f6ee2c77afe9eeb3ede53925f3a71de42855a48f80dccaa008;

    /// @dev sha256("SOUL_CHAIN_TON")
    bytes32 internal constant TON =
        0xe7e69f100af79a1243f3b7b7194ace53bc540400b59e203401ee5f7adb9861e8;

    /// @dev sha256("SOUL_CHAIN_COSMOS")
    bytes32 internal constant COSMOS =
        0xa7bf84d70fbd7923141800f61e72f975bece1f588bb844768dab76af79a0160e;

    /// @dev sha256("SOUL_CHAIN_POLKADOT")
    bytes32 internal constant POLKADOT =
        0xfdb68cbc0ca03afd7e6dce68a91f8e5cf45d0b82ee85d0ef02af996b2c6a87ec;

    /*//////////////////////////////////////////////////////////////
                       PRIVACY-NATIVE L1 CHAINS
    //////////////////////////////////////////////////////////////*/

    /// @dev sha256("SOUL_CHAIN_AZTEC")
    bytes32 internal constant AZTEC =
        0x980be0b60bac1f4968d9b897128012a7c3df208c3c90bbe7d6c86159840892aa;

    /// @dev sha256("SOUL_CHAIN_MIDNIGHT")
    bytes32 internal constant MIDNIGHT =
        0x6d224c583b639af55866e0524ceda8722d3b7e09acad3e62c27af0926030979f;

    /// @dev sha256("SOUL_CHAIN_ZCASH")
    bytes32 internal constant ZCASH =
        0x6dc75ae368ce90054506baacb6b1881959a69b31ee986222d34fac391076fb3e;

    /// @dev sha256("SOUL_CHAIN_ALEO")
    bytes32 internal constant ALEO =
        0x82fc4148c040c873f125299bcb93857636f0d25a0b6cda4dce5b742bb1e8387c;

    /*//////////////////////////////////////////////////////////////
                        BITCOIN & UTXO CHAINS
    //////////////////////////////////////////////////////////////*/

    /// @dev sha256("SOUL_CHAIN_BITCOIN")
    bytes32 internal constant BITCOIN =
        0xfec4871c16fa64958a10c2b46979b1c429a0024b760758147720aa2ab533c168;

    /// @dev sha256("SOUL_CHAIN_XRPL")
    bytes32 internal constant XRPL =
        0xd76b10eff2886f9f616f998fe9ced5e9835e76494550bea955a51a1a15a8a2be;

    /// @dev sha256("SOUL_CHAIN_CARDANO")
    bytes32 internal constant CARDANO =
        0x03a494a34bfe54aa1a74dff927003d6ce6c7d2a8f2f3da0742d8e22335874423;

    /*//////////////////////////////////////////////////////////////
                    PROOF SYSTEM COMPATIBILITY MATRIX
    //////////////////////////////////////////////////////////////*/

    /// @notice Check if two proof systems are natively compatible (no translation needed)
    /// @param a First proof system
    /// @param b Second proof system
    /// @return compatible Whether proofs can pass directly without translation
    function areProofSystemsCompatible(
        IUniversalChainAdapter.ProofSystem a,
        IUniversalChainAdapter.ProofSystem b
    ) internal pure returns (bool compatible) {
        if (a == b) return true;

        // PLONK <-> ULTRAPLONK <-> HONK family
        if (
            (a == IUniversalChainAdapter.ProofSystem.PLONK ||
                a == IUniversalChainAdapter.ProofSystem.ULTRAPLONK ||
                a == IUniversalChainAdapter.ProofSystem.HONK) &&
            (b == IUniversalChainAdapter.ProofSystem.PLONK ||
                b == IUniversalChainAdapter.ProofSystem.ULTRAPLONK ||
                b == IUniversalChainAdapter.ProofSystem.HONK)
        ) {
            return true;
        }

        return false;
    }

    /// @notice Get the default proof system for a chain VM
    /// @param vm The virtual machine type
    /// @return proofSystem The default proof system
    function getDefaultProofSystem(
        IUniversalChainAdapter.ChainVM vm
    ) internal pure returns (IUniversalChainAdapter.ProofSystem proofSystem) {
        if (vm == IUniversalChainAdapter.ChainVM.EVM) {
            return IUniversalChainAdapter.ProofSystem.GROTH16;
        } else if (vm == IUniversalChainAdapter.ChainVM.CAIRO) {
            return IUniversalChainAdapter.ProofSystem.STARK;
        } else if (vm == IUniversalChainAdapter.ChainVM.NOIR_AZTEC) {
            return IUniversalChainAdapter.ProofSystem.HONK;
        } else if (vm == IUniversalChainAdapter.ChainVM.ZCASH) {
            return IUniversalChainAdapter.ProofSystem.HALO2;
        } else if (vm == IUniversalChainAdapter.ChainVM.ALEO) {
            return IUniversalChainAdapter.ProofSystem.GROTH16;
        } else if (vm == IUniversalChainAdapter.ChainVM.SVM) {
            return IUniversalChainAdapter.ProofSystem.GROTH16;
        } else if (vm == IUniversalChainAdapter.ChainVM.MOVE_APTOS) {
            return IUniversalChainAdapter.ProofSystem.GROTH16;
        } else if (vm == IUniversalChainAdapter.ChainVM.MOVE_SUI) {
            return IUniversalChainAdapter.ProofSystem.GROTH16;
        } else {
            return IUniversalChainAdapter.ProofSystem.GROTH16;
        }
    }

    /// @notice Compute universal chain ID for an EVM chain
    /// @dev Uses sha256 to match pre-computed constants (e.g. ETHEREUM_MAINNET)
    /// @param evmChainId The EVM chain ID (e.g. 1, 42161)
    /// @return universalId The deterministic universal chain ID
    function computeEVMChainId(
        uint256 evmChainId
    ) internal pure returns (bytes32 universalId) {
        return sha256(abi.encodePacked("SOUL_CHAIN_", _uint2str(evmChainId)));
    }

    /// @notice Compute universal chain ID for a non-EVM chain
    /// @dev Uses sha256 to match pre-computed constants (e.g. SOLANA)
    /// @param chainName The canonical chain name (e.g. "SOLANA", "APTOS")
    /// @return universalId The deterministic universal chain ID
    function computeNonEVMChainId(
        string memory chainName
    ) internal pure returns (bytes32 universalId) {
        return sha256(abi.encodePacked("SOUL_CHAIN_", chainName));
    }

    /// @dev Convert uint256 to string for hash computation
    function _uint2str(uint256 value) private pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            unchecked { ++digits; }
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            unchecked { --digits; }
            buffer[digits] = bytes1(uint8(48 + (value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}
