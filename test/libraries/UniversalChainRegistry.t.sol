// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/libraries/UniversalChainRegistry.sol";
import "../../contracts/interfaces/IUniversalChainAdapter.sol";

/// @dev Harness to expose internal library functions
contract UniversalChainRegistryHarness {
    function areProofSystemsCompatible(
        IUniversalChainAdapter.ProofSystem a,
        IUniversalChainAdapter.ProofSystem b
    ) external pure returns (bool) {
        return UniversalChainRegistry.areProofSystemsCompatible(a, b);
    }

    function getDefaultProofSystem(
        IUniversalChainAdapter.ChainVM vm
    ) external pure returns (IUniversalChainAdapter.ProofSystem) {
        return UniversalChainRegistry.getDefaultProofSystem(vm);
    }

    function computeEVMChainId(
        uint256 evmChainId
    ) external pure returns (bytes32) {
        return UniversalChainRegistry.computeEVMChainId(evmChainId);
    }

    function computeNonEVMChainId(
        string memory chainName
    ) external pure returns (bytes32) {
        return UniversalChainRegistry.computeNonEVMChainId(chainName);
    }

    // Expose constants
    function ETHEREUM_MAINNET() external pure returns (bytes32) {
        return UniversalChainRegistry.ETHEREUM_MAINNET;
    }

    function ARBITRUM_ONE() external pure returns (bytes32) {
        return UniversalChainRegistry.ARBITRUM_ONE;
    }

    function OPTIMISM() external pure returns (bytes32) {
        return UniversalChainRegistry.OPTIMISM;
    }

    function BASE() external pure returns (bytes32) {
        return UniversalChainRegistry.BASE;
    }

    function ZKSYNC_ERA() external pure returns (bytes32) {
        return UniversalChainRegistry.ZKSYNC_ERA;
    }

    function SCROLL() external pure returns (bytes32) {
        return UniversalChainRegistry.SCROLL;
    }

    function LINEA() external pure returns (bytes32) {
        return UniversalChainRegistry.LINEA;
    }

    function POLYGON_ZKEVM() external pure returns (bytes32) {
        return UniversalChainRegistry.POLYGON_ZKEVM;
    }

    function SOLANA() external pure returns (bytes32) {
        return UniversalChainRegistry.SOLANA;
    }

    function BITCOIN() external pure returns (bytes32) {
        return UniversalChainRegistry.BITCOIN;
    }

    function AZTEC() external pure returns (bytes32) {
        return UniversalChainRegistry.AZTEC;
    }
}

contract UniversalChainRegistryTest is Test {
    UniversalChainRegistryHarness lib;

    function setUp() public {
        lib = new UniversalChainRegistryHarness();
    }

    /* ══════════════════════════════════════════════════
                  CHAIN ID CONSTANTS
       ══════════════════════════════════════════════════ */

    function test_constants_nonZero() public view {
        assertNotEq(lib.ETHEREUM_MAINNET(), bytes32(0));
        assertNotEq(lib.ARBITRUM_ONE(), bytes32(0));
        assertNotEq(lib.OPTIMISM(), bytes32(0));
        assertNotEq(lib.BASE(), bytes32(0));
        assertNotEq(lib.ZKSYNC_ERA(), bytes32(0));
        assertNotEq(lib.SCROLL(), bytes32(0));
        assertNotEq(lib.LINEA(), bytes32(0));
        assertNotEq(lib.POLYGON_ZKEVM(), bytes32(0));
        assertNotEq(lib.SOLANA(), bytes32(0));
        assertNotEq(lib.BITCOIN(), bytes32(0));
        assertNotEq(lib.AZTEC(), bytes32(0));
    }

    function test_constants_allUnique() public view {
        bytes32[11] memory ids = [
            lib.ETHEREUM_MAINNET(),
            lib.ARBITRUM_ONE(),
            lib.OPTIMISM(),
            lib.BASE(),
            lib.ZKSYNC_ERA(),
            lib.SCROLL(),
            lib.LINEA(),
            lib.POLYGON_ZKEVM(),
            lib.SOLANA(),
            lib.BITCOIN(),
            lib.AZTEC()
        ];
        for (uint256 i = 0; i < ids.length; i++) {
            for (uint256 j = i + 1; j < ids.length; j++) {
                assertNotEq(ids[i], ids[j], "Chain IDs must be unique");
            }
        }
    }

    /* ══════════════════════════════════════════════════
              COMPUTE EVM CHAIN ID
       ══════════════════════════════════════════════════ */

    function test_computeEVMChainId_deterministic() public view {
        bytes32 id1 = lib.computeEVMChainId(1);
        bytes32 id2 = lib.computeEVMChainId(1);
        assertEq(id1, id2);
    }

    function test_computeEVMChainId_differentChains() public view {
        bytes32 eth = lib.computeEVMChainId(1);
        bytes32 arb = lib.computeEVMChainId(42161);
        assertNotEq(eth, arb);
    }

    function test_computeEVMChainId_matchesSha256() public view {
        bytes32 expected = sha256(abi.encodePacked("SOUL_CHAIN_", "1"));
        assertEq(lib.computeEVMChainId(1), expected);
    }

    function testFuzz_computeEVMChainId_deterministic(
        uint256 chainId
    ) public view {
        assertEq(
            lib.computeEVMChainId(chainId),
            lib.computeEVMChainId(chainId)
        );
    }

    /* ══════════════════════════════════════════════════
              COMPUTE NON-EVM CHAIN ID
       ══════════════════════════════════════════════════ */

    function test_computeNonEVMChainId_deterministic() public view {
        bytes32 id1 = lib.computeNonEVMChainId("SOLANA");
        bytes32 id2 = lib.computeNonEVMChainId("SOLANA");
        assertEq(id1, id2);
    }

    function test_computeNonEVMChainId_differentChains() public view {
        assertNotEq(
            lib.computeNonEVMChainId("SOLANA"),
            lib.computeNonEVMChainId("APTOS")
        );
    }

    function test_computeNonEVMChainId_matchesSha256() public view {
        bytes32 expected = sha256(abi.encodePacked("SOUL_CHAIN_", "SOLANA"));
        assertEq(lib.computeNonEVMChainId("SOLANA"), expected);
    }

    /* ══════════════════════════════════════════════════
              PROOF SYSTEM COMPATIBILITY
       ══════════════════════════════════════════════════ */

    function test_proofSystemsCompatible_sameSystem() public view {
        assertTrue(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.GROTH16,
                IUniversalChainAdapter.ProofSystem.GROTH16
            )
        );
        assertTrue(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.STARK,
                IUniversalChainAdapter.ProofSystem.STARK
            )
        );
    }

    function test_proofSystemsCompatible_plonkFamily() public view {
        // PLONK <-> ULTRAPLONK
        assertTrue(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.PLONK,
                IUniversalChainAdapter.ProofSystem.ULTRAPLONK
            )
        );
        // ULTRAPLONK <-> HONK
        assertTrue(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.ULTRAPLONK,
                IUniversalChainAdapter.ProofSystem.HONK
            )
        );
        // PLONK <-> HONK
        assertTrue(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.PLONK,
                IUniversalChainAdapter.ProofSystem.HONK
            )
        );
    }

    function test_proofSystemsCompatible_incompatibleSystems() public view {
        assertFalse(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.GROTH16,
                IUniversalChainAdapter.ProofSystem.STARK
            )
        );
        assertFalse(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.GROTH16,
                IUniversalChainAdapter.ProofSystem.PLONK
            )
        );
        assertFalse(
            lib.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.BULLETPROOFS,
                IUniversalChainAdapter.ProofSystem.HALO2
            )
        );
    }

    /* ══════════════════════════════════════════════════
              DEFAULT PROOF SYSTEM
       ══════════════════════════════════════════════════ */

    function test_defaultProofSystem_EVM() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(IUniversalChainAdapter.ChainVM.EVM)
            ),
            uint256(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
    }

    function test_defaultProofSystem_Cairo() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(IUniversalChainAdapter.ChainVM.CAIRO)
            ),
            uint256(IUniversalChainAdapter.ProofSystem.STARK)
        );
    }

    function test_defaultProofSystem_NoirAztec() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.NOIR_AZTEC
                )
            ),
            uint256(IUniversalChainAdapter.ProofSystem.HONK)
        );
    }

    function test_defaultProofSystem_Zcash() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(IUniversalChainAdapter.ChainVM.ZCASH)
            ),
            uint256(IUniversalChainAdapter.ProofSystem.HALO2)
        );
    }

    function test_defaultProofSystem_SVM() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(IUniversalChainAdapter.ChainVM.SVM)
            ),
            uint256(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
    }

    function test_defaultProofSystem_MoveAptos() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.MOVE_APTOS
                )
            ),
            uint256(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
    }

    function test_defaultProofSystem_MoveSui() public view {
        assertEq(
            uint256(
                lib.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.MOVE_SUI
                )
            ),
            uint256(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
    }
}
