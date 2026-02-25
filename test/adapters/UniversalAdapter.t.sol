// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {EVMUniversalAdapter} from "../../contracts/adapters/EVMUniversalAdapter.sol";
import {UniversalAdapterRegistry} from "../../contracts/adapters/UniversalAdapterRegistry.sol";
import {IUniversalChainAdapter} from "../../contracts/interfaces/IUniversalChainAdapter.sol";
import {IProofVerifier} from "../../contracts/interfaces/IProofVerifier.sol";
import {UniversalChainRegistry} from "../../contracts/libraries/UniversalChainRegistry.sol";

/// @notice Mock verifier that accepts all proofs (test-only)
contract AcceptAllVerifierForAdapter is IProofVerifier {
    function verify(
        bytes calldata,
        uint256[] calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure override returns (bool) {
        return true;
    }

    function verifySingle(
        bytes calldata,
        uint256
    ) external pure override returns (bool) {
        return true;
    }

    function getPublicInputCount() external pure override returns (uint256) {
        return 4;
    }

    function getVerificationKeyHash() external pure returns (bytes32) {
        return bytes32(0);
    }

    function isReady() external pure override returns (bool) {
        return true;
    }
}

/**
 * @title EVMUniversalAdapterTest
 * @notice Comprehensive tests for the EVM Universal Adapter
 */
contract EVMUniversalAdapterTest is Test {
    EVMUniversalAdapter public adapter;
    UniversalAdapterRegistry public registry;

    address public admin = makeAddr("admin");
    address public relayer = makeAddr("relayer");
    address public user = makeAddr("user");
    address public operator = makeAddr("operator");

    bytes32 public constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    function setUp() public {
        // Advance block.timestamp so (block.timestamp - 25 hours) doesn't underflow
        vm.warp(100_000);

        vm.startPrank(admin);

        adapter = new EVMUniversalAdapter(
            admin,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            "Arbitrum One"
        );

        registry = new UniversalAdapterRegistry(admin);

        // Deploy and register an accept-all verifier for GROTH16 & PLONK
        AcceptAllVerifierForAdapter acceptVerifier = new AcceptAllVerifierForAdapter();
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(acceptVerifier)
        );
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.PLONK,
            address(acceptVerifier)
        );

        // Grant roles
        adapter.grantRole(RELAYER_ROLE, relayer);
        adapter.grantRole(OPERATOR_ROLE, operator);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialization() public view {
        IUniversalChainAdapter.ChainDescriptor memory desc = adapter
            .getChainDescriptor();
        assertEq(desc.name, "Arbitrum One");
        assertEq(uint8(desc.vm), uint8(IUniversalChainAdapter.ChainVM.EVM));
        assertEq(
            uint8(desc.layer),
            uint8(IUniversalChainAdapter.ChainLayer.L2_ROLLUP)
        );
        assertEq(
            uint8(desc.proofSystem),
            uint8(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
        assertTrue(desc.active);
    }

    function test_universalChainId_isDeterministic() public view {
        bytes32 expectedId = UniversalChainRegistry.computeEVMChainId(
            block.chainid
        );
        assertEq(adapter.getUniversalChainId(), expectedId);
    }

    function test_nativeProofSystem() public view {
        assertEq(
            uint8(adapter.getNativeProofSystem()),
            uint8(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
    }

    function test_defaultProofSystemsSupported() public view {
        assertTrue(
            adapter.isProofSystemSupported(
                IUniversalChainAdapter.ProofSystem.GROTH16
            )
        );
        assertTrue(
            adapter.isProofSystemSupported(
                IUniversalChainAdapter.ProofSystem.PLONK
            )
        );
        assertFalse(
            adapter.isProofSystemSupported(
                IUniversalChainAdapter.ProofSystem.STARK
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                     ENCRYPTED STATE RELAY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_sendEncryptedState() public {
        bytes32 destChainId = UniversalChainRegistry.SOLANA;
        bytes32 commitment = keccak256("state_data");
        bytes memory payload = abi.encodePacked("encrypted_content");
        bytes memory proof = new bytes(128);
        bytes32 nullifier = keccak256("nullifier_1");

        // Register remote adapter first
        vm.prank(admin);
        adapter.registerRemoteAdapter(
            destChainId,
            abi.encodePacked(bytes32(uint256(1)))
        );

        vm.prank(user);
        bytes32 transferId = adapter.sendEncryptedState(
            destChainId,
            commitment,
            payload,
            proof,
            nullifier
        );

        assertTrue(transferId != bytes32(0));
        assertTrue(adapter.isNullifierUsed(nullifier));

        (, , uint256 sent, ) = adapter.getStats();
        assertEq(sent, 1);
    }

    function test_receiveEncryptedState() public {
        bytes32 sourceChainId = UniversalChainRegistry.SOLANA;
        bytes32 destChainId = adapter.getUniversalChainId();
        bytes32 commitment = keccak256("state_data");
        bytes32 nullifier = keccak256("nullifier_2");
        bytes32 newCommitment = keccak256("new_state");
        bytes memory proof = new bytes(128);
        bytes memory payload = abi.encodePacked("encrypted_content");

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: keccak256("transfer_1"),
                sourceChainId: sourceChainId,
                destChainId: destChainId,
                stateCommitment: commitment,
                encryptedPayload: payload,
                nullifier: nullifier,
                newCommitment: newCommitment,
                proof: proof
            });

        vm.prank(relayer);
        bool success = adapter.receiveEncryptedState(transfer);

        assertTrue(success);
        assertTrue(adapter.isNullifierUsed(nullifier));

        (, uint256 received, , ) = adapter.getStats();
        assertEq(received, 1);
    }

    function test_receiveEncryptedState_revert_duplicateNullifier() public {
        bytes32 nullifier = keccak256("nullifier_dup");
        bytes32 destChainId = adapter.getUniversalChainId();

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer1 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: keccak256("transfer_1"),
                sourceChainId: UniversalChainRegistry.SOLANA,
                destChainId: destChainId,
                stateCommitment: keccak256("state1"),
                encryptedPayload: abi.encodePacked("data"),
                nullifier: nullifier,
                newCommitment: keccak256("new1"),
                proof: new bytes(128)
            });

        IUniversalChainAdapter.EncryptedStateTransfer memory transfer2 = IUniversalChainAdapter
            .EncryptedStateTransfer({
                transferId: keccak256("transfer_2"),
                sourceChainId: UniversalChainRegistry.STARKNET,
                destChainId: destChainId,
                stateCommitment: keccak256("state2"),
                encryptedPayload: abi.encodePacked("data2"),
                nullifier: nullifier, // Same nullifier!
                newCommitment: keccak256("new2"),
                proof: new bytes(128)
            });

        vm.startPrank(relayer);
        adapter.receiveEncryptedState(transfer1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalChainAdapter.NullifierAlreadyUsed.selector,
                nullifier
            )
        );
        adapter.receiveEncryptedState(transfer2);
        vm.stopPrank();
    }

    function test_receiveEncryptedState_revert_wrongDestination() public {
        bytes32 wrongDest = keccak256("wrong_chain");

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: keccak256("transfer_wrong"),
                sourceChainId: UniversalChainRegistry.SOLANA,
                destChainId: wrongDest,
                stateCommitment: keccak256("state"),
                encryptedPayload: abi.encodePacked("data"),
                nullifier: keccak256("null"),
                newCommitment: keccak256("new"),
                proof: new bytes(128)
            });

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalChainAdapter.ChainNotSupported.selector,
                wrongDest
            )
        );
        adapter.receiveEncryptedState(transfer);
    }

    /*//////////////////////////////////////////////////////////////
                      UNIVERSAL PROOF TESTS
    //////////////////////////////////////////////////////////////*/

    function test_submitUniversalProof() public {
        bytes32 proofId = keccak256("proof_1");
        bytes32 sourceChain = UniversalChainRegistry.STARKNET;
        bytes32 destChain = adapter.getUniversalChainId();
        bytes32 nullifier = keccak256("null_proof_1");
        bytes32 commitment = keccak256("commitment_1");
        bytes memory proof = new bytes(128);
        bytes32[] memory publicInputs = new bytes32[](2);
        publicInputs[0] = keccak256("input_1");
        publicInputs[1] = keccak256("input_2");

        IUniversalChainAdapter.UniversalProof
            memory universalProof = IUniversalChainAdapter.UniversalProof({
                proofId: proofId,
                sourceChainId: sourceChain,
                destChainId: destChain,
                proofSystem: IUniversalChainAdapter.ProofSystem.GROTH16,
                proof: proof,
                publicInputs: publicInputs,
                stateCommitment: commitment,
                nullifier: nullifier,
                timestamp: block.timestamp
            });

        vm.prank(relayer);
        bytes32 returnedId = adapter.submitUniversalProof(universalProof);

        assertEq(returnedId, proofId);
        assertTrue(adapter.isNullifierUsed(nullifier));

        (uint256 proofs, , , ) = adapter.getStats();
        assertEq(proofs, 1);
    }

    function test_submitUniversalProof_revert_expired() public {
        bytes32 proofId = keccak256("expired_proof");
        bytes32 nullifier = keccak256("null_expired");
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input");

        IUniversalChainAdapter.UniversalProof memory universalProof = IUniversalChainAdapter
            .UniversalProof({
                proofId: proofId,
                sourceChainId: UniversalChainRegistry.SOLANA,
                destChainId: adapter.getUniversalChainId(),
                proofSystem: IUniversalChainAdapter.ProofSystem.GROTH16,
                proof: new bytes(128),
                publicInputs: publicInputs,
                stateCommitment: keccak256("state"),
                nullifier: nullifier,
                timestamp: block.timestamp - 25 hours // Expired
            });

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUniversalChainAdapter.ProofExpired.selector,
                block.timestamp - 25 hours,
                24 hours
            )
        );
        adapter.submitUniversalProof(universalProof);
    }

    function test_submitUniversalProof_revert_unsupportedProofSystem() public {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input");

        IUniversalChainAdapter.UniversalProof memory universalProof = IUniversalChainAdapter
            .UniversalProof({
                proofId: keccak256("stark_proof"),
                sourceChainId: UniversalChainRegistry.STARKNET,
                destChainId: adapter.getUniversalChainId(),
                proofSystem: IUniversalChainAdapter.ProofSystem.STARK, // Not supported by default
                proof: new bytes(128),
                publicInputs: publicInputs,
                stateCommitment: keccak256("state"),
                nullifier: keccak256("null"),
                timestamp: block.timestamp
            });

        vm.prank(relayer);
        vm.expectRevert();
        adapter.submitUniversalProof(universalProof);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_registerRemoteAdapter() public {
        bytes32 chainId = UniversalChainRegistry.AZTEC;
        bytes memory adapterAddr = abi.encodePacked(bytes32(uint256(42)));

        vm.prank(admin);
        adapter.registerRemoteAdapter(chainId, adapterAddr);

        assertTrue(adapter.isRemoteAdapterRegistered(chainId));
    }

    function test_setProofVerifier() public {
        address verifier = makeAddr("stark_verifier");

        vm.prank(admin);
        adapter.setProofVerifier(
            IUniversalChainAdapter.ProofSystem.STARK,
            verifier
        );

        assertTrue(
            adapter.isProofSystemSupported(
                IUniversalChainAdapter.ProofSystem.STARK
            )
        );
    }

    function test_pauseUnpause() public {
        vm.startPrank(admin);
        adapter.pause();

        // Should revert when paused
        vm.stopPrank();

        bytes32 destChainId = UniversalChainRegistry.SOLANA;

        vm.prank(admin);
        adapter.registerRemoteAdapter(
            destChainId,
            abi.encodePacked(bytes32(uint256(1)))
        );

        vm.prank(user);
        vm.expectRevert(); // EnforcedPause
        adapter.sendEncryptedState(
            destChainId,
            keccak256("state"),
            abi.encodePacked("data"),
            new bytes(128),
            keccak256("null")
        );

        vm.prank(admin);
        adapter.unpause();

        // Should work after unpause
        vm.prank(user);
        adapter.sendEncryptedState(
            destChainId,
            keccak256("state"),
            abi.encodePacked("data"),
            new bytes(128),
            keccak256("null")
        );
    }

    /*//////////////////////////////////////////////////////////////
                         ACCESS CONTROL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_onlyRelayer_canSubmitProof() public {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input");

        IUniversalChainAdapter.UniversalProof
            memory universalProof = IUniversalChainAdapter.UniversalProof({
                proofId: keccak256("proof"),
                sourceChainId: UniversalChainRegistry.SOLANA,
                destChainId: adapter.getUniversalChainId(),
                proofSystem: IUniversalChainAdapter.ProofSystem.GROTH16,
                proof: new bytes(128),
                publicInputs: publicInputs,
                stateCommitment: keccak256("state"),
                nullifier: keccak256("null"),
                timestamp: block.timestamp
            });

        // Should revert for non-relayer
        vm.prank(user);
        vm.expectRevert();
        adapter.submitUniversalProof(universalProof);
    }

    function test_onlyRelayer_canReceiveState() public {
        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: keccak256("transfer"),
                sourceChainId: UniversalChainRegistry.SOLANA,
                destChainId: adapter.getUniversalChainId(),
                stateCommitment: keccak256("state"),
                encryptedPayload: abi.encodePacked("data"),
                nullifier: keccak256("null"),
                newCommitment: keccak256("new"),
                proof: new bytes(128)
            });

        vm.prank(user);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer);
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_nullifierPreventsDoubleSpend(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        bytes32 destChainId = adapter.getUniversalChainId();

        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer1 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: keccak256(abi.encodePacked("t1", nullifier)),
                sourceChainId: UniversalChainRegistry.SOLANA,
                destChainId: destChainId,
                stateCommitment: keccak256(
                    abi.encodePacked("state", nullifier)
                ),
                encryptedPayload: abi.encodePacked("data"),
                nullifier: nullifier,
                newCommitment: keccak256(abi.encodePacked("new", nullifier)),
                proof: new bytes(128)
            });

        vm.prank(relayer);
        adapter.receiveEncryptedState(transfer1);
        assertTrue(adapter.isNullifierUsed(nullifier));

        // Second attempt should revert
        IUniversalChainAdapter.EncryptedStateTransfer
            memory transfer2 = IUniversalChainAdapter.EncryptedStateTransfer({
                transferId: keccak256(abi.encodePacked("t2", nullifier)),
                sourceChainId: UniversalChainRegistry.STARKNET,
                destChainId: destChainId,
                stateCommitment: keccak256(
                    abi.encodePacked("state2", nullifier)
                ),
                encryptedPayload: abi.encodePacked("data2"),
                nullifier: nullifier,
                newCommitment: keccak256(abi.encodePacked("new2", nullifier)),
                proof: new bytes(128)
            });

        vm.prank(relayer);
        vm.expectRevert();
        adapter.receiveEncryptedState(transfer2);
    }

    function testFuzz_relayIdUniqueness(uint256 nonce1, uint256 nonce2) public {
        vm.assume(nonce1 != nonce2);

        bytes32 destChainId = UniversalChainRegistry.SOLANA;

        vm.prank(admin);
        adapter.registerRemoteAdapter(
            destChainId,
            abi.encodePacked(bytes32(uint256(1)))
        );

        vm.startPrank(user);
        bytes32 id1 = adapter.sendEncryptedState(
            destChainId,
            keccak256(abi.encodePacked("state", nonce1)),
            abi.encodePacked("data"),
            new bytes(128),
            keccak256(abi.encodePacked("null", nonce1))
        );

        bytes32 id2 = adapter.sendEncryptedState(
            destChainId,
            keccak256(abi.encodePacked("state", nonce2)),
            abi.encodePacked("data"),
            new bytes(128),
            keccak256(abi.encodePacked("null", nonce2))
        );
        vm.stopPrank();

        assertTrue(id1 != id2, "Relay IDs should be unique");
    }
}

/**
 * @title UniversalAdapterRegistryTest
 * @notice Tests for the Universal Adapter Registry
 */
contract UniversalAdapterRegistryTest is Test {
    UniversalAdapterRegistry public registry;
    EVMUniversalAdapter public arbitrumAdapter;
    EVMUniversalAdapter public optimismAdapter;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    function setUp() public {
        vm.startPrank(admin);

        registry = new UniversalAdapterRegistry(admin);

        arbitrumAdapter = new EVMUniversalAdapter(
            admin,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            "Arbitrum One"
        );

        optimismAdapter = new EVMUniversalAdapter(
            admin,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            "Optimism"
        );

        vm.stopPrank();
    }

    function test_registerEVMAdapter() public {
        bytes32 chainId = UniversalChainRegistry.ARBITRUM_ONE;

        vm.prank(admin);
        registry.registerEVMAdapter(
            chainId,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum One"
        );

        assertTrue(registry.isChainRegistered(chainId));
        assertTrue(registry.isAdapterActive(chainId));
        assertEq(
            registry.getEVMAdapterAddress(chainId),
            address(arbitrumAdapter)
        );
        assertEq(registry.totalChains(), 1);
    }

    function test_registerExternalAdapter() public {
        bytes32 chainId = UniversalChainRegistry.SOLANA;
        bytes memory programId = abi.encodePacked(
            bytes32(
                0x1111111111111111111111111111111111111111111111111111111111111111
            )
        );

        vm.prank(admin);
        registry.registerExternalAdapter(
            chainId,
            programId,
            IUniversalChainAdapter.ChainVM.SVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Solana"
        );

        assertTrue(registry.isChainRegistered(chainId));
        assertTrue(registry.isAdapterActive(chainId));
        assertEq(
            uint8(registry.getChainVM(chainId)),
            uint8(IUniversalChainAdapter.ChainVM.SVM)
        );
    }

    function test_registerMultipleChainTypes() public {
        vm.startPrank(admin);

        // EVM L2
        registry.registerEVMAdapter(
            UniversalChainRegistry.ARBITRUM_ONE,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum One"
        );

        // Solana (SVM)
        registry.registerExternalAdapter(
            UniversalChainRegistry.SOLANA,
            abi.encodePacked(bytes32(uint256(1))),
            IUniversalChainAdapter.ChainVM.SVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Solana"
        );

        // StarkNet (Cairo/STARK)
        registry.registerExternalAdapter(
            UniversalChainRegistry.STARKNET,
            abi.encodePacked(bytes32(uint256(2))),
            IUniversalChainAdapter.ChainVM.CAIRO,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.STARK,
            "StarkNet"
        );

        // Aztec (Privacy-native)
        registry.registerExternalAdapter(
            UniversalChainRegistry.AZTEC,
            abi.encodePacked(bytes32(uint256(3))),
            IUniversalChainAdapter.ChainVM.NOIR_AZTEC,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.HONK,
            "Aztec"
        );

        // Midnight (Privacy L1)
        registry.registerExternalAdapter(
            UniversalChainRegistry.MIDNIGHT,
            abi.encodePacked(bytes32(uint256(4))),
            IUniversalChainAdapter.ChainVM.MIDNIGHT,
            IUniversalChainAdapter.ChainLayer.L1_PRIVATE,
            IUniversalChainAdapter.ProofSystem.PLONK,
            "Midnight"
        );

        // Aptos (Move)
        registry.registerExternalAdapter(
            UniversalChainRegistry.APTOS,
            abi.encodePacked(bytes32(uint256(5))),
            IUniversalChainAdapter.ChainVM.MOVE_APTOS,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Aptos"
        );

        // Zcash
        registry.registerExternalAdapter(
            UniversalChainRegistry.ZCASH,
            abi.encodePacked(bytes32(uint256(6))),
            IUniversalChainAdapter.ChainVM.ZCASH,
            IUniversalChainAdapter.ChainLayer.L1_PRIVATE,
            IUniversalChainAdapter.ProofSystem.HALO2,
            "Zcash"
        );

        vm.stopPrank();

        assertEq(registry.totalChains(), 7);

        // Verify all chains are registered
        bytes32[] memory chains = registry.getRegisteredChains();
        assertEq(chains.length, 7);
    }

    function test_createBidirectionalRoute() public {
        vm.startPrank(admin);

        registry.registerEVMAdapter(
            UniversalChainRegistry.ARBITRUM_ONE,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum One"
        );

        registry.registerExternalAdapter(
            UniversalChainRegistry.SOLANA,
            abi.encodePacked(bytes32(uint256(1))),
            IUniversalChainAdapter.ChainVM.SVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Solana"
        );

        registry.createBidirectionalRoute(
            UniversalChainRegistry.ARBITRUM_ONE,
            UniversalChainRegistry.SOLANA
        );

        vm.stopPrank();

        assertTrue(
            registry.isRouteActive(
                UniversalChainRegistry.ARBITRUM_ONE,
                UniversalChainRegistry.SOLANA
            )
        );
        assertTrue(
            registry.isRouteActive(
                UniversalChainRegistry.SOLANA,
                UniversalChainRegistry.ARBITRUM_ONE
            )
        );
        assertEq(registry.totalActiveRoutes(), 2);
    }

    function test_deactivateAdapter() public {
        vm.startPrank(admin);

        registry.registerEVMAdapter(
            UniversalChainRegistry.ARBITRUM_ONE,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum One"
        );

        assertTrue(
            registry.isAdapterActive(UniversalChainRegistry.ARBITRUM_ONE)
        );

        registry.deactivateAdapter(UniversalChainRegistry.ARBITRUM_ONE);

        assertFalse(
            registry.isAdapterActive(UniversalChainRegistry.ARBITRUM_ONE)
        );

        registry.activateAdapter(UniversalChainRegistry.ARBITRUM_ONE);

        assertTrue(
            registry.isAdapterActive(UniversalChainRegistry.ARBITRUM_ONE)
        );

        vm.stopPrank();
    }

    function test_revert_duplicateRegistration() public {
        bytes32 chainId = UniversalChainRegistry.ARBITRUM_ONE;

        vm.startPrank(admin);
        registry.registerEVMAdapter(
            chainId,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum One"
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalAdapterRegistry.ChainAlreadyRegistered.selector,
                chainId
            )
        );
        registry.registerEVMAdapter(
            chainId,
            address(optimismAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Duplicate"
        );
        vm.stopPrank();
    }

    function test_revert_selfRoute() public {
        bytes32 chainId = UniversalChainRegistry.ARBITRUM_ONE;

        vm.startPrank(admin);
        registry.registerEVMAdapter(
            chainId,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum"
        );

        vm.expectRevert(UniversalAdapterRegistry.SelfRoute.selector);
        registry.createRoute(chainId, chainId);
        vm.stopPrank();
    }

    function test_recordProofRelay() public {
        vm.startPrank(admin);

        registry.registerEVMAdapter(
            UniversalChainRegistry.ARBITRUM_ONE,
            address(arbitrumAdapter),
            IUniversalChainAdapter.ChainVM.EVM,
            IUniversalChainAdapter.ChainLayer.L2_ROLLUP,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Arbitrum"
        );

        registry.registerExternalAdapter(
            UniversalChainRegistry.SOLANA,
            abi.encodePacked(bytes32(uint256(1))),
            IUniversalChainAdapter.ChainVM.SVM,
            IUniversalChainAdapter.ChainLayer.L1_PUBLIC,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            "Solana"
        );

        registry.createRoute(
            UniversalChainRegistry.ARBITRUM_ONE,
            UniversalChainRegistry.SOLANA
        );

        registry.recordProofRelay(
            UniversalChainRegistry.ARBITRUM_ONE,
            UniversalChainRegistry.SOLANA,
            keccak256("proof_1")
        );

        (uint256 totalRelays, uint256 lastRelayAt_) = registry.getRouteStats(
            UniversalChainRegistry.ARBITRUM_ONE,
            UniversalChainRegistry.SOLANA
        );

        assertEq(totalRelays, 1);
        assertTrue(lastRelayAt_ > 0);
        vm.stopPrank();
    }
}

/**
 * @title UniversalChainRegistryTest
 * @notice Tests for the chain registry library
 */
contract UniversalChainRegistryTest is Test {
    function test_proofSystemCompatibility_sameSystem() public pure {
        assertTrue(
            UniversalChainRegistry.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.GROTH16,
                IUniversalChainAdapter.ProofSystem.GROTH16
            )
        );
    }

    function test_proofSystemCompatibility_plonkFamily() public pure {
        assertTrue(
            UniversalChainRegistry.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.PLONK,
                IUniversalChainAdapter.ProofSystem.ULTRAPLONK
            )
        );
        assertTrue(
            UniversalChainRegistry.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.ULTRAPLONK,
                IUniversalChainAdapter.ProofSystem.HONK
            )
        );
        assertTrue(
            UniversalChainRegistry.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.PLONK,
                IUniversalChainAdapter.ProofSystem.HONK
            )
        );
    }

    function test_proofSystemCompatibility_incompatible() public pure {
        assertFalse(
            UniversalChainRegistry.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.GROTH16,
                IUniversalChainAdapter.ProofSystem.STARK
            )
        );
        assertFalse(
            UniversalChainRegistry.areProofSystemsCompatible(
                IUniversalChainAdapter.ProofSystem.STARK,
                IUniversalChainAdapter.ProofSystem.PLONK
            )
        );
    }

    function test_defaultProofSystems() public pure {
        assertEq(
            uint8(
                UniversalChainRegistry.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.EVM
                )
            ),
            uint8(IUniversalChainAdapter.ProofSystem.GROTH16)
        );
        assertEq(
            uint8(
                UniversalChainRegistry.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.CAIRO
                )
            ),
            uint8(IUniversalChainAdapter.ProofSystem.STARK)
        );
        assertEq(
            uint8(
                UniversalChainRegistry.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.NOIR_AZTEC
                )
            ),
            uint8(IUniversalChainAdapter.ProofSystem.HONK)
        );
        assertEq(
            uint8(
                UniversalChainRegistry.getDefaultProofSystem(
                    IUniversalChainAdapter.ChainVM.ZCASH
                )
            ),
            uint8(IUniversalChainAdapter.ProofSystem.HALO2)
        );
    }

    function test_computeEVMChainId_deterministic() public pure {
        bytes32 id1 = UniversalChainRegistry.computeEVMChainId(1);
        bytes32 id2 = UniversalChainRegistry.computeEVMChainId(1);
        assertEq(id1, id2);

        bytes32 id3 = UniversalChainRegistry.computeEVMChainId(42161);
        assertTrue(id1 != id3, "Different chains should have different IDs");
    }

    function test_computeNonEVMChainId_deterministic() public pure {
        bytes32 sol1 = UniversalChainRegistry.computeNonEVMChainId("SOLANA");
        bytes32 sol2 = UniversalChainRegistry.computeNonEVMChainId("SOLANA");
        assertEq(sol1, sol2);

        bytes32 aptos = UniversalChainRegistry.computeNonEVMChainId("APTOS");
        assertTrue(sol1 != aptos, "Different chains should have different IDs");
    }
}
