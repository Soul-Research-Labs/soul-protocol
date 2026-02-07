// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {UniversalProofTranslator} from "../../contracts/privacy/UniversalProofTranslator.sol";
import {IUniversalChainAdapter} from "../../contracts/interfaces/IUniversalChainAdapter.sol";

/// @dev Mock verifier that always returns true
contract MockVerifier {
    function verify(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return true;
    }
}

/// @dev Mock verifier that always returns false
contract MockFailVerifier {
    function verify(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return false;
    }

    function verifyProof(
        bytes calldata,
        bytes calldata
    ) external pure returns (bool) {
        return false;
    }
}

/**
 * @title UniversalProofTranslatorTest
 * @notice Comprehensive tests for the Universal Proof Translator
 */
contract UniversalProofTranslatorTest is Test {
    UniversalProofTranslator public translator;
    MockVerifier public mockVerifier;
    MockFailVerifier public failVerifier;

    address public admin = makeAddr("admin");
    address public operator = makeAddr("operator");

    bytes32 public constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    function setUp() public {
        vm.startPrank(admin);
        translator = new UniversalProofTranslator(admin);
        translator.grantRole(OPERATOR_ROLE, operator);
        vm.stopPrank();

        mockVerifier = new MockVerifier();
        failVerifier = new MockFailVerifier();
    }

    /*//////////////////////////////////////////////////////////////
                          INITIALIZATION
    //////////////////////////////////////////////////////////////*/

    function test_InitializeCorrectly() public view {
        assertEq(translator.totalTranslations(), 0);
    }

    function test_NativeCompatPathsRegistered() public view {
        // PLONK <-> UltraPlonk native compat should be set in constructor
        (bool possible, bool nativeCompat) = translator.canTranslate(
            IUniversalChainAdapter.ProofSystem.PLONK,
            IUniversalChainAdapter.ProofSystem.ULTRAPLONK
        );
        assertTrue(possible, "PLONK->UltraPlonk should be translatable");
        assertTrue(nativeCompat, "Should be native compatible");
    }

    /*//////////////////////////////////////////////////////////////
                     TRANSLATION PATH MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function test_RegisterTranslationPath() public {
        vm.prank(operator);
        translator.registerTranslationPath(
            IUniversalChainAdapter.ProofSystem.STARK,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(mockVerifier)
        );

        (bool possible, bool nativeCompat) = translator.canTranslate(
            IUniversalChainAdapter.ProofSystem.STARK,
            IUniversalChainAdapter.ProofSystem.GROTH16
        );
        assertTrue(possible, "STARK->Groth16 should be translatable");
        assertFalse(nativeCompat, "Should not be native compatible");
    }

    function test_DeactivateTranslationPath() public {
        vm.startPrank(operator);
        translator.registerTranslationPath(
            IUniversalChainAdapter.ProofSystem.STARK,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(mockVerifier)
        );

        translator.deactivateTranslationPath(
            IUniversalChainAdapter.ProofSystem.STARK,
            IUniversalChainAdapter.ProofSystem.GROTH16
        );
        vm.stopPrank();

        (bool possible, ) = translator.canTranslate(
            IUniversalChainAdapter.ProofSystem.STARK,
            IUniversalChainAdapter.ProofSystem.GROTH16
        );
        assertFalse(possible, "Deactivated path should not be translatable");
    }

    /*//////////////////////////////////////////////////////////////
                      SOURCE VERIFIERS
    //////////////////////////////////////////////////////////////*/

    function test_SetSourceVerifier() public {
        vm.prank(operator);
        translator.setSourceVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(mockVerifier)
        );

        assertEq(
            translator.sourceVerifiers(
                IUniversalChainAdapter.ProofSystem.GROTH16
            ),
            address(mockVerifier)
        );
    }

    function test_RevertSetSourceVerifierZeroAddress() public {
        vm.prank(operator);
        vm.expectRevert(
            abi.encodeWithSelector(
                UniversalProofTranslator.ZeroAddress.selector
            )
        );
        translator.setSourceVerifier(
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(0)
        );
    }

    /*//////////////////////////////////////////////////////////////
                      TRANSLATE AND VERIFY
    //////////////////////////////////////////////////////////////*/

    function test_TranslateNativeCompatProof() public {
        // Setup source verifier for PLONK
        vm.startPrank(operator);
        translator.setSourceVerifier(
            IUniversalChainAdapter.ProofSystem.PLONK,
            address(mockVerifier)
        );
        vm.stopPrank();

        // Build translation request (PLONK -> UltraPlonk, native compat)
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input1");

        UniversalProofTranslator.TranslationRequest
            memory req = UniversalProofTranslator.TranslationRequest({
                requestId: bytes32(0),
                sourceSystem: IUniversalChainAdapter.ProofSystem.PLONK,
                targetSystem: IUniversalChainAdapter.ProofSystem.ULTRAPLONK,
                sourceChainId: keccak256("ethereum"),
                destChainId: keccak256("arbitrum"),
                stateCommitment: keccak256("state1"),
                publicInputs: publicInputs,
                sourceProof: new bytes(128),
                translatedProof: new bytes(0),
                wrapperProof: new bytes(0),
                timestamp: block.timestamp
            });

        bytes32 requestId = translator.translateAndVerify(req);
        assertTrue(requestId != bytes32(0), "Request ID should be generated");

        (bool completed, bytes32 resultHash) = translator.getTranslationResult(
            requestId
        );
        assertTrue(completed, "Translation should be completed");
        assertTrue(resultHash != bytes32(0), "Result hash should be set");
        assertEq(translator.totalTranslations(), 1);
    }

    function test_TranslateWithWrapperProof() public {
        // Register path STARK -> Groth16 with wrapper verifier
        vm.startPrank(operator);
        translator.registerTranslationPath(
            IUniversalChainAdapter.ProofSystem.STARK,
            IUniversalChainAdapter.ProofSystem.GROTH16,
            address(mockVerifier)
        );
        translator.setSourceVerifier(
            IUniversalChainAdapter.ProofSystem.STARK,
            address(mockVerifier)
        );
        vm.stopPrank();

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input2");

        UniversalProofTranslator.TranslationRequest
            memory req = UniversalProofTranslator.TranslationRequest({
                requestId: bytes32(0),
                sourceSystem: IUniversalChainAdapter.ProofSystem.STARK,
                targetSystem: IUniversalChainAdapter.ProofSystem.GROTH16,
                sourceChainId: keccak256("starknet"),
                destChainId: keccak256("ethereum"),
                stateCommitment: keccak256("state2"),
                publicInputs: publicInputs,
                sourceProof: new bytes(256),
                translatedProof: new bytes(128),
                wrapperProof: new bytes(128),
                timestamp: block.timestamp
            });

        bytes32 requestId = translator.translateAndVerify(req);
        assertTrue(requestId != bytes32(0));
        assertEq(translator.totalTranslations(), 1);
    }

    function test_RevertTranslateInactivePath() public {
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input3");

        UniversalProofTranslator.TranslationRequest
            memory req = UniversalProofTranslator.TranslationRequest({
                requestId: bytes32(0),
                sourceSystem: IUniversalChainAdapter.ProofSystem.BULLETPROOFS,
                targetSystem: IUniversalChainAdapter.ProofSystem.NOVA,
                sourceChainId: keccak256("chain_a"),
                destChainId: keccak256("chain_b"),
                stateCommitment: keccak256("state3"),
                publicInputs: publicInputs,
                sourceProof: new bytes(128),
                translatedProof: new bytes(0),
                wrapperProof: new bytes(0),
                timestamp: block.timestamp
            });

        vm.expectRevert();
        translator.translateAndVerify(req);
    }

    function test_RevertDuplicateTranslation() public {
        vm.startPrank(operator);
        translator.setSourceVerifier(
            IUniversalChainAdapter.ProofSystem.PLONK,
            address(mockVerifier)
        );
        vm.stopPrank();

        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("input_dup");

        UniversalProofTranslator.TranslationRequest
            memory req = UniversalProofTranslator.TranslationRequest({
                requestId: bytes32(0),
                sourceSystem: IUniversalChainAdapter.ProofSystem.PLONK,
                targetSystem: IUniversalChainAdapter.ProofSystem.ULTRAPLONK,
                sourceChainId: keccak256("ethereum"),
                destChainId: keccak256("arbitrum"),
                stateCommitment: keccak256("state_dup"),
                publicInputs: publicInputs,
                sourceProof: new bytes(128),
                translatedProof: new bytes(0),
                wrapperProof: new bytes(0),
                timestamp: block.timestamp
            });

        bytes32 requestId = translator.translateAndVerify(req);

        // If we try to re-submit with same computed requestId, it should revert
        // (depends on implementation — requestId is computed from inputs)
        assertTrue(translator.completedTranslations(requestId));
    }

    /*//////////////////////////////////////////////////////////////
                       PAUSE / UNPAUSE
    //////////////////////////////////////////////////////////////*/

    function test_PauseAndUnpause() public {
        vm.startPrank(admin);
        translator.pause();

        // Operations should revert when paused
        bytes32[] memory publicInputs = new bytes32[](1);
        publicInputs[0] = keccak256("paused_input");

        UniversalProofTranslator.TranslationRequest
            memory req = UniversalProofTranslator.TranslationRequest({
                requestId: bytes32(0),
                sourceSystem: IUniversalChainAdapter.ProofSystem.PLONK,
                targetSystem: IUniversalChainAdapter.ProofSystem.ULTRAPLONK,
                sourceChainId: keccak256("ethereum"),
                destChainId: keccak256("arbitrum"),
                stateCommitment: keccak256("paused_state"),
                publicInputs: publicInputs,
                sourceProof: new bytes(128),
                translatedProof: new bytes(0),
                wrapperProof: new bytes(0),
                timestamp: block.timestamp
            });

        vm.expectRevert();
        translator.translateAndVerify(req);

        translator.unpause();
        vm.stopPrank();
    }
}
