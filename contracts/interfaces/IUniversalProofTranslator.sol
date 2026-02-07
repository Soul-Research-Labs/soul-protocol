// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUniversalChainAdapter} from "./IUniversalChainAdapter.sol";

/**
 * @title IUniversalProofTranslator
 * @author Soul Protocol
 * @notice Interface for cross-proof-system translation coordination
 */
interface IUniversalProofTranslator {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct TranslationRequest {
        bytes32 requestId;
        IUniversalChainAdapter.ProofSystem sourceSystem;
        IUniversalChainAdapter.ProofSystem targetSystem;
        bytes32 sourceChainId;
        bytes32 destChainId;
        bytes32 stateCommitment;
        bytes32[] publicInputs;
        bytes sourceProof;
        bytes translatedProof;
        bytes wrapperProof;
        uint256 timestamp;
    }

    struct TranslationPath {
        IUniversalChainAdapter.ProofSystem fromSystem;
        IUniversalChainAdapter.ProofSystem toSystem;
        address wrapperVerifier;
        bool nativeCompat;
        bool active;
        uint256 totalTranslations;
    }

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/

    event TranslationPathRegistered(
        IUniversalChainAdapter.ProofSystem indexed fromSystem,
        IUniversalChainAdapter.ProofSystem indexed toSystem,
        address wrapperVerifier,
        bool nativeCompat
    );

    event ProofTranslated(
        bytes32 indexed requestId,
        IUniversalChainAdapter.ProofSystem indexed fromSystem,
        IUniversalChainAdapter.ProofSystem indexed toSystem,
        bytes32 stateCommitment
    );

    event SourceVerifierSet(
        IUniversalChainAdapter.ProofSystem indexed proofSystem,
        address indexed verifier
    );

    /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error TranslationPathNotActive(
        IUniversalChainAdapter.ProofSystem from,
        IUniversalChainAdapter.ProofSystem to
    );
    error TranslationAlreadyCompleted(bytes32 requestId);
    error SourceProofVerificationFailed();
    error WrapperProofVerificationFailed();
    error TranslatedProofVerificationFailed();
    error InvalidProofSize();
    error ZeroAddress();
    error EmptyProof();
    error NoSourceVerifier(IUniversalChainAdapter.ProofSystem system);

    /*//////////////////////////////////////////////////////////////
                         CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function translateAndVerify(
        TranslationRequest calldata request
    ) external returns (bytes32 requestId);

    function canTranslate(
        IUniversalChainAdapter.ProofSystem from,
        IUniversalChainAdapter.ProofSystem to
    ) external view returns (bool possible, bool nativeCompat);

    function getTranslationResult(
        bytes32 requestId
    ) external view returns (bool completed, bytes32 translatedProofHash);

    /*//////////////////////////////////////////////////////////////
                          ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function registerTranslationPath(
        IUniversalChainAdapter.ProofSystem fromSystem,
        IUniversalChainAdapter.ProofSystem toSystem,
        address wrapperVerifier
    ) external;

    function setSourceVerifier(
        IUniversalChainAdapter.ProofSystem proofSystem,
        address verifier
    ) external;

    function deactivateTranslationPath(
        IUniversalChainAdapter.ProofSystem fromSystem,
        IUniversalChainAdapter.ProofSystem toSystem
    ) external;

    function pause() external;

    function unpause() external;
}
