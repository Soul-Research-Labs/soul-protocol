// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {HybridPQCVerifier, IPQCVerifierLib} from "../../contracts/experimental/verifiers/HybridPQCVerifier.sol";
import {IPQCVerifier} from "../../contracts/interfaces/IPQCVerifier.sol";

/**
 * @title HybridPQCVerifierTest
 * @notice Comprehensive tests for the HybridPQCVerifier contract
 * @dev Covers key management, hybrid verification, oracle flow, access control, edge cases
 */
contract HybridPQCVerifierTest is Test {
    HybridPQCVerifier public verifier;

    address public admin;
    address public oracle;
    address public guardian;
    address public user1;
    address public user2;
    uint256 public user1Key;
    uint256 public user2Key;

    // Algorith-correct key sizes for test fixtures
    uint256 constant FN_DSA_512_PK_SIZE = 897;
    uint256 constant FN_DSA_512_SIG_SIZE = 690;
    uint256 constant ML_DSA_44_PK_SIZE = 1312;
    uint256 constant ML_DSA_44_SIG_SIZE = 2420;
    uint256 constant ML_DSA_65_PK_SIZE = 1952;
    uint256 constant ML_KEM_768_PK_SIZE = 1184;
    uint256 constant SLH_DSA_128S_PK_SIZE = 32;
    uint256 constant SLH_DSA_128S_SIG_SIZE = 7856;

    bytes32 constant PQC_KEY_DOMAIN =
        keccak256("ZASEON_PQC_KEY_REGISTRATION_V1");
    bytes32 constant HYBRID_SIG_DOMAIN =
        keccak256("ZASEON_HYBRID_SIGNATURE_V1");

    function setUp() public {
        admin = makeAddr("admin");
        oracle = makeAddr("oracle");
        guardian = makeAddr("guardian");
        (user1, user1Key) = makeAddrAndKey("user1");
        (user2, user2Key) = makeAddrAndKey("user2");

        vm.startPrank(admin);
        verifier = new HybridPQCVerifier(admin, oracle);
        verifier.grantRole(verifier.GUARDIAN_ROLE(), guardian);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                            DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    function test_Deployment() public view {
        assertEq(verifier.pqcOracle(), oracle);
        assertTrue(verifier.hasRole(verifier.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(verifier.hasRole(verifier.OPERATOR_ROLE(), admin));
        assertTrue(verifier.hasRole(verifier.GUARDIAN_ROLE(), admin));
        assertTrue(verifier.hasRole(verifier.GUARDIAN_ROLE(), guardian));
        assertEq(
            uint8(verifier.defaultMode()),
            uint8(IPQCVerifier.VerificationMode.HYBRID)
        );
        assertEq(verifier.totalKeysRegistered(), 0);
        assertEq(verifier.totalVerifications(), 0);
    }

    function test_RevertZeroAdmin() public {
        vm.expectRevert(HybridPQCVerifier.ZeroAddress.selector);
        new HybridPQCVerifier(address(0), oracle);
    }

    /*//////////////////////////////////////////////////////////////
                        KEY REGISTRATION
    //////////////////////////////////////////////////////////////*/

    function test_RegisterFalconKey() public {
        bytes memory keyData = _generateKey(FN_DSA_512_PK_SIZE);

        vm.prank(user1);
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user1);
        assertEq(
            uint8(key.algorithm),
            uint8(IPQCVerifier.PQCAlgorithm.FN_DSA_512)
        );
        assertEq(uint8(key.level), uint8(IPQCVerifier.SecurityLevel.LEVEL_1));
        assertFalse(key.revoked);
        assertTrue(key.keyHash != bytes32(0));
        assertEq(verifier.totalKeysRegistered(), 1);
    }

    function test_RegisterDilithiumKey() public {
        bytes memory keyData = _generateKey(ML_DSA_44_PK_SIZE);

        vm.prank(user1);
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.ML_DSA_44);

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user1);
        assertEq(
            uint8(key.algorithm),
            uint8(IPQCVerifier.PQCAlgorithm.ML_DSA_44)
        );
        assertEq(uint8(key.level), uint8(IPQCVerifier.SecurityLevel.LEVEL_1));
    }

    function test_RegisterSPHINCSKey() public {
        bytes memory keyData = _generateKey(SLH_DSA_128S_PK_SIZE);

        vm.prank(user1);
        verifier.registerPQCKey(
            keyData,
            IPQCVerifier.PQCAlgorithm.SLH_DSA_128S
        );

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user1);
        assertEq(
            uint8(key.algorithm),
            uint8(IPQCVerifier.PQCAlgorithm.SLH_DSA_128S)
        );
    }

    function test_RegisterKyberKey() public {
        bytes memory keyData = _generateKey(ML_KEM_768_PK_SIZE);

        vm.prank(user1);
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.ML_KEM_768);

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user1);
        assertEq(
            uint8(key.algorithm),
            uint8(IPQCVerifier.PQCAlgorithm.ML_KEM_768)
        );
        assertEq(uint8(key.level), uint8(IPQCVerifier.SecurityLevel.LEVEL_3));
    }

    function test_RevertDuplicateRegistration() public {
        bytes memory keyData = _generateKey(FN_DSA_512_PK_SIZE);

        vm.startPrank(user1);
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);

        vm.expectRevert(
            abi.encodeWithSelector(
                HybridPQCVerifier.KeyAlreadyRegistered.selector,
                user1
            )
        );
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);
        vm.stopPrank();
    }

    function test_RevertWrongKeySize() public {
        bytes memory wrongSizeKey = _generateKey(100); // Wrong size for any algo

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HybridPQCVerifier.InvalidKeySize.selector,
                IPQCVerifier.PQCAlgorithm.FN_DSA_512,
                FN_DSA_512_PK_SIZE,
                100
            )
        );
        verifier.registerPQCKey(
            wrongSizeKey,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );
    }

    function test_HasValidPQCKey() public {
        assertFalse(verifier.hasValidPQCKey(user1));

        bytes memory keyData = _generateKey(FN_DSA_512_PK_SIZE);
        vm.prank(user1);
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);

        assertTrue(verifier.hasValidPQCKey(user1));
    }

    /*//////////////////////////////////////////////////////////////
                         KEY REVOCATION
    //////////////////////////////////////////////////////////////*/

    function test_RevokeOwnKey() public {
        _registerFalconKey(user1);

        vm.prank(user1);
        verifier.revokePQCKey();

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user1);
        assertTrue(key.revoked);
        assertFalse(verifier.hasValidPQCKey(user1));
    }

    function test_GuardianRevoke() public {
        _registerFalconKey(user1);

        vm.prank(guardian);
        verifier.guardianRevokeKey(user1);

        assertTrue(verifier.getPQCKey(user1).revoked);
    }

    function test_RevertRevokeUnregistered() public {
        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HybridPQCVerifier.KeyNotRegistered.selector,
                user1
            )
        );
        verifier.revokePQCKey();
    }

    function test_CanRegisterAfterRevoke() public {
        _registerFalconKey(user1);

        vm.prank(user1);
        verifier.revokePQCKey();

        // New registration after revocation should work
        bytes memory newKeyData = _generateKey(ML_DSA_44_PK_SIZE);
        vm.prank(user1);
        verifier.registerPQCKey(
            newKeyData,
            IPQCVerifier.PQCAlgorithm.ML_DSA_44
        );

        assertTrue(verifier.hasValidPQCKey(user1));
    }

    /*//////////////////////////////////////////////////////////////
                          KEY ROTATION
    //////////////////////////////////////////////////////////////*/

    function test_RotateKey() public {
        _registerFalconKey(user1);

        // Advance past cooldown
        vm.warp(block.timestamp + 1 hours + 1);

        bytes memory newKeyData = _generateKey(ML_DSA_44_PK_SIZE);

        vm.prank(user1);
        verifier.rotatePQCKey(newKeyData, IPQCVerifier.PQCAlgorithm.ML_DSA_44);

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user1);
        assertEq(
            uint8(key.algorithm),
            uint8(IPQCVerifier.PQCAlgorithm.ML_DSA_44)
        );
        assertFalse(key.revoked);
    }

    function test_RevertRotateDuringCooldown() public {
        _registerFalconKey(user1);

        bytes memory newKeyData = _generateKey(ML_DSA_44_PK_SIZE);

        vm.prank(user1);
        vm.expectRevert(); // RotationCooldownActive
        verifier.rotatePQCKey(newKeyData, IPQCVerifier.PQCAlgorithm.ML_DSA_44);
    }

    function test_RevertRotateUnregistered() public {
        bytes memory keyData = _generateKey(FN_DSA_512_PK_SIZE);

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                HybridPQCVerifier.KeyNotRegistered.selector,
                user1
            )
        );
        verifier.rotatePQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);
    }

    /*//////////////////////////////////////////////////////////////
                     HYBRID VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_HybridVerification_BothPass() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test message");
        bytes memory classicalSig = _signMessage(messageHash, user1Key);
        bytes memory pqcSig = _generateKey(FN_DSA_512_SIG_SIZE);

        // Oracle approves PQC result
        _submitOracleResult(
            messageHash,
            pqcSig,
            user1,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );

        bool result = verifier.verifyHybrid(
            messageHash,
            classicalSig,
            pqcSig,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        assertTrue(result);
        assertEq(verifier.totalVerifications(), 1);
        assertEq(verifier.successfulVerifications(), 1);
    }

    function test_HybridVerification_ClassicalOnly() public {
        bytes32 messageHash = keccak256("test message");
        bytes memory classicalSig = _signMessage(messageHash, user1Key);

        bool result = verifier.verifyHybrid(
            messageHash,
            classicalSig,
            "", // empty pqc sig
            user1,
            IPQCVerifier.VerificationMode.CLASSICAL_ONLY
        );

        assertTrue(result);
    }

    function test_HybridVerification_PQCOnly() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test pqc only");
        bytes memory pqcSig = _generateKey(FN_DSA_512_SIG_SIZE);

        _submitOracleResult(
            messageHash,
            pqcSig,
            user1,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );

        bool result = verifier.verifyHybrid(
            messageHash,
            "", // empty classical sig
            pqcSig,
            user1,
            IPQCVerifier.VerificationMode.PQC_ONLY
        );

        assertTrue(result);
    }

    function test_HybridVerification_FailsBadECDSA() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test message");
        bytes memory badClassicalSig = _signMessage(messageHash, user2Key); // Wrong key
        bytes memory pqcSig = _generateKey(FN_DSA_512_SIG_SIZE);

        _submitOracleResult(
            messageHash,
            pqcSig,
            user1,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );

        bool result = verifier.verifyHybrid(
            messageHash,
            badClassicalSig,
            pqcSig,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        assertFalse(result);
        assertEq(verifier.successfulVerifications(), 0);
    }

    function test_HybridVerification_FailsNoPQCResult() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test message");
        bytes memory classicalSig = _signMessage(messageHash, user1Key);
        bytes memory pqcSig = _generateKey(FN_DSA_512_SIG_SIZE);

        // Don't submit oracle result — PQC verification should fail
        bool result = verifier.verifyHybrid(
            messageHash,
            classicalSig,
            pqcSig,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        assertFalse(result);
    }

    function test_HybridVerification_FailsRevokedKey() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test message");
        bytes memory pqcSig = _generateKey(FN_DSA_512_SIG_SIZE);

        _submitOracleResult(
            messageHash,
            pqcSig,
            user1,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );

        // Revoke key
        vm.prank(user1);
        verifier.revokePQCKey();

        bytes memory classicalSig = _signMessage(messageHash, user1Key);
        bool result = verifier.verifyHybrid(
            messageHash,
            classicalSig,
            pqcSig,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        assertFalse(result);
    }

    /*//////////////////////////////////////////////////////////////
                       VERIFICATION STATS
    //////////////////////////////////////////////////////////////*/

    function test_VerificationStats() public {
        _registerFalconKey(user1);

        bytes32 msg1 = keccak256("msg1");
        bytes memory sig1 = _signMessage(msg1, user1Key);
        bytes memory pqcSig = _generateKey(FN_DSA_512_SIG_SIZE);

        // Submit oracle approval for msg1
        _submitOracleResult(
            msg1,
            pqcSig,
            user1,
            IPQCVerifier.PQCAlgorithm.FN_DSA_512
        );

        // Successful verification
        verifier.verifyHybrid(
            msg1,
            sig1,
            pqcSig,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        // Failed verification (no oracle result)
        bytes32 msg2 = keccak256("msg2");
        bytes memory sig2 = _signMessage(msg2, user1Key);
        bytes memory pqcSig2 = _generateKey(FN_DSA_512_SIG_SIZE);
        verifier.verifyHybrid(
            msg2,
            sig2,
            pqcSig2,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        (uint256 total, uint256 successful, uint256 rate) = verifier
            .getVerificationStats();
        assertEq(total, 2);
        assertEq(successful, 1);
        assertEq(rate, 5000); // 50% success rate in bps
    }

    /*//////////////////////////////////////////////////////////////
                        ORACLE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SubmitPQCResult() public {
        bytes32 resultHash = keccak256("some result");

        vm.prank(oracle);
        verifier.submitPQCResult(resultHash);

        assertTrue(verifier.approvedPQCResults(resultHash));
    }

    function test_BatchSubmitPQCResults() public {
        bytes32[] memory hashes = new bytes32[](3);
        hashes[0] = keccak256("result1");
        hashes[1] = keccak256("result2");
        hashes[2] = keccak256("result3");

        vm.prank(oracle);
        verifier.batchSubmitPQCResults(hashes);

        assertTrue(verifier.approvedPQCResults(hashes[0]));
        assertTrue(verifier.approvedPQCResults(hashes[1]));
        assertTrue(verifier.approvedPQCResults(hashes[2]));
    }

    function test_RevertNonOracleSubmit() public {
        vm.prank(user1);
        vm.expectRevert(HybridPQCVerifier.OnlyOracle.selector);
        verifier.submitPQCResult(keccak256("result"));
    }

    function test_RevertNonOracleBatchSubmit() public {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = keccak256("result");

        vm.prank(user1);
        vm.expectRevert(HybridPQCVerifier.OnlyOracle.selector);
        verifier.batchSubmitPQCResults(hashes);
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function test_SetDefaultMode() public {
        vm.prank(admin);
        verifier.setDefaultMode(IPQCVerifier.VerificationMode.CLASSICAL_ONLY);

        assertEq(
            uint8(verifier.defaultMode()),
            uint8(IPQCVerifier.VerificationMode.CLASSICAL_ONLY)
        );
    }

    function test_SetPQCOracle() public {
        address newOracle = makeAddr("newOracle");
        vm.prank(admin);
        verifier.setPQCOracle(newOracle);

        assertEq(verifier.pqcOracle(), newOracle);
    }

    function test_RevertSetZeroOracle() public {
        vm.prank(admin);
        vm.expectRevert(HybridPQCVerifier.InvalidOracle.selector);
        verifier.setPQCOracle(address(0));
    }

    function test_PauseUnpause() public {
        vm.prank(admin);
        verifier.pause();
        assertTrue(verifier.paused());

        vm.prank(admin);
        verifier.unpause();
        assertFalse(verifier.paused());
    }

    function test_RevertRegisterWhenPaused() public {
        vm.prank(admin);
        verifier.pause();

        bytes memory keyData = _generateKey(FN_DSA_512_PK_SIZE);
        vm.prank(user1);
        vm.expectRevert(); // Pausable: paused
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);
    }

    function test_RevertUnauthorizedAdmin() public {
        vm.prank(user1);
        vm.expectRevert();
        verifier.setDefaultMode(IPQCVerifier.VerificationMode.PQC_ONLY);
    }

    /*//////////////////////////////////////////////////////////////
                      ALGORITHM SIZE LOOKUPS
    //////////////////////////////////////////////////////////////*/

    function test_ExpectedKeySizes() public view {
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.ML_DSA_44),
            1312
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.ML_DSA_65),
            1952
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.ML_DSA_87),
            2592
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.FN_DSA_512),
            897
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.FN_DSA_1024),
            1793
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.SLH_DSA_128S),
            32
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.SLH_DSA_128F),
            32
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.SLH_DSA_256S),
            64
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.ML_KEM_512),
            800
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.ML_KEM_768),
            1184
        );
        assertEq(
            verifier.getExpectedKeySize(IPQCVerifier.PQCAlgorithm.ML_KEM_1024),
            1568
        );
    }

    function test_ExpectedSignatureSizes() public view {
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.ML_DSA_44
            ),
            2420
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.ML_DSA_65
            ),
            3293
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.ML_DSA_87
            ),
            4595
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.FN_DSA_512
            ),
            690
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.FN_DSA_1024
            ),
            1280
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.SLH_DSA_128S
            ),
            7856
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.SLH_DSA_128F
            ),
            17088
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.SLH_DSA_256S
            ),
            29792
        );
        // KEM algorithms return 0 for signature size
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.ML_KEM_512
            ),
            0
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.ML_KEM_768
            ),
            0
        );
        assertEq(
            verifier.getExpectedSignatureSize(
                IPQCVerifier.PQCAlgorithm.ML_KEM_1024
            ),
            0
        );
    }

    /*//////////////////////////////////////////////////////////////
                         SECURITY LEVELS
    //////////////////////////////////////////////////////////////*/

    function test_SecurityLevels() public {
        // Level 1 algorithms
        _registerAndCheckLevel(
            user1,
            IPQCVerifier.PQCAlgorithm.ML_DSA_44,
            ML_DSA_44_PK_SIZE,
            IPQCVerifier.SecurityLevel.LEVEL_1
        );
    }

    function test_SecurityLevel3() public {
        _registerAndCheckLevel(
            user1,
            IPQCVerifier.PQCAlgorithm.ML_DSA_65,
            ML_DSA_65_PK_SIZE,
            IPQCVerifier.SecurityLevel.LEVEL_3
        );
    }

    /*//////////////////////////////////////////////////////////////
                        EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_InvalidECDSASignatureLength() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test");
        bytes memory invalidSig = hex"aabbccdd"; // Too short

        bool result = verifier.verifyHybrid(
            messageHash,
            invalidSig,
            "",
            user1,
            IPQCVerifier.VerificationMode.CLASSICAL_ONLY
        );

        assertFalse(result);
    }

    function test_WrongPQCSignatureSize() public {
        _registerFalconKey(user1);

        bytes32 messageHash = keccak256("test");
        bytes memory classicalSig = _signMessage(messageHash, user1Key);
        bytes memory wrongSizePqcSig = _generateKey(100); // Wrong size

        bool result = verifier.verifyHybrid(
            messageHash,
            classicalSig,
            wrongSizePqcSig,
            user1,
            IPQCVerifier.VerificationMode.HYBRID
        );

        assertFalse(result); // PQC validation rejects wrong sig size
    }

    function test_NoKeyRegistered_PQCMode() public {
        bytes32 messageHash = keccak256("test");

        bool result = verifier.verifyHybrid(
            messageHash,
            "",
            _generateKey(FN_DSA_512_SIG_SIZE),
            user1,
            IPQCVerifier.VerificationMode.PQC_ONLY
        );

        assertFalse(result); // No PQC key registered
    }

    /*//////////////////////////////////////////////////////////////
                       FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_RegisterAnyAlgoKey(uint8 algoIndex) public {
        vm.assume(algoIndex <= 10); // Valid PQCAlgorithm range

        IPQCVerifier.PQCAlgorithm algo = IPQCVerifier.PQCAlgorithm(algoIndex);
        uint256 keySize = verifier.getExpectedKeySize(algo);
        bytes memory keyData = _generateKey(keySize);

        vm.prank(user1);
        verifier.registerPQCKey(keyData, algo);

        assertTrue(verifier.hasValidPQCKey(user1));
    }

    function testFuzz_RejectWrongKeySize(uint256 wrongSize) public {
        vm.assume(
            wrongSize != FN_DSA_512_PK_SIZE &&
                wrongSize > 0 &&
                wrongSize < 10000
        );

        bytes memory keyData = _generateKey(wrongSize);

        vm.prank(user1);
        vm.expectRevert();
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);
    }

    /*//////////////////////////////////////////////////////////////
                      HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _registerFalconKey(address user) internal {
        bytes memory keyData = _generateKey(FN_DSA_512_PK_SIZE);
        vm.prank(user);
        verifier.registerPQCKey(keyData, IPQCVerifier.PQCAlgorithm.FN_DSA_512);
    }

    function _registerAndCheckLevel(
        address user,
        IPQCVerifier.PQCAlgorithm algo,
        uint256 keySize,
        IPQCVerifier.SecurityLevel expectedLevel
    ) internal {
        bytes memory keyData = _generateKey(keySize);
        vm.prank(user);
        verifier.registerPQCKey(keyData, algo);

        IPQCVerifier.PQCPublicKey memory key = verifier.getPQCKey(user);
        assertEq(uint8(key.level), uint8(expectedLevel));
    }

    function _generateKey(uint256 size) internal pure returns (bytes memory) {
        bytes memory key = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            key[i] = bytes1(uint8(i % 256));
        }
        return key;
    }

    function _signMessage(
        bytes32 messageHash,
        uint256 privateKey
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function _submitOracleResult(
        bytes32 messageHash,
        bytes memory pqcSig,
        address signer,
        IPQCVerifier.PQCAlgorithm algorithm
    ) internal {
        bytes32 resultHash = keccak256(
            abi.encodePacked(
                HYBRID_SIG_DOMAIN,
                messageHash,
                keccak256(pqcSig),
                signer,
                algorithm
            )
        );

        vm.prank(oracle);
        verifier.submitPQCResult(resultHash);
    }
}
