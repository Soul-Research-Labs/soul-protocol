// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/verifiers/adapters/RingSignatureHonkBridge.sol";

/**
 * @title MockHonkVerifier
 * @notice Mock UltraHonk verifier for testing the RingSignatureHonkBridge
 */
contract MockHonkVerifier {
    bool public shouldVerify = true;
    bytes32[] public lastPublicInputs;
    bytes public lastProof;

    function setVerifyResult(bool _result) external {
        shouldVerify = _result;
    }

    function verify(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external view returns (bool) {
        return shouldVerify;
    }

    function verifyAndCapture(
        bytes calldata _proof,
        bytes32[] calldata _publicInputs
    ) external returns (bool) {
        lastProof = _proof;
        delete lastPublicInputs;
        for (uint256 i = 0; i < _publicInputs.length; i++) {
            lastPublicInputs.push(_publicInputs[i]);
        }
        return shouldVerify;
    }
}

/**
 * @title RingSignatureHonkBridgeTest
 * @notice Tests for the RingSignatureHonkBridge adapter
 */
contract RingSignatureHonkBridgeTest is Test {
    RingSignatureHonkBridge public bridge;
    MockHonkVerifier public mockVerifier;

    function setUp() public {
        mockVerifier = new MockHonkVerifier();
        bridge = new RingSignatureHonkBridge(address(mockVerifier));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Constructor tests
    // ═══════════════════════════════════════════════════════════════════════

    function test_constructor_setsVerifier() public view {
        assertEq(
            address(bridge.honkVerifier()),
            address(mockVerifier),
            "Verifier address mismatch"
        );
    }

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert(RingSignatureHonkBridge.ZeroVerifierAddress.selector);
        new RingSignatureHonkBridge(address(0));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Constants
    // ═══════════════════════════════════════════════════════════════════════

    function test_constants() public view {
        assertEq(bridge.MAX_RING_SIZE(), 16);
        assertEq(bridge.MAX_KEY_IMAGES(), 16);
        assertEq(bridge.PUBLIC_INPUT_COUNT(), 36);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Successful verification
    // ═══════════════════════════════════════════════════════════════════════

    function test_verify_successWithMinRing() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = bytes32(uint256(0x1111));
        ring[1] = bytes32(uint256(0x2222));

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(0xAAAA));

        bytes memory proof = hex"deadbeef";
        bytes32 commitmentRoot = bytes32(uint256(0xBBBB));
        bytes memory signature = abi.encode(proof, commitmentRoot);

        bytes32 message = bytes32(uint256(0xCCCC));

        mockVerifier.setVerifyResult(true);

        bool result = bridge.verify(ring, keyImages, signature, message);
        assertTrue(result, "Verification should succeed");
    }

    function test_verify_successWithMaxRing() public {
        bytes32[] memory ring = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            ring[i] = bytes32(uint256(i + 1));
        }

        bytes32[] memory keyImages = new bytes32[](16);
        for (uint256 i = 0; i < 16; i++) {
            keyImages[i] = bytes32(uint256(0x1000 + i));
        }

        bytes memory proof = hex"cafe";
        bytes32 commitmentRoot = bytes32(uint256(0xDEAD));
        bytes memory signature = abi.encode(proof, commitmentRoot);

        bytes32 message = bytes32(uint256(0xFACE));

        mockVerifier.setVerifyResult(true);

        bool result = bridge.verify(ring, keyImages, signature, message);
        assertTrue(result, "Max ring verification should succeed");
    }

    function test_verify_returnsFalseWhenHonkFails() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = bytes32(uint256(1));
        ring[1] = bytes32(uint256(2));

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(3));

        bytes memory proof = hex"bad0";
        bytes32 commitmentRoot = bytes32(uint256(4));
        bytes memory signature = abi.encode(proof, commitmentRoot);

        mockVerifier.setVerifyResult(false);

        bool result = bridge.verify(
            ring,
            keyImages,
            signature,
            bytes32(uint256(5))
        );
        assertFalse(result, "Should return false when Honk verifier rejects");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Input validation
    // ═══════════════════════════════════════════════════════════════════════

    function test_verify_revertsOnEmptyRing() public {
        bytes32[] memory ring = new bytes32[](0);
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(1));

        bytes memory sig = abi.encode(hex"dead", bytes32(uint256(1)));

        vm.expectRevert(RingSignatureHonkBridge.EmptyRing.selector);
        bridge.verify(ring, keyImages, sig, bytes32(uint256(1)));
    }

    function test_verify_revertsOnRingTooLarge() public {
        bytes32[] memory ring = new bytes32[](17);
        for (uint256 i = 0; i < 17; i++) ring[i] = bytes32(uint256(i));

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(1));

        bytes memory sig = abi.encode(hex"dead", bytes32(uint256(1)));

        vm.expectRevert(
            abi.encodeWithSelector(
                RingSignatureHonkBridge.RingSizeTooLarge.selector,
                17,
                16
            )
        );
        bridge.verify(ring, keyImages, sig, bytes32(uint256(1)));
    }

    function test_verify_revertsOnEmptyKeyImages() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = bytes32(uint256(1));
        ring[1] = bytes32(uint256(2));

        bytes32[] memory keyImages = new bytes32[](0);

        bytes memory sig = abi.encode(hex"dead", bytes32(uint256(1)));

        vm.expectRevert(RingSignatureHonkBridge.EmptyKeyImages.selector);
        bridge.verify(ring, keyImages, sig, bytes32(uint256(1)));
    }

    function test_verify_revertsOnKeyImagesTooLarge() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = bytes32(uint256(1));
        ring[1] = bytes32(uint256(2));

        bytes32[] memory keyImages = new bytes32[](17);
        for (uint256 i = 0; i < 17; i++) keyImages[i] = bytes32(uint256(i));

        bytes memory sig = abi.encode(hex"dead", bytes32(uint256(1)));

        vm.expectRevert(
            abi.encodeWithSelector(
                RingSignatureHonkBridge.KeyImageCountTooLarge.selector,
                17,
                16
            )
        );
        bridge.verify(ring, keyImages, sig, bytes32(uint256(1)));
    }

    function test_verify_revertsOnInvalidSignatureEncoding() public {
        bytes32[] memory ring = new bytes32[](2);
        ring[0] = bytes32(uint256(1));
        ring[1] = bytes32(uint256(2));

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(3));

        // Too short signature
        bytes memory shortSig = hex"0102";

        vm.expectRevert(
            RingSignatureHonkBridge.InvalidSignatureEncoding.selector
        );
        bridge.verify(ring, keyImages, shortSig, bytes32(uint256(4)));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Fuzz tests
    // ═══════════════════════════════════════════════════════════════════════

    function testFuzz_verify_ringSizeBounds(uint8 ringSize) public {
        vm.assume(ringSize > 0 && ringSize <= 16);

        bytes32[] memory ring = new bytes32[](ringSize);
        for (uint256 i = 0; i < ringSize; i++) {
            ring[i] = bytes32(uint256(i + 1));
        }

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(0xABCD));

        bytes memory proof = hex"aabb";
        bytes32 commitmentRoot = bytes32(uint256(0xDEAD));
        bytes memory signature = abi.encode(proof, commitmentRoot);

        mockVerifier.setVerifyResult(true);

        bool result = bridge.verify(
            ring,
            keyImages,
            signature,
            bytes32(uint256(0xFFFF))
        );
        assertTrue(result, "Valid ring sizes should verify");
    }

    function testFuzz_verify_rejectsOversizedRing(uint256 ringSize) public {
        ringSize = bound(ringSize, 17, 100);

        bytes32[] memory ring = new bytes32[](ringSize);
        for (uint256 i = 0; i < ringSize; i++) {
            ring[i] = bytes32(uint256(i + 1));
        }

        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = bytes32(uint256(1));

        bytes memory sig = abi.encode(hex"dead", bytes32(uint256(1)));

        vm.expectRevert(
            abi.encodeWithSelector(
                RingSignatureHonkBridge.RingSizeTooLarge.selector,
                ringSize,
                16
            )
        );
        bridge.verify(ring, keyImages, sig, bytes32(uint256(1)));
    }
}
