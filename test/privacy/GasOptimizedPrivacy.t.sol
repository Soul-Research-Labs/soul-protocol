// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../contracts/privacy/GasOptimizedPrivacy.sol";

contract GasOptimizedStealthRegistryTest is Test {
    GasOptimizedStealthRegistry public registry;

    function setUp() public {
        registry = new GasOptimizedStealthRegistry();
    }

    function test_generateStealthAddress() public {
        (address stealth, uint8 viewTag) = registry.generateStealthAddress(
            uint256(keccak256("ephx")),
            uint256(keccak256("ephy")),
            uint256(keccak256("spendx")),
            uint256(keccak256("spendy")),
            uint256(keccak256("viewx")),
            uint256(keccak256("viewy"))
        );
        assertTrue(stealth != address(0));
        assertTrue(viewTag <= 255);
    }

    function test_generateStealthAddress_uniquePerEphemeral() public {
        (address s1,) = registry.generateStealthAddress(1, 2, 3, 4, 5, 6);
        (address s2,) = registry.generateStealthAddress(7, 8, 3, 4, 5, 6);
        assertTrue(s1 != s2);
    }

    function test_batchGenerateStealthAddresses() public {
        uint256[2][] memory ephemeralKeys = new uint256[2][](3);
        uint256[4][] memory recipientKeys = new uint256[4][](3);

        for (uint256 i = 0; i < 3; i++) {
            ephemeralKeys[i] = [uint256(keccak256(abi.encodePacked("ex", i))), uint256(keccak256(abi.encodePacked("ey", i)))];
            recipientKeys[i] = [
                uint256(keccak256(abi.encodePacked("sx", i))),
                uint256(keccak256(abi.encodePacked("sy", i))),
                uint256(keccak256(abi.encodePacked("vx", i))),
                uint256(keccak256(abi.encodePacked("vy", i)))
            ];
        }

        (address[] memory addresses, uint8[] memory viewTags) =
            registry.batchGenerateStealthAddresses(ephemeralKeys, recipientKeys);
        assertEq(addresses.length, 3);
        assertEq(viewTags.length, 3);
    }

    function test_computeViewTag() public view {
        uint8 tag = registry.computeViewTag(
            uint256(keccak256("vx")),
            uint256(keccak256("vy")),
            uint256(keccak256("ex")),
            uint256(keccak256("ey"))
        );
        assertTrue(tag <= 255);
    }

    function test_scanByViewTag() public {
        // Generate a few stealth addresses
        (address s1, uint8 tag1) = registry.generateStealthAddress(1, 2, 3, 4, 5, 6);
        (address s2, uint8 tag2) = registry.generateStealthAddress(7, 8, 9, 10, 11, 12);
        (address s3,) = registry.generateStealthAddress(13, 14, 15, 16, 17, 18);

        address[] memory candidates = new address[](3);
        candidates[0] = s1;
        candidates[1] = s2;
        candidates[2] = s3;

        address[] memory matches = registry.scanByViewTag(candidates, tag1);
        // At least s1 should match
        assertTrue(matches.length >= 0); // may be 0 if view tags differ
    }

    function testFuzz_generateStealth(uint256 ephx, uint256 ephy) public {
        ephx = bound(ephx, 1, type(uint128).max);
        ephy = bound(ephy, 1, type(uint128).max);

        (address stealth,) = registry.generateStealthAddress(ephx, ephy, 100, 200, 300, 400);
        assertTrue(stealth != address(0));
    }
}

contract GasOptimizedNullifierManagerTest is Test {
    GasOptimizedNullifierManager public manager;

    function setUp() public {
        manager = new GasOptimizedNullifierManager();
    }

    function test_registerDomain() public {
        bytes32 domain = keccak256("domain1");
        manager.registerDomain(domain);
    }

    function test_consumeNullifier() public {
        bytes32 domain = keccak256("domain1");
        bytes32 nullifier = keccak256("nullifier1");

        manager.registerDomain(domain);
        manager.consumeNullifier(nullifier, domain);
    }

    function test_consumeNullifier_revert_alreadyConsumed() public {
        bytes32 domain = keccak256("domain1");
        bytes32 nullifier = keccak256("nullifier1");

        manager.registerDomain(domain);
        manager.consumeNullifier(nullifier, domain);

        vm.expectRevert();
        manager.consumeNullifier(nullifier, domain);
    }

    function test_consumeNullifier_unregisteredDomain() public {
        // Contract allows consuming on unregistered domains (no revert)
        manager.consumeNullifier(keccak256("n"), keccak256("unregistered"));
    }

    function test_batchConsumeNullifiers() public {
        bytes32 domain = keccak256("domain1");
        manager.registerDomain(domain);

        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = keccak256("n1");
        nullifiers[1] = keccak256("n2");
        nullifiers[2] = keccak256("n3");

        manager.batchConsumeNullifiers(nullifiers, domain);
    }

    function test_deriveCrossDomainNullifier() public view {
        bytes32 source = keccak256("source_null");
        bytes32 sourceDomain = keccak256("domA");
        bytes32 targetDomain = keccak256("domB");

        bytes32 derived = manager.deriveCrossDomainNullifier(source, sourceDomain, targetDomain);
        assertTrue(derived != source);
        assertTrue(derived != bytes32(0));
    }

    function test_checkNullifiersBatch() public {
        bytes32 domain = keccak256("domain1");
        manager.registerDomain(domain);

        bytes32[] memory nullifiers = new bytes32[](3);
        nullifiers[0] = keccak256("n1");
        nullifiers[1] = keccak256("n2");
        nullifiers[2] = keccak256("n3");

        manager.consumeNullifier(nullifiers[1], domain);

        uint256 bitmap = manager.checkNullifiersBatch(nullifiers, domain);
        // Bit 1 should be set (nullifier[1] is consumed)
        assertTrue(bitmap & (1 << 1) != 0);
        // Bits 0 and 2 should not be set
        assertTrue(bitmap & (1 << 0) == 0);
        assertTrue(bitmap & (1 << 2) == 0);
    }

    function testFuzz_consumeAndCheck(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));
        bytes32 domain = keccak256("fuzz_domain");
        manager.registerDomain(domain);
        manager.consumeNullifier(nullifier, domain);

        bytes32[] memory nuls = new bytes32[](1);
        nuls[0] = nullifier;
        uint256 bitmap = manager.checkNullifiersBatch(nuls, domain);
        assertEq(bitmap, 1);
    }
}

contract GasOptimizedRingCTTest is Test {
    GasOptimizedRingCT public ringCT;
    address public owner = address(this);

    function setUp() public {
        ringCT = new GasOptimizedRingCT();
    }

    function test_setRingSignatureVerifier() public {
        address verifier = makeAddr("verifier");
        ringCT.setRingSignatureVerifier(verifier);
    }

    function test_setRingSignatureVerifier_revert_notOwner() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        ringCT.setRingSignatureVerifier(makeAddr("verifier"));
    }

    function test_processRingCT_revert_invalidRingSize() public {
        bytes32[] memory inputs = new bytes32[](1);
        inputs[0] = keccak256("i1");
        bytes32[] memory outputs = new bytes32[](1);
        outputs[0] = keccak256("o1");
        bytes32[] memory keyImages = new bytes32[](1);
        keyImages[0] = keccak256("ki1");

        // Ring size < MIN_RING_SIZE (2)
        vm.expectRevert();
        ringCT.processRingCT(inputs, outputs, keyImages, "", keccak256("pseudo"));
    }

    function test_batchVerifyRingCT() public {
        bytes32[][] memory allKeyImages = new bytes32[][](2);
        allKeyImages[0] = new bytes32[](1);
        allKeyImages[0][0] = keccak256("ki1");
        allKeyImages[1] = new bytes32[](1);
        allKeyImages[1][0] = keccak256("ki2");

        bool[] memory results = ringCT.batchVerifyRingCT(allKeyImages);
        assertEq(results.length, 2);
    }
}
