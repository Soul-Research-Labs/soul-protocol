// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/celestia/CelestiaPrimitives.sol";
import "../../contracts/crosschain/CelestiaBridgeAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title CelestiaFuzz
 * @notice Comprehensive fuzz tests for Celestia primitives and bridge adapter
 * @dev Tests NMT, DAS, blob operations, validator management, and cross-chain nullifiers
 */
contract CelestiaFuzz is Test {
    CelestiaBridgeAdapter public adapter;

    address public owner = address(this);
    address public emergencyCouncil = address(0x911);
    address public validator1 = address(0x1);
    address public validator2 = address(0x2);
    address public validator3 = address(0x3);
    address public user = address(0x4);

    bytes public blsKey1;
    bytes public blsKey2;
    bytes public blsKey3;

    function setUp() public {
        // Deploy implementation
        CelestiaBridgeAdapter implementation = new CelestiaBridgeAdapter();

        // Deploy proxy with initialization
        bytes memory initData = abi.encodeWithSelector(
            CelestiaBridgeAdapter.initialize.selector,
            owner,
            emergencyCouncil,
            "celestia"
        );
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );
        adapter = CelestiaBridgeAdapter(payable(address(proxy)));

        // Initialize BLS keys (96 bytes each)
        blsKey1 = new bytes(96);
        blsKey2 = new bytes(96);
        blsKey3 = new bytes(96);

        for (uint256 i = 0; i < 96; i++) {
            blsKey1[i] = bytes1(uint8(i + 1));
            blsKey2[i] = bytes1(uint8(i + 2));
            blsKey3[i] = bytes1(uint8(i + 3));
        }

        // Fund the adapter for withdrawals
        vm.deal(address(adapter), 1000 ether);
    }

    // =========================================================================
    // HASH FUNCTION TESTS
    // =========================================================================

    function testFuzz_sha256HashDeterminism(bytes memory data) public pure {
        bytes32 hash1 = CelestiaPrimitives.sha256Hash(data);
        bytes32 hash2 = CelestiaPrimitives.sha256Hash(data);
        assertEq(hash1, hash2, "SHA256 hash should be deterministic");
    }

    function testFuzz_sha256HashUniqueness(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));

        bytes32 hash1 = CelestiaPrimitives.sha256Hash(data1);
        bytes32 hash2 = CelestiaPrimitives.sha256Hash(data2);
        assertNotEq(
            hash1,
            hash2,
            "Different data should have different hashes"
        );
    }

    function testFuzz_hashNodeDeterminism(
        bytes32 left,
        bytes32 right
    ) public pure {
        bytes32 hash1 = CelestiaPrimitives.hashNode(left, right);
        bytes32 hash2 = CelestiaPrimitives.hashNode(left, right);
        assertEq(hash1, hash2, "Node hash should be deterministic");
    }

    function testFuzz_hashNodeNonCommutative(
        bytes32 left,
        bytes32 right
    ) public pure {
        vm.assume(left != right);

        bytes32 hash1 = CelestiaPrimitives.hashNode(left, right);
        bytes32 hash2 = CelestiaPrimitives.hashNode(right, left);
        assertNotEq(hash1, hash2, "Node hash should not be commutative");
    }

    function testFuzz_hashLeafDeterminism(
        uint8 version,
        bytes28 id,
        bytes memory data
    ) public pure {
        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: version,
            id: id
        });

        bytes32 hash1 = CelestiaPrimitives.hashLeaf(ns, data);
        bytes32 hash2 = CelestiaPrimitives.hashLeaf(ns, data);
        assertEq(hash1, hash2, "Leaf hash should be deterministic");
    }

    function testFuzz_hashLeafDifferentNamespaces(
        bytes28 id1,
        bytes28 id2,
        bytes memory data
    ) public pure {
        vm.assume(id1 != id2);

        CelestiaPrimitives.Namespace memory ns1 = CelestiaPrimitives.Namespace({
            version: 0,
            id: id1
        });
        CelestiaPrimitives.Namespace memory ns2 = CelestiaPrimitives.Namespace({
            version: 0,
            id: id2
        });

        bytes32 hash1 = CelestiaPrimitives.hashLeaf(ns1, data);
        bytes32 hash2 = CelestiaPrimitives.hashLeaf(ns2, data);
        assertNotEq(
            hash1,
            hash2,
            "Different namespaces should produce different hashes"
        );
    }

    // =========================================================================
    // NAMESPACE TESTS
    // =========================================================================

    function testFuzz_createNamespace(uint8 version, bytes28 id) public pure {
        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives
            .createNamespace(version, id);
        assertEq(ns.version, version);
        assertEq(ns.id, id);
    }

    function testFuzz_createV0Namespace(bytes28 id) public pure {
        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives
            .createV0Namespace(id);
        assertEq(ns.version, 0);
        assertEq(ns.id, id);
    }

    function testFuzz_compareNamespacesSameVersion(
        bytes28 id1,
        bytes28 id2
    ) public pure {
        CelestiaPrimitives.Namespace memory ns1 = CelestiaPrimitives.Namespace({
            version: 0,
            id: id1
        });
        CelestiaPrimitives.Namespace memory ns2 = CelestiaPrimitives.Namespace({
            version: 0,
            id: id2
        });

        int8 result = CelestiaPrimitives.compareNamespaces(ns1, ns2);

        if (id1 < id2) {
            assertEq(result, -1, "Should return -1 when id1 < id2");
        } else if (id1 > id2) {
            assertEq(result, 1, "Should return 1 when id1 > id2");
        } else {
            assertEq(result, 0, "Should return 0 when equal");
        }
    }

    function testFuzz_compareNamespacesDifferentVersion(
        uint8 v1,
        uint8 v2,
        bytes28 id
    ) public pure {
        vm.assume(v1 != v2);

        CelestiaPrimitives.Namespace memory ns1 = CelestiaPrimitives.Namespace({
            version: v1,
            id: id
        });
        CelestiaPrimitives.Namespace memory ns2 = CelestiaPrimitives.Namespace({
            version: v2,
            id: id
        });

        int8 result = CelestiaPrimitives.compareNamespaces(ns1, ns2);

        if (v1 < v2) {
            assertEq(result, -1, "Should return -1 when v1 < v2");
        } else {
            assertEq(result, 1, "Should return 1 when v1 > v2");
        }
    }

    function testFuzz_isNamespaceInRange(
        uint8 version,
        bytes28 id,
        bytes28 minId,
        bytes28 maxId
    ) public pure {
        vm.assume(minId <= maxId);

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: version,
            id: id
        });
        CelestiaPrimitives.Namespace memory min = CelestiaPrimitives.Namespace({
            version: version,
            id: minId
        });
        CelestiaPrimitives.Namespace memory max = CelestiaPrimitives.Namespace({
            version: version,
            id: maxId
        });

        bool inRange = CelestiaPrimitives.isNamespaceInRange(ns, min, max);

        if (id >= minId && id <= maxId) {
            assertTrue(inRange, "Should be in range");
        } else {
            assertFalse(inRange, "Should not be in range");
        }
    }

    function testFuzz_encodeDecodeNamespace(
        uint8 version,
        bytes28 id
    ) public pure {
        CelestiaPrimitives.Namespace memory original = CelestiaPrimitives
            .Namespace({version: version, id: id});

        bytes memory encoded = CelestiaPrimitives.encodeNamespace(original);
        assertEq(encoded.length, 29, "Encoded namespace should be 29 bytes");
    }

    // =========================================================================
    // BLOB TESTS
    // =========================================================================

    function testFuzz_createBlobSmall(
        uint8 version,
        bytes28 id,
        bytes memory data
    ) public pure {
        vm.assume(data.length <= CelestiaPrimitives.MAX_BLOB_SIZE);
        vm.assume(data.length < 10000); // Limit for gas

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: version,
            id: id
        });

        CelestiaPrimitives.Blob memory blob = CelestiaPrimitives.createBlob(
            ns,
            data
        );

        assertEq(blob.namespace.version, version);
        assertEq(blob.namespace.id, id);
        assertEq(blob.shareVersion, 0);
        assertTrue(blob.commitment != bytes32(0));
    }

    function testFuzz_computeBlobCommitmentDeterminism(
        uint8 version,
        bytes28 id,
        bytes memory data
    ) public pure {
        vm.assume(data.length <= 1000);

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: version,
            id: id
        });

        CelestiaPrimitives.Blob memory blob1 = CelestiaPrimitives.Blob({
            namespace: ns,
            data: data,
            shareVersion: 0,
            commitment: bytes32(0)
        });
        CelestiaPrimitives.Blob memory blob2 = CelestiaPrimitives.Blob({
            namespace: ns,
            data: data,
            shareVersion: 0,
            commitment: bytes32(0)
        });

        bytes32 commitment1 = CelestiaPrimitives.computeBlobCommitment(blob1);
        bytes32 commitment2 = CelestiaPrimitives.computeBlobCommitment(blob2);

        assertEq(
            commitment1,
            commitment2,
            "Blob commitment should be deterministic"
        );
    }

    function testFuzz_calculateShareCount(uint256 dataSize) public pure {
        vm.assume(dataSize <= CelestiaPrimitives.MAX_BLOB_SIZE);
        vm.assume(dataSize > 0);

        uint256 shareCount = CelestiaPrimitives.calculateShareCount(dataSize);
        assertTrue(shareCount > 0, "Share count should be positive");

        // Verify shares can hold the data
        uint256 dataPerShare = CelestiaPrimitives.SHARE_SIZE - 2;
        assertTrue(
            shareCount * dataPerShare >= dataSize,
            "Shares should hold all data"
        );
    }

    // =========================================================================
    // MERKLE TREE TESTS
    // =========================================================================

    function testFuzz_computeMerkleRootSingleLeaf(bytes32 leaf) public pure {
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = leaf;

        bytes32 root = CelestiaPrimitives.computeMerkleRoot(leaves);
        assertEq(root, leaf, "Single leaf should be root");
    }

    function testFuzz_computeMerkleRootTwoLeaves(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        bytes32[] memory leaves = new bytes32[](2);
        leaves[0] = leaf1;
        leaves[1] = leaf2;

        bytes32 root = CelestiaPrimitives.computeMerkleRoot(leaves);
        bytes32 expected = CelestiaPrimitives.hashNode(leaf1, leaf2);

        assertEq(root, expected, "Root should be hash of two leaves");
    }

    function testFuzz_computeMerkleRootDeterminism(
        bytes32 leaf1,
        bytes32 leaf2,
        bytes32 leaf3,
        bytes32 leaf4
    ) public pure {
        bytes32[] memory leaves1 = new bytes32[](4);
        leaves1[0] = leaf1;
        leaves1[1] = leaf2;
        leaves1[2] = leaf3;
        leaves1[3] = leaf4;

        bytes32[] memory leaves2 = new bytes32[](4);
        leaves2[0] = leaf1;
        leaves2[1] = leaf2;
        leaves2[2] = leaf3;
        leaves2[3] = leaf4;

        bytes32 root1 = CelestiaPrimitives.computeMerkleRoot(leaves1);
        bytes32 root2 = CelestiaPrimitives.computeMerkleRoot(leaves2);

        assertEq(root1, root2, "Merkle root should be deterministic");
    }

    function testFuzz_computeMerkleRootOrderMatters(
        bytes32 leaf1,
        bytes32 leaf2
    ) public pure {
        vm.assume(leaf1 != leaf2);

        bytes32[] memory leaves1 = new bytes32[](2);
        leaves1[0] = leaf1;
        leaves1[1] = leaf2;

        bytes32[] memory leaves2 = new bytes32[](2);
        leaves2[0] = leaf2;
        leaves2[1] = leaf1;

        bytes32 root1 = CelestiaPrimitives.computeMerkleRoot(leaves1);
        bytes32 root2 = CelestiaPrimitives.computeMerkleRoot(leaves2);

        assertNotEq(
            root1,
            root2,
            "Different order should produce different root"
        );
    }

    // =========================================================================
    // QUORUM TESTS
    // =========================================================================

    function testFuzz_hasQuorumCalculation(
        uint256 signingPower,
        uint256 totalPower
    ) public pure {
        vm.assume(totalPower > 0);
        vm.assume(totalPower < type(uint256).max / 10000);
        vm.assume(signingPower <= totalPower);

        bool hasQuorum = CelestiaPrimitives.hasQuorum(signingPower, totalPower);

        // 66.67% threshold
        bool expected = signingPower * 10000 >= totalPower * 6667;
        assertEq(hasQuorum, expected, "Quorum calculation mismatch");
    }

    function testFuzz_hasQuorumZeroTotal(uint256 signingPower) public pure {
        bool hasQuorum = CelestiaPrimitives.hasQuorum(signingPower, 0);
        assertFalse(hasQuorum, "Zero total should not have quorum");
    }

    function testFuzz_hasQuorumExactThreshold(uint256 totalPower) public pure {
        vm.assume(totalPower > 0);
        vm.assume(totalPower < type(uint256).max / 10000);

        // Calculate exact threshold (ceiling)
        uint256 threshold = (totalPower * 6667 + 9999) / 10000;
        bool hasQuorum = CelestiaPrimitives.hasQuorum(threshold, totalPower);
        assertTrue(hasQuorum, "Exact threshold should have quorum");
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    function testFuzz_computeCelestiaNullifier(
        bytes32 commitment,
        uint64 height,
        uint8 version,
        bytes28 id
    ) public pure {
        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: version,
            id: id
        });

        bytes32 nullifier1 = CelestiaPrimitives.computeCelestiaNullifier(
            commitment,
            height,
            ns
        );
        bytes32 nullifier2 = CelestiaPrimitives.computeCelestiaNullifier(
            commitment,
            height,
            ns
        );

        assertEq(nullifier1, nullifier2, "Nullifier should be deterministic");
    }

    function testFuzz_computeCelestiaNullifierUniqueness(
        bytes32 commitment1,
        bytes32 commitment2,
        uint64 height
    ) public pure {
        vm.assume(commitment1 != commitment2);

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: 0,
            id: bytes28(0)
        });

        bytes32 nullifier1 = CelestiaPrimitives.computeCelestiaNullifier(
            commitment1,
            height,
            ns
        );
        bytes32 nullifier2 = CelestiaPrimitives.computeCelestiaNullifier(
            commitment2,
            height,
            ns
        );

        assertNotEq(
            nullifier1,
            nullifier2,
            "Different commitments should produce different nullifiers"
        );
    }

    function testFuzz_computeCrossChainNullifier(
        bytes32 celestiaNullifier,
        bytes32 pilDomain
    ) public pure {
        bytes32 crossChain1 = CelestiaPrimitives.computeCrossChainNullifier(
            celestiaNullifier,
            pilDomain
        );
        bytes32 crossChain2 = CelestiaPrimitives.computeCrossChainNullifier(
            celestiaNullifier,
            pilDomain
        );

        assertEq(
            crossChain1,
            crossChain2,
            "Cross-chain nullifier should be deterministic"
        );
    }

    function testFuzz_bindNullifier(
        bytes32 celestiaCommitment,
        bytes32 pilNullifier,
        bytes32 domainSeparator,
        uint64 height
    ) public pure {
        CelestiaPrimitives.CelestiaNullifierBinding
            memory binding = CelestiaPrimitives.bindNullifier(
                celestiaCommitment,
                pilNullifier,
                domainSeparator,
                height
            );

        assertEq(binding.celestiaCommitment, celestiaCommitment);
        assertEq(binding.pilNullifier, pilNullifier);
        assertEq(binding.domainSeparator, domainSeparator);
        assertEq(binding.height, height);
    }

    // =========================================================================
    // HEADER TESTS
    // =========================================================================

    function testFuzz_computeHeaderHashDeterminism(
        uint64 height,
        uint64 timestamp,
        bytes32 dataHash
    ) public pure {
        vm.assume(height > 0);
        vm.assume(dataHash != bytes32(0));

        CelestiaPrimitives.CelestiaHeader memory header = CelestiaPrimitives
            .CelestiaHeader({
                height: height,
                timestamp: timestamp,
                lastBlockId: bytes32(0),
                dataHash: dataHash,
                validatorsHash: bytes32(uint256(1)),
                nextValidatorsHash: bytes32(0),
                consensusHash: bytes32(0),
                appHash: bytes32(0),
                lastResultsHash: bytes32(0),
                evidenceHash: bytes32(0),
                proposerAddress: ""
            });

        bytes32 hash1 = CelestiaPrimitives.computeHeaderHash(header);
        bytes32 hash2 = CelestiaPrimitives.computeHeaderHash(header);

        assertEq(hash1, hash2, "Header hash should be deterministic");
    }

    function testFuzz_isValidHeader(
        uint64 height,
        bytes32 dataHash,
        bytes32 validatorsHash
    ) public pure {
        CelestiaPrimitives.CelestiaHeader memory header = CelestiaPrimitives
            .CelestiaHeader({
                height: height,
                timestamp: 0,
                lastBlockId: bytes32(0),
                dataHash: dataHash,
                validatorsHash: validatorsHash,
                nextValidatorsHash: bytes32(0),
                consensusHash: bytes32(0),
                appHash: bytes32(0),
                lastResultsHash: bytes32(0),
                evidenceHash: bytes32(0),
                proposerAddress: ""
            });

        bool valid = CelestiaPrimitives.isValidHeader(header);

        if (
            height == 0 ||
            dataHash == bytes32(0) ||
            validatorsHash == bytes32(0)
        ) {
            assertFalse(valid, "Invalid header should return false");
        } else {
            assertTrue(valid, "Valid header should return true");
        }
    }

    // =========================================================================
    // SQUARE SIZE TESTS
    // =========================================================================

    function testFuzz_isValidSquareSize(uint64 size) public pure {
        bool valid = CelestiaPrimitives.isValidSquareSize(size);

        if (size < 1 || size > 128) {
            assertFalse(valid, "Out of range should be invalid");
        } else if (size > 0 && (size & (size - 1)) == 0) {
            assertTrue(valid, "Power of 2 in range should be valid");
        } else {
            assertFalse(valid, "Non-power of 2 should be invalid");
        }
    }

    function testFuzz_extendedSquareSize(uint64 originalSize) public pure {
        vm.assume(originalSize <= type(uint64).max / 2);

        uint64 extended = CelestiaPrimitives.extendedSquareSize(originalSize);
        assertEq(extended, originalSize * 2, "Extended should be 2x original");
    }

    // =========================================================================
    // CHAIN ID TESTS
    // =========================================================================

    function test_isValidChainIdMainnet() public pure {
        assertTrue(
            CelestiaPrimitives.isValidChainId("celestia"),
            "Mainnet should be valid"
        );
    }

    function test_isValidChainIdTestnet() public pure {
        assertTrue(
            CelestiaPrimitives.isValidChainId("mocha-4"),
            "Testnet should be valid"
        );
    }

    function test_isValidChainIdDevnet() public pure {
        assertTrue(
            CelestiaPrimitives.isValidChainId("arabica-11"),
            "Devnet should be valid"
        );
    }

    function testFuzz_isValidChainIdInvalid(string memory chainId) public pure {
        bytes32 hash = keccak256(bytes(chainId));
        if (
            hash != keccak256(bytes("celestia")) &&
            hash != keccak256(bytes("mocha-4")) &&
            hash != keccak256(bytes("arabica-11"))
        ) {
            assertFalse(
                CelestiaPrimitives.isValidChainId(chainId),
                "Invalid chain ID should return false"
            );
        }
    }

    // =========================================================================
    // BRIDGE ADAPTER TESTS
    // =========================================================================

    function testFuzz_registerValidator(uint256 power) public {
        vm.assume(power > 0);
        vm.assume(power <= type(uint128).max);

        adapter.registerValidator(validator1, blsKey1, power);

        assertEq(adapter.totalVotingPower(), power);
        assertEq(adapter.getValidatorCount(), 1);
    }

    function testFuzz_registerMultipleValidators(
        uint256 power1,
        uint256 power2
    ) public {
        vm.assume(power1 > 0 && power1 <= type(uint64).max);
        vm.assume(power2 > 0 && power2 <= type(uint64).max);

        adapter.registerValidator(validator1, blsKey1, power1);
        adapter.registerValidator(validator2, blsKey2, power2);

        assertEq(adapter.totalVotingPower(), power1 + power2);
        assertEq(adapter.getValidatorCount(), 2);
    }

    function testFuzz_updateValidatorPower(
        uint256 initialPower,
        uint256 newPower
    ) public {
        vm.assume(initialPower > 0 && initialPower <= type(uint64).max);
        vm.assume(newPower > 0 && newPower <= type(uint64).max);

        adapter.registerValidator(validator1, blsKey1, initialPower);
        adapter.updateValidatorPower(validator1, newPower);

        assertEq(adapter.totalVotingPower(), newPower);
    }

    function testFuzz_removeValidator(uint256 power) public {
        vm.assume(power > 0);
        vm.assume(power <= type(uint128).max);

        adapter.registerValidator(validator1, blsKey1, power);
        adapter.removeValidator(validator1);

        assertEq(adapter.totalVotingPower(), 0);
        assertEq(adapter.getValidatorCount(), 0);
    }

    function testFuzz_deposit(uint256 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= adapter.MAX_TRANSFER());

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: 0,
            id: bytes28(0)
        });

        vm.deal(user, amount);
        vm.prank(user);
        adapter.deposit{value: amount}(ns);
    }

    function testFuzz_depositExceedsMaxReverts(uint256 seed) public {
        // Use bound to ensure amount is in valid range (just above MAX_TRANSFER)
        uint256 maxTransfer = adapter.MAX_TRANSFER();
        uint256 amount = bound(seed, maxTransfer + 1, maxTransfer + 100 ether);

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: 0,
            id: bytes28(0)
        });

        vm.deal(user, amount);
        vm.prank(user);
        vm.expectRevert(CelestiaBridgeAdapter.ExceedsMaxTransfer.selector);
        adapter.deposit{value: amount}(ns);
    }

    function testFuzz_updateRelayerFee(uint256 feeBps) public {
        if (feeBps <= adapter.MAX_RELAYER_FEE_BPS()) {
            adapter.updateRelayerFee(feeBps);
            assertEq(adapter.relayerFeeBps(), feeBps);
        } else {
            vm.expectRevert("Fee too high");
            adapter.updateRelayerFee(feeBps);
        }
    }

    function testFuzz_updateEmergencyCouncil(address newCouncil) public {
        adapter.updateEmergencyCouncil(newCouncil);
        assertEq(adapter.emergencyCouncil(), newCouncil);
    }

    // =========================================================================
    // CIRCUIT BREAKER TESTS
    // =========================================================================

    function test_triggerCircuitBreakerOwner() public {
        adapter.triggerCircuitBreaker("test");
        assertTrue(adapter.circuitBreakerActive());
    }

    function test_triggerCircuitBreakerEmergencyCouncil() public {
        vm.prank(emergencyCouncil);
        adapter.triggerCircuitBreaker("emergency");
        assertTrue(adapter.circuitBreakerActive());
    }

    function test_resetCircuitBreaker() public {
        adapter.triggerCircuitBreaker("test");
        adapter.resetCircuitBreaker();
        assertFalse(adapter.circuitBreakerActive());
    }

    function testFuzz_circuitBreakerBlocksDeposit(uint256 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= adapter.MAX_TRANSFER());

        adapter.triggerCircuitBreaker("test");

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: 0,
            id: bytes28(0)
        });

        vm.deal(user, amount);
        vm.prank(user);
        vm.expectRevert(CelestiaBridgeAdapter.CircuitBreakerActive.selector);
        adapter.deposit{value: amount}(ns);
    }

    // =========================================================================
    // PAUSE TESTS
    // =========================================================================

    function test_pauseAndUnpause() public {
        adapter.pause();
        assertTrue(adapter.paused());

        adapter.unpause();
        assertFalse(adapter.paused());
    }

    function testFuzz_pauseBlocksDeposit(uint256 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= adapter.MAX_TRANSFER());

        adapter.pause();

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: 0,
            id: bytes28(0)
        });

        vm.deal(user, amount);
        vm.prank(user);
        vm.expectRevert();
        adapter.deposit{value: amount}(ns);
    }

    // =========================================================================
    // NULLIFIER CONSUMPTION TESTS
    // =========================================================================

    function testFuzz_consumeNullifier(bytes32 nullifier) public {
        adapter.consumeNullifier(nullifier);
        assertTrue(adapter.isNullifierConsumed(nullifier));
    }

    function testFuzz_doubleConsumeReverts(bytes32 nullifier) public {
        adapter.consumeNullifier(nullifier);

        vm.expectRevert(
            CelestiaBridgeAdapter.NullifierAlreadyConsumed.selector
        );
        adapter.consumeNullifier(nullifier);
    }

    // =========================================================================
    // VALIDATOR SET HASH TESTS
    // =========================================================================

    function testFuzz_computeValidatorSetHashDeterminism(
        uint256 power1,
        uint256 power2
    ) public pure {
        vm.assume(power1 > 0 && power1 <= type(uint64).max);
        vm.assume(power2 > 0 && power2 <= type(uint64).max);

        bytes memory key1 = new bytes(96);
        bytes memory key2 = new bytes(96);

        CelestiaPrimitives.Validator[]
            memory validators = new CelestiaPrimitives.Validator[](2);
        validators[0] = CelestiaPrimitives.Validator({
            pubKey: key1,
            votingPower: power1,
            proposerPriority: ""
        });
        validators[1] = CelestiaPrimitives.Validator({
            pubKey: key2,
            votingPower: power2,
            proposerPriority: ""
        });

        bytes32 hash1 = CelestiaPrimitives.computeValidatorSetHash(validators);
        bytes32 hash2 = CelestiaPrimitives.computeValidatorSetHash(validators);

        assertEq(hash1, hash2, "Validator set hash should be deterministic");
    }

    function testFuzz_calculateTotalPower(
        uint256 power1,
        uint256 power2,
        uint256 power3
    ) public pure {
        vm.assume(power1 <= type(uint64).max);
        vm.assume(power2 <= type(uint64).max);
        vm.assume(power3 <= type(uint64).max);

        CelestiaPrimitives.Validator[]
            memory validators = new CelestiaPrimitives.Validator[](3);
        validators[0] = CelestiaPrimitives.Validator({
            pubKey: "",
            votingPower: power1,
            proposerPriority: ""
        });
        validators[1] = CelestiaPrimitives.Validator({
            pubKey: "",
            votingPower: power2,
            proposerPriority: ""
        });
        validators[2] = CelestiaPrimitives.Validator({
            pubKey: "",
            votingPower: power3,
            proposerPriority: ""
        });

        uint256 total = CelestiaPrimitives.calculateTotalPower(validators);
        assertEq(total, power1 + power2 + power3);
    }

    // =========================================================================
    // DATA AVAILABILITY HEADER TESTS
    // =========================================================================

    function testFuzz_computeDataRoot(
        bytes32 row1,
        bytes32 row2,
        bytes32 col1,
        bytes32 col2
    ) public pure {
        bytes32[] memory rowRoots = new bytes32[](2);
        rowRoots[0] = row1;
        rowRoots[1] = row2;

        bytes32[] memory colRoots = new bytes32[](2);
        colRoots[0] = col1;
        colRoots[1] = col2;

        CelestiaPrimitives.DataAvailabilityHeader
            memory dah = CelestiaPrimitives.DataAvailabilityHeader({
                rowRoots: rowRoots,
                columnRoots: colRoots,
                squareSize: 2
            });

        bytes32 dataRoot = CelestiaPrimitives.computeDataRoot(dah);
        assertTrue(dataRoot != bytes32(0), "Data root should not be zero");
    }

    // =========================================================================
    // DAS COORDINATE TESTS
    // =========================================================================

    function testFuzz_computeSampleCoordinates(
        bytes32 seed,
        uint8 squareSizeExp,
        uint256 sampleIndex
    ) public pure {
        vm.assume(squareSizeExp > 0 && squareSizeExp <= 7);
        uint64 squareSize = uint64(1 << squareSizeExp);

        (uint64 row, uint64 col) = CelestiaPrimitives.computeSampleCoordinates(
            seed,
            squareSize,
            sampleIndex
        );

        assertTrue(row < squareSize, "Row should be within bounds");
        assertTrue(col < squareSize, "Col should be within bounds");
    }

    function testFuzz_computeSampleCoordinatesDeterminism(
        bytes32 seed,
        uint64 squareSize,
        uint256 sampleIndex
    ) public pure {
        vm.assume(squareSize > 0);

        (uint64 row1, uint64 col1) = CelestiaPrimitives
            .computeSampleCoordinates(seed, squareSize, sampleIndex);
        (uint64 row2, uint64 col2) = CelestiaPrimitives
            .computeSampleCoordinates(seed, squareSize, sampleIndex);

        assertEq(row1, row2, "Row should be deterministic");
        assertEq(col1, col2, "Col should be deterministic");
    }

    // =========================================================================
    // CONSTANTS TESTS
    // =========================================================================

    function test_constants() public pure {
        assertEq(CelestiaPrimitives.BLS_SIGNATURE_LENGTH, 48);
        assertEq(CelestiaPrimitives.BLS_PUBKEY_LENGTH, 96);
        assertEq(CelestiaPrimitives.ED25519_SIGNATURE_LENGTH, 64);
        assertEq(CelestiaPrimitives.ED25519_PUBKEY_LENGTH, 32);
        assertEq(CelestiaPrimitives.NAMESPACE_SIZE, 29);
        assertEq(CelestiaPrimitives.SHARE_SIZE, 512);
        assertEq(CelestiaPrimitives.MAX_BLOB_SIZE, 2 * 1024 * 1024);
        assertEq(CelestiaPrimitives.MIN_SQUARE_SIZE, 1);
        assertEq(CelestiaPrimitives.MAX_SQUARE_SIZE, 128);
        assertEq(CelestiaPrimitives.QUORUM_THRESHOLD_BPS, 6667);
    }

    // =========================================================================
    // SIGNING POWER TESTS
    // =========================================================================

    function testFuzz_calculateSigningPowerAllSigned(
        uint8 validatorCount
    ) public pure {
        vm.assume(validatorCount > 0 && validatorCount <= 64);

        CelestiaPrimitives.Validator[]
            memory validators = new CelestiaPrimitives.Validator[](
                validatorCount
            );
        uint256 expectedTotal = 0;

        for (uint256 i = 0; i < validatorCount; i++) {
            validators[i] = CelestiaPrimitives.Validator({
                pubKey: "",
                votingPower: i + 1,
                proposerPriority: ""
            });
            expectedTotal += i + 1;
        }

        // Create bitmap with all bits set
        bytes memory bitmap = new bytes((validatorCount + 7) / 8);
        for (uint256 i = 0; i < bitmap.length; i++) {
            bitmap[i] = bytes1(uint8(0xFF));
        }

        uint256 signingPower = CelestiaPrimitives.calculateSigningPower(
            bitmap,
            validators
        );
        assertEq(
            signingPower,
            expectedTotal,
            "All signed should sum all powers"
        );
    }

    function testFuzz_calculateSigningPowerNoneSigned(
        uint8 validatorCount
    ) public pure {
        vm.assume(validatorCount > 0 && validatorCount <= 64);

        CelestiaPrimitives.Validator[]
            memory validators = new CelestiaPrimitives.Validator[](
                validatorCount
            );
        for (uint256 i = 0; i < validatorCount; i++) {
            validators[i] = CelestiaPrimitives.Validator({
                pubKey: "",
                votingPower: i + 1,
                proposerPriority: ""
            });
        }

        // Empty bitmap
        bytes memory bitmap = new bytes((validatorCount + 7) / 8);

        uint256 signingPower = CelestiaPrimitives.calculateSigningPower(
            bitmap,
            validators
        );
        assertEq(signingPower, 0, "None signed should have zero power");
    }

    // =========================================================================
    // SHARE COMMITMENT TESTS
    // =========================================================================

    function testFuzz_computeShareCommitment(
        uint64 startShare,
        uint64 endShare,
        uint8 version,
        bytes28 id
    ) public pure {
        vm.assume(endShare >= startShare);

        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: version,
            id: id
        });

        CelestiaPrimitives.Blob memory blob = CelestiaPrimitives.Blob({
            namespace: ns,
            data: "",
            shareVersion: 0,
            commitment: bytes32(uint256(1))
        });

        CelestiaPrimitives.ShareCommitment memory sc = CelestiaPrimitives
            .computeShareCommitment(blob, startShare, endShare);

        assertEq(sc.startShare, startShare);
        assertEq(sc.endShare, endShare);
        assertEq(sc.namespace.version, version);
        assertEq(sc.namespace.id, id);
    }

    // =========================================================================
    // DATA COMMITMENT HASH TESTS
    // =========================================================================

    function testFuzz_computeDataCommitmentHash(
        bytes32 dataRoot,
        uint64 startBlock,
        uint64 endBlock,
        uint64 nonce
    ) public pure {
        CelestiaPrimitives.DataCommitment memory commitment = CelestiaPrimitives
            .DataCommitment({
                dataRoot: dataRoot,
                startBlock: startBlock,
                endBlock: endBlock,
                nonce: nonce
            });

        bytes32 hash1 = CelestiaPrimitives.computeDataCommitmentHash(
            commitment
        );
        bytes32 hash2 = CelestiaPrimitives.computeDataCommitmentHash(
            commitment
        );

        assertEq(hash1, hash2, "Data commitment hash should be deterministic");
    }

    // =========================================================================
    // EDGE CASE TESTS
    // =========================================================================

    function test_emptyMerkleRoot() public pure {
        bytes32[] memory leaves = new bytes32[](0);
        bytes32 root = CelestiaPrimitives.computeMerkleRoot(leaves);
        assertEq(root, bytes32(0), "Empty tree should have zero root");
    }

    function test_zeroDepositReverts() public {
        CelestiaPrimitives.Namespace memory ns = CelestiaPrimitives.Namespace({
            version: 0,
            id: bytes28(0)
        });

        vm.expectRevert(CelestiaBridgeAdapter.InsufficientDeposit.selector);
        adapter.deposit{value: 0}(ns);
    }

    function test_invalidBLSKeyLengthReverts() public {
        bytes memory invalidKey = new bytes(95); // Should be 96

        vm.expectRevert(CelestiaBridgeAdapter.InvalidPublicKeyLength.selector);
        adapter.registerValidator(validator1, invalidKey, 1000);
    }

    function test_duplicateValidatorReverts() public {
        adapter.registerValidator(validator1, blsKey1, 1000);

        vm.expectRevert(
            CelestiaBridgeAdapter.ValidatorAlreadyRegistered.selector
        );
        adapter.registerValidator(validator1, blsKey1, 2000);
    }

    function test_zeroVotingPowerReverts() public {
        vm.expectRevert(CelestiaBridgeAdapter.InvalidVotingPower.selector);
        adapter.registerValidator(validator1, blsKey1, 0);
    }

    function test_removeNonExistentValidatorReverts() public {
        vm.expectRevert(CelestiaBridgeAdapter.ValidatorNotRegistered.selector);
        adapter.removeValidator(validator1);
    }
}
