// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {AptosPrimitives} from "../../contracts/aptos/AptosPrimitives.sol";
import {AptosBridgeAdapter} from "../../contracts/crosschain/AptosBridgeAdapter.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title AptosFuzz
 * @notice Comprehensive fuzz tests for Aptos integration
 * @dev Tests primitives, bridge adapter, and security properties
 */
contract AptosFuzz is Test {
    AptosBridgeAdapter public adapter;
    AptosBridgeAdapter public implementation;

    address public owner = address(this);
    address public emergencyCouncil = address(0x911);
    address public validator1 = address(0x1001);
    address public validator2 = address(0x1002);
    address public validator3 = address(0x1003);
    address public user = address(0x2001);

    bytes public blsKey1;
    bytes public blsKey2;
    bytes public blsKey3;
    bytes public ed25519Key1;
    bytes public ed25519Key2;
    bytes public ed25519Key3;

    function setUp() public {
        // Deploy implementation
        implementation = new AptosBridgeAdapter();

        // Deploy proxy
        bytes memory initData = abi.encodeWithSelector(
            AptosBridgeAdapter.initialize.selector,
            emergencyCouncil,
            100 // 1% relayer fee
        );

        ERC1967Proxy proxy = new ERC1967Proxy(
            address(implementation),
            initData
        );

        adapter = AptosBridgeAdapter(payable(address(proxy)));

        // Generate test keys
        blsKey1 = new bytes(96);
        blsKey2 = new bytes(96);
        blsKey3 = new bytes(96);
        ed25519Key1 = new bytes(32);
        ed25519Key2 = new bytes(32);
        ed25519Key3 = new bytes(32);

        for (uint256 i = 0; i < 96; i++) {
            blsKey1[i] = bytes1(uint8(i + 1));
            blsKey2[i] = bytes1(uint8(i + 101));
            blsKey3[i] = bytes1(uint8(i + 201));
        }

        for (uint256 i = 0; i < 32; i++) {
            ed25519Key1[i] = bytes1(uint8(i + 1));
            ed25519Key2[i] = bytes1(uint8(i + 51));
            ed25519Key3[i] = bytes1(uint8(i + 101));
        }

        // Fund test accounts
        vm.deal(user, 100 ether);
        vm.deal(address(adapter), 1000 ether);
    }

    // =========================================================================
    // HASH FUNCTION TESTS
    // =========================================================================

    function testFuzz_sha3HashDeterminism(bytes memory data) public pure {
        bytes32 hash1 = AptosPrimitives.sha3Hash(data);
        bytes32 hash2 = AptosPrimitives.sha3Hash(data);
        assertEq(hash1, hash2, "SHA3 hash should be deterministic");
    }

    function testFuzz_sha3HashUniqueness(
        bytes memory data1,
        bytes memory data2
    ) public pure {
        vm.assume(keccak256(data1) != keccak256(data2));
        bytes32 hash1 = AptosPrimitives.sha3Hash(data1);
        bytes32 hash2 = AptosPrimitives.sha3Hash(data2);
        assertNotEq(
            hash1,
            hash2,
            "Different inputs should produce different hashes"
        );
    }

    function testFuzz_hash2Commutativity(bytes32 a, bytes32 b) public pure {
        // Note: hash2 is NOT commutative by design, verify this
        bytes32 hash1 = AptosPrimitives.hash2(a, b);
        bytes32 hash2 = AptosPrimitives.hash2(b, a);
        if (a != b) {
            assertNotEq(hash1, hash2, "hash2 should not be commutative");
        }
    }

    function testFuzz_hashWithPrefix(
        string memory prefix,
        bytes memory data
    ) public pure {
        bytes32 hash1 = AptosPrimitives.hashWithPrefix(prefix, data);
        bytes32 hash2 = AptosPrimitives.hashWithPrefix(prefix, data);
        assertEq(hash1, hash2, "Prefixed hash should be deterministic");
    }

    function testFuzz_computeBlockHash(
        uint64 epoch,
        uint64 round,
        bytes32 executedStateId,
        uint64 version,
        uint64 timestampUsecs
    ) public pure {
        bytes32 hash1 = AptosPrimitives.computeBlockHash(
            epoch,
            round,
            executedStateId,
            version,
            timestampUsecs
        );
        bytes32 hash2 = AptosPrimitives.computeBlockHash(
            epoch,
            round,
            executedStateId,
            version,
            timestampUsecs
        );
        assertEq(hash1, hash2, "Block hash should be deterministic");
    }

    // =========================================================================
    // NULLIFIER TESTS
    // =========================================================================

    function testFuzz_deriveNullifierDeterminism(
        bytes32 txHash,
        uint64 version
    ) public pure {
        bytes32 nf1 = AptosPrimitives.deriveNullifier(txHash, version);
        bytes32 nf2 = AptosPrimitives.deriveNullifier(txHash, version);
        assertEq(nf1, nf2, "Nullifier derivation should be deterministic");
    }

    function testFuzz_deriveNullifierUniqueness(
        bytes32 txHash1,
        bytes32 txHash2,
        uint64 version1,
        uint64 version2
    ) public pure {
        vm.assume(txHash1 != txHash2 || version1 != version2);
        bytes32 nf1 = AptosPrimitives.deriveNullifier(txHash1, version1);
        bytes32 nf2 = AptosPrimitives.deriveNullifier(txHash2, version2);
        assertNotEq(
            nf1,
            nf2,
            "Different inputs should produce different nullifiers"
        );
    }

    function testFuzz_crossDomainNullifierDeterminism(
        bytes32 aptosNullifier,
        uint256 sourceChain,
        uint256 targetChain
    ) public pure {
        bytes32 cdn1 = AptosPrimitives.deriveCrossDomainNullifier(
            aptosNullifier,
            sourceChain,
            targetChain
        );
        bytes32 cdn2 = AptosPrimitives.deriveCrossDomainNullifier(
            aptosNullifier,
            sourceChain,
            targetChain
        );
        assertEq(cdn1, cdn2, "Cross-domain nullifier should be deterministic");
    }

    function testFuzz_crossDomainNullifierUniqueness(
        bytes32 nf1,
        bytes32 nf2,
        uint256 source1,
        uint256 source2,
        uint256 target1,
        uint256 target2
    ) public pure {
        vm.assume(nf1 != nf2 || source1 != source2 || target1 != target2);
        bytes32 cdn1 = AptosPrimitives.deriveCrossDomainNullifier(
            nf1,
            source1,
            target1
        );
        bytes32 cdn2 = AptosPrimitives.deriveCrossDomainNullifier(
            nf2,
            source2,
            target2
        );
        assertNotEq(
            cdn1,
            cdn2,
            "Different inputs should produce different cross-domain nullifiers"
        );
    }

    function testFuzz_pilBindingDeterminism(
        bytes32 aptosNullifier
    ) public pure {
        bytes32 binding1 = AptosPrimitives.derivePILBinding(aptosNullifier);
        bytes32 binding2 = AptosPrimitives.derivePILBinding(aptosNullifier);
        assertEq(binding1, binding2, "PIL binding should be deterministic");
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
        vm.assume(signingPower < type(uint256).max / 10000);

        bool hasQuorum = AptosPrimitives.hasQuorum(signingPower, totalPower);

        // Contract uses: signingPower * 10000 >= totalPower * 6667
        bool expected = signingPower * 10000 >= totalPower * 6667;

        assertEq(hasQuorum, expected, "Quorum calculation mismatch");
    }

    function testFuzz_hasQuorumZeroTotal(uint256 signingPower) public pure {
        bool hasQuorum = AptosPrimitives.hasQuorum(signingPower, 0);
        assertFalse(hasQuorum, "Zero total power should not have quorum");
    }

    function testFuzz_hasQuorumExactThreshold(uint256 totalPower) public pure {
        vm.assume(totalPower > 0);
        vm.assume(totalPower < type(uint256).max / 10000);

        uint256 exactThreshold = (totalPower * 6667 + 9999) / 10000; // Ceiling
        bool hasQuorum = AptosPrimitives.hasQuorum(exactThreshold, totalPower);
        assertTrue(hasQuorum, "Exact threshold should have quorum");
    }

    // =========================================================================
    // CHAIN VALIDATION TESTS
    // =========================================================================

    function testFuzz_isAptosChain(uint8 chainId) public pure {
        bool isAptos = AptosPrimitives.isAptosChain(chainId);
        bool expected = chainId == 1 || chainId == 2 || chainId == 34;
        assertEq(isAptos, expected, "Chain validation mismatch");
    }

    function test_isAptosChainMainnet() public pure {
        assertTrue(AptosPrimitives.isAptosChain(AptosPrimitives.APTOS_MAINNET));
    }

    function test_isAptosChainTestnet() public pure {
        assertTrue(AptosPrimitives.isAptosChain(AptosPrimitives.APTOS_TESTNET));
    }

    function test_isAptosChainDevnet() public pure {
        assertTrue(AptosPrimitives.isAptosChain(AptosPrimitives.APTOS_DEVNET));
    }

    // =========================================================================
    // RESOURCE ADDRESS TESTS
    // =========================================================================

    function testFuzz_computeResourceAddressDeterminism(
        address creator,
        bytes memory seed
    ) public pure {
        address addr1 = AptosPrimitives.computeResourceAddress(creator, seed);
        address addr2 = AptosPrimitives.computeResourceAddress(creator, seed);
        assertEq(addr1, addr2, "Resource address should be deterministic");
    }

    function testFuzz_computeResourceAddressUniqueness(
        address creator1,
        address creator2,
        bytes memory seed1,
        bytes memory seed2
    ) public pure {
        vm.assume(creator1 != creator2 || keccak256(seed1) != keccak256(seed2));
        address addr1 = AptosPrimitives.computeResourceAddress(creator1, seed1);
        address addr2 = AptosPrimitives.computeResourceAddress(creator2, seed2);
        assertNotEq(
            addr1,
            addr2,
            "Different inputs should produce different addresses"
        );
    }

    function testFuzz_computeObjectAddressDeterminism(
        address creator,
        bytes memory seed
    ) public pure {
        address addr1 = AptosPrimitives.computeObjectAddress(creator, seed);
        address addr2 = AptosPrimitives.computeObjectAddress(creator, seed);
        assertEq(addr1, addr2, "Object address should be deterministic");
    }

    // =========================================================================
    // MERKLE PROOF TESTS
    // =========================================================================

    function testFuzz_verifySparseMerkleProofSingleLevel(
        bytes32 leaf,
        bytes32 sibling,
        bool isLeft
    ) public pure {
        bytes32 root;
        if (isLeft) {
            root = AptosPrimitives.hash2(leaf, sibling);
        } else {
            root = AptosPrimitives.hash2(sibling, leaf);
        }

        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = sibling;

        AptosPrimitives.SparseMerkleProof memory proof = AptosPrimitives
            .SparseMerkleProof({
                leaf: leaf,
                siblings: siblings,
                leafIndex: isLeft ? 0 : 1
            });

        bool valid = AptosPrimitives.verifySparseMerkleProof(
            proof,
            root,
            bytes32(0),
            bytes32(0)
        );
        assertTrue(valid, "Single level proof should verify");
    }

    function testFuzz_verifyAccumulatorProofSingleLevel(
        bytes32 txHash,
        bytes32 sibling,
        bool isLeft
    ) public pure {
        bytes32 root;
        if (isLeft) {
            root = AptosPrimitives.hash2(txHash, sibling);
        } else {
            root = AptosPrimitives.hash2(sibling, txHash);
        }

        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = sibling;

        AptosPrimitives.TransactionAccumulatorProof
            memory proof = AptosPrimitives.TransactionAccumulatorProof({
                siblings: siblings,
                leafIndex: isLeft ? 0 : 1
            });

        bool valid = AptosPrimitives.verifyAccumulatorProof(
            proof,
            root,
            txHash
        );
        assertTrue(valid, "Single level accumulator proof should verify");
    }

    // =========================================================================
    // VALIDATOR MANAGEMENT TESTS
    // =========================================================================

    function testFuzz_registerValidatorPower(uint256 power) public {
        vm.assume(power > 0);
        vm.assume(power < type(uint128).max);

        adapter.registerValidator(validator1, blsKey1, ed25519Key1, power);

        assertTrue(adapter.isValidator(validator1));
        assertEq(adapter.getValidatorPower(validator1), power);
        assertEq(adapter.totalVotingPower(), power);
    }

    function testFuzz_registerMultipleValidators(
        uint256 power1,
        uint256 power2,
        uint256 power3
    ) public {
        vm.assume(power1 > 0 && power2 > 0 && power3 > 0);
        vm.assume(power1 < type(uint64).max);
        vm.assume(power2 < type(uint64).max);
        vm.assume(power3 < type(uint64).max);
        vm.assume(
            uint256(power1) + uint256(power2) + uint256(power3) <
                type(uint128).max
        );

        adapter.registerValidator(validator1, blsKey1, ed25519Key1, power1);
        adapter.registerValidator(validator2, blsKey2, ed25519Key2, power2);
        adapter.registerValidator(validator3, blsKey3, ed25519Key3, power3);

        assertEq(adapter.activeValidatorCount(), 3);
        assertEq(adapter.totalVotingPower(), power1 + power2 + power3);
    }

    function testFuzz_updateValidatorPower(
        uint256 initialPower,
        uint256 newPower
    ) public {
        vm.assume(initialPower > 0 && newPower > 0);
        vm.assume(initialPower < type(uint128).max);
        vm.assume(newPower < type(uint128).max);

        adapter.registerValidator(
            validator1,
            blsKey1,
            ed25519Key1,
            initialPower
        );
        adapter.updateValidatorPower(validator1, newPower);

        assertEq(adapter.getValidatorPower(validator1), newPower);
        assertEq(adapter.totalVotingPower(), newPower);
    }

    function testFuzz_removeValidator(uint256 power) public {
        vm.assume(power > 0);
        vm.assume(power < type(uint128).max);

        adapter.registerValidator(validator1, blsKey1, ed25519Key1, power);
        adapter.removeValidator(validator1);

        assertFalse(adapter.isValidator(validator1));
        assertEq(adapter.getValidatorPower(validator1), 0);
        assertEq(adapter.totalVotingPower(), 0);
    }

    // =========================================================================
    // NULLIFIER CONSUMPTION TESTS
    // =========================================================================

    function testFuzz_consumeNullifier(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        assertFalse(adapter.isNullifierConsumed(nullifier));
        adapter.consumeNullifier(nullifier);
        assertTrue(adapter.isNullifierConsumed(nullifier));
    }

    function testFuzz_doubleConsumeNullifierReverts(bytes32 nullifier) public {
        vm.assume(nullifier != bytes32(0));

        adapter.consumeNullifier(nullifier);

        vm.expectRevert(AptosBridgeAdapter.NullifierAlreadyConsumed.selector);
        adapter.consumeNullifier(nullifier);
    }

    function testFuzz_bindCrossDomainNullifier(
        bytes32 aptosNf,
        bytes32 pilNf
    ) public {
        vm.assume(aptosNf != bytes32(0) && pilNf != bytes32(0));

        adapter.bindCrossDomainNullifier(aptosNf, pilNf);

        assertEq(adapter.aptosNullifierToPIL(aptosNf), pilNf);
        assertEq(adapter.pilNullifierToAptos(pilNf), aptosNf);
    }

    function testFuzz_rebindNullifierReverts(
        bytes32 aptosNf,
        bytes32 pilNf1,
        bytes32 pilNf2
    ) public {
        vm.assume(aptosNf != bytes32(0));
        vm.assume(pilNf1 != bytes32(0) && pilNf2 != bytes32(0));
        vm.assume(pilNf1 != pilNf2);

        adapter.bindCrossDomainNullifier(aptosNf, pilNf1);

        vm.expectRevert("Already bound");
        adapter.bindCrossDomainNullifier(aptosNf, pilNf2);
    }

    // =========================================================================
    // DEPOSIT TESTS
    // =========================================================================

    function testFuzz_depositETH(uint256 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= 10 ether);

        bytes32 aptosRecipient = keccak256("aptos_recipient");

        vm.prank(user);
        adapter.deposit{value: amount}(address(0), amount, aptosRecipient);

        assertEq(adapter.depositNonce(), 1);
    }

    function testFuzz_depositZeroReverts() public {
        bytes32 aptosRecipient = keccak256("aptos_recipient");

        vm.prank(user);
        vm.expectRevert(AptosBridgeAdapter.InvalidAmount.selector);
        adapter.deposit{value: 0}(address(0), 0, aptosRecipient);
    }

    function testFuzz_depositAmountMismatchReverts(uint256 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= 10 ether);

        bytes32 aptosRecipient = keccak256("aptos_recipient");

        vm.prank(user);
        vm.expectRevert(AptosBridgeAdapter.InvalidAmount.selector);
        adapter.deposit{value: amount / 2}(address(0), amount, aptosRecipient);
    }

    // =========================================================================
    // CIRCUIT BREAKER TESTS
    // =========================================================================

    function test_triggerCircuitBreaker() public {
        vm.prank(emergencyCouncil);
        adapter.triggerCircuitBreaker();

        assertTrue(adapter.circuitBreakerTriggered());
        assertTrue(adapter.isPaused());
    }

    function test_resetCircuitBreaker() public {
        vm.prank(emergencyCouncil);
        adapter.triggerCircuitBreaker();

        adapter.resetCircuitBreaker();

        assertFalse(adapter.circuitBreakerTriggered());
    }

    function testFuzz_circuitBreakerBlocksDeposit(uint256 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount <= 10 ether);

        vm.prank(emergencyCouncil);
        adapter.triggerCircuitBreaker();

        bytes32 aptosRecipient = keccak256("aptos_recipient");

        vm.prank(user);
        vm.expectRevert(); // Paused or circuit breaker
        adapter.deposit{value: amount}(address(0), amount, aptosRecipient);
    }

    // =========================================================================
    // RELAYER FEE TESTS
    // =========================================================================

    function testFuzz_updateRelayerFee(uint256 newFee) public {
        vm.assume(newFee <= 500); // Max 5%

        adapter.updateRelayerFee(newFee);
        assertEq(adapter.relayerFeeBps(), newFee);
    }

    function testFuzz_updateRelayerFeeExceedsMaxReverts(uint256 newFee) public {
        vm.assume(newFee > 500);

        vm.expectRevert(AptosBridgeAdapter.InvalidRelayerFee.selector);
        adapter.updateRelayerFee(newFee);
    }

    // =========================================================================
    // ACCESS CONTROL TESTS
    // =========================================================================

    function testFuzz_onlyOwnerCanRegisterValidator(address attacker) public {
        vm.assume(attacker != owner);

        vm.prank(attacker);
        vm.expectRevert();
        adapter.registerValidator(validator1, blsKey1, ed25519Key1, 1000);
    }

    function testFuzz_onlyOwnerCanRemoveValidator(address attacker) public {
        vm.assume(attacker != owner);

        adapter.registerValidator(validator1, blsKey1, ed25519Key1, 1000);

        vm.prank(attacker);
        vm.expectRevert();
        adapter.removeValidator(validator1);
    }

    function testFuzz_onlyOwnerCanConsumeNullifier(address attacker) public {
        vm.assume(attacker != owner);

        vm.prank(attacker);
        vm.expectRevert();
        adapter.consumeNullifier(keccak256("test"));
    }

    function testFuzz_onlyEmergencyCouncilCanTriggerCircuitBreaker(
        address attacker
    ) public {
        vm.assume(attacker != emergencyCouncil && attacker != owner);

        vm.prank(attacker);
        vm.expectRevert(AptosBridgeAdapter.NotEmergencyCouncil.selector);
        adapter.triggerCircuitBreaker();
    }

    // =========================================================================
    // SIGNATURE VERIFICATION TESTS
    // =========================================================================

    function testFuzz_verifyEd25519ValidLength(bytes32 message) public pure {
        // Valid lengths should not revert
        bytes memory sig = new bytes(64);
        bytes memory pk = new bytes(32);

        bool result = AptosPrimitives.verifyEd25519Signature(message, sig, pk);
        assertTrue(result, "Valid lengths should return true");
    }

    function testFuzz_verifyBLSValidLength(bytes32 message) public pure {
        // Valid lengths should not revert
        bytes memory sig = new bytes(48);
        bytes memory pk = new bytes(96);

        bool result = AptosPrimitives.verifyBLSSignature(message, sig, pk);
        assertTrue(result, "Valid lengths should return true");
    }

    // =========================================================================
    // EPOCH STATE TESTS
    // =========================================================================

    function testFuzz_computeEpochStateHash(
        uint64 epoch,
        uint8 validatorCount
    ) public {
        vm.assume(validatorCount > 0 && validatorCount <= 10);

        address[] memory validators = new address[](validatorCount);
        uint256[] memory powers = new uint256[](validatorCount);
        for (uint8 i = 0; i < validatorCount; i++) {
            validators[i] = address(uint160(i + 1));
            powers[i] = uint256(i + 1) * 1000;
        }

        bytes32 hash1 = AptosPrimitives.computeEpochStateHash(
            epoch,
            validators,
            powers
        );
        bytes32 hash2 = AptosPrimitives.computeEpochStateHash(
            epoch,
            validators,
            powers
        );
        assertEq(hash1, hash2, "Epoch state hash should be deterministic");
    }

    // =========================================================================
    // SIGNING POWER CALCULATION TESTS
    // =========================================================================

    function testFuzz_calculateSigningPowerAllSigned(
        uint256[] memory powers
    ) public pure {
        vm.assume(powers.length > 0 && powers.length <= 64);

        // Bound each power to prevent overflow
        uint256 maxPower = type(uint256).max / 64;
        uint256 expectedTotal = 0;
        for (uint256 i = 0; i < powers.length; i++) {
            powers[i] = powers[i] % maxPower;
            expectedTotal += powers[i];
        }

        // Create bitmap with all bits set
        bytes memory bitmap = new bytes((powers.length + 7) / 8);
        for (uint256 i = 0; i < bitmap.length; i++) {
            bitmap[i] = bytes1(uint8(0xFF));
        }

        uint256 signingPower = AptosPrimitives.calculateSigningPower(
            bitmap,
            powers
        );
        assertEq(
            signingPower,
            expectedTotal,
            "All signed should sum all powers"
        );
    }

    function testFuzz_calculateSigningPowerNoneSigned(
        uint256[] memory powers
    ) public pure {
        vm.assume(powers.length > 0 && powers.length <= 64);

        // Create bitmap with no bits set
        bytes memory bitmap = new bytes((powers.length + 7) / 8);

        uint256 signingPower = AptosPrimitives.calculateSigningPower(
            bitmap,
            powers
        );
        assertEq(signingPower, 0, "None signed should have zero power");
    }

    // =========================================================================
    // CONSTANTS TESTS
    // =========================================================================

    function test_constants() public pure {
        assertEq(
            AptosPrimitives.BLS12_381_SCALAR_ORDER,
            52435875175126190479447740508185965837690552500527637822603658699938581184513
        );
        assertEq(
            AptosPrimitives.ED25519_ORDER,
            7237005577332262213973186563042994240857116359379907606001950938285454250989
        );
        assertEq(AptosPrimitives.APTOS_MAINNET, 1);
        assertEq(AptosPrimitives.APTOS_TESTNET, 2);
        assertEq(AptosPrimitives.APTOS_DEVNET, 34);
        assertEq(AptosPrimitives.QUORUM_THRESHOLD_BPS, 6667);
        assertEq(AptosPrimitives.BLS_SIGNATURE_LENGTH, 48);
        assertEq(AptosPrimitives.BLS_PUBKEY_LENGTH, 96);
        assertEq(AptosPrimitives.ED25519_SIGNATURE_LENGTH, 64);
        assertEq(AptosPrimitives.ED25519_PUBKEY_LENGTH, 32);
    }

    // =========================================================================
    // EDGE CASE TESTS
    // =========================================================================

    function test_emptyProof() public pure {
        bytes32[] memory siblings = new bytes32[](0);
        AptosPrimitives.SparseMerkleProof memory proof = AptosPrimitives
            .SparseMerkleProof({
                leaf: keccak256("leaf"),
                siblings: siblings,
                leafIndex: 0
            });

        // Empty proof - leaf should equal root
        bool valid = AptosPrimitives.verifySparseMerkleProof(
            proof,
            keccak256("leaf"),
            bytes32(0),
            bytes32(0)
        );
        assertTrue(valid, "Empty proof with leaf==root should verify");
    }

    function testFuzz_ledgerInfoValidation(
        uint64 epoch,
        uint64 round,
        bytes32 blockHash,
        bytes32 executedStateId,
        uint64 version,
        uint64 timestampUsecs
    ) public pure {
        vm.assume(epoch > 0);
        vm.assume(blockHash != bytes32(0));
        vm.assume(executedStateId != bytes32(0));

        bytes memory aggregateSig = new bytes(48);
        bytes memory bitmap = new bytes(1);

        AptosPrimitives.LedgerInfoWithSignatures memory info = AptosPrimitives
            .LedgerInfoWithSignatures({
                epoch: epoch,
                round: round,
                blockHash: blockHash,
                executedStateId: executedStateId,
                version: version,
                timestampUsecs: timestampUsecs,
                nextEpochState: bytes32(0),
                aggregateSignature: aggregateSig,
                validatorBitmap: bitmap
            });

        assertTrue(
            AptosPrimitives.isValidLedgerInfo(info),
            "Valid ledger info should pass validation"
        );
    }

    function test_invalidLedgerInfoZeroEpoch() public pure {
        bytes memory aggregateSig = new bytes(48);
        bytes memory bitmap = new bytes(1);

        AptosPrimitives.LedgerInfoWithSignatures memory info = AptosPrimitives
            .LedgerInfoWithSignatures({
                epoch: 0, // Invalid
                round: 1,
                blockHash: keccak256("block"),
                executedStateId: keccak256("state"),
                version: 100,
                timestampUsecs: 1000000,
                nextEpochState: bytes32(0),
                aggregateSignature: aggregateSig,
                validatorBitmap: bitmap
            });

        assertFalse(
            AptosPrimitives.isValidLedgerInfo(info),
            "Zero epoch should be invalid"
        );
    }

    // =========================================================================
    // ADDITIONAL HASH TESTS
    // =========================================================================

    function testFuzz_hashWithPrefixDomainSeparation(
        string memory prefix1,
        string memory prefix2,
        bytes memory data
    ) public pure {
        vm.assume(keccak256(bytes(prefix1)) != keccak256(bytes(prefix2)));

        bytes32 hash1 = AptosPrimitives.hashWithPrefix(prefix1, data);
        bytes32 hash2 = AptosPrimitives.hashWithPrefix(prefix2, data);

        assertNotEq(
            hash1,
            hash2,
            "Different prefixes should produce different hashes"
        );
    }

    function testFuzz_computeBlockHashDifferentEpochs(
        uint64 epoch1,
        uint64 epoch2,
        uint64 round,
        bytes32 executedStateId,
        uint64 version,
        uint64 timestampUsecs
    ) public pure {
        vm.assume(epoch1 != epoch2);

        bytes32 hash1 = AptosPrimitives.computeBlockHash(
            epoch1,
            round,
            executedStateId,
            version,
            timestampUsecs
        );
        bytes32 hash2 = AptosPrimitives.computeBlockHash(
            epoch2,
            round,
            executedStateId,
            version,
            timestampUsecs
        );

        assertNotEq(
            hash1,
            hash2,
            "Different epochs should produce different block hashes"
        );
    }

    function testFuzz_computeBlockHashDifferentRounds(
        uint64 epoch,
        uint64 round1,
        uint64 round2,
        bytes32 executedStateId,
        uint64 version,
        uint64 timestampUsecs
    ) public pure {
        vm.assume(round1 != round2);

        bytes32 hash1 = AptosPrimitives.computeBlockHash(
            epoch,
            round1,
            executedStateId,
            version,
            timestampUsecs
        );
        bytes32 hash2 = AptosPrimitives.computeBlockHash(
            epoch,
            round2,
            executedStateId,
            version,
            timestampUsecs
        );

        assertNotEq(
            hash1,
            hash2,
            "Different rounds should produce different block hashes"
        );
    }

    // =========================================================================
    // ADDITIONAL NULLIFIER TESTS
    // =========================================================================

    function testFuzz_nullifierVersionSensitivity(
        bytes32 txHash,
        uint64 version1,
        uint64 version2
    ) public pure {
        vm.assume(version1 != version2);

        bytes32 nf1 = AptosPrimitives.deriveNullifier(txHash, version1);
        bytes32 nf2 = AptosPrimitives.deriveNullifier(txHash, version2);

        assertNotEq(
            nf1,
            nf2,
            "Different versions should produce different nullifiers"
        );
    }

    function testFuzz_crossDomainNullifierChainSensitivity(
        bytes32 aptosNullifier,
        uint256 chain1,
        uint256 chain2
    ) public pure {
        vm.assume(chain1 != chain2);

        bytes32 cdn1 = AptosPrimitives.deriveCrossDomainNullifier(
            aptosNullifier,
            chain1,
            1
        );
        bytes32 cdn2 = AptosPrimitives.deriveCrossDomainNullifier(
            aptosNullifier,
            chain2,
            1
        );

        assertNotEq(
            cdn1,
            cdn2,
            "Different source chains should produce different cross-domain nullifiers"
        );
    }

    function testFuzz_pilBindingUniqueness(
        bytes32 nf1,
        bytes32 nf2
    ) public pure {
        vm.assume(nf1 != nf2);

        bytes32 binding1 = AptosPrimitives.derivePILBinding(nf1);
        bytes32 binding2 = AptosPrimitives.derivePILBinding(nf2);

        assertNotEq(
            binding1,
            binding2,
            "Different nullifiers should produce different PIL bindings"
        );
    }

    // =========================================================================
    // ADDITIONAL QUORUM TESTS
    // =========================================================================

    function testFuzz_quorumBoundaryConditions(uint256 totalPower) public pure {
        vm.assume(totalPower > 0);
        vm.assume(totalPower < type(uint128).max);

        // Calculate exact threshold (2/3 + 1)
        uint256 threshold = (totalPower * 6667 + 9999) / 10000;

        // Just below threshold should not have quorum
        if (threshold > 0) {
            bool belowQuorum = AptosPrimitives.hasQuorum(
                threshold - 1,
                totalPower
            );
            assertFalse(belowQuorum, "Below threshold should not have quorum");
        }

        // At threshold should have quorum
        bool atQuorum = AptosPrimitives.hasQuorum(threshold, totalPower);
        assertTrue(atQuorum, "At threshold should have quorum");
    }

    function testFuzz_quorumFullPower(uint256 totalPower) public pure {
        vm.assume(totalPower > 0);
        vm.assume(totalPower < type(uint128).max);

        bool hasQuorum = AptosPrimitives.hasQuorum(totalPower, totalPower);
        assertTrue(hasQuorum, "Full power should always have quorum");
    }

    function testFuzz_quorumHalfPower(uint256 totalPower) public pure {
        vm.assume(totalPower > 1);
        vm.assume(totalPower < type(uint128).max);

        uint256 halfPower = totalPower / 2;
        bool hasQuorum = AptosPrimitives.hasQuorum(halfPower, totalPower);
        assertFalse(hasQuorum, "Half power should not have quorum");
    }

    // =========================================================================
    // ADDITIONAL MERKLE PROOF TESTS
    // =========================================================================

    function testFuzz_sparseMerkleProofTwoLevels(
        bytes32 leaf,
        bytes32 sibling1,
        bytes32 sibling2,
        uint8 leafIndexRaw
    ) public pure {
        uint256 leafIndex = uint256(leafIndexRaw % 4); // 2-level tree has 4 leaves

        bytes32[] memory siblings = new bytes32[](2);
        siblings[0] = sibling1;
        siblings[1] = sibling2;

        // Compute expected root
        bytes32 level1;
        if (leafIndex & 1 == 0) {
            level1 = AptosPrimitives.hash2(leaf, sibling1);
        } else {
            level1 = AptosPrimitives.hash2(sibling1, leaf);
        }

        bytes32 root;
        if ((leafIndex >> 1) & 1 == 0) {
            root = AptosPrimitives.hash2(level1, sibling2);
        } else {
            root = AptosPrimitives.hash2(sibling2, level1);
        }

        AptosPrimitives.SparseMerkleProof memory proof = AptosPrimitives
            .SparseMerkleProof({
                leaf: leaf,
                siblings: siblings,
                leafIndex: leafIndex
            });

        bool valid = AptosPrimitives.verifySparseMerkleProof(
            proof,
            root,
            bytes32(0),
            bytes32(0)
        );
        assertTrue(valid, "Two-level proof should verify");
    }

    function testFuzz_accumulatorProofTwoLevels(
        bytes32 txHash,
        bytes32 sibling1,
        bytes32 sibling2,
        uint8 leafIndexRaw
    ) public pure {
        uint64 leafIndex = uint64(leafIndexRaw % 4);

        bytes32[] memory siblings = new bytes32[](2);
        siblings[0] = sibling1;
        siblings[1] = sibling2;

        // Compute expected root
        bytes32 level1;
        if (leafIndex & 1 == 0) {
            level1 = AptosPrimitives.hash2(txHash, sibling1);
        } else {
            level1 = AptosPrimitives.hash2(sibling1, txHash);
        }

        bytes32 root;
        if ((leafIndex >> 1) & 1 == 0) {
            root = AptosPrimitives.hash2(level1, sibling2);
        } else {
            root = AptosPrimitives.hash2(sibling2, level1);
        }

        AptosPrimitives.TransactionAccumulatorProof
            memory proof = AptosPrimitives.TransactionAccumulatorProof({
                siblings: siblings,
                leafIndex: leafIndex
            });

        bool valid = AptosPrimitives.verifyAccumulatorProof(
            proof,
            root,
            txHash
        );
        assertTrue(valid, "Two-level accumulator proof should verify");
    }

    function testFuzz_invalidMerkleProof(
        bytes32 leaf,
        bytes32 sibling,
        bytes32 wrongRoot
    ) public pure {
        bytes32 correctRoot = AptosPrimitives.hash2(leaf, sibling);
        vm.assume(wrongRoot != correctRoot);

        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = sibling;

        AptosPrimitives.SparseMerkleProof memory proof = AptosPrimitives
            .SparseMerkleProof({leaf: leaf, siblings: siblings, leafIndex: 0});

        bool valid = AptosPrimitives.verifySparseMerkleProof(
            proof,
            wrongRoot,
            bytes32(0),
            bytes32(0)
        );
        assertFalse(valid, "Proof with wrong root should not verify");
    }

    // =========================================================================
    // ADDITIONAL VALIDATOR TESTS
    // =========================================================================

    function testFuzz_validatorPowerUpdate(
        uint256 power1,
        uint256 power2,
        uint256 power3
    ) public {
        vm.assume(power1 > 0 && power2 > 0 && power3 > 0);
        vm.assume(power1 < type(uint64).max);
        vm.assume(power2 < type(uint64).max);
        vm.assume(power3 < type(uint64).max);

        adapter.registerValidator(validator1, blsKey1, ed25519Key1, power1);
        assertEq(adapter.totalVotingPower(), power1);

        adapter.updateValidatorPower(validator1, power2);
        assertEq(adapter.totalVotingPower(), power2);
        assertEq(adapter.getValidatorPower(validator1), power2);

        adapter.updateValidatorPower(validator1, power3);
        assertEq(adapter.totalVotingPower(), power3);
    }

    function testFuzz_validatorRegistrationReverts(address attacker) public {
        vm.assume(attacker != owner);
        vm.assume(attacker != address(0));

        vm.prank(attacker);
        vm.expectRevert();
        adapter.registerValidator(validator1, blsKey1, ed25519Key1, 1000);
    }

    function testFuzz_cannotRegisterWithZeroPower() public {
        vm.expectRevert(AptosBridgeAdapter.InvalidVotingPower.selector);
        adapter.registerValidator(validator1, blsKey1, ed25519Key1, 0);
    }

    function testFuzz_cannotRegisterWithInvalidBlsKeyLength(
        uint8 wrongLengthRaw
    ) public {
        uint256 wrongLength = uint256(wrongLengthRaw);
        if (wrongLength == 96) wrongLength = 97; // Ensure not valid length

        bytes memory wrongKey = new bytes(wrongLength);

        vm.expectRevert(AptosBridgeAdapter.InvalidPublicKeyLength.selector);
        adapter.registerValidator(validator1, wrongKey, ed25519Key1, 1000);
    }

    function testFuzz_cannotRegisterWithInvalidEd25519KeyLength(
        uint8 wrongLengthRaw
    ) public {
        uint256 wrongLength = uint256(wrongLengthRaw);
        if (wrongLength == 32) wrongLength = 33; // Ensure not valid length

        bytes memory wrongKey = new bytes(wrongLength);

        vm.expectRevert(AptosBridgeAdapter.InvalidPublicKeyLength.selector);
        adapter.registerValidator(validator1, blsKey1, wrongKey, 1000);
    }

    // =========================================================================
    // ADDITIONAL RESOURCE ADDRESS TESTS
    // =========================================================================

    function testFuzz_resourceAndObjectAddressesDifferent(
        address creator,
        bytes memory seed
    ) public pure {
        address resourceAddr = AptosPrimitives.computeResourceAddress(
            creator,
            seed
        );
        address objectAddr = AptosPrimitives.computeObjectAddress(
            creator,
            seed
        );

        // Different scheme bytes (255 vs 254) should produce different addresses
        assertNotEq(
            resourceAddr,
            objectAddr,
            "Resource and object addresses should differ"
        );
    }

    function testFuzz_resourceAddressDifferentSeeds(
        address creator,
        bytes memory seed1,
        bytes memory seed2
    ) public pure {
        vm.assume(keccak256(seed1) != keccak256(seed2));

        address addr1 = AptosPrimitives.computeResourceAddress(creator, seed1);
        address addr2 = AptosPrimitives.computeResourceAddress(creator, seed2);

        assertNotEq(
            addr1,
            addr2,
            "Different seeds should produce different addresses"
        );
    }

    function testFuzz_resourceAddressDifferentCreators(
        address creator1,
        address creator2,
        bytes memory seed
    ) public pure {
        vm.assume(creator1 != creator2);

        address addr1 = AptosPrimitives.computeResourceAddress(creator1, seed);
        address addr2 = AptosPrimitives.computeResourceAddress(creator2, seed);

        assertNotEq(
            addr1,
            addr2,
            "Different creators should produce different addresses"
        );
    }

    // =========================================================================
    // ADDITIONAL DEPOSIT/WITHDRAWAL TESTS
    // =========================================================================

    function testFuzz_multipleDeposits(uint8 numDeposits) public {
        vm.assume(numDeposits > 0 && numDeposits <= 10);

        bytes32 aptosRecipient = keccak256("aptos_recipient");

        for (uint8 i = 0; i < numDeposits; i++) {
            vm.prank(user);
            adapter.deposit{value: 0.1 ether}(
                address(0),
                0.1 ether,
                aptosRecipient
            );
        }

        assertEq(adapter.depositNonce(), numDeposits);
    }

    function testFuzz_depositWithDifferentRecipients(
        bytes32 recipient1,
        bytes32 recipient2
    ) public {
        vm.assume(recipient1 != recipient2);

        vm.prank(user);
        adapter.deposit{value: 1 ether}(address(0), 1 ether, recipient1);

        vm.prank(user);
        adapter.deposit{value: 1 ether}(address(0), 1 ether, recipient2);

        assertEq(adapter.depositNonce(), 2);
    }

    // =========================================================================
    // ADDITIONAL CIRCUIT BREAKER TESTS
    // =========================================================================

    function test_circuitBreakerOnlyEmergencyCouncil() public {
        address randomUser = address(0x9999);

        vm.prank(randomUser);
        vm.expectRevert(AptosBridgeAdapter.NotEmergencyCouncil.selector);
        adapter.triggerCircuitBreaker();
    }

    function test_ownerCanTriggerCircuitBreaker() public {
        adapter.triggerCircuitBreaker();
        assertTrue(adapter.circuitBreakerTriggered());
    }

    function test_circuitBreakerResetOnlyOwner() public {
        vm.prank(emergencyCouncil);
        adapter.triggerCircuitBreaker();

        vm.prank(emergencyCouncil);
        vm.expectRevert();
        adapter.resetCircuitBreaker();
    }

    function test_pauseAndUnpause() public {
        adapter.pause();
        assertTrue(adapter.isPaused());

        adapter.unpause();
        assertFalse(adapter.isPaused());
    }

    function testFuzz_pauseOnlyOwner(address attacker) public {
        vm.assume(attacker != owner);

        vm.prank(attacker);
        vm.expectRevert();
        adapter.pause();
    }

    // =========================================================================
    // ADDITIONAL LEDGER INFO TESTS
    // =========================================================================

    function test_invalidLedgerInfoZeroBlockHash() public pure {
        bytes memory aggregateSig = new bytes(48);
        bytes memory bitmap = new bytes(1);

        AptosPrimitives.LedgerInfoWithSignatures memory info = AptosPrimitives
            .LedgerInfoWithSignatures({
                epoch: 1,
                round: 1,
                blockHash: bytes32(0), // Invalid
                executedStateId: keccak256("state"),
                version: 100,
                timestampUsecs: 1000000,
                nextEpochState: bytes32(0),
                aggregateSignature: aggregateSig,
                validatorBitmap: bitmap
            });

        assertFalse(
            AptosPrimitives.isValidLedgerInfo(info),
            "Zero block hash should be invalid"
        );
    }

    function test_invalidLedgerInfoZeroStateId() public pure {
        bytes memory aggregateSig = new bytes(48);
        bytes memory bitmap = new bytes(1);

        AptosPrimitives.LedgerInfoWithSignatures memory info = AptosPrimitives
            .LedgerInfoWithSignatures({
                epoch: 1,
                round: 1,
                blockHash: keccak256("block"),
                executedStateId: bytes32(0), // Invalid
                version: 100,
                timestampUsecs: 1000000,
                nextEpochState: bytes32(0),
                aggregateSignature: aggregateSig,
                validatorBitmap: bitmap
            });

        assertFalse(
            AptosPrimitives.isValidLedgerInfo(info),
            "Zero state ID should be invalid"
        );
    }

    function test_invalidLedgerInfoWrongSigLength() public pure {
        bytes memory wrongSig = new bytes(47); // Wrong length
        bytes memory bitmap = new bytes(1);

        AptosPrimitives.LedgerInfoWithSignatures memory info = AptosPrimitives
            .LedgerInfoWithSignatures({
                epoch: 1,
                round: 1,
                blockHash: keccak256("block"),
                executedStateId: keccak256("state"),
                version: 100,
                timestampUsecs: 1000000,
                nextEpochState: bytes32(0),
                aggregateSignature: wrongSig,
                validatorBitmap: bitmap
            });

        assertFalse(
            AptosPrimitives.isValidLedgerInfo(info),
            "Wrong signature length should be invalid"
        );
    }

    // =========================================================================
    // EPOCH STATE HASH TESTS
    // =========================================================================

    function testFuzz_epochStateHashDifferentEpochs(
        uint64 epoch1,
        uint64 epoch2
    ) public {
        vm.assume(epoch1 != epoch2);

        address[] memory validators = new address[](2);
        validators[0] = validator1;
        validators[1] = validator2;

        uint256[] memory powers = new uint256[](2);
        powers[0] = 100;
        powers[1] = 200;

        bytes32 hash1 = AptosPrimitives.computeEpochStateHash(
            epoch1,
            validators,
            powers
        );
        bytes32 hash2 = AptosPrimitives.computeEpochStateHash(
            epoch2,
            validators,
            powers
        );

        assertNotEq(
            hash1,
            hash2,
            "Different epochs should produce different hashes"
        );
    }

    function testFuzz_epochStateHashDifferentValidators(
        address val1,
        address val2
    ) public pure {
        vm.assume(val1 != val2);

        address[] memory validators1 = new address[](1);
        validators1[0] = val1;

        address[] memory validators2 = new address[](1);
        validators2[0] = val2;

        uint256[] memory powers = new uint256[](1);
        powers[0] = 100;

        bytes32 hash1 = AptosPrimitives.computeEpochStateHash(
            1,
            validators1,
            powers
        );
        bytes32 hash2 = AptosPrimitives.computeEpochStateHash(
            1,
            validators2,
            powers
        );

        assertNotEq(
            hash1,
            hash2,
            "Different validators should produce different hashes"
        );
    }

    // =========================================================================
    // RESOURCE TAG HASH TESTS
    // =========================================================================

    function testFuzz_resourceTagHashDeterminism(
        address moduleAddr,
        bytes32 moduleName,
        bytes32 structName
    ) public pure {
        bytes[] memory typeArgs = new bytes[](0);

        AptosPrimitives.ResourceTag memory tag = AptosPrimitives.ResourceTag({
            moduleAddress: moduleAddr,
            moduleName: moduleName,
            structName: structName,
            typeArgs: typeArgs
        });

        bytes32 hash1 = AptosPrimitives.computeResourceTagHash(tag);
        bytes32 hash2 = AptosPrimitives.computeResourceTagHash(tag);

        assertEq(hash1, hash2, "Resource tag hash should be deterministic");
    }

    function testFuzz_resourceTagHashDifferentModules(
        address addr1,
        address addr2
    ) public pure {
        vm.assume(addr1 != addr2);

        bytes[] memory typeArgs = new bytes[](0);

        AptosPrimitives.ResourceTag memory tag1 = AptosPrimitives.ResourceTag({
            moduleAddress: addr1,
            moduleName: bytes32("module"),
            structName: bytes32("struct"),
            typeArgs: typeArgs
        });

        AptosPrimitives.ResourceTag memory tag2 = AptosPrimitives.ResourceTag({
            moduleAddress: addr2,
            moduleName: bytes32("module"),
            structName: bytes32("struct"),
            typeArgs: typeArgs
        });

        bytes32 hash1 = AptosPrimitives.computeResourceTagHash(tag1);
        bytes32 hash2 = AptosPrimitives.computeResourceTagHash(tag2);

        assertNotEq(
            hash1,
            hash2,
            "Different module addresses should produce different hashes"
        );
    }

    // =========================================================================
    // EMERGENCY COUNCIL TESTS
    // =========================================================================

    function testFuzz_updateEmergencyCouncil(address newCouncil) public {
        vm.assume(newCouncil != address(0));

        adapter.updateEmergencyCouncil(newCouncil);
        assertEq(adapter.emergencyCouncil(), newCouncil);
    }

    function testFuzz_updateEmergencyCouncilOnlyOwner(address attacker) public {
        vm.assume(attacker != owner);

        vm.prank(attacker);
        vm.expectRevert();
        adapter.updateEmergencyCouncil(address(0x1234));
    }

    // =========================================================================
    // SIGNING POWER CALCULATION TESTS
    // =========================================================================

    function test_signingPowerPartialSigned() public pure {
        uint256[] memory powers = new uint256[](4);
        powers[0] = 100;
        powers[1] = 200;
        powers[2] = 300;
        powers[3] = 400;

        // Bitmap: 0b0101 = first and third signed
        bytes memory bitmap = new bytes(1);
        bitmap[0] = bytes1(uint8(5)); // 0b00000101

        uint256 signingPower = AptosPrimitives.calculateSigningPower(
            bitmap,
            powers
        );
        assertEq(signingPower, 400, "Should sum powers at indices 0 and 2"); // 100 + 300
    }

    function test_signingPowerAlternating() public pure {
        uint256[] memory powers = new uint256[](8);
        for (uint256 i = 0; i < 8; i++) {
            powers[i] = (i + 1) * 100;
        }

        // Bitmap: 0b10101010 = even indices signed
        bytes memory bitmap = new bytes(1);
        bitmap[0] = bytes1(uint8(170)); // 0b10101010

        uint256 signingPower = AptosPrimitives.calculateSigningPower(
            bitmap,
            powers
        );
        // Indices 1, 3, 5, 7 signed: 200 + 400 + 600 + 800 = 2000
        assertEq(signingPower, 2000);
    }
}
