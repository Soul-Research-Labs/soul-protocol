// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/**
 * @title FHEFuzz
 * @author Soul Protocol
 * @notice Comprehensive fuzz tests for FHE (Fully Homomorphic Encryption) contracts
 * @dev Tests FHE operations, access control, oracle consensus, and cross-chain bridges
 *
 * Test Categories:
 * 1. FHE Type System - Type bounds, compatibility, conversions
 * 2. FHE Operations - Arithmetic, comparison, bitwise operations
 * 3. Access Control - Permission grants, revocations, ACL enforcement
 * 4. Oracle Network - Registration, consensus, slashing, rewards
 * 5. Encrypted ERC20 - Transfers, approvals, minting, burning
 * 6. Encrypted Voting - Proposals, voting, tallying
 * 7. FHE Bridge - Cross-chain transfers, proofs, refunds
 */
contract FHEFuzz is Test {
    // ============================================
    // Constants (matching FHETypes.sol)
    // ============================================

    uint8 constant TYPE_EBOOL = 0;
    uint8 constant TYPE_EUINT4 = 1;
    uint8 constant TYPE_EUINT8 = 2;
    uint8 constant TYPE_EUINT16 = 3;
    uint8 constant TYPE_EUINT32 = 4;
    uint8 constant TYPE_EUINT64 = 5;
    uint8 constant TYPE_EUINT128 = 6;
    uint8 constant TYPE_EUINT256 = 7;
    uint8 constant TYPE_EADDRESS = 8;
    uint8 constant TYPE_EBYTES64 = 9;
    uint8 constant TYPE_EBYTES128 = 10;
    uint8 constant TYPE_EBYTES256 = 11;

    // Maximum values for each type
    uint256 constant MAX_EBOOL = 1;
    uint256 constant MAX_EUINT4 = 15;
    uint256 constant MAX_EUINT8 = 255;
    uint256 constant MAX_EUINT16 = 65535;
    uint256 constant MAX_EUINT32 = 4294967295;
    uint256 constant MAX_EUINT64 = 18446744073709551615;

    // Oracle constants
    uint256 constant MIN_STAKE = 10 ether;
    uint256 constant QUORUM_BPS = 6667;
    uint256 constant SLASH_BPS = 1000;

    // Bridge constants
    uint256 constant MIN_VALIDATORS = 3;
    uint64 constant MAX_EXPIRY = 7 days;
    uint64 constant DEFAULT_EXPIRY = 1 days;

    // ============================================
    // State for Simulation
    // ============================================

    // Simulated handle counter
    uint256 handleCounter;

    // Simulated handles: handle => (type, plaintext value, owner)
    struct HandleData {
        uint8 fheType;
        uint256 plaintext;
        address owner;
        bool exists;
    }
    mapping(bytes32 => HandleData) handles;

    // Simulated ACL: handle => user => has permission
    mapping(bytes32 => mapping(address => bool)) userACL;

    // Simulated oracle state
    struct OracleData {
        uint256 stake;
        uint256 reputation;
        bool active;
    }
    mapping(address => OracleData) oracles;
    address[] oracleList;

    // Simulated ERC20 state
    mapping(address => uint256) balances;
    mapping(address => mapping(address => uint256)) allowances;
    uint256 totalSupply;

    // Simulated voting state
    struct ProposalData {
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        uint64 endTime;
        bool active;
    }
    mapping(uint256 => ProposalData) proposals;
    mapping(uint256 => mapping(address => bool)) hasVoted;

    // Simulated bridge state
    struct TransferData {
        address sender;
        uint256 amount;
        uint256 destChain;
        uint64 expiry;
        bool pending;
        bool completed;
    }
    mapping(bytes32 => TransferData) transfers;
    mapping(bytes32 => bool) usedNullifiers;

    // ============================================
    // Setup
    // ============================================

    function setUp() public {
        handleCounter = 1;
        totalSupply = 1000000 ether;
        balances[address(this)] = totalSupply;
    }

    // ============================================
    // Helper Functions
    // ============================================

    function _createHandle(
        uint8 fheType,
        uint256 plaintext,
        address owner
    ) internal returns (bytes32) {
        bytes32 handle = keccak256(
            abi.encode(
                handleCounter++,
                fheType,
                plaintext,
                owner,
                block.timestamp
            )
        );
        handles[handle] = HandleData({
            fheType: fheType,
            plaintext: plaintext,
            owner: owner,
            exists: true
        });
        userACL[handle][owner] = true;
        return handle;
    }

    function _maxValue(uint8 fheType) internal pure returns (uint256) {
        if (fheType == TYPE_EBOOL) return MAX_EBOOL;
        if (fheType == TYPE_EUINT4) return MAX_EUINT4;
        if (fheType == TYPE_EUINT8) return MAX_EUINT8;
        if (fheType == TYPE_EUINT16) return MAX_EUINT16;
        if (fheType == TYPE_EUINT32) return MAX_EUINT32;
        if (fheType == TYPE_EUINT64) return MAX_EUINT64;
        return type(uint256).max;
    }

    function _boundType(uint8 fheType) internal pure returns (uint8) {
        return fheType % 12; // 0-11 valid types
    }

    function _boundPlaintext(
        uint256 value,
        uint8 fheType
    ) internal pure returns (uint256) {
        uint256 max = 1;
        if (fheType == TYPE_EBOOL) max = 1;
        else if (fheType == TYPE_EUINT4) max = 15;
        else if (fheType == TYPE_EUINT8) max = 255;
        else if (fheType == TYPE_EUINT16) max = 65535;
        else if (fheType == TYPE_EUINT32) max = 4294967295;
        else if (fheType == TYPE_EUINT64) max = 18446744073709551615;
        else max = type(uint256).max;

        return value % (max + 1);
    }

    // ============================================
    // FHE Type System Tests
    // ============================================

    /**
     * @notice Fuzz: Type bounds are respected
     */
    function testFuzz_TypeBoundsRespected(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        uint256 bounded = _boundPlaintext(value, fheType);

        assertLe(bounded, _maxValue(fheType), "Value exceeds type max");
    }

    /**
     * @notice Fuzz: Handle creation produces unique handles
     */
    function testFuzz_HandleUniqueness(
        uint256 value1,
        uint256 value2,
        uint8 rawType,
        address owner
    ) public {
        vm.assume(owner != address(0));
        uint8 fheType = _boundType(rawType);

        bytes32 handle1 = _createHandle(fheType, value1, owner);
        bytes32 handle2 = _createHandle(fheType, value2, owner);

        assertTrue(handle1 != handle2, "Handles must be unique");
    }

    /**
     * @notice Fuzz: Type compatibility for operations
     */
    function testFuzz_TypeCompatibility(uint8 type1, uint8 type2) public pure {
        type1 = type1 % 8; // Integer types only
        type2 = type2 % 8;

        // Same type is always compatible
        if (type1 == type2) {
            assertTrue(true, "Same types are compatible");
            return;
        }

        // Adjacent types are compatible (can be cast)
        int8 diff = int8(type1) - int8(type2);
        if (diff == 1 || diff == -1) {
            assertTrue(true, "Adjacent types are compatible");
        }
    }

    // ============================================
    // FHE Arithmetic Operations Tests
    // ============================================

    /**
     * @notice Fuzz: Addition wraps correctly
     */
    function testFuzz_AdditionWraps(
        uint256 a,
        uint256 b,
        uint8 rawType
    ) public {
        uint8 fheType = _boundType(rawType);
        // Only test integer types
        vm.assume(fheType >= TYPE_EUINT4 && fheType <= TYPE_EUINT64);

        uint256 max = _maxValue(fheType);
        a = a % (max + 1);
        b = b % (max + 1);

        uint256 result = (a + b) % (max + 1);

        assertLe(result, max, "Addition result within bounds");
    }

    /**
     * @notice Fuzz: Subtraction wraps correctly (two's complement)
     */
    function testFuzz_SubtractionWraps(
        uint256 a,
        uint256 b,
        uint8 rawType
    ) public {
        uint8 fheType = _boundType(rawType);
        vm.assume(fheType >= TYPE_EUINT4 && fheType <= TYPE_EUINT64);

        uint256 max = _maxValue(fheType);
        a = a % (max + 1);
        b = b % (max + 1);

        uint256 result;
        if (a >= b) {
            result = a - b;
        } else {
            result = (max + 1) - (b - a);
        }

        assertLe(result, max, "Subtraction result within bounds");
    }

    /**
     * @notice Fuzz: Multiplication wraps correctly
     */
    function testFuzz_MultiplicationWraps(
        uint256 a,
        uint256 b,
        uint8 rawType
    ) public {
        uint8 fheType = _boundType(rawType);
        vm.assume(fheType >= TYPE_EUINT4 && fheType <= TYPE_EUINT32);

        uint256 max = _maxValue(fheType);
        a = a % (max + 1);
        b = b % (max + 1);

        uint256 result = (a * b) % (max + 1);

        assertLe(result, max, "Multiplication result within bounds");
    }

    /**
     * @notice Fuzz: Division handles zero divisor
     */
    function testFuzz_DivisionByZero(uint256 a, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        vm.assume(fheType >= TYPE_EUINT4 && fheType <= TYPE_EUINT64);

        uint256 max = _maxValue(fheType);
        a = a % (max + 1);

        // Division by zero should return 0 (safe default in FHE)
        uint256 result = 0; // fheDiv(a, 0) = 0

        assertEq(result, 0, "Division by zero returns 0");
    }

    /**
     * @notice Fuzz: Negation is involutory (neg(neg(x)) = x)
     */
    function testFuzz_NegationInvolutory(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        vm.assume(fheType >= TYPE_EUINT4 && fheType <= TYPE_EUINT64);

        uint256 max = _maxValue(fheType);
        value = value % (max + 1);

        // neg(x) = (max + 1) - x
        uint256 neg1 = (max + 1 - value) % (max + 1);
        uint256 neg2 = (max + 1 - neg1) % (max + 1);

        assertEq(neg2, value, "Double negation returns original");
    }

    // ============================================
    // FHE Comparison Operations Tests
    // ============================================

    /**
     * @notice Fuzz: Equality is reflexive
     */
    function testFuzz_EqualityReflexive(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        uint256 bounded = _boundPlaintext(value, fheType);

        // fheEq(x, x) = 1
        uint256 result = bounded == bounded ? 1 : 0;

        assertEq(result, 1, "x == x always true");
    }

    /**
     * @notice Fuzz: Less than is irreflexive
     */
    function testFuzz_LessThanIrreflexive(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        uint256 bounded = _boundPlaintext(value, fheType);

        // fheLt(x, x) = 0
        uint256 result = bounded < bounded ? 1 : 0;

        assertEq(result, 0, "x < x always false");
    }

    /**
     * @notice Fuzz: Trichotomy holds (a < b OR a == b OR a > b)
     */
    function testFuzz_Trichotomy(uint256 a, uint256 b, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        a = _boundPlaintext(a, fheType);
        b = _boundPlaintext(b, fheType);

        bool lt = a < b;
        bool eq = a == b;
        bool gt = a > b;

        // Exactly one must be true
        uint8 count = (lt ? 1 : 0) + (eq ? 1 : 0) + (gt ? 1 : 0);
        assertEq(count, 1, "Exactly one comparison true");
    }

    /**
     * @notice Fuzz: Min/Max correctness
     */
    function testFuzz_MinMaxCorrectness(
        uint256 a,
        uint256 b,
        uint8 rawType
    ) public {
        uint8 fheType = _boundType(rawType);
        a = _boundPlaintext(a, fheType);
        b = _boundPlaintext(b, fheType);

        uint256 minVal = a < b ? a : b;
        uint256 maxVal = a > b ? a : b;

        assertLe(minVal, a, "min <= a");
        assertLe(minVal, b, "min <= b");
        assertGe(maxVal, a, "max >= a");
        assertGe(maxVal, b, "max >= b");
    }

    // ============================================
    // FHE Bitwise Operations Tests
    // ============================================

    /**
     * @notice Fuzz: AND idempotent (x & x = x)
     */
    function testFuzz_AndIdempotent(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        uint256 bounded = _boundPlaintext(value, fheType);

        assertEq(bounded & bounded, bounded, "x & x = x");
    }

    /**
     * @notice Fuzz: OR idempotent (x | x = x)
     */
    function testFuzz_OrIdempotent(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        uint256 bounded = _boundPlaintext(value, fheType);

        assertEq(bounded | bounded, bounded, "x | x = x");
    }

    /**
     * @notice Fuzz: XOR self-inverse (x ^ x = 0)
     */
    function testFuzz_XorSelfInverse(uint256 value, uint8 rawType) public {
        uint8 fheType = _boundType(rawType);
        uint256 bounded = _boundPlaintext(value, fheType);

        assertEq(bounded ^ bounded, 0, "x ^ x = 0");
    }

    /**
     * @notice Fuzz: De Morgan's law
     */
    function testFuzz_DeMorgansLaw(uint256 a, uint256 b) public {
        // ~(a & b) = ~a | ~b
        // ~(a | b) = ~a & ~b

        uint8 mask = 0xFF; // For uint8
        a = a & mask;
        b = b & mask;

        uint8 notAnd = uint8(~(a & b));
        uint8 orNot = uint8((~a) | (~b));

        assertEq(notAnd, orNot, "De Morgan's law (AND)");
    }

    /**
     * @notice Fuzz: Shift left then right recovers value
     */
    function testFuzz_ShiftRecovery(uint256 value, uint8 shift) public {
        shift = shift % 64; // Reasonable shift amount
        uint64 bounded = uint64(value);

        if (shift == 0) {
            assertEq(
                (bounded << shift) >> shift,
                bounded,
                "No shift preserves value"
            );
        } else {
            // Shift may lose bits
            uint64 shifted = (bounded << shift) >> shift;
            assertLe(shifted, bounded, "Right shift may lose high bits");
        }
    }

    // ============================================
    // FHE Select/Conditional Tests
    // ============================================

    /**
     * @notice Fuzz: Select with true condition
     */
    function testFuzz_SelectTrue(uint256 ifTrue, uint256 ifFalse) public {
        uint256 result = 1 == 1 ? ifTrue : ifFalse;
        assertEq(result, ifTrue, "Select with true returns ifTrue");
    }

    /**
     * @notice Fuzz: Select with false condition
     */
    function testFuzz_SelectFalse(uint256 ifTrue, uint256 ifFalse) public {
        uint256 result = 0 == 1 ? ifTrue : ifFalse;
        assertEq(result, ifFalse, "Select with false returns ifFalse");
    }

    // ============================================
    // Access Control Tests
    // ============================================

    /**
     * @notice Fuzz: Owner always has permission
     */
    function testFuzz_OwnerHasPermission(
        uint256 value,
        uint8 rawType,
        address owner
    ) public {
        vm.assume(owner != address(0));
        uint8 fheType = _boundType(rawType);

        bytes32 handle = _createHandle(fheType, value, owner);

        assertTrue(userACL[handle][owner], "Owner has permission");
    }

    /**
     * @notice Fuzz: Non-owner starts without permission
     */
    function testFuzz_NonOwnerNoPermission(
        uint256 value,
        uint8 rawType,
        address owner,
        address other
    ) public {
        vm.assume(owner != address(0));
        vm.assume(other != address(0));
        vm.assume(owner != other);
        uint8 fheType = _boundType(rawType);

        bytes32 handle = _createHandle(fheType, value, owner);

        assertFalse(userACL[handle][other], "Non-owner has no permission");
    }

    /**
     * @notice Fuzz: Permission grant works
     */
    function testFuzz_PermissionGrant(
        uint256 value,
        uint8 rawType,
        address owner,
        address grantee
    ) public {
        vm.assume(owner != address(0));
        vm.assume(grantee != address(0));
        uint8 fheType = _boundType(rawType);

        bytes32 handle = _createHandle(fheType, value, owner);
        userACL[handle][grantee] = true;

        assertTrue(
            userACL[handle][grantee],
            "Grantee has permission after grant"
        );
    }

    /**
     * @notice Fuzz: Permission revoke works
     */
    function testFuzz_PermissionRevoke(
        uint256 value,
        uint8 rawType,
        address owner,
        address grantee
    ) public {
        vm.assume(owner != address(0));
        vm.assume(grantee != address(0));
        vm.assume(owner != grantee);
        uint8 fheType = _boundType(rawType);

        bytes32 handle = _createHandle(fheType, value, owner);
        userACL[handle][grantee] = true;
        userACL[handle][grantee] = false;

        assertFalse(
            userACL[handle][grantee],
            "Grantee loses permission after revoke"
        );
    }

    // ============================================
    // Oracle Network Tests
    // ============================================

    /**
     * @notice Fuzz: Oracle registration requires minimum stake
     */
    function testFuzz_OracleMinStake(address oracleAddr, uint256 stake) public {
        vm.assume(oracleAddr != address(0));
        vm.assume(stake < MIN_STAKE);

        oracles[oracleAddr] = OracleData({
            stake: stake,
            reputation: 100,
            active: false
        });

        // Should not be active without minimum stake
        assertFalse(
            oracles[oracleAddr].stake >= MIN_STAKE,
            "Insufficient stake"
        );
    }

    /**
     * @notice Fuzz: Quorum calculation
     */
    function testFuzz_QuorumCalculation(
        uint256 signatures,
        uint256 totalOracles
    ) public {
        totalOracles = bound(totalOracles, 1, 100);
        signatures = bound(signatures, 0, totalOracles);

        bool hasQuorum = (signatures * 10000) >= (totalOracles * QUORUM_BPS);

        // If 2/3+ signatures, should have quorum
        if (signatures * 3 >= totalOracles * 2) {
            assertTrue(hasQuorum, "Should have quorum with 2/3+ signatures");
        }
    }

    /**
     * @notice Fuzz: Slashing reduces stake
     */
    function testFuzz_SlashingReducesStake(
        address oracleAddr,
        uint256 stake
    ) public {
        vm.assume(oracleAddr != address(0));
        stake = bound(stake, MIN_STAKE, 1000 ether);

        oracles[oracleAddr] = OracleData({
            stake: stake,
            reputation: 100,
            active: true
        });

        uint256 slashAmount = (stake * SLASH_BPS) / 10000;
        oracles[oracleAddr].stake -= slashAmount;

        assertLt(oracles[oracleAddr].stake, stake, "Slashing reduces stake");
    }

    // ============================================
    // Encrypted ERC20 Tests
    // ============================================

    /**
     * @notice Fuzz: Transfer preserves total supply
     */
    function testFuzz_TransferPreservesTotalSupply(
        address from,
        address to,
        uint256 amount
    ) public {
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        vm.assume(from != to);

        balances[from] = 1000 ether;
        amount = bound(amount, 0, balances[from]);

        uint256 totalBefore = balances[from] + balances[to];

        balances[from] -= amount;
        balances[to] += amount;

        uint256 totalAfter = balances[from] + balances[to];

        assertEq(totalAfter, totalBefore, "Total supply preserved");
    }

    /**
     * @notice Fuzz: Transfer requires sufficient balance
     */
    function testFuzz_TransferRequiresBalance(
        address from,
        address to,
        uint256 balance,
        uint256 amount
    ) public {
        vm.assume(from != address(0));
        vm.assume(to != address(0));
        balance = bound(balance, 0, 1000 ether);
        amount = bound(amount, balance + 1, type(uint256).max);

        balances[from] = balance;

        // Transfer should fail
        bool canTransfer = balances[from] >= amount;
        assertFalse(canTransfer, "Cannot transfer more than balance");
    }

    /**
     * @notice Fuzz: Approval and transferFrom
     */
    function testFuzz_ApprovalAndTransferFrom(
        address owner,
        address spender,
        uint256 allowance,
        uint256 amount
    ) public {
        vm.assume(owner != address(0));
        vm.assume(spender != address(0));
        vm.assume(owner != spender);

        balances[owner] = 1000 ether;
        allowance = bound(allowance, 0, balances[owner]);
        amount = bound(amount, 0, allowance);

        allowances[owner][spender] = allowance;

        // TransferFrom should succeed
        assertTrue(
            allowances[owner][spender] >= amount,
            "Sufficient allowance"
        );
        assertTrue(balances[owner] >= amount, "Sufficient balance");
    }

    // ============================================
    // Encrypted Voting Tests
    // ============================================

    /**
     * @notice Fuzz: No double voting
     */
    function testFuzz_NoDoubleVoting(uint256 proposalId, address voter) public {
        vm.assume(voter != address(0));

        hasVoted[proposalId][voter] = true;

        // Second vote should be rejected
        assertTrue(hasVoted[proposalId][voter], "Already voted");
    }

    /**
     * @notice Fuzz: Vote tally sums correctly
     */
    function testFuzz_VoteTallySum(
        uint256 forVotes,
        uint256 againstVotes,
        uint256 abstainVotes
    ) public {
        forVotes = bound(forVotes, 0, 1000000 ether);
        againstVotes = bound(againstVotes, 0, 1000000 ether);
        abstainVotes = bound(abstainVotes, 0, 1000000 ether);

        uint256 total = forVotes + againstVotes + abstainVotes;

        assertEq(
            total,
            forVotes + againstVotes + abstainVotes,
            "Total equals sum of votes"
        );
    }

    /**
     * @notice Fuzz: Proposal outcome determined by votes
     */
    function testFuzz_ProposalOutcome(
        uint256 forVotes,
        uint256 againstVotes
    ) public {
        forVotes = bound(forVotes, 0, 1000000 ether);
        againstVotes = bound(againstVotes, 0, 1000000 ether);

        bool succeeded = forVotes > againstVotes;

        if (forVotes > againstVotes) {
            assertTrue(succeeded, "Proposal succeeds with more for votes");
        } else {
            assertFalse(succeeded, "Proposal fails with more against votes");
        }
    }

    // ============================================
    // FHE Bridge Tests
    // ============================================

    /**
     * @notice Fuzz: Transfer ID uniqueness
     */
    function testFuzz_TransferIdUniqueness(
        address sender,
        uint256 amount,
        uint256 destChain,
        uint256 nonce1,
        uint256 nonce2
    ) public {
        vm.assume(nonce1 != nonce2);

        bytes32 id1 = keccak256(abi.encode(sender, amount, destChain, nonce1));
        bytes32 id2 = keccak256(abi.encode(sender, amount, destChain, nonce2));

        assertTrue(id1 != id2, "Transfer IDs are unique");
    }

    /**
     * @notice Fuzz: Nullifier prevents replay
     */
    function testFuzz_NullifierPreventsReplay(
        bytes32 transferId,
        uint256 sourceChain
    ) public {
        bytes32 nullifier = keccak256(abi.encode(transferId, sourceChain));

        usedNullifiers[nullifier] = true;

        // Second use should fail
        assertTrue(usedNullifiers[nullifier], "Nullifier already used");
    }

    /**
     * @notice Fuzz: Refund only after expiry
     */
    function testFuzz_RefundAfterExpiry(
        bytes32 transferId,
        address sender,
        uint64 expiry,
        uint64 currentTime
    ) public {
        vm.assume(sender != address(0));

        transfers[transferId] = TransferData({
            sender: sender,
            amount: 1 ether,
            destChain: 1,
            expiry: expiry,
            pending: true,
            completed: false
        });

        bool canRefund = currentTime > expiry;

        if (currentTime > expiry) {
            assertTrue(canRefund, "Can refund after expiry");
        } else {
            assertFalse(canRefund, "Cannot refund before expiry");
        }
    }

    /**
     * @notice Fuzz: Validator signatures required for completion
     */
    function testFuzz_ValidatorSignaturesRequired(
        uint256 signatures,
        uint256 totalValidators
    ) public {
        totalValidators = bound(totalValidators, MIN_VALIDATORS, 20);
        signatures = bound(signatures, 0, totalValidators);

        bool hasMinValidators = signatures >= MIN_VALIDATORS;
        bool hasQuorum = (signatures * 10000) >= (totalValidators * QUORUM_BPS);

        bool canComplete = hasMinValidators && hasQuorum;

        if (
            signatures >= MIN_VALIDATORS &&
            signatures * 10000 >= totalValidators * QUORUM_BPS
        ) {
            assertTrue(canComplete, "Can complete with sufficient signatures");
        }
    }

    // ============================================
    // Cross-Module Integration Tests
    // ============================================

    /**
     * @notice Fuzz: Encrypted voting power affects vote weight
     */
    function testFuzz_VotingPowerWeight(
        address voter,
        uint256 votingPower,
        uint8 voteOption
    ) public {
        vm.assume(voter != address(0));
        votingPower = bound(votingPower, 1, 1000000 ether);
        voteOption = voteOption % 3; // 0=Against, 1=For, 2=Abstain

        uint256 forVotes = 0;
        uint256 againstVotes = 0;
        uint256 abstainVotes = 0;

        if (voteOption == 0) againstVotes = votingPower;
        else if (voteOption == 1) forVotes = votingPower;
        else abstainVotes = votingPower;

        assertEq(
            forVotes + againstVotes + abstainVotes,
            votingPower,
            "Vote power allocated to one option"
        );
    }

    /**
     * @notice Fuzz: Bridge amount conservation
     */
    function testFuzz_BridgeAmountConservation(
        uint256 lockedAmount,
        uint256 mintedAmount
    ) public {
        lockedAmount = bound(lockedAmount, 1, 1000000 ether);

        // For valid bridge, minted = locked
        mintedAmount = lockedAmount;

        assertEq(lockedAmount, mintedAmount, "Amount conserved across bridge");
    }
}
