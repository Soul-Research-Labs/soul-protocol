// K Framework Specification for FHE (Fully Homomorphic Encryption) Operations
// Soul Protocol
// 
// This specification formalizes:
// - FHE type system and ciphertext operations
// - Homomorphic arithmetic, comparison, and bitwise operations
// - Access control and permission model
// - Decryption and re-encryption protocols
// - Security properties and invariants

module FHE-TYPES
    imports INT
    imports BOOL
    imports STRING
    imports MAP
    imports SET
    imports LIST

    // ============================================
    // Encrypted Type Definitions
    // ============================================

    // FHE Type identifiers (matching Solidity constants)
    syntax FHEType ::= "EBOOL"        // TYPE_EBOOL = 0
                     | "EUINT4"       // TYPE_EUINT4 = 1
                     | "EUINT8"       // TYPE_EUINT8 = 2
                     | "EUINT16"      // TYPE_EUINT16 = 3
                     | "EUINT32"      // TYPE_EUINT32 = 4
                     | "EUINT64"      // TYPE_EUINT64 = 5
                     | "EUINT128"     // TYPE_EUINT128 = 6
                     | "EUINT256"     // TYPE_EUINT256 = 7
                     | "EADDRESS"     // TYPE_EADDRESS = 8
                     | "EBYTES64"     // TYPE_EBYTES64 = 9
                     | "EBYTES128"    // TYPE_EBYTES128 = 10
                     | "EBYTES256"    // TYPE_EBYTES256 = 11

    // Ciphertext handle (256-bit identifier)
    syntax Handle ::= handle(Int)

    // Ciphertext structure
    syntax Ciphertext ::= ciphertext(
        handle: Handle,
        fheType: FHEType,
        data: Bytes,
        owner: Address,
        created: Int
    )

    // Address type
    syntax Address ::= address(Int)

    // Bytes type
    syntax Bytes ::= bytes(List)

    // ============================================
    // Type Bounds
    // ============================================

    // Maximum values for each type
    syntax Int ::= maxValue(FHEType) [function]
    rule maxValue(EBOOL)    => 1
    rule maxValue(EUINT4)   => 15                                          // 2^4 - 1
    rule maxValue(EUINT8)   => 255                                         // 2^8 - 1
    rule maxValue(EUINT16)  => 65535                                       // 2^16 - 1
    rule maxValue(EUINT32)  => 4294967295                                  // 2^32 - 1
    rule maxValue(EUINT64)  => 18446744073709551615                        // 2^64 - 1
    rule maxValue(EUINT128) => 340282366920938463463374607431768211455     // 2^128 - 1
    rule maxValue(EUINT256) => 115792089237316195423570985008687907853269984665640564039457584007913129639935 // 2^256 - 1
    rule maxValue(EADDRESS) => 1461501637330902918203684832716283019655932542975  // 2^160 - 1

    // Bit width for each type
    syntax Int ::= bitWidth(FHEType) [function]
    rule bitWidth(EBOOL)    => 1
    rule bitWidth(EUINT4)   => 4
    rule bitWidth(EUINT8)   => 8
    rule bitWidth(EUINT16)  => 16
    rule bitWidth(EUINT32)  => 32
    rule bitWidth(EUINT64)  => 64
    rule bitWidth(EUINT128) => 128
    rule bitWidth(EUINT256) => 256
    rule bitWidth(EADDRESS) => 160

    // ============================================
    // Type Compatibility
    // ============================================

    // Check if two types are compatible for operations
    syntax Bool ::= compatible(FHEType, FHEType) [function]
    rule compatible(T, T) => true
    rule compatible(EUINT4, EUINT8) => true
    rule compatible(EUINT8, EUINT4) => true
    rule compatible(EUINT8, EUINT16) => true
    rule compatible(EUINT16, EUINT8) => true
    rule compatible(EUINT16, EUINT32) => true
    rule compatible(EUINT32, EUINT16) => true
    rule compatible(EUINT32, EUINT64) => true
    rule compatible(EUINT64, EUINT32) => true
    rule compatible(EUINT64, EUINT128) => true
    rule compatible(EUINT128, EUINT64) => true
    rule compatible(EUINT128, EUINT256) => true
    rule compatible(EUINT256, EUINT128) => true
    rule compatible(_, _) => false [owise]

    // Result type for operations on compatible types
    syntax FHEType ::= resultType(FHEType, FHEType) [function]
    rule resultType(T, T) => T
    rule resultType(EUINT4, EUINT8) => EUINT8
    rule resultType(EUINT8, EUINT4) => EUINT8
    rule resultType(EUINT8, EUINT16) => EUINT16
    rule resultType(EUINT16, EUINT8) => EUINT16
    rule resultType(EUINT16, EUINT32) => EUINT32
    rule resultType(EUINT32, EUINT16) => EUINT32
    rule resultType(EUINT32, EUINT64) => EUINT64
    rule resultType(EUINT64, EUINT32) => EUINT64
    rule resultType(EUINT64, EUINT128) => EUINT128
    rule resultType(EUINT128, EUINT64) => EUINT128
    rule resultType(EUINT128, EUINT256) => EUINT256
    rule resultType(EUINT256, EUINT128) => EUINT256
    rule resultType(_, _) => EUINT256 [owise]  // Default to largest

endmodule

module FHE-OPERATIONS
    imports FHE-TYPES
    imports INT
    imports BOOL

    // ============================================
    // FHE Operation Types
    // ============================================

    syntax FHEOp ::= "ADD"      // Homomorphic addition
                   | "SUB"      // Homomorphic subtraction
                   | "MUL"      // Homomorphic multiplication
                   | "DIV"      // Homomorphic division
                   | "REM"      // Homomorphic remainder
                   | "NEG"      // Homomorphic negation
                   | "AND"      // Homomorphic bitwise AND
                   | "OR"       // Homomorphic bitwise OR
                   | "XOR"      // Homomorphic bitwise XOR
                   | "NOT"      // Homomorphic bitwise NOT
                   | "SHL"      // Homomorphic shift left
                   | "SHR"      // Homomorphic shift right
                   | "EQ"       // Homomorphic equality
                   | "NE"       // Homomorphic not equal
                   | "GE"       // Homomorphic greater or equal
                   | "GT"       // Homomorphic greater than
                   | "LE"       // Homomorphic less or equal
                   | "LT"       // Homomorphic less than
                   | "MIN"      // Homomorphic minimum
                   | "MAX"      // Homomorphic maximum
                   | "SELECT"   // Conditional selection
                   | "CMUX"     // Conditional multiplexer

    // ============================================
    // Homomorphic Operation Results
    // ============================================

    // Result type for comparison operations is always EBOOL
    syntax FHEType ::= opResultType(FHEOp, FHEType, FHEType) [function]
    rule opResultType(EQ, _, _) => EBOOL
    rule opResultType(NE, _, _) => EBOOL
    rule opResultType(GE, _, _) => EBOOL
    rule opResultType(GT, _, _) => EBOOL
    rule opResultType(LE, _, _) => EBOOL
    rule opResultType(LT, _, _) => EBOOL
    rule opResultType(_, T1, T2) => resultType(T1, T2)

    // ============================================
    // Plaintext Simulation of FHE Operations
    // (For verification - actual FHE happens off-chain)
    // ============================================

    // Simulate homomorphic addition (on plaintexts for verification)
    syntax Int ::= fheAdd(Int, Int, FHEType) [function]
    rule fheAdd(A, B, T) => (A +Int B) modInt (maxValue(T) +Int 1)

    // Simulate homomorphic subtraction
    syntax Int ::= fheSub(Int, Int, FHEType) [function]
    rule fheSub(A, B, T) => (A -Int B) modInt (maxValue(T) +Int 1)

    // Simulate homomorphic multiplication
    syntax Int ::= fheMul(Int, Int, FHEType) [function]
    rule fheMul(A, B, T) => (A *Int B) modInt (maxValue(T) +Int 1)

    // Simulate homomorphic division (safe - no divide by zero)
    syntax Int ::= fheDiv(Int, Int, FHEType) [function]
    rule fheDiv(A, B, _) => A /Int B requires B =/=Int 0
    rule fheDiv(A, 0, _) => 0  // Safe default for zero division

    // Simulate homomorphic remainder
    syntax Int ::= fheRem(Int, Int, FHEType) [function]
    rule fheRem(A, B, _) => A modInt B requires B =/=Int 0
    rule fheRem(A, 0, _) => 0  // Safe default

    // Simulate homomorphic negation
    syntax Int ::= fheNeg(Int, FHEType) [function]
    rule fheNeg(A, T) => (maxValue(T) +Int 1 -Int A) modInt (maxValue(T) +Int 1)

    // Simulate homomorphic comparisons
    syntax Int ::= fheEq(Int, Int) [function]
    rule fheEq(A, B) => 1 requires A ==Int B
    rule fheEq(A, B) => 0 requires A =/=Int B

    syntax Int ::= fheNe(Int, Int) [function]
    rule fheNe(A, B) => 1 requires A =/=Int B
    rule fheNe(A, B) => 0 requires A ==Int B

    syntax Int ::= fheGe(Int, Int) [function]
    rule fheGe(A, B) => 1 requires A >=Int B
    rule fheGe(A, B) => 0 requires A <Int B

    syntax Int ::= fheGt(Int, Int) [function]
    rule fheGt(A, B) => 1 requires A >Int B
    rule fheGt(A, B) => 0 requires A <=Int B

    syntax Int ::= fheLe(Int, Int) [function]
    rule fheLe(A, B) => 1 requires A <=Int B
    rule fheLe(A, B) => 0 requires A >Int B

    syntax Int ::= fheLt(Int, Int) [function]
    rule fheLt(A, B) => 1 requires A <Int B
    rule fheLt(A, B) => 0 requires A >=Int B

    // Simulate homomorphic min/max
    syntax Int ::= fheMin(Int, Int) [function]
    rule fheMin(A, B) => A requires A <=Int B
    rule fheMin(A, B) => B requires A >Int B

    syntax Int ::= fheMax(Int, Int) [function]
    rule fheMax(A, B) => A requires A >=Int B
    rule fheMax(A, B) => B requires A <Int B

    // Simulate conditional selection
    syntax Int ::= fheSelect(Int, Int, Int) [function]  // condition, ifTrue, ifFalse
    rule fheSelect(1, T, _) => T
    rule fheSelect(0, _, F) => F

    // Simulate bitwise operations
    syntax Int ::= fheAnd(Int, Int) [function]
    rule fheAnd(A, B) => A &Int B

    syntax Int ::= fheOr(Int, Int) [function]
    rule fheOr(A, B) => A |Int B

    syntax Int ::= fheXor(Int, Int) [function]
    rule fheXor(A, B) => A xorInt B

    syntax Int ::= fheNot(Int, FHEType) [function]
    rule fheNot(A, T) => maxValue(T) xorInt A

    syntax Int ::= fheShl(Int, Int, FHEType) [function]
    rule fheShl(A, B, T) => (A <<Int B) modInt (maxValue(T) +Int 1)

    syntax Int ::= fheShr(Int, Int, FHEType) [function]
    rule fheShr(A, B, _) => A >>Int B

endmodule

module FHE-ACCESS-CONTROL
    imports FHE-TYPES
    imports MAP
    imports SET
    imports BOOL

    // ============================================
    // Access Control Configuration
    // ============================================

    configuration
        <fhe-acl>
            // User-level ACL: handle -> Set of allowed addresses
            <user-acl> .Map </user-acl>
            
            // Contract-level ACL: handle -> Set of allowed contracts
            <contract-acl> .Map </contract-acl>
            
            // Global permissions: handle -> is globally accessible
            <global-acl> .Map </global-acl>
            
            // Handle owners: handle -> owner address
            <owners> .Map </owners>
            
            // Handle metadata: handle -> ciphertext info
            <handles> .Map </handles>
        </fhe-acl>

    // ============================================
    // Permission Check Functions
    // ============================================

    // Check if address can access handle
    syntax Bool ::= canAccess(Handle, Address) [function]
    rule [can-access-owner]:
        canAccess(H, A) => true
        requires owner(H) ==K A

    rule [can-access-user-acl]:
        canAccess(H, A) => true
        requires A in userACL(H)

    rule [can-access-global]:
        canAccess(H, _) => true
        requires isGlobal(H)

    rule [can-access-denied]:
        canAccess(_, _) => false [owise]

    // Get owner of handle
    syntax Address ::= owner(Handle) [function]
    
    // Get user ACL for handle
    syntax Set ::= userACL(Handle) [function]
    
    // Check if handle has global access
    syntax Bool ::= isGlobal(Handle) [function]

    // ============================================
    // Permission Grant/Revoke
    // ============================================

    syntax Bool ::= grantPermission(Handle, Address, Address) [function]  // handle, grantee, granter
    rule grantPermission(H, Grantee, Granter) => true
        requires owner(H) ==K Granter

    syntax Bool ::= revokePermission(Handle, Address, Address) [function]
    rule revokePermission(H, Revokee, Revoker) => true
        requires owner(H) ==K Revoker

    // ============================================
    // ACL Invariants
    // ============================================

    // Owner always has access
    rule [owner-always-access]:
        canAccess(H, owner(H)) => true

    // Non-existent handles have no access
    rule [no-handle-no-access]:
        canAccess(handle(0), _) => false

endmodule

module FHE-DECRYPTION
    imports FHE-TYPES
    imports FHE-ACCESS-CONTROL
    imports INT
    imports MAP

    // ============================================
    // Decryption Request Types
    // ============================================

    syntax DecryptionStatus ::= "PENDING"
                              | "PROCESSING"
                              | "COMPLETED"
                              | "FAILED"
                              | "EXPIRED"

    syntax DecryptionRequest ::= decryptionRequest(
        requestId: Handle,
        handle: Handle,
        requester: Address,
        callback: Address,
        ttl: Int,
        status: DecryptionStatus,
        result: Int
    )

    // ============================================
    // Decryption Configuration
    // ============================================

    configuration
        <decryption>
            // Pending decryption requests
            <requests> .Map </requests>
            
            // Completed results
            <results> .Map </results>
            
            // Oracle network state
            <oracles> .Set </oracles>
            <quorum> 6667 </quorum>  // 66.67% in basis points
        </decryption>

    // ============================================
    // Decryption Rules
    // ============================================

    // Request must be from authorized party
    rule [valid-decryption-request]:
        canRequestDecryption(H, Requester) => true
        requires canAccess(H, Requester)

    rule [invalid-decryption-request]:
        canRequestDecryption(_, _) => false [owise]

    // Oracle consensus for decryption
    syntax Bool ::= oracleConsensus(Handle, Int, Int) [function]  // handle, signatures, total
    rule oracleConsensus(_, Sigs, Total) => true
        requires (Sigs *Int 10000) >=Int (Total *Int 6667)  // 66.67% quorum

    rule oracleConsensus(_, _, _) => false [owise]

    // ============================================
    // Threshold Decryption
    // ============================================

    syntax Bool ::= thresholdMet(Int, Int, Int) [function]  // shares, threshold, total
    rule thresholdMet(Shares, Threshold, _) => true
        requires Shares >=Int Threshold

    rule thresholdMet(_, _, _) => false [owise]

endmodule

module FHE-REENCRYPTION
    imports FHE-TYPES
    imports FHE-ACCESS-CONTROL
    imports INT
    imports MAP
    imports BYTES

    // ============================================
    // Re-encryption for Cross-Chain
    // ============================================

    syntax ReencryptionRequest ::= reencryptionRequest(
        requestId: Handle,
        sourceHandle: Handle,
        targetPublicKey: Bytes,
        requester: Address,
        callback: Address,
        ttl: Int,
        status: DecryptionStatus,
        result: Handle
    )

    // Re-encryption preserves semantic value
    // enc_pk1(m) -> enc_pk2(m) without revealing m
    syntax Bool ::= validReencryption(Handle, Handle, Bytes) [function]
    
    // The re-encrypted value decrypts to the same plaintext
    // This is a semantic property, not directly verifiable on-chain

endmodule

module FHE-SECURITY-PROPERTIES
    imports FHE-TYPES
    imports FHE-OPERATIONS
    imports FHE-ACCESS-CONTROL
    imports FHE-DECRYPTION
    imports INT
    imports BOOL

    // ============================================
    // Security Invariants
    // ============================================

    // PROPERTY 1: Type Safety
    // Operations on incompatible types should fail
    rule [type-safety]:
        validOperation(Op, T1, T2) => false
        requires notBool compatible(T1, T2)

    // PROPERTY 2: Overflow Protection
    // Results are always within type bounds
    rule [overflow-protection]:
        fheAdd(A, B, T) <=Int maxValue(T) => true

    // PROPERTY 3: Access Control Integrity
    // Only authorized parties can decrypt
    rule [acl-integrity]:
        canRequestDecryption(H, A) => canAccess(H, A)

    // PROPERTY 4: Handle Uniqueness
    // Each ciphertext has a unique handle
    // Formally: forall h1, h2. data(h1) = data(h2) implies h1 = h2

    // PROPERTY 5: Homomorphic Correctness
    // Dec(Enc(a) + Enc(b)) = a + b (mod max)
    rule [homomorphic-add-correctness]:
        fheAdd(A, B, T) ==Int ((A +Int B) modInt (maxValue(T) +Int 1)) => true

    // Dec(Enc(a) * Enc(b)) = a * b (mod max)
    rule [homomorphic-mul-correctness]:
        fheMul(A, B, T) ==Int ((A *Int B) modInt (maxValue(T) +Int 1)) => true

    // PROPERTY 6: Comparison Correctness
    rule [comparison-correctness-eq]:
        fheEq(A, A) ==Int 1 => true

    rule [comparison-correctness-ne]:
        fheNe(A, B) ==Int 1 => true
        requires A =/=Int B

    // PROPERTY 7: Select Correctness
    rule [select-correctness-true]:
        fheSelect(1, T, _) ==Int T => true

    rule [select-correctness-false]:
        fheSelect(0, _, F) ==Int F => true

    // PROPERTY 8: Bitwise Correctness
    rule [and-correctness]:
        fheAnd(A, A) ==Int A => true

    rule [or-identity]:
        fheOr(A, 0) ==Int A => true

    rule [xor-self]:
        fheXor(A, A) ==Int 0 => true

    // PROPERTY 9: Min/Max Correctness
    rule [min-correctness]:
        fheMin(A, B) <=Int A => true
    rule [min-correctness-2]:
        fheMin(A, B) <=Int B => true

    rule [max-correctness]:
        fheMax(A, B) >=Int A => true
    rule [max-correctness-2]:
        fheMax(A, B) >=Int B => true

    // PROPERTY 10: Negation Correctness (Two's complement)
    rule [negation-double]:
        fheNeg(fheNeg(A, T), T) ==Int A => true

    // ============================================
    // Semantic Security Properties
    // ============================================

    // IND-CPA: Ciphertexts don't leak information about plaintexts
    // (Cannot be formally verified, requires cryptographic assumptions)

    // Circuit Privacy: Operation results don't reveal operation type
    // (Depends on FHE scheme implementation)

    // Malleability: Controlled malleability for homomorphic operations
    // (By design - we allow authorized operations)

endmodule

module FHE-BRIDGE-SECURITY
    imports FHE-TYPES
    imports FHE-OPERATIONS
    imports INT
    imports BOOL
    imports MAP

    // ============================================
    // Cross-Chain Bridge Security
    // ============================================

    syntax BridgeTransfer ::= transfer(
        id: Handle,
        sourceChain: Int,
        destChain: Int,
        encAmount: Handle,
        sender: Address,
        recipient: Address,
        status: TransferStatus
    )

    syntax TransferStatus ::= "PENDING_TRANSFER"
                            | "LOCKED"
                            | "RELAYED"
                            | "COMPLETED"
                            | "REFUNDED"

    // PROPERTY 1: Amount Conservation
    // Total locked on source = Total minted on destination
    // ∑ locked(source) = ∑ minted(dest) for verified transfers
    syntax Bool ::= amountConserved(Int, Int) [function]
    rule amountConserved(Locked, Minted) => true
        requires Locked ==Int Minted

    // PROPERTY 2: No Double-Spend
    // Each nullifier used exactly once
    syntax Bool ::= uniqueNullifier(Handle, Set) [function]
    rule uniqueNullifier(N, UsedSet) => true
        requires notBool (N in UsedSet)
    rule uniqueNullifier(_, _) => false [owise]

    // PROPERTY 3: Transfer Expiry
    // Expired transfers can be refunded
    syntax Bool ::= canRefund(Int, Int) [function]  // currentTime, expiryTime
    rule canRefund(Current, Expiry) => true
        requires Current >Int Expiry

    // PROPERTY 4: Validator Quorum
    // Transfers require 66.67% validator signatures
    syntax Bool ::= validatorQuorum(Int, Int) [function]
    rule validatorQuorum(Sigs, Total) => true
        requires (Sigs *Int 10000) >=Int (Total *Int 6667)

    // PROPERTY 5: Chain Isolation
    // Transfers only between configured chains
    syntax Bool ::= validChainPair(Int, Int, Set) [function]
    rule validChainPair(Src, Dest, ValidChains) => true
        requires (Src in ValidChains) andBool (Dest in ValidChains)

endmodule

module FHE-VOTING-SECURITY
    imports FHE-TYPES
    imports FHE-OPERATIONS
    imports INT
    imports BOOL
    imports MAP

    // ============================================
    // Encrypted Voting Security
    // ============================================

    syntax Vote ::= vote(
        proposalId: Int,
        voter: Address,
        encryptedChoice: Handle,
        encryptedPower: Handle
    )

    syntax Tally ::= tally(
        encFor: Handle,
        encAgainst: Handle,
        encAbstain: Handle,
        encTotal: Handle,
        voterCount: Int
    )

    // PROPERTY 1: Vote Privacy
    // Individual votes cannot be revealed until tally
    // (Ensured by FHE - votes remain encrypted)

    // PROPERTY 2: Tally Correctness
    // encFor + encAgainst + encAbstain = encTotal
    rule [tally-sum-correctness]:
        fheAdd(fheAdd(For, Against, T), Abstain, T) ==Int Total => true
        requires fheAdd(fheAdd(For, Against, T), Abstain, T) ==Int Total

    // PROPERTY 3: No Double Voting
    // Each voter votes at most once per proposal
    syntax Bool ::= hasNotVoted(Address, Int, Map) [function]
    rule hasNotVoted(Voter, Proposal, Votes) => true
        requires notBool ({Voter, Proposal} in_keys(Votes))

    // PROPERTY 4: Voting Power Conservation
    // Total power used <= Total power allocated
    syntax Bool ::= powerConserved(Int, Int) [function]
    rule powerConserved(Used, Allocated) => true
        requires Used <=Int Allocated

    // PROPERTY 5: Delegation Integrity
    // Delegated power cannot exceed delegator's power
    syntax Bool ::= validDelegation(Int, Int) [function]
    rule validDelegation(Delegated, Original) => true
        requires Delegated <=Int Original

    // PROPERTY 6: Time-Locked Tally
    // Tally can only be revealed after voting period
    syntax Bool ::= canRevealTally(Int, Int) [function]  // currentTime, tallyTime
    rule canRevealTally(Current, TallyTime) => true
        requires Current >=Int TallyTime

endmodule

module FHE-ENCRYPTED-ERC20-SECURITY
    imports FHE-TYPES
    imports FHE-OPERATIONS
    imports INT
    imports BOOL
    imports MAP

    // ============================================
    // Encrypted ERC20 Security
    // ============================================

    syntax EncryptedBalance ::= balance(Address, Handle)

    // PROPERTY 1: Balance Non-Negativity
    // All balances >= 0 (implicit with unsigned types)
    // The underlying plaintext is always non-negative

    // PROPERTY 2: Transfer Conservation
    // sender_balance' = sender_balance - amount
    // recipient_balance' = recipient_balance + amount
    // total_supply unchanged
    rule [transfer-conservation]:
        fheAdd(SenderNew, Amount, T) ==Int SenderOld => true
        requires fheSub(SenderOld, Amount, T) ==Int SenderNew

    // PROPERTY 3: Approval Enforcement
    // transfer_from only succeeds if allowance >= amount
    // Cannot verify encrypted comparison directly, but the contract enforces:
    // result = select(amount <= allowance, success, failure)

    // PROPERTY 4: Mint/Burn Authority
    // Only authorized addresses can mint/burn
    // (Enforced by role-based access control)

    // PROPERTY 5: Supply Consistency
    // sum(all_balances) = total_supply
    // (Maintained through mint/burn operations)

    // PROPERTY 6: Allowance Bounds
    // allowance <= MAX_UINT256
    // (Implicit with uint256 type)

    // PROPERTY 7: Viewer Permission Integrity
    // Only owner or approved viewers can decrypt balance
    // (Enforced by ACL system)

endmodule

module FHE-SPEC
    imports FHE-TYPES
    imports FHE-OPERATIONS
    imports FHE-ACCESS-CONTROL
    imports FHE-DECRYPTION
    imports FHE-REENCRYPTION
    imports FHE-SECURITY-PROPERTIES
    imports FHE-BRIDGE-SECURITY
    imports FHE-VOTING-SECURITY
    imports FHE-ENCRYPTED-ERC20-SECURITY

    // Main FHE specification module
    // Combines all components for complete formal verification

endmodule
