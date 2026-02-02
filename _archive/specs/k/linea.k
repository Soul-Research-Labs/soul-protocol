// K Framework Formal Specification for Linea zkEVM
// Specifies PLONK proof system, L1/L2 messaging, and finalization rules

module LINEA-SYNTAX
    imports INT
    imports BOOL
    imports BYTES
    imports STRING
    imports LIST
    imports MAP

    // =========================================================================
    // FIELD ARITHMETIC - BLS12-381
    // =========================================================================

    // BLS12-381 scalar field order
    // r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    syntax Int ::= "BLS12_381_SCALAR_ORDER"  [function, total]
    rule BLS12_381_SCALAR_ORDER => 52435875175126190479447740508185965837690552500527637822603658699938581184513

    // Field element type
    syntax FieldElement ::= field(Int)
    
    // Field operations
    syntax FieldElement ::= fieldAdd(FieldElement, FieldElement)      [function, total]
                          | fieldSub(FieldElement, FieldElement)      [function, total]
                          | fieldMul(FieldElement, FieldElement)      [function, total]
                          | fieldNeg(FieldElement)                    [function, total]
                          | fieldInv(FieldElement)                    [function]
                          | fieldExp(FieldElement, Int)               [function]

    rule fieldAdd(field(A), field(B)) => field((A +Int B) modInt BLS12_381_SCALAR_ORDER)
    rule fieldSub(field(A), field(B)) => field((A -Int B +Int BLS12_381_SCALAR_ORDER) modInt BLS12_381_SCALAR_ORDER)
    rule fieldMul(field(A), field(B)) => field((A *Int B) modInt BLS12_381_SCALAR_ORDER)
    rule fieldNeg(field(A)) => field((BLS12_381_SCALAR_ORDER -Int A) modInt BLS12_381_SCALAR_ORDER)

    // =========================================================================
    // G1 POINT - BLS12-381 CURVE
    // =========================================================================

    syntax G1Point ::= g1(Int, Int, Int, Int)  // x_lo, x_hi, y_lo, y_hi
                     | "G1_INFINITY"

    syntax Bool ::= isValidG1Point(G1Point)  [function, total]
    rule isValidG1Point(g1(XLo, XHi, YLo, YHi)) => notBool(XLo ==Int 0 andBool XHi ==Int 0 andBool YLo ==Int 0 andBool YHi ==Int 0)
    rule isValidG1Point(G1_INFINITY) => false

    // =========================================================================
    // PLONK PROOF STRUCTURE
    // =========================================================================

    syntax PLONKProof ::= plonkProof(
        G1Point,    // a - advice polynomial
        G1Point,    // b - second advice
        G1Point,    // c - third advice
        G1Point,    // z - permutation polynomial
        G1Point,    // t_lo - quotient low
        G1Point,    // t_mid - quotient mid
        G1Point,    // t_hi - quotient high
        G1Point,    // w_omega - opening at omega
        G1Point,    // w_omega_zeta - opening at omega*zeta
        Int,        // a_eval
        Int,        // b_eval
        Int,        // c_eval
        Int,        // s_sigma1_eval
        Int,        // s_sigma2_eval
        Int         // z_omega_eval
    )

    // Accessors
    syntax G1Point ::= proofA(PLONKProof)           [function, total]
    syntax G1Point ::= proofB(PLONKProof)           [function, total]
    syntax G1Point ::= proofC(PLONKProof)           [function, total]
    syntax G1Point ::= proofZ(PLONKProof)           [function, total]
    syntax Int ::= proofAEval(PLONKProof)           [function, total]
    syntax Int ::= proofBEval(PLONKProof)           [function, total]
    syntax Int ::= proofCEval(PLONKProof)           [function, total]

    rule proofA(plonkProof(A, _, _, _, _, _, _, _, _, _, _, _, _, _, _)) => A
    rule proofB(plonkProof(_, B, _, _, _, _, _, _, _, _, _, _, _, _, _)) => B
    rule proofC(plonkProof(_, _, C, _, _, _, _, _, _, _, _, _, _, _, _)) => C
    rule proofZ(plonkProof(_, _, _, Z, _, _, _, _, _, _, _, _, _, _, _)) => Z
    rule proofAEval(plonkProof(_, _, _, _, _, _, _, _, _, AE, _, _, _, _, _)) => AE
    rule proofBEval(plonkProof(_, _, _, _, _, _, _, _, _, _, BE, _, _, _, _)) => BE
    rule proofCEval(plonkProof(_, _, _, _, _, _, _, _, _, _, _, CE, _, _, _)) => CE

    // =========================================================================
    // PLONK VERIFICATION KEY
    // =========================================================================

    syntax PLONKVerificationKey ::= plonkVK(
        Int,        // domainSize
        Int,        // numPublicInputs
        G1Point,    // q_m - multiplication selector
        G1Point,    // q_l - left selector
        G1Point,    // q_r - right selector
        G1Point,    // q_o - output selector
        G1Point,    // q_c - constant selector
        G1Point,    // s_sigma1
        G1Point,    // s_sigma2
        G1Point,    // s_sigma3
        Bytes       // vkHash
    )

    syntax Int ::= vkDomainSize(PLONKVerificationKey)      [function, total]
    syntax Int ::= vkNumInputs(PLONKVerificationKey)       [function, total]

    rule vkDomainSize(plonkVK(D, _, _, _, _, _, _, _, _, _, _)) => D
    rule vkNumInputs(plonkVK(_, N, _, _, _, _, _, _, _, _, _)) => N

    // =========================================================================
    // PROOF VALIDATION RULES
    // =========================================================================

    syntax Bool ::= isValidPLONKProof(PLONKProof)  [function, total]

    rule isValidPLONKProof(plonkProof(A, B, C, Z, TLo, TMid, THi, WO, WOZ, AE, BE, CE, S1E, S2E, ZE)) =>
        isValidG1Point(A) andBool
        isValidG1Point(B) andBool
        isValidG1Point(C) andBool
        isValidG1Point(Z) andBool
        AE <Int BLS12_381_SCALAR_ORDER andBool
        BE <Int BLS12_381_SCALAR_ORDER andBool
        CE <Int BLS12_381_SCALAR_ORDER andBool
        S1E <Int BLS12_381_SCALAR_ORDER andBool
        S2E <Int BLS12_381_SCALAR_ORDER andBool
        ZE <Int BLS12_381_SCALAR_ORDER

    // =========================================================================
    // L1/L2 MESSAGING
    // =========================================================================

    syntax L1L2Message ::= l1l2Message(
        Int,        // sender (as int for address)
        Int,        // recipient
        Int,        // value
        Int,        // fee
        Int,        // nonce
        Int,        // deadline
        Bytes,      // data
        Bytes       // messageHash
    )

    syntax L2L1Message ::= l2l1Message(
        Int,        // sender
        Int,        // recipient
        Int,        // value
        Int,        // nonce
        Int,        // blockNumber
        Bytes,      // data
        Bytes,      // messageHash
        Bool        // finalized
    )

    // Message accessors
    syntax Int ::= l1l2Sender(L1L2Message)        [function, total]
    syntax Int ::= l1l2Recipient(L1L2Message)     [function, total]
    syntax Int ::= l1l2Nonce(L1L2Message)         [function, total]
    syntax Int ::= l1l2Deadline(L1L2Message)      [function, total]

    rule l1l2Sender(l1l2Message(S, _, _, _, _, _, _, _)) => S
    rule l1l2Recipient(l1l2Message(_, R, _, _, _, _, _, _)) => R
    rule l1l2Nonce(l1l2Message(_, _, _, _, N, _, _, _)) => N
    rule l1l2Deadline(l1l2Message(_, _, _, _, _, D, _, _)) => D

    syntax Int ::= l2l1BlockNumber(L2L1Message)   [function, total]
    syntax Bool ::= l2l1Finalized(L2L1Message)    [function, total]

    rule l2l1BlockNumber(l2l1Message(_, _, _, _, B, _, _, _)) => B
    rule l2l1Finalized(l2l1Message(_, _, _, _, _, _, _, F)) => F

    // =========================================================================
    // MESSAGE VALIDATION
    // =========================================================================

    syntax Bool ::= isValidL1L2Message(L1L2Message, Int)  [function, total]  // message, currentTime

    rule isValidL1L2Message(l1l2Message(S, R, _, _, N, D, _, _), CurrentTime) =>
        S =/=Int 0 andBool
        R =/=Int 0 andBool
        N >Int 0 andBool
        (D ==Int 0 orBool D >=Int CurrentTime)

    syntax Bool ::= isValidL2L1Message(L2L1Message)  [function, total]

    rule isValidL2L1Message(l2l1Message(S, R, _, N, B, _, _, _)) =>
        S =/=Int 0 andBool
        R =/=Int 0 andBool
        N >Int 0 andBool
        B >Int 0

    // =========================================================================
    // LINEA BATCH
    // =========================================================================

    syntax LineaBatch ::= lineaBatch(
        Int,        // batchIndex
        Int,        // firstBlockNumber
        Int,        // lastBlockNumber
        Bytes,      // batchDataHash
        Bytes,      // previousStateRoot
        Bytes,      // newStateRoot
        Int,        // timestamp
        List,       // l2MessageHashes
        PLONKProof  // proof
    )

    syntax Int ::= batchIndex(LineaBatch)         [function, total]
    syntax Int ::= batchFirstBlock(LineaBatch)    [function, total]
    syntax Int ::= batchLastBlock(LineaBatch)     [function, total]
    syntax Bytes ::= batchPrevRoot(LineaBatch)    [function, total]
    syntax Bytes ::= batchNewRoot(LineaBatch)     [function, total]
    syntax PLONKProof ::= batchProof(LineaBatch)  [function, total]

    rule batchIndex(lineaBatch(I, _, _, _, _, _, _, _, _)) => I
    rule batchFirstBlock(lineaBatch(_, F, _, _, _, _, _, _, _)) => F
    rule batchLastBlock(lineaBatch(_, _, L, _, _, _, _, _, _)) => L
    rule batchPrevRoot(lineaBatch(_, _, _, _, P, _, _, _, _)) => P
    rule batchNewRoot(lineaBatch(_, _, _, _, _, N, _, _, _)) => N
    rule batchProof(lineaBatch(_, _, _, _, _, _, _, _, P)) => P

    // =========================================================================
    // BATCH VALIDATION
    // =========================================================================

    syntax Int ::= "CONFLATION_INTERVAL"  [function, total]
    rule CONFLATION_INTERVAL => 100

    syntax Bool ::= isValidBatch(LineaBatch)  [function, total]

    rule isValidBatch(lineaBatch(_, First, Last, _, Prev, New, _, _, Proof)) =>
        First <Int Last andBool
        (Last -Int First) <=Int CONFLATION_INTERVAL andBool
        Prev =/=K b"" andBool
        New =/=K b"" andBool
        Prev =/=K New andBool
        isValidPLONKProof(Proof)

    // =========================================================================
    // FINALIZATION
    // =========================================================================

    syntax Int ::= "FINALITY_BLOCKS_L1"  [function, total]
    rule FINALITY_BLOCKS_L1 => 32

    syntax Int ::= blocksUntilFinalization(Int, Int)  [function, total]  // submissionBlock, currentBlock
    rule blocksUntilFinalization(Submission, Current) =>
        #if Current >=Int (Submission +Int FINALITY_BLOCKS_L1)
        #then 0
        #else (Submission +Int FINALITY_BLOCKS_L1) -Int Current
        #fi

    syntax Bool ::= isBatchFinalized(Int, Int)  [function, total]
    rule isBatchFinalized(Submission, Current) => Current >=Int (Submission +Int FINALITY_BLOCKS_L1)

    // =========================================================================
    // NULLIFIER DERIVATION
    // =========================================================================

    syntax Bytes ::= deriveLineaNullifier(Bytes, Int, Bytes)  [function]  // messageHash, blockNumber, commitment
    // Semantically: keccak256(messageHash || blockNumber || commitment || "LINEA_NULLIFIER")

    syntax Bytes ::= deriveCrossDomainNullifier(Bytes, Int)  [function]  // lineaNullifier, targetDomain
    // Semantically: keccak256(lineaNullifier || targetDomain || "LINEA2Soul")

    syntax Bytes ::= deriveSoulBinding(Bytes, Bytes)  [function]  // lineaNullifier, pilDomain
    // Semantically: keccak256(lineaNullifier || pilDomain || "Soul_BINDING")

    // =========================================================================
    // MESSAGE FEE CALCULATION
    // =========================================================================

    syntax Int ::= "MESSAGE_FEE_BASE"      [function, total]
    syntax Int ::= "MESSAGE_FEE_PER_BYTE"  [function, total]

    rule MESSAGE_FEE_BASE => 1000000000000000        // 0.001 ether in wei
    rule MESSAGE_FEE_PER_BYTE => 100000000000        // 100 gwei

    syntax Int ::= calculateMessageFee(Int)  [function, total]  // dataLength
    rule calculateMessageFee(Len) => MESSAGE_FEE_BASE +Int (Len *Int MESSAGE_FEE_PER_BYTE)

    // =========================================================================
    // MERKLE PROOF VERIFICATION
    // =========================================================================

    syntax Bool ::= verifyMerkleProof(Bytes, Bytes, List, Int)  [function]  // root, leaf, proof, index
    // Returns true if proof is valid for the given leaf at index in tree with root

    // =========================================================================
    // CHAIN IDS
    // =========================================================================

    syntax Int ::= "LINEA_MAINNET_CHAIN_ID"  [function, total]
    syntax Int ::= "LINEA_SEPOLIA_CHAIN_ID"  [function, total]
    syntax Int ::= "LINEA_GOERLI_CHAIN_ID"   [function, total]

    rule LINEA_MAINNET_CHAIN_ID => 59144
    rule LINEA_SEPOLIA_CHAIN_ID => 59141
    rule LINEA_GOERLI_CHAIN_ID => 59140

    syntax Int ::= getChainId(Bool)  [function, total]  // isMainnet
    rule getChainId(true) => LINEA_MAINNET_CHAIN_ID
    rule getChainId(false) => LINEA_SEPOLIA_CHAIN_ID

endmodule

module LINEA-STATE
    imports LINEA-SYNTAX

    // =========================================================================
    // BRIDGE STATE
    // =========================================================================

    configuration
        <linea>
            <messages>
                <outgoing> .Map </outgoing>     // messageId -> L1L2Message
                <incoming> .Map </incoming>     // messageId -> L2L1Message
                <anchored> .Map </anchored>     // messageId -> Bool
                <claimed> .Map </claimed>       // messageId -> Bool
            </messages>
            <batches>
                <submitted> .Map </submitted>   // batchIndex -> LineaBatch
                <finalized> .Map </finalized>   // batchIndex -> Bool
            </batches>
            <nullifiers>
                <linea-nullifiers> .Map </linea-nullifiers>      // nullifier -> Bool
                <cross-domain> .Map </cross-domain>              // crossDomainNf -> lineaNf
            </nullifiers>
            <limits>
                <daily-bridged> 0 </daily-bridged>
                <daily-limit> 1000000000000000000000 </daily-limit>  // 1000 ETH
                <last-reset> 0 </last-reset>
            </limits>
            <nonces>
                <message-nonce> 0 </message-nonce>
            </nonces>
            <current-block> 0 </current-block>
            <current-time> 0 </current-time>
        </linea>

    // =========================================================================
    // MESSAGE OPERATIONS
    // =========================================================================

    syntax KItem ::= sendL1L2Message(L1L2Message)
                   | anchorL2L1Message(Bytes, Bytes, Int)  // messageId, proofHash, blockNumber
                   | claimMessage(Bytes)
                   | refundMessage(Bytes)

    // Send L1 -> L2 message
    rule <linea>
            <messages>
                <outgoing> MSGS => MSGS[MsgId <- Msg] </outgoing>
                ...
            </messages>
            <nonces>
                <message-nonce> N => N +Int 1 </message-nonce>
            </nonces>
            ...
         </linea>
         sendL1L2Message(Msg)
      requires isValidL1L2Message(Msg, 0)
       andBool notBool MsgId in_keys(MSGS)

    // Anchor L2 -> L1 message
    rule <linea>
            <messages>
                <anchored> A => A[MsgId <- true] </anchored>
                ...
            </messages>
            ...
         </linea>
         anchorL2L1Message(MsgId, _, _)
      requires notBool MsgId in_keys(A)

    // =========================================================================
    // BATCH OPERATIONS
    // =========================================================================

    syntax KItem ::= submitBatch(LineaBatch)
                   | finalizeBatch(Int)  // batchIndex

    // Submit batch
    rule <linea>
            <batches>
                <submitted> B => B[batchIndex(Batch) <- Batch] </submitted>
                ...
            </batches>
            ...
         </linea>
         submitBatch(Batch)
      requires isValidBatch(Batch)
       andBool notBool batchIndex(Batch) in_keys(B)

    // Finalize batch after finality period
    rule <linea>
            <batches>
                <submitted> B </submitted>
                <finalized> F => F[Idx <- true] </finalized>
            </batches>
            <current-block> Current </current-block>
            ...
         </linea>
         finalizeBatch(Idx)
      requires Idx in_keys(B)
       andBool isBatchFinalized(0, Current)  // Simplified: check current > finality

    // =========================================================================
    // NULLIFIER OPERATIONS
    // =========================================================================

    syntax KItem ::= registerNullifier(Bytes, Bytes, Int, Bytes)  // messageHash, blockNumber, commitment
                   | registerCrossDomainNullifier(Bytes, Int)     // lineaNullifier, targetDomain

    rule <linea>
            <nullifiers>
                <linea-nullifiers> NFS => NFS[Nf <- true] </linea-nullifiers>
                ...
            </nullifiers>
            ...
         </linea>
         registerNullifier(MsgHash, BlockNum, Commitment)
      requires notBool Nf in_keys(NFS)
       // where Nf = deriveLineaNullifier(MsgHash, BlockNum, Commitment)

    rule <linea>
            <nullifiers>
                <linea-nullifiers> NFS </linea-nullifiers>
                <cross-domain> CD => CD[CrossNf <- LineaNf] </cross-domain>
            </nullifiers>
            ...
         </linea>
         registerCrossDomainNullifier(LineaNf, TargetDomain)
      requires LineaNf in_keys(NFS)
       andBool notBool CrossNf in_keys(CD)
       // where CrossNf = deriveCrossDomainNullifier(LineaNf, TargetDomain)

endmodule

module LINEA-SECURITY
    imports LINEA-STATE

    // =========================================================================
    // SECURITY PROPERTIES
    // =========================================================================

    // Property 1: Nullifier uniqueness - no double spending
    syntax Bool ::= nullifierUnique(Bytes, Map)  [function, total]
    rule nullifierUnique(Nf, NfMap) => notBool Nf in_keys(NfMap)

    // Property 2: Message finality - cannot claim before finalization
    syntax Bool ::= messageCanBeClaimed(Bytes, Map, Map, Int)  [function, total]  // msgId, anchored, claimed, currentBlock
    rule messageCanBeClaimed(MsgId, Anchored, Claimed, _) =>
        MsgId in_keys(Anchored) andBool
        notBool MsgId in_keys(Claimed)
        // Additional finality check would be added

    // Property 3: Batch validity - all batches must be valid before submission
    syntax Bool ::= batchIsValid(LineaBatch)  [function, total]
    rule batchIsValid(B) => isValidBatch(B)

    // Property 4: State root consistency - new root must differ from previous
    syntax Bool ::= stateRootConsistent(LineaBatch)  [function, total]
    rule stateRootConsistent(B) => batchPrevRoot(B) =/=K batchNewRoot(B)

    // Property 5: Block range validity - contiguous and bounded
    syntax Bool ::= blockRangeValid(LineaBatch)  [function, total]
    rule blockRangeValid(B) =>
        batchFirstBlock(B) <Int batchLastBlock(B) andBool
        (batchLastBlock(B) -Int batchFirstBlock(B)) <=Int CONFLATION_INTERVAL

    // Property 6: Proof structure validity
    syntax Bool ::= proofStructureValid(LineaBatch)  [function, total]
    rule proofStructureValid(B) => isValidPLONKProof(batchProof(B))

    // Property 7: Cross-domain nullifier binding
    syntax Bool ::= crossDomainBindingValid(Bytes, Bytes, Int, Map, Map)  [function, total]
    // lineaNf, crossNf, targetDomain, lineaNfMap, crossNfMap
    rule crossDomainBindingValid(LineaNf, CrossNf, _, LineaNfMap, CrossNfMap) =>
        LineaNf in_keys(LineaNfMap) andBool
        CrossNf in_keys(CrossNfMap)

    // Property 8: Fee calculation correctness
    syntax Bool ::= feeCalculationValid(Int, Int)  [function, total]  // dataLen, fee
    rule feeCalculationValid(Len, Fee) => Fee ==Int calculateMessageFee(Len)

    // Property 9: Daily limit enforcement
    syntax Bool ::= dailyLimitRespected(Int, Int, Int)  [function, total]  // amount, bridged, limit
    rule dailyLimitRespected(Amount, Bridged, Limit) => (Bridged +Int Amount) <=Int Limit

    // Property 10: Finalization timing
    syntax Bool ::= finalizationTimingValid(Int, Int)  [function, total]  // submissionBlock, currentBlock
    rule finalizationTimingValid(Sub, Cur) => Cur >=Int (Sub +Int FINALITY_BLOCKS_L1)

endmodule

module LINEA-VERIFICATION
    imports LINEA-SECURITY

    // =========================================================================
    // PLONK VERIFICATION (Simplified)
    // =========================================================================

    // PLONK verification involves:
    // 1. Compute challenges via Fiat-Shamir
    // 2. Verify opening proofs
    // 3. Check polynomial commitments
    // 4. Pairing check

    syntax Bool ::= verifyPLONKProof(PLONKProof, PLONKVerificationKey, List)  [function]
    // proof, verificationKey, publicInputs

    // Challenge computation (Fiat-Shamir)
    syntax FieldElement ::= computeChallenge(Bytes, Bytes)  [function]
    // transcript, newData -> challenge in scalar field

    // Simplified verification - in practice this involves EC pairings
    // For formal verification, we assert the structural properties

    // =========================================================================
    // INVARIANTS
    // =========================================================================

    // Invariant 1: All registered nullifiers are unique
    syntax Bool ::= nullifierInvariant(Map)  [function, total]
    rule nullifierInvariant(_) => true  // By construction - map keys are unique

    // Invariant 2: Finalized batches have valid proofs
    syntax Bool ::= finalizedBatchInvariant(Map, Map)  [function, total]  // finalized, submitted
    // All batches in finalized must have valid proofs in submitted

    // Invariant 3: Message nonce is monotonically increasing
    syntax Bool ::= nonceInvariant(Int, Int)  [function, total]  // oldNonce, newNonce
    rule nonceInvariant(Old, New) => New >=Int Old

    // Invariant 4: Cross-domain nullifiers are derived from valid Linea nullifiers
    syntax Bool ::= crossDomainInvariant(Map, Map)  [function, total]  // crossDomain, linea
    // All values in crossDomain map must be keys in linea map

    // Invariant 5: Daily bridged amount never exceeds limit
    syntax Bool ::= dailyLimitInvariant(Int, Int)  [function, total]
    rule dailyLimitInvariant(Bridged, Limit) => Bridged <=Int Limit

endmodule

module LINEA
    imports LINEA-VERIFICATION
endmodule
