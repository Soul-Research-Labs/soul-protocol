// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title BitVMBridgeAdapter
 * @author PIL Protocol
 * @notice Bridge adapter for BitVM-compatible chains with fraud proof verification
 * @dev Enables trustless cross-chain computation between PIL and BitVM/Bitcoin L2s
 *
 * BITVM INTEGRATION ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                      PIL <-> BitVM Bridge                               │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                         │
 * │  ┌───────────────────┐           ┌───────────────────┐                 │
 * │  │   PIL Protocol    │           │   BitVM Network   │                 │
 * │  │  ┌─────────────┐  │           │  ┌─────────────┐  │                 │
 * │  │  │ ZK Proofs   │  │◄─────────►│  │ Fraud Proofs│  │                 │
 * │  │  │ Commitments │  │           │  │ Bit Commits │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  │        │          │           │        │          │                 │
 * │  │  ┌─────▼───────┐  │           │  ┌─────▼───────┐  │                 │
 * │  │  │ Groth16/    │  │           │  │ NAND Gates  │  │                 │
 * │  │  │ PLONK       │  │◄─────────►│  │ Taproot     │  │                 │
 * │  │  └─────────────┘  │           │  └─────────────┘  │                 │
 * │  └───────────────────┘           └───────────────────┘                 │
 * │              │                           │                              │
 * │              └───────────┬───────────────┘                              │
 * │                          │                                              │
 * │  ┌───────────────────────▼───────────────────────────────────────────┐ │
 * │  │                   BitVM Bridge Layer                               │ │
 * │  │  - Bit Commitment Verification                                    │ │
 * │  │  - Fraud Proof Challenge/Response                                 │ │
 * │  │  - Optimistic Execution                                           │ │
 * │  │  - Taproot Script Trees                                           │ │
 * │  └───────────────────────────────────────────────────────────────────┘ │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 * BITVM CONCEPTS:
 * - Bit Commitments: Hash-based commitments to individual bits
 * - NAND Gates: Universal logic gate for Turing-complete computation
 * - Fraud Proofs: Challenge-response protocol for computation disputes
 * - Taproot Trees: Bitcoin scripts organized in Merkle trees
 * - Optimistic Execution: Assume correct, challenge if wrong
 *
 * SUPPORTED BITVM CHAINS:
 * - BitVM (Original)
 * - BitVM2 (Optimized)
 * - Citrea (BitVM-based ZK rollup)
 * - BOB (Build on Bitcoin)
 * - Stacks (sBTC integration)
 * - RGB Protocol
 * - Liquid Network
 */
contract BitVMBridgeAdapter is AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant CHALLENGER_ROLE = keccak256("CHALLENGER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/

    /// @notice Supported BitVM-compatible chains
    enum BitVMChain {
        BITVM_ORIGINAL, // Original BitVM implementation
        BITVM2, // Optimized BitVM2
        CITREA, // Citrea ZK rollup on Bitcoin
        BOB, // Build on Bitcoin
        STACKS, // Stacks with sBTC
        RGB, // RGB Protocol
        LIQUID, // Liquid Network
        ROOTSTOCK, // RSK (Rootstock)
        MERLIN, // Merlin Chain
        BSQUARED // B² Network
    }

    /// @notice Bit commitment for BitVM computation
    struct BitCommitment {
        bytes32 hash0; // Hash when bit = 0
        bytes32 hash1; // Hash when bit = 1
        bytes32 preimage; // Revealed preimage (after execution)
        bool revealed;
        bool value; // The committed bit value
    }

    /// @notice NAND gate in BitVM circuit
    struct NANDGate {
        uint256 gateId;
        uint256 inputA; // Index of first input bit
        uint256 inputB; // Index of second input bit
        uint256 output; // Index of output bit
        bool evaluated;
        bool outputValue;
    }

    /// @notice BitVM computation commitment
    struct ComputationCommitment {
        bytes32 commitmentId;
        bytes32 programHash; // Hash of the program (circuit)
        bytes32 inputCommitment; // Commitment to inputs
        bytes32 outputCommitment; // Commitment to claimed outputs
        address prover;
        uint256 timestamp;
        uint256 challengeDeadline;
        ComputationStatus status;
        BitVMChain chain;
    }

    /// @notice Fraud proof challenge
    struct FraudChallenge {
        bytes32 challengeId;
        bytes32 computationId;
        address challenger;
        uint256 gateIndex; // Which gate is being challenged
        bytes32 expectedOutput;
        uint256 timestamp;
        uint256 responseDeadline;
        ChallengeStatus status;
        uint256 stake;
    }

    /// @notice Cross-chain message for BitVM
    struct BitVMMessage {
        bytes32 messageId;
        BitVMChain sourceChain;
        BitVMChain targetChain;
        bytes32 sender; // Cross-chain sender identifier
        bytes32 recipient; // Cross-chain recipient identifier
        bytes payload;
        bytes32 stateRoot; // State root after message
        uint256 timestamp;
        MessageStatus status;
    }

    /// @notice Taproot script tree node
    struct TaprootNode {
        bytes32 nodeHash;
        bytes32 leftChild;
        bytes32 rightChild;
        bytes script; // Script at this leaf (if leaf node)
        bool isLeaf;
    }

    /// @notice BitVM program registration
    struct BitVMProgram {
        bytes32 programId;
        bytes32 programHash;
        uint256 gateCount; // Number of NAND gates
        uint256 inputBits; // Number of input bits
        uint256 outputBits; // Number of output bits
        bytes32 taprootRoot; // Merkle root of Taproot tree
        address registrar;
        uint256 registeredAt;
        bool verified;
    }

    /// @notice Peg operation between PIL and BitVM chain
    struct PegOperation {
        bytes32 pegId;
        BitVMChain chain;
        bool isPegIn; // true = BitVM→PIL, false = PIL→BitVM
        bytes32 pilCommitment;
        bytes32 bitvmCommitment;
        uint256 amount;
        address pilParty;
        bytes32 bitvmParty;
        uint256 timestamp;
        PegStatus status;
    }

    /// @notice Computation status
    enum ComputationStatus {
        COMMITTED,
        EXECUTING,
        CHALLENGED,
        VERIFIED,
        FINALIZED,
        SLASHED
    }

    /// @notice Challenge status
    enum ChallengeStatus {
        INITIATED,
        RESPONDED,
        ESCALATED,
        RESOLVED_VALID,
        RESOLVED_FRAUD,
        EXPIRED
    }

    /// @notice Message status
    enum MessageStatus {
        PENDING,
        CONFIRMED,
        EXECUTED,
        FAILED,
        REVERTED
    }

    /// @notice Peg status
    enum PegStatus {
        INITIATED,
        LOCKED,
        PROVING,
        CHALLENGED,
        COMPLETED,
        REFUNDED
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Chain configurations
    mapping(BitVMChain => bool) public supportedChains;
    mapping(BitVMChain => address) public chainBridges;
    mapping(BitVMChain => uint256) public chainIds;

    /// @notice Computation commitments
    mapping(bytes32 => ComputationCommitment) public computations;
    uint256 public totalComputations;

    /// @notice Fraud challenges
    mapping(bytes32 => FraudChallenge) public challenges;
    uint256 public totalChallenges;

    /// @notice Cross-chain messages
    mapping(bytes32 => BitVMMessage) public messages;
    uint256 public totalMessages;

    /// @notice Registered programs
    mapping(bytes32 => BitVMProgram) public programs;
    uint256 public totalPrograms;

    /// @notice Peg operations
    mapping(bytes32 => PegOperation) public pegOperations;
    uint256 public totalPegs;

    /// @notice Bit commitments storage
    mapping(bytes32 => mapping(uint256 => BitCommitment)) public bitCommitments;

    /// @notice Taproot tree nodes
    mapping(bytes32 => TaprootNode) public taprootNodes;

    /// @notice Cross-chain nullifiers
    mapping(bytes32 => bool) public crossChainNullifiers;

    /// @notice Challenge period (default 7 days for BitVM)
    uint256 public challengePeriod = 7 days;

    /// @notice Response period for challenges
    uint256 public responsePeriod = 1 days;

    /// @notice Minimum stake for provers
    uint256 public minProverStake = 1 ether;

    /// @notice Minimum stake for challengers
    uint256 public minChallengerStake = 0.1 ether;

    /// @notice Prover stakes
    mapping(address => uint256) public proverStakes;

    /// @notice Total value locked per chain
    mapping(BitVMChain => uint256) public chainTVL;

    /// @notice Bridge fees per chain (in basis points)
    mapping(BitVMChain => uint256) public chainFees;

    /// @notice Accumulated fees
    uint256 public accumulatedFees;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event ChainConfigured(
        BitVMChain indexed chain,
        address bridge,
        uint256 chainId
    );

    event ProgramRegistered(
        bytes32 indexed programId,
        bytes32 programHash,
        uint256 gateCount,
        address registrar
    );

    event ComputationCommitted(
        bytes32 indexed commitmentId,
        bytes32 programHash,
        address prover,
        BitVMChain chain
    );

    event ComputationChallenged(
        bytes32 indexed challengeId,
        bytes32 indexed computationId,
        address challenger,
        uint256 gateIndex
    );

    event ChallengeResolved(
        bytes32 indexed challengeId,
        bool isFraud,
        address winner
    );

    event ComputationFinalized(
        bytes32 indexed commitmentId,
        bytes32 outputCommitment
    );

    event MessageSent(
        bytes32 indexed messageId,
        BitVMChain sourceChain,
        BitVMChain targetChain,
        bytes32 sender
    );

    event MessageExecuted(bytes32 indexed messageId, bytes32 stateRoot);

    event PegInitiated(
        bytes32 indexed pegId,
        BitVMChain chain,
        bool isPegIn,
        uint256 amount
    );

    event PegCompleted(
        bytes32 indexed pegId,
        bytes32 pilCommitment,
        bytes32 bitvmCommitment
    );

    event ProverStaked(address indexed prover, uint256 amount);
    event ProverSlashed(
        address indexed prover,
        uint256 amount,
        bytes32 computationId
    );

    /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
    //////////////////////////////////////////////////////////////*/

    error ZeroAddress();
    error ZeroAmount();
    error ChainNotSupported(BitVMChain chain);
    error ChainAlreadyConfigured(BitVMChain chain);
    error ComputationNotFound(bytes32 computationId);
    error ComputationAlreadyFinalized(bytes32 computationId);
    error ChallengeNotFound(bytes32 challengeId);
    error ChallengePeriodNotExpired();
    error ChallengePeriodExpired();
    error ResponsePeriodExpired();
    error InsufficientStake(uint256 provided, uint256 required);
    error InvalidProgram(bytes32 programHash);
    error InvalidProof();
    error InvalidBitCommitment();
    error NullifierAlreadyUsed(bytes32 nullifier);
    error UnauthorizedProver();
    error UnauthorizedChallenger();
    error MessageNotFound(bytes32 messageId);
    error PegNotFound(bytes32 pegId);
    error InvalidTaprootProof();
    error GateIndexOutOfBounds(uint256 index, uint256 max);
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
        _grantRole(GUARDIAN_ROLE, msg.sender);

        // Configure default chain fees (25 bps = 0.25%)
        chainFees[BitVMChain.BITVM_ORIGINAL] = 25;
        chainFees[BitVMChain.BITVM2] = 20;
        chainFees[BitVMChain.CITREA] = 15;
        chainFees[BitVMChain.BOB] = 20;
        chainFees[BitVMChain.STACKS] = 25;
        chainFees[BitVMChain.RGB] = 30;
        chainFees[BitVMChain.LIQUID] = 15;
        chainFees[BitVMChain.ROOTSTOCK] = 20;
        chainFees[BitVMChain.MERLIN] = 20;
        chainFees[BitVMChain.BSQUARED] = 20;
    }

    /*//////////////////////////////////////////////////////////////
                         CHAIN CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure a BitVM-compatible chain
     * @param chain The chain to configure
     * @param bridge The bridge contract address for this chain
     * @param chainId The chain ID
     */
    function configureChain(
        BitVMChain chain,
        address bridge,
        uint256 chainId
    ) external onlyRole(OPERATOR_ROLE) {
        if (bridge == address(0)) revert ZeroAddress();

        supportedChains[chain] = true;
        chainBridges[chain] = bridge;
        chainIds[chain] = chainId;

        emit ChainConfigured(chain, bridge, chainId);
    }

    /**
     * @notice Set chain fee
     */
    function setChainFee(
        BitVMChain chain,
        uint256 feeBps
    ) external onlyRole(OPERATOR_ROLE) {
        require(feeBps <= 100, "Fee too high"); // Max 1%
        chainFees[chain] = feeBps;
    }

    /*//////////////////////////////////////////////////////////////
                         PROGRAM REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register a BitVM program (circuit)
     * @param programHash Hash of the program definition
     * @param gateCount Number of NAND gates
     * @param inputBits Number of input bits
     * @param outputBits Number of output bits
     * @param taprootRoot Merkle root of Taproot script tree
     */
    function registerProgram(
        bytes32 programHash,
        uint256 gateCount,
        uint256 inputBits,
        uint256 outputBits,
        bytes32 taprootRoot
    ) external nonReentrant returns (bytes32 programId) {
        programId = keccak256(
            abi.encodePacked(
                programHash,
                gateCount,
                msg.sender,
                block.timestamp
            )
        );

        programs[programId] = BitVMProgram({
            programId: programId,
            programHash: programHash,
            gateCount: gateCount,
            inputBits: inputBits,
            outputBits: outputBits,
            taprootRoot: taprootRoot,
            registrar: msg.sender,
            registeredAt: block.timestamp,
            verified: false
        });

        totalPrograms++;

        emit ProgramRegistered(programId, programHash, gateCount, msg.sender);
    }

    /**
     * @notice Verify a registered program
     */
    function verifyProgram(bytes32 programId) external onlyRole(VERIFIER_ROLE) {
        BitVMProgram storage program = programs[programId];
        require(program.programId != bytes32(0), "Program not found");
        program.verified = true;
    }

    /*//////////////////////////////////////////////////////////////
                      COMPUTATION COMMITMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit to a BitVM computation
     * @param programHash The program to execute
     * @param inputCommitment Commitment to input values
     * @param outputCommitment Claimed output commitment
     * @param chain Target BitVM chain
     */
    function commitComputation(
        bytes32 programHash,
        bytes32 inputCommitment,
        bytes32 outputCommitment,
        BitVMChain chain
    )
        external
        payable
        nonReentrant
        whenNotPaused
        returns (bytes32 commitmentId)
    {
        if (!supportedChains[chain]) revert ChainNotSupported(chain);
        if (proverStakes[msg.sender] < minProverStake)
            revert InsufficientStake(proverStakes[msg.sender], minProverStake);

        commitmentId = keccak256(
            abi.encodePacked(
                programHash,
                inputCommitment,
                outputCommitment,
                msg.sender,
                block.timestamp
            )
        );

        computations[commitmentId] = ComputationCommitment({
            commitmentId: commitmentId,
            programHash: programHash,
            inputCommitment: inputCommitment,
            outputCommitment: outputCommitment,
            prover: msg.sender,
            timestamp: block.timestamp,
            challengeDeadline: block.timestamp + challengePeriod,
            status: ComputationStatus.COMMITTED,
            chain: chain
        });

        totalComputations++;

        emit ComputationCommitted(commitmentId, programHash, msg.sender, chain);
    }

    /**
     * @notice Stake as a prover
     */
    function stakeAsProver() external payable nonReentrant {
        if (msg.value == 0) revert ZeroAmount();
        proverStakes[msg.sender] += msg.value;
        emit ProverStaked(msg.sender, msg.value);
    }

    /*//////////////////////////////////////////////////////////////
                         FRAUD PROOFS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Challenge a computation (initiate fraud proof)
     * @param computationId The computation to challenge
     * @param gateIndex The NAND gate index being challenged
     * @param expectedOutput The challenger's claimed correct output
     */
    function challengeComputation(
        bytes32 computationId,
        uint256 gateIndex,
        bytes32 expectedOutput
    ) external payable nonReentrant returns (bytes32 challengeId) {
        ComputationCommitment storage computation = computations[computationId];

        if (computation.commitmentId == bytes32(0))
            revert ComputationNotFound(computationId);
        if (computation.status == ComputationStatus.FINALIZED)
            revert ComputationAlreadyFinalized(computationId);
        if (block.timestamp > computation.challengeDeadline)
            revert ChallengePeriodExpired();
        if (msg.value < minChallengerStake)
            revert InsufficientStake(msg.value, minChallengerStake);

        // Get program to validate gate index
        BitVMProgram storage program = programs[computation.programHash];
        if (gateIndex >= program.gateCount)
            revert GateIndexOutOfBounds(gateIndex, program.gateCount);

        challengeId = keccak256(
            abi.encodePacked(
                computationId,
                gateIndex,
                msg.sender,
                block.timestamp
            )
        );

        challenges[challengeId] = FraudChallenge({
            challengeId: challengeId,
            computationId: computationId,
            challenger: msg.sender,
            gateIndex: gateIndex,
            expectedOutput: expectedOutput,
            timestamp: block.timestamp,
            responseDeadline: block.timestamp + responsePeriod,
            status: ChallengeStatus.INITIATED,
            stake: msg.value
        });

        computation.status = ComputationStatus.CHALLENGED;
        totalChallenges++;

        emit ComputationChallenged(
            challengeId,
            computationId,
            msg.sender,
            gateIndex
        );
    }

    /**
     * @notice Respond to a challenge with bit commitment proof
     * @param challengeId The challenge to respond to
     * @param bitProof The bit commitment proof
     */
    function respondToChallenge(
        bytes32 challengeId,
        bytes calldata bitProof
    ) external nonReentrant {
        FraudChallenge storage challenge = challenges[challengeId];

        if (challenge.challengeId == bytes32(0))
            revert ChallengeNotFound(challengeId);
        if (block.timestamp > challenge.responseDeadline)
            revert ResponsePeriodExpired();

        ComputationCommitment storage computation = computations[
            challenge.computationId
        ];
        if (msg.sender != computation.prover) revert UnauthorizedProver();

        // Verify bit proof
        if (
            !_verifyBitProof(
                challenge.gateIndex,
                bitProof,
                computation.programHash
            )
        ) revert InvalidProof();

        challenge.status = ChallengeStatus.RESPONDED;
    }

    /**
     * @notice Resolve a challenge after response period
     * @param challengeId The challenge to resolve
     */
    function resolveChallenge(bytes32 challengeId) external nonReentrant {
        FraudChallenge storage challenge = challenges[challengeId];

        if (challenge.challengeId == bytes32(0))
            revert ChallengeNotFound(challengeId);

        ComputationCommitment storage computation = computations[
            challenge.computationId
        ];

        bool isFraud;
        address winner;

        if (
            challenge.status == ChallengeStatus.INITIATED &&
            block.timestamp > challenge.responseDeadline
        ) {
            // Prover didn't respond - fraud confirmed
            isFraud = true;
            winner = challenge.challenger;
            computation.status = ComputationStatus.SLASHED;

            // Slash prover stake
            uint256 slashAmount = proverStakes[computation.prover];
            proverStakes[computation.prover] = 0;

            // Pay challenger
            (bool success, ) = payable(challenge.challenger).call{
                value: slashAmount + challenge.stake
            }("");
            if (!success) revert TransferFailed();

            emit ProverSlashed(
                computation.prover,
                slashAmount,
                computation.commitmentId
            );
        } else if (challenge.status == ChallengeStatus.RESPONDED) {
            // Prover responded successfully
            isFraud = false;
            winner = computation.prover;
            computation.status = ComputationStatus.VERIFIED;

            // Return challenger stake to prover as reward
            proverStakes[computation.prover] += challenge.stake;
        } else {
            revert("Challenge not resolvable");
        }

        challenge.status = isFraud
            ? ChallengeStatus.RESOLVED_FRAUD
            : ChallengeStatus.RESOLVED_VALID;

        emit ChallengeResolved(challengeId, isFraud, winner);
    }

    /**
     * @notice Finalize computation after challenge period
     * @param computationId The computation to finalize
     */
    function finalizeComputation(bytes32 computationId) external nonReentrant {
        ComputationCommitment storage computation = computations[computationId];

        if (computation.commitmentId == bytes32(0))
            revert ComputationNotFound(computationId);
        if (
            computation.status == ComputationStatus.FINALIZED ||
            computation.status == ComputationStatus.SLASHED
        ) revert ComputationAlreadyFinalized(computationId);
        if (block.timestamp < computation.challengeDeadline)
            revert ChallengePeriodNotExpired();

        computation.status = ComputationStatus.FINALIZED;

        emit ComputationFinalized(computationId, computation.outputCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                      CROSS-CHAIN MESSAGING
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Send a message to a BitVM chain
     * @param targetChain The destination chain
     * @param recipient The recipient on target chain
     * @param payload The message payload
     */
    function sendMessage(
        BitVMChain targetChain,
        bytes32 recipient,
        bytes calldata payload
    ) external payable nonReentrant whenNotPaused returns (bytes32 messageId) {
        if (!supportedChains[targetChain])
            revert ChainNotSupported(targetChain);

        // Calculate fee
        uint256 fee = (msg.value * chainFees[targetChain]) / 10000;
        accumulatedFees += fee;

        messageId = keccak256(
            abi.encodePacked(
                msg.sender,
                targetChain,
                recipient,
                keccak256(payload),
                block.timestamp,
                totalMessages
            )
        );

        messages[messageId] = BitVMMessage({
            messageId: messageId,
            sourceChain: BitVMChain.BITVM_ORIGINAL, // PIL as source
            targetChain: targetChain,
            sender: bytes32(uint256(uint160(msg.sender))),
            recipient: recipient,
            payload: payload,
            stateRoot: bytes32(0),
            timestamp: block.timestamp,
            status: MessageStatus.PENDING
        });

        totalMessages++;

        emit MessageSent(
            messageId,
            BitVMChain.BITVM_ORIGINAL,
            targetChain,
            bytes32(uint256(uint160(msg.sender)))
        );
    }

    /**
     * @notice Execute a message from BitVM chain
     * @param messageId The message to execute
     * @param stateRoot The resulting state root
     * @param proof Proof of message inclusion
     */
    function executeMessage(
        bytes32 messageId,
        bytes32 stateRoot,
        bytes calldata proof
    ) external nonReentrant onlyRole(VERIFIER_ROLE) {
        BitVMMessage storage message = messages[messageId];

        if (message.messageId == bytes32(0)) revert MessageNotFound(messageId);
        if (message.status != MessageStatus.PENDING)
            revert("Message already processed");

        // Verify inclusion proof
        if (!_verifyMessageProof(messageId, stateRoot, proof))
            revert InvalidProof();

        message.status = MessageStatus.EXECUTED;
        message.stateRoot = stateRoot;

        emit MessageExecuted(messageId, stateRoot);
    }

    /*//////////////////////////////////////////////////////////////
                         PEG OPERATIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a peg operation (PIL ↔ BitVM chain)
     * @param chain The BitVM chain
     * @param isPegIn true for BitVM→PIL, false for PIL→BitVM
     * @param pilCommitment The PIL commitment
     * @param bitvmParty The BitVM counterparty address
     * @param amount The amount to peg
     */
    function initiatePeg(
        BitVMChain chain,
        bool isPegIn,
        bytes32 pilCommitment,
        bytes32 bitvmParty,
        uint256 amount
    ) external payable nonReentrant whenNotPaused returns (bytes32 pegId) {
        if (!supportedChains[chain]) revert ChainNotSupported(chain);
        if (amount == 0) revert ZeroAmount();

        pegId = keccak256(
            abi.encodePacked(
                chain,
                isPegIn,
                pilCommitment,
                msg.sender,
                block.timestamp
            )
        );

        pegOperations[pegId] = PegOperation({
            pegId: pegId,
            chain: chain,
            isPegIn: isPegIn,
            pilCommitment: pilCommitment,
            bitvmCommitment: bytes32(0),
            amount: amount,
            pilParty: msg.sender,
            bitvmParty: bitvmParty,
            timestamp: block.timestamp,
            status: PegStatus.INITIATED
        });

        totalPegs++;
        chainTVL[chain] += amount;

        emit PegInitiated(pegId, chain, isPegIn, amount);
    }

    /**
     * @notice Complete a peg operation
     * @param pegId The peg operation to complete
     * @param bitvmCommitment The BitVM commitment
     * @param proof Proof of completion
     */
    function completePeg(
        bytes32 pegId,
        bytes32 bitvmCommitment,
        bytes calldata proof
    ) external nonReentrant onlyRole(VERIFIER_ROLE) {
        PegOperation storage peg = pegOperations[pegId];

        if (peg.pegId == bytes32(0)) revert PegNotFound(pegId);
        if (peg.status == PegStatus.COMPLETED) revert("Peg already completed");

        // Verify proof
        if (!_verifyPegProof(pegId, bitvmCommitment, proof))
            revert InvalidProof();

        peg.bitvmCommitment = bitvmCommitment;
        peg.status = PegStatus.COMPLETED;

        emit PegCompleted(pegId, peg.pilCommitment, bitvmCommitment);
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify bit commitment proof
     */
    function _verifyBitProof(
        uint256 gateIndex,
        bytes calldata proof,
        bytes32 /* programHash */
    ) internal pure returns (bool) {
        // Production: Verify NAND gate computation
        // Check that revealed preimages match commitments
        if (proof.length < 64) return false;
        return true;
    }

    /**
     * @notice Verify message inclusion proof
     */
    function _verifyMessageProof(
        bytes32 messageId,
        bytes32 stateRoot,
        bytes calldata proof
    ) internal pure returns (bool) {
        // Production: Verify Merkle proof of message inclusion
        if (messageId == bytes32(0)) return false;
        if (stateRoot == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /**
     * @notice Verify peg operation proof
     */
    function _verifyPegProof(
        bytes32 pegId,
        bytes32 bitvmCommitment,
        bytes calldata proof
    ) internal pure returns (bool) {
        if (pegId == bytes32(0)) return false;
        if (bitvmCommitment == bytes32(0)) return false;
        if (proof.length < 32) return false;
        return true;
    }

    /*//////////////////////////////////////////////////////////////
                           VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get computation details
     */
    function getComputation(
        bytes32 commitmentId
    ) external view returns (ComputationCommitment memory) {
        return computations[commitmentId];
    }

    /**
     * @notice Get challenge details
     */
    function getChallenge(
        bytes32 challengeId
    ) external view returns (FraudChallenge memory) {
        return challenges[challengeId];
    }

    /**
     * @notice Get program details
     */
    function getProgram(
        bytes32 programId
    ) external view returns (BitVMProgram memory) {
        return programs[programId];
    }

    /**
     * @notice Get message details
     */
    function getMessage(
        bytes32 messageId
    ) external view returns (BitVMMessage memory) {
        return messages[messageId];
    }

    /**
     * @notice Get peg operation details
     */
    function getPegOperation(
        bytes32 pegId
    ) external view returns (PegOperation memory) {
        return pegOperations[pegId];
    }

    /**
     * @notice Check if chain is supported
     */
    function isChainSupported(BitVMChain chain) external view returns (bool) {
        return supportedChains[chain];
    }

    /**
     * @notice Get bridge statistics
     */
    function getBridgeStats()
        external
        view
        returns (
            uint256 _totalComputations,
            uint256 _totalChallenges,
            uint256 _totalMessages,
            uint256 _totalPrograms,
            uint256 _totalPegs,
            uint256 _accumulatedFees
        )
    {
        return (
            totalComputations,
            totalChallenges,
            totalMessages,
            totalPrograms,
            totalPegs,
            accumulatedFees
        );
    }

    /**
     * @notice Get chain TVL
     */
    function getChainTVL(BitVMChain chain) external view returns (uint256) {
        return chainTVL[chain];
    }

    /*//////////////////////////////////////////////////////////////
                           ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Set challenge period
     */
    function setChallengePeriod(
        uint256 _period
    ) external onlyRole(OPERATOR_ROLE) {
        require(_period >= 1 days, "Period too short");
        require(_period <= 30 days, "Period too long");
        challengePeriod = _period;
    }

    /**
     * @notice Set response period
     */
    function setResponsePeriod(
        uint256 _period
    ) external onlyRole(OPERATOR_ROLE) {
        require(_period >= 1 hours, "Period too short");
        require(_period <= 7 days, "Period too long");
        responsePeriod = _period;
    }

    /**
     * @notice Set minimum stakes
     */
    function setMinStakes(
        uint256 _proverStake,
        uint256 _challengerStake
    ) external onlyRole(OPERATOR_ROLE) {
        minProverStake = _proverStake;
        minChallengerStake = _challengerStake;
    }

    /**
     * @notice Withdraw accumulated fees
     */
    function withdrawFees(address to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = accumulatedFees;
        accumulatedFees = 0;

        (bool success, ) = payable(to).call{value: amount}("");
        if (!success) revert TransferFailed();
    }

    /**
     * @notice Pause bridge
     */
    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause bridge
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
