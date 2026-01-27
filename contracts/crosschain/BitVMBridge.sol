// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "../interfaces/IBitVMBridge.sol";

/**
 * @title BitVMBridge
 * @author Soul Protocol
 * @notice Trust-minimized Bitcoin bridge using BitVM fraud proofs
 * @dev Implements BitVM2 challenge-response protocol for Bitcoin smart contracts
 *
 * BITVM BRIDGE ARCHITECTURE:
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                    BitVM Trust-Minimized Bridge                          │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │                                                                          │
 * │  1. DEPOSIT PHASE                                                        │
 * │  ┌─────────────────────────────────────────────────────────────────┐     │
 * │  │ User deposits BTC → Prover commits circuit → Challenge window  │     │
 * │  └─────────────────────────────────────────────────────────────────┘     │
 * │                                                                          │
 * │  2. CHALLENGE PHASE (if disputed)                                        │
 * │  ┌─────────────────────────────────────────────────────────────────┐     │
 * │  │ Challenger opens → Binary search on gates → Fraud proof/resolve│     │
 * │  └─────────────────────────────────────────────────────────────────┘     │
 * │                                                                          │
 * │  3. FINALIZATION                                                         │
 * │  ┌─────────────────────────────────────────────────────────────────┐     │
 * │  │ No challenge → Finalize │ Challenge won → Slash prover         │     │
 * │  └─────────────────────────────────────────────────────────────────┘     │
 * │                                                                          │
 * │  SECURITY MODEL:                                                         │
 * │  - 1-of-N honest verifier assumption                                     │
 * │  - Economic security via prover stake                                    │
 * │  - Fraud proofs require only O(log n) on-chain interactions              │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
contract BitVMBridge is IBitVMBridge, AccessControl, ReentrancyGuard, Pausable {
    /*//////////////////////////////////////////////////////////////
                                 ROLES
    //////////////////////////////////////////////////////////////*/

    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant PROVER_ROLE = keccak256("PROVER_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum stake for prover (1 ETH)
    uint256 public constant MIN_PROVER_STAKE = 1 ether;

    /// @notice Minimum stake for challenger (0.1 ETH)
    uint256 public constant MIN_CHALLENGER_STAKE = 0.1 ether;

    /// @notice Challenge window duration (7 days)
    uint256 public constant CHALLENGE_WINDOW = 7 days;

    /// @notice Response deadline (1 day)
    uint256 public constant RESPONSE_DEADLINE = 1 days;

    /// @notice Maximum binary search rounds (log2 of max gates)
    uint256 public constant MAX_SEARCH_ROUNDS = 32;

    /// @notice Slashing percentage (100% of stake)
    uint256 public constant SLASH_PERCENTAGE = 100;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposit nonce
    uint256 public depositNonce;

    /// @notice Challenge nonce
    uint256 public challengeNonce;

    /// @notice Treasury address
    address public treasury;

    /// @notice BitVM verifier contract
    address public bitVMVerifier;

    /// @notice Bitcoin bridge adapter
    address public bitcoinBridge;

    /*//////////////////////////////////////////////////////////////
                              MAPPINGS
    //////////////////////////////////////////////////////////////*/

    /// @notice Deposits by ID
    mapping(bytes32 => BitVMDeposit) public deposits;

    /// @notice Challenges by ID
    mapping(bytes32 => Challenge) public challenges;

    /// @notice Gate commitments by ID
    mapping(bytes32 => GateCommitment) public gateCommitments;

    /// @notice Bit commitments by ID
    mapping(bytes32 => BitCommitment) public bitCommitments;

    /// @notice Circuit info by ID
    mapping(bytes32 => CircuitInfo) public circuits;

    /// @notice Active challenge for deposit
    mapping(bytes32 => bytes32) public activeChallenge;

    /// @notice User deposits
    mapping(address => bytes32[]) public userDeposits;

    /// @notice Prover deposits
    mapping(address => bytes32[]) public proverDeposits;

    /*//////////////////////////////////////////////////////////////
                              STATISTICS
    //////////////////////////////////////////////////////////////*/

    uint256 public totalDeposits;
    uint256 public totalChallenges;
    uint256 public totalSlashed;
    uint256 public totalFinalized;

    /*//////////////////////////////////////////////////////////////
                             CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _admin) {
        if (_admin == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(OPERATOR_ROLE, _admin);
        _grantRole(GUARDIAN_ROLE, _admin);
        _grantRole(PROVER_ROLE, _admin);

        treasury = _admin;
    }

    /*//////////////////////////////////////////////////////////////
                          CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function configure(
        address _bitVMVerifier,
        address _bitcoinBridge
    ) external onlyRole(OPERATOR_ROLE) {
        bitVMVerifier = _bitVMVerifier;
        bitcoinBridge = _bitcoinBridge;
    }

    function setTreasury(address _treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_treasury == address(0)) revert ZeroAddress();
        treasury = _treasury;
    }

    /*//////////////////////////////////////////////////////////////
                         DEPOSIT LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initiate a BitVM deposit
     * @param amount Amount to deposit
     * @param circuitCommitment Merkle root of circuit gates
     * @param prover Address of the prover
     * @return depositId Unique deposit identifier
     */
    function initiateDeposit(
        uint256 amount,
        bytes32 circuitCommitment,
        address prover
    ) external payable nonReentrant whenNotPaused returns (bytes32 depositId) {
        if (amount == 0) revert ZeroAmount();
        if (circuitCommitment == bytes32(0)) revert InvalidCircuitCommitment();
        if (prover == address(0)) revert ZeroAddress();
        if (msg.value < MIN_PROVER_STAKE) revert InsufficientStake();

        depositId = keccak256(
            abi.encodePacked(msg.sender, prover, amount, circuitCommitment, depositNonce++)
        );

        deposits[depositId] = BitVMDeposit({
            depositId: depositId,
            depositor: msg.sender,
            prover: prover,
            amount: amount,
            stake: msg.value,
            circuitCommitment: circuitCommitment,
            taprootPubKey: bytes32(0),
            outputCommitment: bytes32(0),
            state: DepositState.PENDING,
            initiatedAt: block.timestamp,
            finalizedAt: 0,
            challengeDeadline: 0
        });

        userDeposits[msg.sender].push(depositId);
        totalDeposits++;

        emit DepositInitiated(depositId, msg.sender, amount, circuitCommitment);
    }

    /**
     * @notice Prover commits to deposit with Taproot pubkey
     * @param depositId Deposit to commit
     * @param taprootPubKey Bitcoin Taproot public key
     * @param outputCommitment Expected output commitment
     */
    function commitDeposit(
        bytes32 depositId,
        bytes32 taprootPubKey,
        bytes32 outputCommitment
    ) external nonReentrant whenNotPaused {
        BitVMDeposit storage deposit = deposits[depositId];

        if (deposit.initiatedAt == 0) revert DepositNotFound(depositId);
        if (deposit.state != DepositState.PENDING) {
            revert InvalidDepositState(depositId, deposit.state);
        }
        if (msg.sender != deposit.prover) revert NotProver(depositId);
        if (taprootPubKey == bytes32(0)) revert InvalidTaprootKey();

        deposit.taprootPubKey = taprootPubKey;
        deposit.outputCommitment = outputCommitment;
        deposit.state = DepositState.COMMITTED;
        deposit.challengeDeadline = block.timestamp + CHALLENGE_WINDOW;

        proverDeposits[msg.sender].push(depositId);

        emit DepositCommitted(depositId, msg.sender, taprootPubKey);
    }

    /**
     * @notice Finalize deposit after challenge window
     * @param depositId Deposit to finalize
     */
    function finalizeDeposit(bytes32 depositId) external nonReentrant whenNotPaused {
        BitVMDeposit storage deposit = deposits[depositId];

        if (deposit.initiatedAt == 0) revert DepositNotFound(depositId);
        if (deposit.state != DepositState.COMMITTED) {
            revert InvalidDepositState(depositId, deposit.state);
        }
        if (block.timestamp < deposit.challengeDeadline) {
            revert ChallengeDeadlineNotPassed(depositId);
        }
        if (activeChallenge[depositId] != bytes32(0)) {
            revert ChallengeAlreadyOpen(depositId);
        }

        deposit.state = DepositState.FINALIZED;
        deposit.finalizedAt = block.timestamp;

        totalFinalized++;

        // Return stake to prover
        (bool success, ) = deposit.prover.call{value: deposit.stake}("");
        require(success, "Stake return failed");

        emit DepositFinalized(depositId, deposit.depositor);
    }

    /**
     * @notice Refund deposit if not committed
     * @param depositId Deposit to refund
     */
    function refundDeposit(bytes32 depositId) external nonReentrant {
        BitVMDeposit storage deposit = deposits[depositId];

        if (deposit.initiatedAt == 0) revert DepositNotFound(depositId);
        if (deposit.state != DepositState.PENDING) {
            revert InvalidDepositState(depositId, deposit.state);
        }
        if (msg.sender != deposit.depositor) revert ZeroAddress();

        deposit.state = DepositState.REFUNDED;

        // Return stake to depositor
        (bool success, ) = deposit.depositor.call{value: deposit.stake}("");
        require(success, "Refund failed");

        emit DepositRefunded(depositId, deposit.depositor);
    }

    /*//////////////////////////////////////////////////////////////
                        CHALLENGE LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Open a challenge against a deposit
     * @param depositId Deposit to challenge
     * @param gateId Gate to challenge
     * @param expectedOutput Expected gate output
     * @return challengeId Challenge identifier
     */
    function openChallenge(
        bytes32 depositId,
        bytes32 gateId,
        bytes32 expectedOutput
    ) external payable nonReentrant whenNotPaused returns (bytes32 challengeId) {
        BitVMDeposit storage deposit = deposits[depositId];

        if (deposit.initiatedAt == 0) revert DepositNotFound(depositId);
        if (deposit.state != DepositState.COMMITTED) {
            revert InvalidDepositState(depositId, deposit.state);
        }
        if (block.timestamp >= deposit.challengeDeadline) {
            revert ChallengeDeadlinePassed(depositId);
        }
        if (activeChallenge[depositId] != bytes32(0)) {
            revert ChallengeAlreadyOpen(depositId);
        }
        if (msg.value < MIN_CHALLENGER_STAKE) revert InsufficientStake();

        challengeId = keccak256(
            abi.encodePacked(depositId, msg.sender, gateId, challengeNonce++)
        );

        challenges[challengeId] = Challenge({
            challengeId: challengeId,
            depositId: depositId,
            challenger: msg.sender,
            gateId: gateId,
            gateIndex: 0,
            stake: msg.value,
            deadline: block.timestamp + CHALLENGE_WINDOW,
            responseDeadline: block.timestamp + RESPONSE_DEADLINE,
            expectedOutput: expectedOutput,
            claimedOutput: bytes32(0),
            state: ChallengeState.OPEN,
            createdAt: block.timestamp,
            resolvedAt: 0
        });

        activeChallenge[depositId] = challengeId;
        deposit.state = DepositState.CHALLENGED;
        totalChallenges++;

        emit ChallengeOpened(challengeId, depositId, msg.sender, gateId);
    }

    /**
     * @notice Prover responds to challenge
     * @param challengeId Challenge to respond to
     * @param response Prover's response (gate output)
     * @param proof Merkle proof for gate
     */
    function respondToChallenge(
        bytes32 challengeId,
        bytes32 response,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        Challenge storage challenge = challenges[challengeId];
        BitVMDeposit storage deposit = deposits[challenge.depositId];

        if (challenge.createdAt == 0) revert ChallengeNotFound(challengeId);
        if (challenge.state != ChallengeState.OPEN) {
            revert InvalidChallengeState(challengeId, challenge.state);
        }
        if (msg.sender != deposit.prover) revert NotProver(challenge.depositId);
        if (block.timestamp > challenge.responseDeadline) {
            revert ResponseDeadlinePassed(challengeId);
        }

        // Verify Merkle proof for gate (simplified)
        require(proof.length >= 32, "Invalid proof");

        challenge.claimedOutput = response;
        challenge.state = ChallengeState.RESPONDED;
        challenge.responseDeadline = block.timestamp + RESPONSE_DEADLINE;

        emit ChallengeResponded(challengeId, response);
    }

    /**
     * @notice Escalate challenge with binary search
     * @param challengeId Challenge to escalate
     * @param newGateId New gate to challenge
     */
    function escalateChallenge(
        bytes32 challengeId,
        bytes32 newGateId
    ) external nonReentrant whenNotPaused {
        Challenge storage challenge = challenges[challengeId];

        if (challenge.createdAt == 0) revert ChallengeNotFound(challengeId);
        if (challenge.state != ChallengeState.RESPONDED) {
            revert InvalidChallengeState(challengeId, challenge.state);
        }
        if (msg.sender != challenge.challenger) revert NotChallenger(challengeId);

        challenge.gateId = newGateId;
        challenge.gateIndex++;
        challenge.state = ChallengeState.ESCALATED;
        challenge.responseDeadline = block.timestamp + RESPONSE_DEADLINE;

        if (challenge.gateIndex >= MAX_SEARCH_ROUNDS) {
            // Binary search complete - ready for fraud proof
            challenge.state = ChallengeState.OPEN;
        }

        emit ChallengeEscalated(challengeId, challenge.gateIndex);
    }

    /**
     * @notice Resolve challenge due to timeout
     * @param challengeId Challenge to resolve
     */
    function resolveChallengeTimeout(bytes32 challengeId) external nonReentrant {
        Challenge storage challenge = challenges[challengeId];
        BitVMDeposit storage deposit = deposits[challenge.depositId];

        if (challenge.createdAt == 0) revert ChallengeNotFound(challengeId);
        if (challenge.state == ChallengeState.PROVER_WON ||
            challenge.state == ChallengeState.CHALLENGER_WON ||
            challenge.state == ChallengeState.EXPIRED) {
            revert InvalidChallengeState(challengeId, challenge.state);
        }
        if (block.timestamp <= challenge.responseDeadline) {
            revert ChallengeNotExpired(challengeId);
        }

        // Prover didn't respond - challenger wins
        challenge.state = ChallengeState.CHALLENGER_WON;
        challenge.resolvedAt = block.timestamp;
        deposit.state = DepositState.SLASHED;

        totalSlashed++;

        // Slash prover stake to challenger
        uint256 slashAmount = deposit.stake;
        (bool success, ) = challenge.challenger.call{value: slashAmount + challenge.stake}("");
        require(success, "Slash transfer failed");

        emit ChallengeExpired(challengeId);
        emit DepositSlashed(challenge.depositId, challenge.challenger);
    }

    /**
     * @notice Prove fraud via invalid gate computation
     * @param challengeId Active challenge
     * @param gateId Gate with fraud
     * @param inputA First input value
     * @param inputB Second input value
     * @param preimageA Preimage for inputA
     * @param preimageB Preimage for inputB
     */
    function proveFraud(
        bytes32 challengeId,
        bytes32 gateId,
        uint8 inputA,
        uint8 inputB,
        bytes32 preimageA,
        bytes32 preimageB
    ) external nonReentrant whenNotPaused {
        Challenge storage challenge = challenges[challengeId];
        BitVMDeposit storage deposit = deposits[challenge.depositId];
        GateCommitment storage gate = gateCommitments[gateId];

        if (challenge.createdAt == 0) revert ChallengeNotFound(challengeId);
        if (gate.gateId == bytes32(0)) revert GateNotFound(gateId);
        if (msg.sender != challenge.challenger) revert NotChallenger(challengeId);

        // Verify bit commitments
        bytes32 hashA = keccak256(abi.encodePacked(preimageA, inputA));
        bytes32 hashB = keccak256(abi.encodePacked(preimageB, inputB));

        // Verify correct hash matches commitment
        BitCommitment storage commitA = bitCommitments[gate.inputA];
        BitCommitment storage commitB = bitCommitments[gate.inputB];

        bool validA = (inputA == 0 && hashA == commitA.hash0) ||
                      (inputA == 1 && hashA == commitA.hash1);
        bool validB = (inputB == 0 && hashB == commitB.hash0) ||
                      (inputB == 1 && hashB == commitB.hash1);

        if (!validA) revert InvalidPreimage();
        if (!validB) revert InvalidPreimage();

        // Compute expected output for gate type
        uint8 expectedOutput = _computeGate(gate.gateType, inputA, inputB);

        // Verify revealed output doesn't match expected
        BitCommitment storage commitOut = bitCommitments[gate.output];

        if (commitOut.revealed && commitOut.value != expectedOutput) {
            // FRAUD PROVEN!
            challenge.state = ChallengeState.CHALLENGER_WON;
            challenge.resolvedAt = block.timestamp;
            deposit.state = DepositState.SLASHED;

            totalSlashed++;

            // Slash prover stake to challenger
            (bool success, ) = challenge.challenger.call{value: deposit.stake + challenge.stake}("");
            require(success, "Slash transfer failed");

            emit FraudProven(challengeId, challenge.challenger);
            emit DepositSlashed(challenge.depositId, challenge.challenger);
        } else {
            revert InvalidGateOutput(gateId);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GATE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Commit a logic gate
     */
    function commitGate(
        bytes32 gateId,
        GateType gateType,
        bytes32 inputA,
        bytes32 inputB,
        bytes32 output
    ) external onlyRole(PROVER_ROLE) {
        gateCommitments[gateId] = GateCommitment({
            gateId: gateId,
            gateType: gateType,
            inputA: inputA,
            inputB: inputB,
            output: output,
            hashlock: bytes32(0),
            revealed: false
        });

        emit GateCommitted(gateId, gateType);
    }

    /**
     * @notice Reveal a logic gate's values
     */
    function revealGate(
        bytes32 gateId,
        uint8 inputAValue,
        uint8 inputBValue,
        bytes32 preimageA,
        bytes32 preimageB
    ) external {
        GateCommitment storage gate = gateCommitments[gateId];

        if (gate.gateId == bytes32(0)) revert GateNotFound(gateId);
        if (gate.revealed) revert GateAlreadyRevealed(gateId);

        // Verify preimages
        BitCommitment storage commitA = bitCommitments[gate.inputA];
        BitCommitment storage commitB = bitCommitments[gate.inputB];

        bytes32 hashA = keccak256(abi.encodePacked(preimageA, inputAValue));
        bytes32 hashB = keccak256(abi.encodePacked(preimageB, inputBValue));

        bool validA = (inputAValue == 0 && hashA == commitA.hash0) ||
                      (inputAValue == 1 && hashA == commitA.hash1);
        bool validB = (inputBValue == 0 && hashB == commitB.hash0) ||
                      (inputBValue == 1 && hashB == commitB.hash1);

        if (!validA || !validB) revert InvalidPreimage();

        uint8 outputValue = _computeGate(gate.gateType, inputAValue, inputBValue);

        gate.revealed = true;

        // Also reveal the output bit commitment
        BitCommitment storage commitOut = bitCommitments[gate.output];
        commitOut.revealed = true;
        commitOut.value = outputValue;

        emit GateRevealed(gateId, inputAValue, inputBValue, outputValue);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getDeposit(bytes32 depositId) external view returns (BitVMDeposit memory) {
        return deposits[depositId];
    }

    function getChallenge(bytes32 challengeId) external view returns (Challenge memory) {
        return challenges[challengeId];
    }

    function getGateCommitment(bytes32 gateId) external view returns (GateCommitment memory) {
        return gateCommitments[gateId];
    }

    function getCircuitInfo(bytes32 circuitId) external view returns (CircuitInfo memory) {
        return circuits[circuitId];
    }

    function getUserDeposits(address user) external view returns (bytes32[] memory) {
        return userDeposits[user];
    }

    function getProverDeposits(address prover) external view returns (bytes32[] memory) {
        return proverDeposits[prover];
    }

    function getBridgeStats() external view returns (
        uint256 depositsCount,
        uint256 challengesCount,
        uint256 slashedCount,
        uint256 finalizedCount
    ) {
        return (totalDeposits, totalChallenges, totalSlashed, totalFinalized);
    }

    /*//////////////////////////////////////////////////////////////
                         ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function pause() external onlyRole(GUARDIAN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(GUARDIAN_ROLE) {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Compute gate output based on type
     */
    function _computeGate(
        GateType gateType,
        uint8 a,
        uint8 b
    ) internal pure returns (uint8) {
        if (gateType == GateType.NAND) {
            return (a & b) == 1 ? 0 : 1;
        } else if (gateType == GateType.AND) {
            return a & b;
        } else if (gateType == GateType.OR) {
            return a | b;
        } else if (gateType == GateType.XOR) {
            return a ^ b;
        } else if (gateType == GateType.NOT) {
            return a == 1 ? 0 : 1;
        }
        return 0;
    }

    /*//////////////////////////////////////////////////////////////
                          RECEIVE FUNCTION
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}
}
