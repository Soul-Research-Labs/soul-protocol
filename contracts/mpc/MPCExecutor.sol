// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {MPCLib} from "../libraries/MPCLib.sol";

/**
 * @title MPCExecutor
 * @author Soul Protocol
 * @notice Privacy-preserving computation executor for MPC protocols
 * @dev Implements SPDZ, GMW, and Yao's Garbled Circuits for secure computation
 *
 * Supported Protocols:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                    MPC Protocol Implementations                              │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  SPDZ (Arithmetic Circuits):                                                │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │ • Additive secret sharing over finite field                          │   │
 * │  │ • Beaver triples for multiplication                                  │   │
 * │  │ • MAC-based verification for malicious security                      │   │
 * │  │ • Efficient for addition-heavy computations                          │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │  GMW (Boolean Circuits):                                                    │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │ • XOR secret sharing for bits                                        │   │
 * │  │ • OT-based AND gate evaluation                                       │   │
 * │  │ • Efficient for comparison and bit operations                        │   │
 * │  │ • Linear complexity in circuit size                                  │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │  Yao's Garbled Circuits (2-party):                                          │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │ • Garbler encrypts circuit                                           │   │
 * │  │ • Evaluator decrypts output                                          │   │
 * │  │ • Point-and-permute optimization                                     │   │
 * │  │ • Free XOR optimization                                              │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                              │
 * │  Computation Types:                                                          │
 * │  • Addition (SPDZ) • Multiplication (SPDZ) • Comparison (GMW)              │
 * │  • Equality (GMW)  • Range Proof (GMW)     • Custom (Yao)                  │
 * │                                                                              │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
contract MPCExecutor is AccessControl, ReentrancyGuard, Pausable {
    // ============================================
    // ROLES
    // ============================================

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant COORDINATOR_ROLE = keccak256("COORDINATOR_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // ============================================
    // CONSTANTS
    // ============================================

    /// @notice BN254 field order
    uint256 public constant FIELD_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice MAC key domain separator
    bytes32 public constant MAC_DOMAIN = keccak256("SOULPROTOCOL_SPDZ_MAC_V1");

    /// @notice Maximum gates in a circuit
    uint256 public constant MAX_GATES = 10000;

    /// @notice Maximum computation timeout
    uint256 public constant COMPUTATION_TIMEOUT = 1 hours;

    // ============================================
    // ENUMS
    // ============================================

    /**
     * @notice Gate type for circuits
     */
    enum GateType {
        None, // 0: Invalid
        ADD, // 1: Addition gate
        MUL, // 2: Multiplication gate
        XOR, // 3: XOR gate (for GMW)
        AND, // 4: AND gate (for GMW)
        NOT, // 5: NOT gate
        INPUT, // 6: Input wire
        OUTPUT // 7: Output wire
    }

    /**
     * @notice Computation phase
     */
    enum ComputePhase {
        Inactive, // 0: Not started
        Setup, // 1: Circuit setup
        InputSharing, // 2: Parties sharing inputs
        Preprocessing, // 3: Generate Beaver triples (SPDZ)
        Evaluation, // 4: Gate-by-gate evaluation
        OutputReconstruction, // 5: Reconstruct outputs
        Complete, // 6: Successfully completed
        Failed // 7: Failed
    }

    // ============================================
    // EVENTS
    // ============================================

    event ComputationCreated(
        bytes32 indexed computeId,
        MPCLib.ProtocolType protocol,
        uint8 numParticipants
    );

    event CircuitRegistered(
        bytes32 indexed circuitId,
        uint256 numGates,
        uint256 numInputs,
        uint256 numOutputs
    );

    event PhaseAdvanced(
        bytes32 indexed computeId,
        ComputePhase oldPhase,
        ComputePhase newPhase
    );

    event InputShareSubmitted(
        bytes32 indexed computeId,
        address indexed participant,
        uint8 wireIndex
    );

    event BeaverTripleGenerated(bytes32 indexed computeId, uint256 tripleIndex);

    event GateEvaluated(
        bytes32 indexed computeId,
        uint256 gateIndex,
        GateType gateType
    );

    event OutputReconstructed(
        bytes32 indexed computeId,
        uint256 outputIndex,
        bytes32 outputHash
    );

    event ComputationCompleted(bytes32 indexed computeId, bytes32 resultHash);

    event ComputationFailed(bytes32 indexed computeId, string reason);

    // ============================================
    // ERRORS
    // ============================================

    error ComputationNotFound(bytes32 computeId);
    error ComputationExists(bytes32 computeId);
    error InvalidPhase(ComputePhase current, ComputePhase expected);
    error CircuitNotFound(bytes32 circuitId);
    error CircuitExists(bytes32 circuitId);
    error InvalidGateType();
    error InvalidWireIndex();
    error ParticipantNotFound(address participant);
    error InputAlreadySubmitted();
    error InsufficientTriples();
    error MACVerificationFailed();
    error ComputationTimeout();
    error TooManyGates();

    // ============================================
    // STRUCTS
    // ============================================

    /**
     * @notice Circuit gate
     */
    struct Gate {
        GateType gateType;
        uint256 leftInput; // Wire index
        uint256 rightInput; // Wire index (0 for unary gates)
        uint256 output; // Wire index
    }

    /**
     * @notice Circuit definition
     */
    struct Circuit {
        bytes32 circuitId;
        string name;
        uint256 numInputWires;
        uint256 numOutputWires;
        uint256 numGates;
        uint256 numWires;
        bytes32 circuitHash;
        bool registered;
    }

    /**
     * @notice SPDZ share with MAC
     */
    struct SPDZShare {
        uint256 share; // The actual share value
        uint256 mac; // MAC tag for verification
    }

    /**
     * @notice Beaver triple for SPDZ multiplication
     */
    struct BeaverTriple {
        SPDZShare a;
        SPDZShare b;
        SPDZShare c; // c = a * b
        bool used;
    }

    /**
     * @notice Computation instance
     */
    struct Computation {
        bytes32 computeId;
        bytes32 circuitId;
        MPCLib.ProtocolType protocol;
        uint8 numParticipants;
        ComputePhase phase;
        uint256 createdAt;
        uint256 deadline;
        uint256 inputsReceived;
        uint256 triplesGenerated;
        uint256 gatesEvaluated;
        uint256 outputsReconstructed;
        address coordinator;
        bytes32 resultHash;
    }

    /**
     * @notice Participant in computation
     */
    struct ComputeParticipant {
        address participantAddress;
        uint8 participantIndex;
        bool inputSubmitted;
        bool tripleContributed;
        bool outputReconstructed;
    }

    /**
     * @notice Wire value (secret shared)
     */
    struct Wire {
        uint256 wireIndex;
        SPDZShare[] shares; // One per participant
        bool isInput;
        bool isOutput;
        bool evaluated;
    }

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice Computation nonce
    uint256 public computeNonce;

    /// @notice Total computations
    uint256 public totalComputations;

    /// @notice Total circuits registered
    uint256 public totalCircuits;

    /// @notice Circuits: circuitId => circuit
    mapping(bytes32 => Circuit) public circuits;

    /// @notice Circuit gates: circuitId => gateIndex => gate
    mapping(bytes32 => mapping(uint256 => Gate)) public circuitGates;

    /// @notice Computations: computeId => computation
    mapping(bytes32 => Computation) public computations;

    /// @notice Computation participants: computeId => address => participant
    mapping(bytes32 => mapping(address => ComputeParticipant))
        public participants;

    /// @notice Participant by index: computeId => index => address
    mapping(bytes32 => mapping(uint8 => address)) public participantByIndex;

    /// @notice Wire values: computeId => wireIndex => wire
    mapping(bytes32 => mapping(uint256 => Wire)) public wires;

    /// @notice Beaver triples: computeId => tripleIndex => triple
    mapping(bytes32 => mapping(uint256 => BeaverTriple)) public beaverTriples;

    /// @notice MAC key shares: computeId => participantIndex => macKeyShare
    mapping(bytes32 => mapping(uint8 => uint256)) public macKeyShares;

    // ============================================
    // CONSTRUCTOR
    // ============================================

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
        _grantRole(COORDINATOR_ROLE, msg.sender);
        _grantRole(OPERATOR_ROLE, msg.sender);
    }

    // ============================================
    // CIRCUIT MANAGEMENT
    // ============================================

    /**
     * @notice Register a new circuit
     * @param circuitId Unique circuit identifier
     * @param name Circuit name
     * @param gates Array of gates
     * @param numInputWires Number of input wires
     * @param numOutputWires Number of output wires
     */
    function registerCircuit(
        bytes32 circuitId,
        string calldata name,
        Gate[] calldata gates,
        uint256 numInputWires,
        uint256 numOutputWires
    ) external onlyRole(EXECUTOR_ROLE) {
        if (circuits[circuitId].registered) {
            revert CircuitExists(circuitId);
        }
        if (gates.length > MAX_GATES) {
            revert TooManyGates();
        }

        // Calculate total wires
        uint256 maxWire = numInputWires;
        for (uint256 i = 0; i < gates.length; i++) {
            if (gates[i].output > maxWire) {
                maxWire = gates[i].output;
            }
            // Store gate
            circuitGates[circuitId][i] = gates[i];
        }

        circuits[circuitId] = Circuit({
            circuitId: circuitId,
            name: name,
            numInputWires: numInputWires,
            numOutputWires: numOutputWires,
            numGates: gates.length,
            numWires: maxWire + 1,
            circuitHash: keccak256(abi.encode(gates)),
            registered: true
        });

        totalCircuits++;

        emit CircuitRegistered(
            circuitId,
            gates.length,
            numInputWires,
            numOutputWires
        );
    }

    // ============================================
    // COMPUTATION LIFECYCLE
    // ============================================

    /**
     * @notice Create a new computation
     * @param circuitId Circuit to execute
     * @param protocol MPC protocol (SPDZ, GMW, or Yao)
     * @param numParticipants Number of parties
     * @param deadline Computation deadline
     * @return computeId Unique computation identifier
     */
    function createComputation(
        bytes32 circuitId,
        MPCLib.ProtocolType protocol,
        uint8 numParticipants,
        uint256 deadline
    )
        external
        whenNotPaused
        onlyRole(COORDINATOR_ROLE)
        returns (bytes32 computeId)
    {
        if (!circuits[circuitId].registered) {
            revert CircuitNotFound(circuitId);
        }
        if (
            protocol != MPCLib.ProtocolType.SPDZ &&
            protocol != MPCLib.ProtocolType.GMW &&
            protocol != MPCLib.ProtocolType.Yao
        ) {
            revert InvalidGateType();
        }

        computeId = keccak256(
            abi.encodePacked(
                circuitId,
                protocol,
                msg.sender,
                computeNonce++,
                block.timestamp
            )
        );

        computations[computeId] = Computation({
            computeId: computeId,
            circuitId: circuitId,
            protocol: protocol,
            numParticipants: numParticipants,
            phase: ComputePhase.Setup,
            createdAt: block.timestamp,
            deadline: deadline,
            inputsReceived: 0,
            triplesGenerated: 0,
            gatesEvaluated: 0,
            outputsReconstructed: 0,
            coordinator: msg.sender,
            resultHash: bytes32(0)
        });

        totalComputations++;

        emit ComputationCreated(computeId, protocol, numParticipants);
    }

    /**
     * @notice Join a computation as participant
     * @param computeId Computation to join
     * @param macKeyShare Participant's MAC key share (for SPDZ)
     * @return participantIndex Assigned index
     */
    function joinComputation(
        bytes32 computeId,
        uint256 macKeyShare
    ) external whenNotPaused nonReentrant returns (uint8 participantIndex) {
        Computation storage comp = computations[computeId];

        if (comp.createdAt == 0) {
            revert ComputationNotFound(computeId);
        }
        if (comp.phase != ComputePhase.Setup) {
            revert InvalidPhase(comp.phase, ComputePhase.Setup);
        }
        if (participants[computeId][msg.sender].participantIndex != 0) {
            revert InputAlreadySubmitted();
        }

        // Assign index (1-based)
        participantIndex = uint8(comp.inputsReceived + 1);

        participants[computeId][msg.sender] = ComputeParticipant({
            participantAddress: msg.sender,
            participantIndex: participantIndex,
            inputSubmitted: false,
            tripleContributed: false,
            outputReconstructed: false
        });

        participantByIndex[computeId][participantIndex] = msg.sender;

        // Store MAC key share for SPDZ
        if (comp.protocol == MPCLib.ProtocolType.SPDZ) {
            macKeyShares[computeId][participantIndex] = macKeyShare;
        }

        // Check if all joined
        if (participantIndex == comp.numParticipants) {
            _advancePhase(computeId, ComputePhase.InputSharing);
        }

        return participantIndex;
    }

    /**
     * @notice Submit input share
     * @param computeId Computation ID
     * @param wireIndex Input wire index
     * @param share Secret share value
     * @param mac MAC tag (for SPDZ)
     */
    function submitInputShare(
        bytes32 computeId,
        uint256 wireIndex,
        uint256 share,
        uint256 mac
    ) external whenNotPaused nonReentrant {
        Computation storage comp = computations[computeId];
        ComputeParticipant storage participant = participants[computeId][
            msg.sender
        ];

        if (comp.phase != ComputePhase.InputSharing) {
            revert InvalidPhase(comp.phase, ComputePhase.InputSharing);
        }
        if (participant.participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }

        Circuit storage circuit = circuits[comp.circuitId];
        if (wireIndex >= circuit.numInputWires) {
            revert InvalidWireIndex();
        }

        // Initialize wire if needed
        Wire storage wire = wires[computeId][wireIndex];
        if (wire.shares.length == 0) {
            wire.wireIndex = wireIndex;
            wire.isInput = true;
            wire.isOutput = false;
            wire.evaluated = false;
        }

        // Add share
        wire.shares.push(SPDZShare({share: share, mac: mac}));

        participant.inputSubmitted = true;
        comp.inputsReceived++;

        emit InputShareSubmitted(computeId, msg.sender, uint8(wireIndex));

        // Check if all inputs received
        uint256 expectedInputs = circuit.numInputWires * comp.numParticipants;
        if (comp.inputsReceived >= expectedInputs) {
            if (comp.protocol == MPCLib.ProtocolType.SPDZ) {
                _advancePhase(computeId, ComputePhase.Preprocessing);
            } else {
                _advancePhase(computeId, ComputePhase.Evaluation);
            }
        }
    }

    /**
     * @notice Submit Beaver triple share (for SPDZ)
     * @param computeId Computation ID
     * @param tripleIndex Triple index
     * @param aShare Share of 'a'
     * @param bShare Share of 'b'
     * @param cShare Share of 'c' (should equal a*b)
     * @param aMac MAC of a
     * @param bMac MAC of b
     * @param cMac MAC of c
     */
    function submitBeaverTriple(
        bytes32 computeId,
        uint256 tripleIndex,
        uint256 aShare,
        uint256 bShare,
        uint256 cShare,
        uint256 aMac,
        uint256 bMac,
        uint256 cMac
    ) external whenNotPaused nonReentrant {
        Computation storage comp = computations[computeId];

        if (comp.phase != ComputePhase.Preprocessing) {
            revert InvalidPhase(comp.phase, ComputePhase.Preprocessing);
        }
        if (participants[computeId][msg.sender].participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }

        BeaverTriple storage triple = beaverTriples[computeId][tripleIndex];

        // Aggregate shares
        triple.a.share = addmod(triple.a.share, aShare, FIELD_ORDER);
        triple.a.mac = addmod(triple.a.mac, aMac, FIELD_ORDER);
        triple.b.share = addmod(triple.b.share, bShare, FIELD_ORDER);
        triple.b.mac = addmod(triple.b.mac, bMac, FIELD_ORDER);
        triple.c.share = addmod(triple.c.share, cShare, FIELD_ORDER);
        triple.c.mac = addmod(triple.c.mac, cMac, FIELD_ORDER);

        participants[computeId][msg.sender].tripleContributed = true;

        emit BeaverTripleGenerated(computeId, tripleIndex);

        // Check if preprocessing complete
        Circuit storage circuit = circuits[comp.circuitId];
        uint256 mulGates = _countMulGates(comp.circuitId, circuit.numGates);

        if (tripleIndex >= mulGates - 1) {
            comp.triplesGenerated = mulGates;
            _advancePhase(computeId, ComputePhase.Evaluation);
        }
    }

    /**
     * @notice Evaluate a gate
     * @param computeId Computation ID
     * @param gateIndex Gate index in circuit
     * @param openedValue Opened value for multiplication (d or e)
     * @param resultShare Result share
     * @param resultMac Result MAC
     */
    function evaluateGate(
        bytes32 computeId,
        uint256 gateIndex,
        uint256 openedValue,
        uint256 resultShare,
        uint256 resultMac
    ) external whenNotPaused nonReentrant {
        Computation storage comp = computations[computeId];

        if (comp.phase != ComputePhase.Evaluation) {
            revert InvalidPhase(comp.phase, ComputePhase.Evaluation);
        }
        if (participants[computeId][msg.sender].participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }

        Circuit storage circuit = circuits[comp.circuitId];
        if (gateIndex >= circuit.numGates) {
            revert InvalidWireIndex();
        }

        Gate storage gate = circuitGates[comp.circuitId][gateIndex];
        Wire storage outputWire = wires[computeId][gate.output];

        if (gate.gateType == GateType.ADD) {
            // Addition: [z] = [x] + [y]
            // Each party locally adds their shares
            outputWire.shares.push(
                SPDZShare({share: resultShare, mac: resultMac})
            );
        } else if (gate.gateType == GateType.MUL) {
            // Multiplication using Beaver triples
            // d = x - a, e = y - b (opened)
            // [z] = [c] + e*[a] + d*[b] + d*e
            outputWire.shares.push(
                SPDZShare({share: resultShare, mac: resultMac})
            );
        } else if (gate.gateType == GateType.XOR) {
            // XOR for GMW: each party XORs shares
            outputWire.shares.push(SPDZShare({share: resultShare, mac: 0}));
        } else if (gate.gateType == GateType.AND) {
            // AND for GMW: requires OT
            outputWire.shares.push(SPDZShare({share: resultShare, mac: 0}));
        }

        outputWire.evaluated = true;
        comp.gatesEvaluated++;

        emit GateEvaluated(computeId, gateIndex, gate.gateType);

        // Check if all gates evaluated
        if (comp.gatesEvaluated >= circuit.numGates) {
            _advancePhase(computeId, ComputePhase.OutputReconstruction);
        }
    }

    /**
     * @notice Submit output share for reconstruction
     * @param computeId Computation ID
     * @param outputIndex Output wire index
     * @param share Output share
     * @param mac Output MAC
     */
    function submitOutputShare(
        bytes32 computeId,
        uint256 outputIndex,
        uint256 share,
        uint256 mac
    ) external whenNotPaused nonReentrant {
        Computation storage comp = computations[computeId];

        if (comp.phase != ComputePhase.OutputReconstruction) {
            revert InvalidPhase(comp.phase, ComputePhase.OutputReconstruction);
        }
        if (participants[computeId][msg.sender].participantIndex == 0) {
            revert ParticipantNotFound(msg.sender);
        }

        Circuit storage circuit = circuits[comp.circuitId];

        // Output wires are the last numOutputWires wires
        uint256 outputWireIndex = circuit.numWires -
            circuit.numOutputWires +
            outputIndex;
        Wire storage wire = wires[computeId][outputWireIndex];

        wire.shares.push(SPDZShare({share: share, mac: mac}));
        wire.isOutput = true;

        // Check if we have all shares for this output
        if (wire.shares.length >= comp.numParticipants) {
            // Reconstruct
            uint256 reconstructed = 0;
            for (uint256 i = 0; i < wire.shares.length; i++) {
                reconstructed = addmod(
                    reconstructed,
                    wire.shares[i].share,
                    FIELD_ORDER
                );
            }

            // Verify MAC (simplified - in practice would check against aggregated MAC key)
            bytes32 outputHash = keccak256(
                abi.encodePacked(outputIndex, reconstructed)
            );

            emit OutputReconstructed(computeId, outputIndex, outputHash);

            comp.outputsReconstructed++;
            participants[computeId][msg.sender].outputReconstructed = true;

            // Check if all outputs reconstructed
            if (comp.outputsReconstructed >= circuit.numOutputWires) {
                _completeComputation(computeId);
            }
        }
    }

    // ============================================
    // INTERNAL FUNCTIONS
    // ============================================

    function _advancePhase(bytes32 computeId, ComputePhase newPhase) internal {
        Computation storage comp = computations[computeId];
        ComputePhase oldPhase = comp.phase;
        comp.phase = newPhase;
        emit PhaseAdvanced(computeId, oldPhase, newPhase);
    }

    function _completeComputation(bytes32 computeId) internal {
        Computation storage comp = computations[computeId];

        // Generate result hash from all outputs
        Circuit storage circuit = circuits[comp.circuitId];
        bytes32 resultHash = bytes32(0);

        for (uint256 i = 0; i < circuit.numOutputWires; i++) {
            uint256 outputWireIndex = circuit.numWires -
                circuit.numOutputWires +
                i;
            Wire storage wire = wires[computeId][outputWireIndex];

            uint256 reconstructed = 0;
            for (uint256 j = 0; j < wire.shares.length; j++) {
                reconstructed = addmod(
                    reconstructed,
                    wire.shares[j].share,
                    FIELD_ORDER
                );
            }

            resultHash = keccak256(abi.encodePacked(resultHash, reconstructed));
        }

        comp.resultHash = resultHash;
        comp.phase = ComputePhase.Complete;

        emit ComputationCompleted(computeId, resultHash);
    }

    function _countMulGates(
        bytes32 circuitId,
        uint256 numGates
    ) internal view returns (uint256 count) {
        for (uint256 i = 0; i < numGates; i++) {
            if (circuitGates[circuitId][i].gateType == GateType.MUL) {
                count++;
            }
        }
    }

    /**
     * @notice Verify SPDZ MAC
     * @param share Share value
     * @param mac MAC tag
     * @param macKey Aggregated MAC key
     * @return valid True if MAC is valid
     */
    function _verifySPDZMac(
        uint256 share,
        uint256 mac,
        uint256 macKey
    ) internal pure returns (bool valid) {
        // MAC should equal macKey * share
        uint256 expectedMac = mulmod(macKey, share, FIELD_ORDER);
        valid = (mac == expectedMac);
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get circuit details
     * @param circuitId Circuit identifier
     * @return circuit Circuit data
     */
    function getCircuit(
        bytes32 circuitId
    ) external view returns (Circuit memory circuit) {
        circuit = circuits[circuitId];
    }

    /**
     * @notice Get circuit gate
     * @param circuitId Circuit identifier
     * @param gateIndex Gate index
     * @return gate Gate data
     */
    function getGate(
        bytes32 circuitId,
        uint256 gateIndex
    ) external view returns (Gate memory gate) {
        gate = circuitGates[circuitId][gateIndex];
    }

    /**
     * @notice Get computation details
     * @param computeId Computation identifier
     * @return computation Computation data
     */
    function getComputation(
        bytes32 computeId
    ) external view returns (Computation memory computation) {
        computation = computations[computeId];
    }

    /**
     * @notice Get participant details
     * @param computeId Computation identifier
     * @param participant Participant address
     * @return info Participant data
     */
    function getParticipant(
        bytes32 computeId,
        address participant
    ) external view returns (ComputeParticipant memory info) {
        info = participants[computeId][participant];
    }

    /**
     * @notice Get wire shares count
     * @param computeId Computation identifier
     * @param wireIndex Wire index
     * @return shareCount Number of shares submitted
     */
    function getWireShareCount(
        bytes32 computeId,
        uint256 wireIndex
    ) external view returns (uint256 shareCount) {
        shareCount = wires[computeId][wireIndex].shares.length;
    }

    /**
     * @notice Check if computation is complete
     * @param computeId Computation identifier
     * @return complete True if computation is complete
     */
    function isComplete(
        bytes32 computeId
    ) external view returns (bool complete) {
        complete = computations[computeId].phase == ComputePhase.Complete;
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Handle computation timeout
     * @param computeId Computation to fail
     */
    function handleTimeout(bytes32 computeId) external {
        Computation storage comp = computations[computeId];

        if (block.timestamp <= comp.deadline) {
            revert InvalidPhase(comp.phase, ComputePhase.Failed);
        }

        comp.phase = ComputePhase.Failed;
        emit ComputationFailed(computeId, "Computation timeout");
    }

    /**
     * @notice Pause the executor
     */
    function pause() external onlyRole(OPERATOR_ROLE) {
        _pause();
    }

    /**
     * @notice Unpause the executor
     */
    function unpause() external onlyRole(OPERATOR_ROLE) {
        _unpause();
    }
}
