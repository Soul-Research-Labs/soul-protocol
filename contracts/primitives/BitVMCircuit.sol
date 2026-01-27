// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BitVMCircuit
 * @author Soul Protocol
 * @notice Circuit representation and gate operations for BitVM
 * @dev Provides circuit compilation and gate management utilities
 *
 * CIRCUIT STRUCTURE:
 * ┌─────────────────────────────────────────────────────────────────┐
 * │                    BitVM Circuit Layout                          │
 * ├─────────────────────────────────────────────────────────────────┤
 * │                                                                  │
 * │  INPUTS: [x0, x1, x2, ...]                                       │
 * │     │                                                            │
 * │     ▼                                                            │
 * │  ┌──────┐  ┌──────┐  ┌──────┐                                   │
 * │  │ NAND │  │ NAND │  │ NAND │  ... Layer 0                      │
 * │  └───┬──┘  └───┬──┘  └───┬──┘                                   │
 * │      │         │         │                                       │
 * │      ▼         ▼         ▼                                       │
 * │  ┌──────┐  ┌──────┐                                             │
 * │  │ NAND │  │ NAND │  ... Layer 1                                │
 * │  └───┬──┘  └───┬──┘                                             │
 * │      │         │                                                 │
 * │      ▼         ▼                                                 │
 * │  ┌──────────────┐                                               │
 * │  │    OUTPUT    │                                               │
 * │  └──────────────┘                                               │
 * │                                                                  │
 * │  All gates stored in Merkle tree for efficient fraud proofs     │
 * └─────────────────────────────────────────────────────────────────┘
 */
contract BitVMCircuit {
    /*//////////////////////////////////////////////////////////////
                              STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuit gate
    struct Gate {
        bytes32 gateId;
        bytes32 inputAId;
        bytes32 inputBId;
        bytes32 outputId;
        uint256 layer;
        uint256 indexInLayer;
    }

    /// @notice Wire (input/output connection)
    struct Wire {
        bytes32 wireId;
        bytes32 sourceGateId;
        bytes32 destGateId;
        bool isInput;
        bool isOutput;
    }

    /// @notice Complete circuit
    struct Circuit {
        bytes32 circuitId;
        uint256 numInputs;
        uint256 numOutputs;
        uint256 numGates;
        uint256 numLayers;
        bytes32 merkleRoot;
        bool compiled;
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /// @notice Circuits by ID
    mapping(bytes32 => Circuit) public circuits;

    /// @notice Gates by ID
    mapping(bytes32 => Gate) public gates;

    /// @notice Wires by ID
    mapping(bytes32 => Wire) public wires;

    /// @notice Circuit gates (circuitId => gateId[])
    mapping(bytes32 => bytes32[]) public circuitGates;

    /// @notice Circuit inputs (circuitId => inputWireId[])
    mapping(bytes32 => bytes32[]) public circuitInputs;

    /// @notice Circuit outputs (circuitId => outputWireId[])
    mapping(bytes32 => bytes32[]) public circuitOutputs;

    /// @notice Gate Merkle tree leaves
    mapping(bytes32 => bytes32[]) public gateLeaves;

    /// @notice Total circuits created
    uint256 public totalCircuits;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event CircuitCreated(bytes32 indexed circuitId, uint256 numInputs, uint256 numOutputs);
    event GateAdded(bytes32 indexed circuitId, bytes32 indexed gateId, uint256 layer);
    event CircuitCompiled(bytes32 indexed circuitId, bytes32 merkleRoot, uint256 numGates);
    event WireConnected(bytes32 indexed wireId, bytes32 sourceGate, bytes32 destGate);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error CircuitNotFound();
    error CircuitAlreadyCompiled();
    error InvalidInputCount();
    error InvalidGate();
    error GateNotFound();

    /*//////////////////////////////////////////////////////////////
                       CIRCUIT MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new circuit
     * @param numInputs Number of input wires
     * @param numOutputs Number of output wires
     * @return circuitId Unique circuit identifier
     */
    function createCircuit(
        uint256 numInputs,
        uint256 numOutputs
    ) external returns (bytes32 circuitId) {
        if (numInputs == 0 || numOutputs == 0) revert InvalidInputCount();

        circuitId = keccak256(abi.encodePacked(msg.sender, numInputs, numOutputs, totalCircuits));

        circuits[circuitId] = Circuit({
            circuitId: circuitId,
            numInputs: numInputs,
            numOutputs: numOutputs,
            numGates: 0,
            numLayers: 0,
            merkleRoot: bytes32(0),
            compiled: false
        });

        // Create input wires
        for (uint256 i = 0; i < numInputs; i++) {
            bytes32 wireId = keccak256(abi.encodePacked(circuitId, "input", i));
            wires[wireId] = Wire({
                wireId: wireId,
                sourceGateId: bytes32(0),
                destGateId: bytes32(0),
                isInput: true,
                isOutput: false
            });
            circuitInputs[circuitId].push(wireId);
        }

        totalCircuits++;

        emit CircuitCreated(circuitId, numInputs, numOutputs);
    }

    /**
     * @notice Add a NAND gate to circuit
     * @param circuitId Circuit to add gate to
     * @param inputAId Input A wire ID
     * @param inputBId Input B wire ID
     * @param layer Gate layer (depth in circuit)
     * @return gateId New gate ID
     */
    function addGate(
        bytes32 circuitId,
        bytes32 inputAId,
        bytes32 inputBId,
        uint256 layer
    ) external returns (bytes32 gateId) {
        Circuit storage circuit = circuits[circuitId];
        if (circuit.numInputs == 0) revert CircuitNotFound();
        if (circuit.compiled) revert CircuitAlreadyCompiled();

        gateId = keccak256(abi.encodePacked(circuitId, inputAId, inputBId, circuit.numGates));

        // Create output wire
        bytes32 outputId = keccak256(abi.encodePacked(gateId, "output"));
        wires[outputId] = Wire({
            wireId: outputId,
            sourceGateId: gateId,
            destGateId: bytes32(0),
            isInput: false,
            isOutput: false
        });

        // Create gate
        uint256 indexInLayer = 0;
        bytes32[] storage layerGates = circuitGates[circuitId];
        for (uint256 i = 0; i < layerGates.length; i++) {
            if (gates[layerGates[i]].layer == layer) {
                indexInLayer++;
            }
        }

        gates[gateId] = Gate({
            gateId: gateId,
            inputAId: inputAId,
            inputBId: inputBId,
            outputId: outputId,
            layer: layer,
            indexInLayer: indexInLayer
        });

        circuitGates[circuitId].push(gateId);
        circuit.numGates++;

        if (layer >= circuit.numLayers) {
            circuit.numLayers = layer + 1;
        }

        emit GateAdded(circuitId, gateId, layer);
    }

    /**
     * @notice Mark a gate output as circuit output
     * @param circuitId Circuit ID
     * @param gateId Gate whose output is circuit output
     */
    function setOutputGate(bytes32 circuitId, bytes32 gateId) external {
        Circuit storage circuit = circuits[circuitId];
        if (circuit.numInputs == 0) revert CircuitNotFound();
        if (circuit.compiled) revert CircuitAlreadyCompiled();

        Gate storage gate = gates[gateId];
        if (gate.gateId == bytes32(0)) revert GateNotFound();

        Wire storage outputWire = wires[gate.outputId];
        outputWire.isOutput = true;

        circuitOutputs[circuitId].push(gate.outputId);
    }

    /**
     * @notice Compile circuit and compute Merkle root
     * @param circuitId Circuit to compile
     * @return merkleRoot Root of gate Merkle tree
     */
    function compileCircuit(bytes32 circuitId) external returns (bytes32 merkleRoot) {
        Circuit storage circuit = circuits[circuitId];
        if (circuit.numInputs == 0) revert CircuitNotFound();
        if (circuit.compiled) revert CircuitAlreadyCompiled();

        // Build Merkle tree from gates
        bytes32[] storage gateIds = circuitGates[circuitId];
        bytes32[] memory leaves = new bytes32[](gateIds.length);

        for (uint256 i = 0; i < gateIds.length; i++) {
            Gate storage gate = gates[gateIds[i]];
            leaves[i] = keccak256(abi.encodePacked(
                gate.gateId,
                gate.inputAId,
                gate.inputBId,
                gate.outputId,
                gate.layer
            ));
            gateLeaves[circuitId].push(leaves[i]);
        }

        // Compute Merkle root (simplified - left-to-right pairing)
        merkleRoot = _computeMerkleRoot(leaves);

        circuit.merkleRoot = merkleRoot;
        circuit.compiled = true;

        emit CircuitCompiled(circuitId, merkleRoot, circuit.numGates);
    }

    /*//////////////////////////////////////////////////////////////
                       GATE COMPUTATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute NAND gate
     * @param a First input (0 or 1)
     * @param b Second input (0 or 1)
     * @return output NAND result
     */
    function computeNAND(uint8 a, uint8 b) public pure returns (uint8 output) {
        return (a & b) == 1 ? 0 : 1;
    }

    /**
     * @notice Compute AND from NAND gates
     * @param a First input
     * @param b Second input
     * @return output AND result (uses 2 NANDs)
     */
    function computeAND(uint8 a, uint8 b) public pure returns (uint8 output) {
        // AND = NAND(NAND(a,b), NAND(a,b))
        uint8 nand1 = computeNAND(a, b);
        return computeNAND(nand1, nand1);
    }

    /**
     * @notice Compute OR from NAND gates
     * @param a First input
     * @param b Second input
     * @return output OR result (uses 3 NANDs)
     */
    function computeOR(uint8 a, uint8 b) public pure returns (uint8 output) {
        // OR = NAND(NAND(a,a), NAND(b,b))
        uint8 notA = computeNAND(a, a);
        uint8 notB = computeNAND(b, b);
        return computeNAND(notA, notB);
    }

    /**
     * @notice Compute XOR from NAND gates
     * @param a First input
     * @param b Second input
     * @return output XOR result (uses 4 NANDs)
     */
    function computeXOR(uint8 a, uint8 b) public pure returns (uint8 output) {
        // XOR = NAND(NAND(a, NAND(a,b)), NAND(b, NAND(a,b)))
        uint8 nandAB = computeNAND(a, b);
        uint8 left = computeNAND(a, nandAB);
        uint8 right = computeNAND(b, nandAB);
        return computeNAND(left, right);
    }

    /**
     * @notice Compute NOT from NAND gate
     * @param a Input
     * @return output NOT result (uses 1 NAND)
     */
    function computeNOT(uint8 a) public pure returns (uint8 output) {
        return computeNAND(a, a);
    }

    /*//////////////////////////////////////////////////////////////
                          VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function getCircuit(bytes32 circuitId) external view returns (Circuit memory) {
        return circuits[circuitId];
    }

    function getGate(bytes32 gateId) external view returns (Gate memory) {
        return gates[gateId];
    }

    function getCircuitGates(bytes32 circuitId) external view returns (bytes32[] memory) {
        return circuitGates[circuitId];
    }

    function getCircuitInputs(bytes32 circuitId) external view returns (bytes32[] memory) {
        return circuitInputs[circuitId];
    }

    function getCircuitOutputs(bytes32 circuitId) external view returns (bytes32[] memory) {
        return circuitOutputs[circuitId];
    }

    function getGateLeaves(bytes32 circuitId) external view returns (bytes32[] memory) {
        return gateLeaves[circuitId];
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Compute Merkle root from leaves
     */
    function _computeMerkleRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        if (leaves.length == 0) return bytes32(0);
        if (leaves.length == 1) return leaves[0];

        uint256 n = leaves.length;
        
        // Pad to power of 2
        uint256 size = 1;
        while (size < n) {
            size *= 2;
        }

        bytes32[] memory tree = new bytes32[](size);
        for (uint256 i = 0; i < n; i++) {
            tree[i] = leaves[i];
        }
        for (uint256 i = n; i < size; i++) {
            tree[i] = bytes32(0);
        }

        // Build tree bottom-up
        while (size > 1) {
            for (uint256 i = 0; i < size / 2; i++) {
                tree[i] = keccak256(abi.encodePacked(tree[2*i], tree[2*i + 1]));
            }
            size = size / 2;
        }

        return tree[0];
    }
}
