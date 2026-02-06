// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockBitVMVerifier
 * @notice Mock BitVM verification contract for testing BitVMBridge
 * @dev Simulates gate-level challenge-response protocol verification
 */
contract MockBitVMVerifier {
    mapping(bytes32 => bool) public verifiedCircuits;
    mapping(bytes32 => mapping(bytes32 => bool)) public gateCommitments;
    bool public shouldVerify = true;

    event CircuitVerified(bytes32 indexed circuitId);
    event GateVerified(bytes32 indexed depositId, bytes32 indexed gateId);

    function setShouldVerify(bool _should) external {
        shouldVerify = _should;
    }

    function verifyCircuit(bytes32 circuitId, bytes calldata) external returns (bool) {
        if (shouldVerify) {
            verifiedCircuits[circuitId] = true;
            emit CircuitVerified(circuitId);
        }
        return shouldVerify;
    }

    function verifyGateExecution(
        bytes32 depositId,
        bytes32 gateId,
        bytes32, // inputA
        bytes32, // inputB
        bytes32, // output
        uint8    // gateType
    ) external returns (bool) {
        if (shouldVerify) {
            gateCommitments[depositId][gateId] = true;
            emit GateVerified(depositId, gateId);
        }
        return shouldVerify;
    }

    function isCircuitVerified(bytes32 circuitId) external view returns (bool) {
        return verifiedCircuits[circuitId];
    }

    function isGateCommitted(bytes32 depositId, bytes32 gateId) external view returns (bool) {
        return gateCommitments[depositId][gateId];
    }
}

/**
 * @title MockTaprootSignatureVerifier
 * @notice Mock Schnorr/Taproot signature verification for BitVM
 */
contract MockTaprootSignatureVerifier {
    function verifySchnorr(
        bytes32, // pubKey
        bytes32, // messageHash
        bytes calldata // signature
    ) external pure returns (bool) {
        return true;
    }

    function verifyTaprootSpend(
        bytes32, // taprootOutput
        bytes calldata, // controlBlock
        bytes calldata  // scriptLeaf
    ) external pure returns (bool) {
        return true;
    }
}
