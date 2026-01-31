// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// STUB for coverage only
library FHEUtils {
    struct Handle { bytes32 id; uint8 valueType; bytes32 securityZone; bool verified; uint64 createdAt; }
    struct DecryptionRequest { bytes32 requestId; bytes32 handle; address requester; address callbackContract; bytes4 callbackSelector; uint256 maxTimestamp; bool fulfilled; bytes32 result; }
    struct ReencryptionRequest { bytes32 requestId; bytes32 handle; address requester; bytes32 targetPublicKey; uint256 maxTimestamp; bool fulfilled; bytes reencryptedCiphertext; }
    struct ComputeRequest { bytes32 requestId; uint8 opcode; bytes32[] inputs; bytes32 output; address requester; uint256 gasUsed; uint256 timestamp; RequestStatus status; }
    enum RequestStatus { Pending, Processing, Completed, Failed, Expired }
    enum FHEScheme { TFHE, BFV, BGV, CKKS }
    enum ValueType { ebool, euint4, euint8, euint16, euint32, euint64, euint128, euint256, eaddress, ebytes64, ebytes128, ebytes256 }
    enum Opcode { ADD, SUB, MUL, DIV, REM, NEG, EQ, NE, GE, GT, LE, LT, AND, OR, XOR, NOT, SHL, SHR, ROTL, ROTR, MIN, MAX, SELECT, CMUX, RAND, TRIVIAL, DECRYPT, REENCRYPT }
}
