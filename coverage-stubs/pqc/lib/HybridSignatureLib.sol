// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

// STUB for coverage only
library HybridSignatureLib {
    bytes4 public constant HYBRID_SIG_MAGIC = 0x50514331;
    uint8 public constant VERSION = 1;
    uint256 public constant ECDSA_SIG_SIZE = 65;
    uint8 public constant ALG_DILITHIUM3 = 1;
    uint8 public constant ALG_DILITHIUM5 = 2;
    uint8 public constant ALG_SPHINCS_128S = 3;
    uint8 public constant ALG_SPHINCS_256S = 4;

    struct HybridSig {
        bytes4 magic;
        uint8 version;
        uint8 algorithm;
        bytes ecdsaSig;
        bytes pqSig;
        bytes pqPubKey;
    }

    struct CompactHybridSig {
        bytes4 magic;
        uint8 version;
        uint8 algorithm;
        bytes32 ecdsaR;
        bytes32 ecdsaS;
        uint8 ecdsaV;
        bytes pqSig;
        bytes32 pqPubKeyHash;
    }

    function encode(HybridSig memory) internal pure returns (bytes memory) { return ""; }
    function encodeCompact(CompactHybridSig memory) internal pure returns (bytes memory) { return ""; }
    function decode(bytes calldata) internal pure returns (HybridSig memory) { 
        return HybridSig(HYBRID_SIG_MAGIC, VERSION, 0, "", "", ""); 
    }
    function decodeCompact(bytes calldata) internal pure returns (CompactHybridSig memory) {
        return CompactHybridSig(HYBRID_SIG_MAGIC, VERSION, 0, bytes32(0), bytes32(0), 0, "", bytes32(0));
    }
    function extractECDSA(bytes memory) internal pure returns (bytes32 r, bytes32 s, uint8 v) { return (bytes32(0), bytes32(0), 0); }
    function verifyECDSA(bytes32, bytes memory, address) internal pure returns (bool) { return true; }
    function verifyECDSAWithPrefix(bytes32, bytes memory, address) internal pure returns (bool) { return true; }
    function create(uint8, bytes memory, bytes memory, bytes memory) internal pure returns (HybridSig memory) {
        return HybridSig(HYBRID_SIG_MAGIC, VERSION, 0, "", "", "");
    }
    function isHybridSignature(bytes calldata) internal pure returns (bool) { return true; }
    function algorithmName(uint8) internal pure returns (string memory) { return ""; }
    function estimateSize(uint8) internal pure returns (uint256) { return 0; }
    function hash(HybridSig memory) internal pure returns (bytes32) { return bytes32(0); }
}
