// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "../../contracts/pqc/lib/HybridSignatureLib.sol";

contract HybridSignatureWrapper {
    function decode(bytes calldata data) external pure returns (HybridSignatureLib.HybridSig memory) {
        return HybridSignatureLib.decode(data);
    }
    
    function decodeCompact(bytes calldata data) external pure returns (HybridSignatureLib.CompactHybridSig memory) {
        return HybridSignatureLib.decodeCompact(data);
    }
}

contract PQCFuzz is HybridSignatureWrapper {
    // Track successful decodes for invariant checking
    bool public lastDecodeSuccess;
    HybridSignatureLib.HybridSig public lastSig;

    /**
     * @dev Invariant: Round-trip encoding/decoding should be consistent.
     */
    function echidna_decode_roundtrip_consistent() public view returns (bool) {
        if (!lastDecodeSuccess) return true;
        
        bytes memory reencoded = HybridSignatureLib.encode(lastSig);
        try this.decode(reencoded) returns (HybridSignatureLib.HybridSig memory sig2) {
             return sig2.algorithm == lastSig.algorithm && 
                    keccak256(sig2.ecdsaSig) == keccak256(lastSig.ecdsaSig) &&
                    keccak256(sig2.pqSig) == keccak256(lastSig.pqSig);
        } catch {
             return false;
        }
    }

    /**
     * @dev Fuzzing entry point for decode
     */
    function fuzzDecode(bytes calldata data) public {
        try this.decode(data) returns (HybridSignatureLib.HybridSig memory sig) {
            lastSig = sig;
            lastDecodeSuccess = true;
        } catch {
            lastDecodeSuccess = false;
        }
    }

    /**
     * @dev Fuzzing entry point for decodeCompact
     */
    function fuzzDecodeCompact(bytes calldata data) public {
        try this.decodeCompact(data) returns (HybridSignatureLib.CompactHybridSig memory sig) {
            lastDecodeSuccess = true;
        } catch {
            lastDecodeSuccess = false;
        }
    }
}
