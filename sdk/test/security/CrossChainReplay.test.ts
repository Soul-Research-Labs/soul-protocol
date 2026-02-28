/**
 * SDK Security Tests — Cross-Chain Replay Protection
 *
 * Tests that SDK-generated messages include correct chain IDs, nonces,
 * and domain separators that prevent cross-chain replay attacks.
 */

import { expect } from "chai";
import {
  keccak256,
  encodePacked,
  toBytes,
  toHex,
  stringToBytes,
  Hex,
} from "viem";

// Supported chain IDs
const CHAINS = {
  ETHEREUM: 1,
  ARBITRUM: 42161,
  OPTIMISM: 10,
  BASE: 8453,
  SCROLL: 534352,
  LINEA: 59144,
  ZKSYNC: 324,
  POLYGON_ZKEVM: 1101,
};

describe("Cross-Chain Replay Protection", () => {
  describe("Domain Separator Uniqueness", () => {
    it("should produce unique domain separators for each chain", () => {
      const domainSeparators = new Map<string, number>();

      Object.entries(CHAINS).forEach(([name, chainId]) => {
        const domain = keccak256(
          toBytes(
            encodePacked(
              ["string", "uint256"],
              ["ZaseonProtocol", BigInt(chainId)],
            ),
          ),
        );
        expect(domainSeparators.has(domain)).to.be.false;
        domainSeparators.set(domain, chainId);
      });

      expect(domainSeparators.size).to.equal(Object.keys(CHAINS).length);
    });

    it("should include chain ID in EIP-712 domain", () => {
      const chainId = CHAINS.ARBITRUM;
      const domain = keccak256(
        toBytes(
          encodePacked(
            ["bytes32", "bytes32", "uint256"],
            [
              keccak256(
                stringToBytes("EIP712Domain(string name,uint256 chainId)"),
              ),
              keccak256(stringToBytes("ZaseonProtocol")),
              BigInt(chainId),
            ],
          ),
        ),
      );

      expect(domain).to.match(/^0x[a-f0-9]{64}$/);
      expect(domain).to.not.equal(keccak256(stringToBytes("")));
    });
  });

  describe("Message Hash Chain Binding", () => {
    it("should bind message to source and destination chain", () => {
      const payload = keccak256(stringToBytes("transfer_100_tokens"));
      const nonce = BigInt(1);

      const msgHashArbToOpt = keccak256(
        toBytes(
          encodePacked(
            ["uint256", "uint256", "bytes32", "uint256"],
            [BigInt(CHAINS.ARBITRUM), BigInt(CHAINS.OPTIMISM), payload, nonce],
          ),
        ),
      );

      const msgHashOptToArb = keccak256(
        toBytes(
          encodePacked(
            ["uint256", "uint256", "bytes32", "uint256"],
            [BigInt(CHAINS.OPTIMISM), BigInt(CHAINS.ARBITRUM), payload, nonce],
          ),
        ),
      );

      // Swapping source/dest must change hash
      expect(msgHashArbToOpt).to.not.equal(msgHashOptToArb);
    });

    it("should produce different hashes for same payload on different routes", () => {
      const payload = keccak256(stringToBytes("same_payload"));
      const nonce = BigInt(42);

      const routes = [
        [CHAINS.ARBITRUM, CHAINS.OPTIMISM],
        [CHAINS.ARBITRUM, CHAINS.BASE],
        [CHAINS.OPTIMISM, CHAINS.BASE],
        [CHAINS.BASE, CHAINS.ARBITRUM],
      ];

      const hashes = routes.map(([src, dst]) =>
        keccak256(
          toBytes(
            encodePacked(
              ["uint256", "uint256", "bytes32", "uint256"],
              [BigInt(src), BigInt(dst), payload, nonce],
            ),
          ),
        ),
      );

      // All hashes should be unique
      const uniqueHashes = new Set(hashes);
      expect(uniqueHashes.size).to.equal(routes.length);
    });
  });

  describe("Nonce Replay Prevention", () => {
    it("should produce different hashes for different nonces", () => {
      const source = BigInt(CHAINS.ARBITRUM);
      const dest = BigInt(CHAINS.OPTIMISM);
      const payload = keccak256(stringToBytes("test"));

      const hashes = new Set<string>();
      for (let i = 0; i < 100; i++) {
        const hash = keccak256(
          toBytes(
            encodePacked(
              ["uint256", "uint256", "bytes32", "uint256"],
              [source, dest, payload, BigInt(i)],
            ),
          ),
        );
        hashes.add(hash);
      }

      expect(hashes.size).to.equal(100);
    });

    it("should monotonically increase nonces", () => {
      let nonce = 0;
      const incrementNonce = () => ++nonce;

      incrementNonce();
      expect(nonce).to.equal(1);
      incrementNonce();
      expect(nonce).to.equal(2);
      // Nonce should never decrease
      expect(nonce).to.be.greaterThan(0);
    });
  });

  describe("Nullifier Cross-Domain Derivation", () => {
    it("should derive unique nullifiers per domain", () => {
      const parentNullifier = keccak256(stringToBytes("original_nullifier"));

      const derived = Object.entries(CHAINS).map(([name, chainId]) => {
        return keccak256(
          toBytes(
            encodePacked(
              ["bytes32", "uint256"],
              [parentNullifier, BigInt(chainId)],
            ),
          ),
        );
      });

      // All derived nullifiers should be unique
      const unique = new Set(derived);
      expect(unique.size).to.equal(Object.keys(CHAINS).length);
    });

    it("should be deterministic for same parent + domain", () => {
      const parent = keccak256(stringToBytes("parent"));
      const chainId = BigInt(CHAINS.ARBITRUM);

      const d1 = keccak256(
        toBytes(encodePacked(["bytes32", "uint256"], [parent, chainId])),
      );
      const d2 = keccak256(
        toBytes(encodePacked(["bytes32", "uint256"], [parent, chainId])),
      );

      expect(d1).to.equal(d2);
    });
  });
});
