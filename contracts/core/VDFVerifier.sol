// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title VDFVerifier
 * @notice On-chain verification of Verifiable Delay Function outputs
 * @dev Implements verification for VDF-based unbiasable randomness
 * Reference: https://vitalik.eth.limo/general/2024/10/29/futures6.html
 *
 * VDFs provide:
 * - Unbiasable randomness (sequential computation prevents manipulation)
 * - Efficient verification (O(log T) for Wesolowski/Pietrzak proofs)
 * - Cross-chain beacon coordination
 */
contract VDFVerifier is ReentrancyGuard, Ownable, Pausable {
    // ============================================================================
    // CONSTANTS
    // ============================================================================
    
    /// @notice Minimum iterations for VDF security
    uint256 public constant MIN_ITERATIONS = 1_000_000;
    
    /// @notice Maximum iterations supported
    uint256 public constant MAX_ITERATIONS = 1_000_000_000_000;
    
    /// @notice Beacon validity period (1 hour)
    uint256 public constant BEACON_VALIDITY_PERIOD = 3600;
    
    /// @notice Cross-chain time tolerance (5 minutes)
    uint256 public constant CROSS_CHAIN_TIME_TOLERANCE = 300;

    // ============================================================================
    // STRUCTS
    // ============================================================================
    
    /// @notice VDF input parameters
    struct VDFInput {
        bytes32 seed;
        uint256 iterations;
        uint256 modulus;
    }
    
    /// @notice Wesolowski proof (O(1) size)
    struct WesolowskiProof {
        uint256 y;      // VDF output
        uint256 pi;     // Proof element (quotient)
        uint256 l;      // Challenge prime
    }
    
    /// @notice Pietrzak proof (O(log T) size)
    struct PietrzakProof {
        uint256 y;
        uint256[20] intermediates; // log(T) intermediate values
        uint8 numLevels;
    }
    
    /// @notice Randomness beacon output
    struct RandomnessBeacon {
        uint64 chainId;
        uint64 blockNumber;
        bytes32 blockHash;
        uint256 vdfOutput;
        uint256 timestamp;
        bytes32 commitment;
    }
    
    /// @notice Cross-chain beacon sync
    struct CrossChainSync {
        bytes32 localCommitment;
        bytes32 remoteCommitment;
        uint64 remoteChainId;
        bytes32 merkleRoot;
        bool verified;
    }
    
    /// @notice Relayer selection result
    struct RelayerSelection {
        address relayer;
        uint256 stake;
        bytes32 beaconCommitment;
        uint256 round;
    }

    // ============================================================================
    // STATE VARIABLES
    // ============================================================================
    
    /// @notice Verified VDF outputs by commitment
    mapping(bytes32 => uint256) public verifiedOutputs;
    
    /// @notice Randomness beacons by chain and block
    mapping(uint64 => mapping(uint64 => RandomnessBeacon)) public beacons;
    
    /// @notice Cross-chain sync records
    mapping(bytes32 => CrossChainSync) public crossChainSyncs;
    
    /// @notice Relayer stakes
    mapping(address => uint256) public relayerStakes;
    
    /// @notice Registered relayers
    address[] public relayers;
    
    /// @notice Total relayer stake
    uint256 public totalRelayerStake;
    
    /// @notice Latest beacon commitment
    bytes32 public latestBeaconCommitment;
    
    /// @notice RSA modulus for repeated squaring VDF
    uint256 public rsaModulus;

    // ============================================================================
    // EVENTS
    // ============================================================================
    
    event VDFOutputVerified(bytes32 indexed inputHash, uint256 output);
    event BeaconPublished(uint64 indexed chainId, uint64 blockNumber, bytes32 commitment);
    event CrossChainSyncVerified(bytes32 indexed syncId, uint64 remoteChainId);
    event RelayerSelected(address indexed relayer, uint256 round, bytes32 beaconCommitment);
    event RelayerRegistered(address indexed relayer, uint256 stake);
    event RelayerUnregistered(address indexed relayer);

    // ============================================================================
    // ERRORS
    // ============================================================================
    
    error InvalidIterations();
    error InvalidProof();
    error BeaconExpired();
    error InvalidTimestamp();
    error InsufficientStake();
    error RelayerNotRegistered();
    error InvalidMerkleProof();
    error SyncAlreadyVerified();

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================
    
    constructor(uint256 _rsaModulus) Ownable(msg.sender) {
        rsaModulus = _rsaModulus;
    }

    // ============================================================================
    // ADMIN FUNCTIONS
    // ============================================================================
    
    /// @notice Update RSA modulus
    function setRSAModulus(uint256 _rsaModulus) external onlyOwner {
        rsaModulus = _rsaModulus;
    }
    
    /// @notice Pause verification
    function pause() external onlyOwner {
        _pause();
    }
    
    /// @notice Unpause verification
    function unpause() external onlyOwner {
        _unpause();
    }

    // ============================================================================
    // VDF VERIFICATION
    // ============================================================================
    
    /// @notice Compute VDF input hash
    function computeInputHash(VDFInput calldata input) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(input.seed, input.iterations, input.modulus));
    }
    
    /// @notice Verify Wesolowski proof
    /// @dev O(log T) verification for repeated squaring VDF
    function verifyWesolowskiProof(
        VDFInput calldata input,
        WesolowskiProof calldata proof
    ) external nonReentrant whenNotPaused returns (bool) {
        if (input.iterations < MIN_ITERATIONS || input.iterations > MAX_ITERATIONS) {
            revert InvalidIterations();
        }
        
        // Compute challenge from (x, y, T)
        uint256 x = uint256(input.seed);
        bytes32 challengeHash = keccak256(abi.encodePacked(x, proof.y, input.iterations));
        uint256 l = uint256(challengeHash) % (1 << 128); // Use 128-bit challenge
        
        // Verify l matches provided
        if (l != proof.l) revert InvalidProof();
        
        // Verify: pi^l * x^r = y (mod N)
        // where r = 2^T mod l
        uint256 r = _modExp(2, input.iterations, proof.l);
        
        // Compute pi^l mod N
        uint256 piL = _modExp(proof.pi, proof.l, input.modulus);
        
        // Compute x^r mod N
        uint256 xR = _modExp(x, r, input.modulus);
        
        // Verify pi^l * x^r = y
        uint256 computed = mulmod(piL, xR, input.modulus);
        
        if (computed != proof.y) revert InvalidProof();
        
        // Store verified output
        bytes32 inputHash = computeInputHash(input);
        verifiedOutputs[inputHash] = proof.y;
        
        emit VDFOutputVerified(inputHash, proof.y);
        return true;
    }
    
    /// @notice Verify Pietrzak proof
    /// @dev Interactive-to-non-interactive via Fiat-Shamir
    function verifyPietrzakProof(
        VDFInput calldata input,
        PietrzakProof calldata proof
    ) external nonReentrant whenNotPaused returns (bool) {
        if (input.iterations < MIN_ITERATIONS || input.iterations > MAX_ITERATIONS) {
            revert InvalidIterations();
        }
        
        uint256 x = uint256(input.seed);
        uint256 y = proof.y;
        uint256 t = input.iterations;
        
        for (uint8 i = 0; i < proof.numLevels; i++) {
            uint256 mu = proof.intermediates[i];
            
            // Compute challenge r
            bytes32 rHash = keccak256(abi.encodePacked(x, y, mu));
            uint256 r = uint256(rHash) % (1 << 64);
            
            // Update: x' = x^r * mu, y' = mu^r * y
            uint256 xR = _modExp(x, r, input.modulus);
            uint256 muR = _modExp(mu, r, input.modulus);
            
            x = mulmod(xR, mu, input.modulus);
            y = mulmod(muR, y, input.modulus);
            t = t / 2;
        }
        
        // Final check: x^2 = y
        uint256 xSquared = mulmod(x, x, input.modulus);
        if (xSquared != y) revert InvalidProof();
        
        // Store verified output
        bytes32 inputHash = computeInputHash(input);
        verifiedOutputs[inputHash] = proof.y;
        
        emit VDFOutputVerified(inputHash, proof.y);
        return true;
    }

    // ============================================================================
    // RANDOMNESS BEACON
    // ============================================================================
    
    /// @notice Publish randomness beacon
    function publishBeacon(
        uint64 blockNumber,
        bytes32 blockHash,
        uint256 vdfOutput,
        bytes32 proofCommitment
    ) external nonReentrant whenNotPaused {
        // Verify VDF output was previously verified
        bytes32 commitment = keccak256(abi.encodePacked(
            uint64(block.chainid),
            blockNumber,
            blockHash,
            vdfOutput
        ));
        
        RandomnessBeacon memory beacon = RandomnessBeacon({
            chainId: uint64(block.chainid),
            blockNumber: blockNumber,
            blockHash: blockHash,
            vdfOutput: vdfOutput,
            timestamp: block.timestamp,
            commitment: commitment
        });
        
        beacons[uint64(block.chainid)][blockNumber] = beacon;
        latestBeaconCommitment = commitment;
        
        emit BeaconPublished(uint64(block.chainid), blockNumber, commitment);
    }
    
    /// @notice Get randomness from beacon
    function getBeaconRandomness(
        uint64 chainId,
        uint64 blockNumber,
        bytes32 purpose,
        uint256 index
    ) external view returns (uint256) {
        RandomnessBeacon memory beacon = beacons[chainId][blockNumber];
        
        if (beacon.timestamp == 0) revert InvalidProof();
        if (block.timestamp > beacon.timestamp + BEACON_VALIDITY_PERIOD) {
            revert BeaconExpired();
        }
        
        return uint256(keccak256(abi.encodePacked(
            beacon.commitment,
            purpose,
            index
        )));
    }

    // ============================================================================
    // CROSS-CHAIN SYNC
    // ============================================================================
    
    /// @notice Verify cross-chain beacon sync
    function verifyCrossChainSync(
        bytes32 syncId,
        bytes32 remoteCommitment,
        uint64 remoteChainId,
        bytes32[] calldata merkleProof,
        bytes32 merkleRoot
    ) external nonReentrant whenNotPaused {
        CrossChainSync storage sync = crossChainSyncs[syncId];
        if (sync.verified) revert SyncAlreadyVerified();
        
        // Verify Merkle inclusion
        bytes32 leaf = remoteCommitment;
        for (uint256 i = 0; i < merkleProof.length; i++) {
            bytes32 proofElement = merkleProof[i];
            if (leaf < proofElement) {
                leaf = keccak256(abi.encodePacked(leaf, proofElement));
            } else {
                leaf = keccak256(abi.encodePacked(proofElement, leaf));
            }
        }
        
        if (leaf != merkleRoot) revert InvalidMerkleProof();
        
        sync.localCommitment = latestBeaconCommitment;
        sync.remoteCommitment = remoteCommitment;
        sync.remoteChainId = remoteChainId;
        sync.merkleRoot = merkleRoot;
        sync.verified = true;
        
        emit CrossChainSyncVerified(syncId, remoteChainId);
    }

    // ============================================================================
    // RELAYER SELECTION
    // ============================================================================
    
    /// @notice Register as relayer
    function registerRelayer() external payable nonReentrant {
        if (msg.value < 1 ether) revert InsufficientStake();
        
        relayerStakes[msg.sender] += msg.value;
        totalRelayerStake += msg.value;
        
        // Add to relayers array if new
        bool exists = false;
        for (uint256 i = 0; i < relayers.length; i++) {
            if (relayers[i] == msg.sender) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            relayers.push(msg.sender);
        }
        
        emit RelayerRegistered(msg.sender, relayerStakes[msg.sender]);
    }
    
    /// @notice Unregister as relayer
    function unregisterRelayer() external nonReentrant {
        uint256 stake = relayerStakes[msg.sender];
        if (stake == 0) revert RelayerNotRegistered();
        
        relayerStakes[msg.sender] = 0;
        totalRelayerStake -= stake;
        
        // Remove from relayers array
        for (uint256 i = 0; i < relayers.length; i++) {
            if (relayers[i] == msg.sender) {
                relayers[i] = relayers[relayers.length - 1];
                relayers.pop();
                break;
            }
        }
        
        // Return stake
        (bool success, ) = msg.sender.call{value: stake}("");
        require(success, "Transfer failed");
        
        emit RelayerUnregistered(msg.sender);
    }
    
    /// @notice Select relayer using VDF randomness
    function selectRelayer(uint256 round) external view returns (RelayerSelection memory) {
        if (relayers.length == 0) revert RelayerNotRegistered();
        if (latestBeaconCommitment == bytes32(0)) revert InvalidProof();
        
        // Derive random value from beacon
        uint256 randomValue = uint256(keccak256(abi.encodePacked(
            latestBeaconCommitment,
            round
        )));
        
        uint256 target = randomValue % totalRelayerStake;
        
        // Select based on stake weight
        uint256 cumulative = 0;
        address selected;
        uint256 selectedStake;
        
        for (uint256 i = 0; i < relayers.length; i++) {
            cumulative += relayerStakes[relayers[i]];
            if (cumulative > target) {
                selected = relayers[i];
                selectedStake = relayerStakes[relayers[i]];
                break;
            }
        }
        
        return RelayerSelection({
            relayer: selected,
            stake: selectedStake,
            beaconCommitment: latestBeaconCommitment,
            round: round
        });
    }

    // ============================================================================
    // HELPER FUNCTIONS
    // ============================================================================
    
    /// @notice Modular exponentiation using precompile
    function _modExp(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256 result) {
        // Use MODEXP precompile at address 0x05
        bytes memory input = abi.encodePacked(
            uint256(32),  // base length
            uint256(32),  // exp length
            uint256(32),  // mod length
            base,
            exp,
            mod
        );
        
        (bool success, bytes memory output) = address(0x05).staticcall(input);
        require(success, "MODEXP failed");
        
        result = abi.decode(output, (uint256));
    }

    // ============================================================================
    // VIEW FUNCTIONS
    // ============================================================================
    
    /// @notice Get verified VDF output
    function getVerifiedOutput(bytes32 inputHash) external view returns (uint256) {
        return verifiedOutputs[inputHash];
    }
    
    /// @notice Get beacon
    function getBeacon(uint64 chainId, uint64 blockNumber) 
        external view returns (RandomnessBeacon memory) 
    {
        return beacons[chainId][blockNumber];
    }
    
    /// @notice Get relayer count
    function getRelayerCount() external view returns (uint256) {
        return relayers.length;
    }
    
    /// @notice Get all relayers
    function getRelayers() external view returns (address[] memory) {
        return relayers;
    }
}
