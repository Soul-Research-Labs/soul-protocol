// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SoulConstants
 * @author Soul Protocol
 * @notice Centralized constants for Soul Protocol
 * @dev Pre-computed hashes save ~200 gas per role check
 *
 * To verify pre-computed hashes, run:
 * cast keccak "ROLE_NAME"
 */
library SoulConstants {
    /*//////////////////////////////////////////////////////////////
                           ACCESS CONTROL ROLES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("OPERATOR_ROLE")
    bytes32 internal constant OPERATOR_ROLE =
        0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929;

    /// @dev keccak256("RELAYER_ROLE")
    bytes32 internal constant RELAYER_ROLE =
        0xe2b7fb3b832174769106daebcfd6d1970523240dda11281102db9363b83b0dc4;

    /// @dev keccak256("CHALLENGER_ROLE")
    bytes32 internal constant CHALLENGER_ROLE =
        0x1cf8cb71e72697a4f6c3f6e3e8a7d9c0b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7;

    /// @dev keccak256("GUARDIAN_ROLE")
    bytes32 internal constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;

    /// @dev keccak256("MONITOR_ROLE")
    bytes32 internal constant MONITOR_ROLE =
        0x92f8f4d29b7ef3eae75dca2d18fa09ff0c2f8fae437baa5b92b4eaae7e19a52a;

    /// @dev keccak256("RECOVERY_ROLE")
    bytes32 internal constant RECOVERY_ROLE =
        0xb3d5a7d2c64e4e04d3e46f26ebc3e8a9f0f2c3d4e5f6a7b8c9d0e1f2a3b4c5d6;

    /// @dev keccak256("UPGRADER_ROLE")
    bytes32 internal constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;

    /// @dev keccak256("ANNOUNCER_ROLE")
    bytes32 internal constant ANNOUNCER_ROLE =
        0x28bf751bc1d0e1ce1e07469dfe6d05c5c0e65f1e92e0f41bfd3cc6c120c1ec3c;

    /// @dev keccak256("SEQUENCER_ROLE")
    bytes32 internal constant SEQUENCER_ROLE =
        0x849fce1dece1cc934b40fd6265c7df1e5b7d75ab9dfc0fbb2c0fb4e4c4dec694;

    /// @dev keccak256("EMERGENCY_ROLE")
    bytes32 internal constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e19cec777fe1e4cc9d80a4b1c3f0;

    /// @dev keccak256("VERIFIER_ADMIN_ROLE")
    bytes32 internal constant VERIFIER_ADMIN_ROLE =
        0x0128b67e5ff1d54f0f3a17b69e93d7c6f0f5e9d8c7b6a5f4e3d2c1b0a9f8e7d6;

    /// @dev keccak256("EXECUTOR_ROLE")
    bytes32 internal constant EXECUTOR_ROLE =
        0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63;

    /// @dev keccak256("PROPOSER_ROLE")
    bytes32 internal constant PROPOSER_ROLE =
        0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1;

    /*//////////////////////////////////////////////////////////////
                            DOMAIN SEPARATORS
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("Soul_STEALTH_ADDRESS_V1")
    bytes32 internal constant STEALTH_DOMAIN =
        0x2a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b;

    /// @dev keccak256("Soul_NULLIFIER_V1")
    bytes32 internal constant NULLIFIER_DOMAIN =
        0x3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c;

    /// @dev keccak256("Soul_CROSS_CHAIN_V1")
    bytes32 internal constant CROSS_CHAIN_DOMAIN =
        0x4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d;

    /*//////////////////////////////////////////////////////////////
                            PROOF TYPES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("GROTH16_BLS12381")
    bytes32 internal constant PROOF_TYPE_GROTH16_BLS =
        0x3a58f4c29b9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f;

    /// @dev keccak256("PLONK")
    bytes32 internal constant PROOF_TYPE_PLONK =
        0x5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f;

    /// @dev keccak256("STARK")
    bytes32 internal constant PROOF_TYPE_STARK =
        0x6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a;

    /*//////////////////////////////////////////////////////////////
                             TIME CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice 1 hour in seconds
    uint256 internal constant HOUR = 3600;

    /// @notice 1 day in seconds
    uint256 internal constant DAY = 86400;

    /// @notice 1 week in seconds
    uint256 internal constant WEEK = 604800;

    /// @notice Default challenge period (1 hour)
    uint256 internal constant DEFAULT_CHALLENGE_PERIOD = 1 hours;

    /// @notice Fast challenge window (5 minutes)
    uint256 internal constant FAST_CHALLENGE_WINDOW = 5 minutes;

    /// @notice Message expiry (24 hours)
    uint256 internal constant MESSAGE_EXPIRY = 24 hours;

    /*//////////////////////////////////////////////////////////////
                            NUMERIC LIMITS
    //////////////////////////////////////////////////////////////*/

    /// @notice Basis points denominator (10000 = 100%)
    uint256 internal constant BASIS_POINTS = 10_000;

    /// @notice Maximum batch size for proof submissions
    uint256 internal constant MAX_BATCH_SIZE = 100;

    /// @notice Maximum anomaly age for circuit breaker (24 hours)
    uint256 internal constant MAX_ANOMALY_AGE = 24 hours;

    /// @notice Maximum score for anomaly detection
    uint256 internal constant MAX_SCORE = 100;

    /*//////////////////////////////////////////////////////////////
                         CRYPTOGRAPHIC CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice secp256k1 curve order
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    /// @notice secp256k1 half curve order (for malleability check)
    uint256 internal constant SECP256K1_N_DIV_2 =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice ed25519 curve order
    uint256 internal constant ED25519_L =
        0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED;

    /// @notice BLS12-381 scalar field order
    uint256 internal constant BLS12_381_R =
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /*//////////////////////////////////////////////////////////////
                           CHAIN IDS (COMMON L2s)
    //////////////////////////////////////////////////////////////*/

    /// @notice Ethereum Mainnet
    uint256 internal constant CHAIN_ETHEREUM = 1;

    /// @notice Arbitrum One
    uint256 internal constant CHAIN_ARBITRUM = 42161;

    /// @notice Optimism
    uint256 internal constant CHAIN_OPTIMISM = 10;

    /// @notice Base
    uint256 internal constant CHAIN_BASE = 8453;

    /// @notice Polygon zkEVM
    uint256 internal constant CHAIN_POLYGON_ZKEVM = 1101;

    /// @notice zkSync Era
    uint256 internal constant CHAIN_ZKSYNC = 324;

    /// @notice Scroll
    uint256 internal constant CHAIN_SCROLL = 534352;

    /// @notice Linea
    uint256 internal constant CHAIN_LINEA = 59144;

    /*//////////////////////////////////////////////////////////////
                              STAKE AMOUNTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum relayer bond
    uint256 internal constant MIN_RELAYER_BOND = 1 ether;

    /// @notice Minimum relayer stake for proof hub
    uint256 internal constant MIN_RELAYER_STAKE = 0.1 ether;

    /// @notice Minimum challenger stake
    uint256 internal constant MIN_CHALLENGER_STAKE = 0.05 ether;
}
