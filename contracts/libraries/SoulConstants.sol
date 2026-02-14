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
        0xe752add323323eb13e36c71ee508dfd16d74e9e4c4fd78786ba97989e5e13818;

    /// @dev keccak256("GUARDIAN_ROLE")
    bytes32 internal constant GUARDIAN_ROLE =
        0x55435dd261a4b9b3364963f7738a7a662ad9c84396d64be3365284bb7f0a5041;

    /// @dev keccak256("MONITOR_ROLE")
    bytes32 internal constant MONITOR_ROLE =
        0x8227712ef8ad39d0f26f06731ef0df8665eb7ada7f41b1ee089adf3c238862a2;

    /// @dev keccak256("RECOVERY_ROLE")
    bytes32 internal constant RECOVERY_ROLE =
        0x0acf805600123ef007091da3b3ffb39474074c656c127aa68cb0ffec232a8ff8;

    /// @dev keccak256("UPGRADER_ROLE")
    bytes32 internal constant UPGRADER_ROLE =
        0x189ab7a9244df0848122154315af71fe140f3db0fe014031783b0946b8c9d2e3;

    /// @dev keccak256("ANNOUNCER_ROLE")
    bytes32 internal constant ANNOUNCER_ROLE =
        0x6e925cbf9b246ec609b2c956a4ec0074fde4bcbc1f65aadcebf89efbd7f60a6a;

    /// @dev keccak256("SEQUENCER_ROLE")
    bytes32 internal constant SEQUENCER_ROLE =
        0xac4f1890dc96c9a02330d1fa696648a38f3b282d2449c2d8e6f10507488c84c8;

    /// @dev keccak256("EMERGENCY_ROLE")
    bytes32 internal constant EMERGENCY_ROLE =
        0xbf233dd2aafeb4d50879c4aa5c81e96d92f6e6945c906a58f9f2d1c1631b4b26;

    /// @dev keccak256("VERIFIER_ADMIN_ROLE")
    bytes32 internal constant VERIFIER_ADMIN_ROLE =
        0xb194a0b06484f8a501e0bef8877baf2a303f803540f5ddeb9d985c0cd76f3e70;

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
        0xa219e6ccf48da8087a92d8762778a8ffa3ee060308b58c3817ecd1ef293e182f;

    /// @dev keccak256("Soul_NULLIFIER_V1")
    bytes32 internal constant NULLIFIER_DOMAIN =
        0xf7f782cc8fce305d843ac89c8740753ef950563552125592ec4bd78a3f817d18;

    /// @dev keccak256("Soul_CROSS_CHAIN_V1")
    bytes32 internal constant CROSS_CHAIN_DOMAIN =
        0x6614a1204bb950ebcea006429f54e5944f45260fce2c2a11144fa0e9939928f8;

    /*//////////////////////////////////////////////////////////////
                            PROOF TYPES
    //////////////////////////////////////////////////////////////*/

    /// @dev keccak256("GROTH16_BLS12381")
    bytes32 internal constant PROOF_TYPE_GROTH16_BLS =
        0xde9274eb15475d7b1ada2fb3369f6493b97a5fab24247e8a7a10e15df93b9c94;

    /// @dev keccak256("PLONK")
    bytes32 internal constant PROOF_TYPE_PLONK =
        0x1ed479f945b11c8bc1baeea5959da750449aca7d7a597c510beff0a053ba9791;

    /// @dev keccak256("STARK")
    bytes32 internal constant PROOF_TYPE_STARK =
        0xd377136c2fbeb41ddcec98a939844ed750bef1d2a33d24d6f0355730a9cc7b44;

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
