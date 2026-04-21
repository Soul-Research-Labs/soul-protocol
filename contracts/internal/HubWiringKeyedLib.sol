// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZaseonProtocolHub} from "../interfaces/IZaseonProtocolHub.sol";

/// @title HubWiringKeyedLib
/// @author ZASEON
/// @notice Builds the canonical keyed payload for `ZaseonProtocolHub.wireAllKeyed`.
library HubWiringKeyedLib {
    uint256 internal constant WIRE_ALL_KEY_COUNT = 23;

    function fromWireAllParams(
        IZaseonProtocolHub.WireAllParams memory p
    ) internal pure returns (bytes32[] memory keys, address[] memory addrs) {
        keys = new bytes32[](WIRE_ALL_KEY_COUNT);
        addrs = new address[](WIRE_ALL_KEY_COUNT);

        keys[0] = keccak256("verifierRegistry");
        addrs[0] = p._verifierRegistry;
        keys[1] = keccak256("universalVerifier");
        addrs[1] = p._universalVerifier;
        keys[2] = keccak256("crossChainMessageRelay");
        addrs[2] = p._crossChainMessageRelay;
        keys[3] = keccak256("crossChainPrivacyHub");
        addrs[3] = p._crossChainPrivacyHub;
        keys[4] = keccak256("stealthAddressRegistry");
        addrs[4] = p._stealthAddressRegistry;
        keys[5] = keccak256("privateRelayerNetwork");
        addrs[5] = p._privateRelayerNetwork;
        keys[6] = keccak256("viewKeyRegistry");
        addrs[6] = p._viewKeyRegistry;
        keys[7] = keccak256("shieldedPool");
        addrs[7] = p._shieldedPool;
        keys[8] = keccak256("nullifierManager");
        addrs[8] = p._nullifierManager;
        keys[9] = keccak256("complianceOracle");
        addrs[9] = p._complianceOracle;
        keys[10] = keccak256("proofTranslator");
        addrs[10] = p._proofTranslator;
        keys[11] = keccak256("privacyRouter");
        addrs[11] = p._privacyRouter;
        keys[12] = keccak256("relayProofValidator");
        addrs[12] = p._relayProofValidator;
        keys[13] = keccak256("zkBoundStateLocks");
        addrs[13] = p._zkBoundStateLocks;
        keys[14] = keccak256("proofCarryingContainer");
        addrs[14] = p._proofCarryingContainer;
        keys[15] = keccak256("crossDomainNullifierAlgebra");
        addrs[15] = p._crossDomainNullifierAlgebra;
        keys[16] = keccak256("policyBoundProofs");
        addrs[16] = p._policyBoundProofs;
        keys[17] = keccak256("multiProver");
        addrs[17] = p._multiProver;
        keys[18] = keccak256("relayWatchtower");
        addrs[18] = p._relayWatchtower;
        keys[19] = keccak256("intentCompletionLayer");
        addrs[19] = p._intentCompletionLayer;
        keys[20] = keccak256("instantCompletionGuarantee");
        addrs[20] = p._instantCompletionGuarantee;
        keys[21] = keccak256("dynamicRoutingOrchestrator");
        addrs[21] = p._dynamicRoutingOrchestrator;
        keys[22] = keccak256("crossChainLiquidityVault");
        addrs[22] = p._crossChainLiquidityVault;
    }
}
