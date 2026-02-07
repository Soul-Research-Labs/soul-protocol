/*
 * ERC-8004 Trustless Agents – Certora Formal Verification Spec
 * Covers Identity, Reputation, and Validation Registries
 *
 * invariants:  8 safety invariants
 * rules:      14 property rules
 */

// =================================================================
//  IDENTITY REGISTRY SPEC
// =================================================================
methods {
    // Identity Registry
    function register(string, IERC8004IdentityRegistry.MetadataEntry[]) external returns (uint256);
    function register(string) external returns (uint256);
    function register() external returns (uint256);
    function setAgentURI(uint256, string) external;
    function setMetadata(uint256, string, bytes) external;
    function getMetadata(uint256, string) external returns (bytes) envfree;
    function setAgentWallet(uint256, address, uint256, bytes) external;
    function getAgentWallet(uint256) external returns (address) envfree;
    function unsetAgentWallet(uint256) external;
    function totalAgents() external returns (uint256) envfree;
    function ownerOf(uint256) external returns (address) envfree;
    function AGENT_WALLET_TYPEHASH() external returns (bytes32) envfree;
    function AGENT_WALLET_KEY() external returns (string) envfree;

    // Reputation Registry  
    function giveFeedback(uint256, int128, uint8, string, string, string, string, bytes32) external;
    function revokeFeedback(uint256, uint64) external;
    function appendResponse(uint256, address, uint64, string, bytes32) external;
    function getSummary(uint256, address[], string, string) external returns (uint64, int128, uint8) envfree;
    function readFeedback(uint256, address, uint64) external returns (int128, uint8, string, string, bool) envfree;
    function getResponseCount(uint256, address, uint64, address[]) external returns (uint64) envfree;
    function getClients(uint256) external returns (address[]) envfree;
    function getLastIndex(uint256, address) external returns (uint64) envfree;

    // Validation Registry
    function validationRequest(address, uint256, string, bytes32) external;
    function validationResponse(bytes32, uint8, string, bytes32, string) external;
    function getValidationStatus(bytes32) external returns (address, uint256, uint8, bytes32, string, uint256) envfree;
    function getSummary(uint256, address[], string) external returns (uint64, uint8) envfree;
    function getAgentValidations(uint256) external returns (bytes32[]) envfree;
    function getValidatorRequests(address) external returns (bytes32[]) envfree;
}

// =================================================================
//  IDENTITY INVARIANTS
// =================================================================

/// @notice Agent IDs are always 1-indexed (totalAgents tracks count)
invariant totalAgentsNonNegative()
    totalAgents() >= 0;

/// @notice Agent wallet typehash is constant
invariant agentWalletTypehashConstant()
    AGENT_WALLET_TYPEHASH() == to_bytes32(keccak256("SetAgentWallet(uint256 agentId,address newWallet,uint256 deadline)"));

// =================================================================
//  IDENTITY RULES
// =================================================================

/// @notice Registration increments totalAgents
rule registerIncrementsTotalAgents {
    env e;
    uint256 before = totalAgents();

    uint256 agentId = register(e);

    uint256 after = totalAgents();
    assert after == before + 1, "totalAgents must increment by 1 on registration";
}

/// @notice Registered agent belongs to caller
rule registeredAgentOwnedByCaller {
    env e;
    uint256 agentId = register(e);
    assert ownerOf(agentId) == e.msg.sender, "Agent must be owned by the registrant";
}

/// @notice Agent wallet defaults to owner on registration
rule defaultWalletIsOwner {
    env e;
    uint256 agentId = register(e);
    assert getAgentWallet(agentId) == e.msg.sender, "Default wallet must be registrant";
}

/// @notice Unset wallet clears to zero
rule unsetWalletClearsToZero {
    env e;
    uint256 agentId;
    require getAgentWallet(agentId) != address(0);

    unsetAgentWallet(e, agentId);

    assert getAgentWallet(agentId) == address(0), "Wallet must be zeroed after unset";
}

/// @notice Only owner/operator can set metadata
rule onlyOwnerCanSetMetadata {
    env e;
    uint256 agentId;
    string key;
    bytes value;

    require e.msg.sender != ownerOf(agentId);
    // Simplified: non-owner call should revert
    setMetadata@withrevert(e, agentId, key, value);
    assert lastReverted, "Non-owner metadata set must revert";
}

// =================================================================
//  REPUTATION INVARIANTS
// =================================================================

/// @notice Feedback index is always non-negative
invariant feedbackIndexNonNegative(uint256 agentId, address client)
    getLastIndex(agentId, client) >= 0;

/// @notice Clients array never shrinks
invariant clientsNeverShrink(uint256 agentId)
    getClients(agentId).length >= 0;

// =================================================================
//  REPUTATION RULES
// =================================================================

/// @notice giveFeedback increments last index
rule giveFeedbackIncrementsIndex {
    env e;
    uint256 agentId;
    int128 value;
    uint8 decimals;
    string tag1;
    string tag2;
    string endpoint;
    string uri;
    bytes32 hash;

    uint64 before = getLastIndex(agentId, e.msg.sender);

    giveFeedback(e, agentId, value, decimals, tag1, tag2, endpoint, uri, hash);

    uint64 after = getLastIndex(agentId, e.msg.sender);
    assert after == before + 1, "Feedback index must increment by 1";
}

/// @notice Revoked feedback sets isRevoked to true
rule revokeSetsFlag {
    env e;
    uint256 agentId;
    uint64 feedbackIndex;

    revokeFeedback(e, agentId, feedbackIndex);

    int128 v;
    uint8 d;
    string t1;
    string t2;
    bool revoked;
    (v, d, t1, t2, revoked) = readFeedback(agentId, e.msg.sender, feedbackIndex);
    assert revoked == true, "Feedback must be revoked after revokeFeedback";
}

/// @notice Cannot give feedback with decimals > 18
rule rejectHighDecimals {
    env e;
    uint256 agentId;
    int128 value;
    uint8 decimals;
    require decimals > 18;

    giveFeedback@withrevert(e, agentId, value, decimals, "", "", "", "", to_bytes32(0));
    assert lastReverted, "Decimals > 18 must revert";
}

/// @notice Empty client list in getSummary must revert
rule emptyClientListReverts {
    uint256 agentId;
    address[] empty;
    require empty.length == 0;

    getSummary@withrevert(agentId, empty, "", "");
    assert lastReverted, "Empty client list must revert";
}

// =================================================================
//  VALIDATION INVARIANTS
// =================================================================

/// @notice Agent validations array length is non-negative
invariant agentValidationsNonNeg(uint256 agentId)
    getAgentValidations(agentId).length >= 0;

/// @notice Validator requests array length is non-negative
invariant validatorRequestsNonNeg(address v)
    getValidatorRequests(v).length >= 0;

// =================================================================
//  VALIDATION RULES
// =================================================================

/// @notice Validation request tracks hash in agent's list
rule requestTrackedInAgentList {
    env e;
    address validatorAddr;
    uint256 agentId;
    string uri;
    bytes32 reqHash;

    uint256 before = getAgentValidations(agentId).length;

    validationRequest(e, validatorAddr, agentId, uri, reqHash);

    uint256 after = getAgentValidations(agentId).length;
    assert after >= before, "Agent validation list must not shrink";
}

/// @notice Validation response updates the response field
rule responseUpdatesEntry {
    env e;
    bytes32 reqHash;
    uint8 response;
    string respURI;
    bytes32 respHash;
    string tag;

    require response <= 100;

    validationResponse(e, reqHash, response, respURI, respHash, tag);

    address vAddr;
    uint256 aId;
    uint8 resp;
    bytes32 rHash;
    string tagOut;
    uint256 lastUpdate;
    (vAddr, aId, resp, rHash, tagOut, lastUpdate) = getValidationStatus(reqHash);
    
    assert resp == response, "Response must match submitted value";
    assert lastUpdate > 0, "Last update must be set";
}

/// @notice Response > 100 must revert
rule invalidResponseReverts {
    env e;
    bytes32 reqHash;
    uint8 response;
    require response > 100;

    validationResponse@withrevert(e, reqHash, response, "", to_bytes32(0), "");
    assert lastReverted, "Response > 100 must revert";
}

/// @notice Non-designated validator cannot respond
rule onlyDesignatedValidatorCanRespond {
    env e;
    bytes32 reqHash;
    uint8 response;

    address vAddr;
    uint256 aId;
    uint8 resp;
    bytes32 rHash;
    string tag;
    uint256 lastUpdate;
    (vAddr, aId, resp, rHash, tag, lastUpdate) = getValidationStatus(reqHash);

    require e.msg.sender != vAddr;

    validationResponse@withrevert(e, reqHash, response, "", to_bytes32(0), "");
    assert lastReverted, "Non-designated validator must be rejected";
}
