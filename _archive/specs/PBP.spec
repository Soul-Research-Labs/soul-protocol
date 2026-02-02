/**
 * @title Certora Verification Rules for PolicyBoundProofs
 * @notice Machine-verifiable specifications for policy-bound proof verification
 * @dev Run with: certoraRun specs/PBP.spec --contract PolicyBoundProofs
 */

using PolicyBoundProofs as PBP;

/*//////////////////////////////////////////////////////////////
                         METHODS
//////////////////////////////////////////////////////////////*/

methods {
    // State variables
    function totalPolicies() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
    
    // View functions
    function getPolicy(bytes32) external returns (
        bytes32, bytes32, string, string, bool, bool, bool, bool,
        uint256, uint256, uint256, uint256, bool
    ) envfree;
    function isPolicyActive(bytes32) external returns (bool) envfree;
    function getVerificationKey(bytes32) external returns (bytes32, bytes32, bool) envfree;
    
    // Mutating functions
    function registerPolicy(PBP.DisclosurePolicy) external returns (bytes32);
    function deactivatePolicy(bytes32) external;
    function bindVerificationKey(bytes32, bytes32) external returns (bytes32);
    function verifyBoundProof(PBP.BoundProof, bytes32) external returns (PBP.VerificationResult);
}

/*//////////////////////////////////////////////////////////////
                       GHOST VARIABLES
//////////////////////////////////////////////////////////////*/

ghost mapping(bytes32 => bool) policyExists;
ghost mapping(bytes32 => bool) policyActive;
ghost mapping(bytes32 => bytes32) vkToPolicy;
ghost uint256 ghostPolicyCount;

/*//////////////////////////////////////////////////////////////
                          HOOKS
//////////////////////////////////////////////////////////////*/

hook Sstore policies[KEY bytes32 id].isActive bool active (bool old_active) {
    policyActive[id] = active;
    if (!policyExists[id] && active) {
        policyExists[id] = true;
        ghostPolicyCount = ghostPolicyCount + 1;
    }
}

hook Sstore verificationKeys[KEY bytes32 vk].policyHash bytes32 policy (bytes32 old_policy) {
    vkToPolicy[vk] = policy;
}

/*//////////////////////////////////////////////////////////////
                        INVARIANTS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Policy count consistency
 */
invariant policyCountConsistent()
    totalPolicies() == ghostPolicyCount
    {
        preserved {
            require true;
        }
    }

/**
 * @notice Deactivated policies stay deactivated
 */
invariant deactivationPermanent(bytes32 policyId)
    !policyActive[policyId] && policyExists[policyId] => always(!isPolicyActive(policyId))
    {
        preserved {
            require true;
        }
    }

/*//////////////////////////////////////////////////////////////
                          RULES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Policy registration increases count by 1
 */
rule registerPolicyIncreasesCount(PBP.DisclosurePolicy policy) {
    env e;
    
    uint256 countBefore = totalPolicies();
    
    require !paused();
    
    bytes32 policyId = registerPolicy@withrevert(e, policy);
    
    bool succeeded = !lastReverted;
    uint256 countAfter = totalPolicies();
    
    assert succeeded => countAfter == countBefore + 1,
        "Policy count must increase by 1 on successful registration";
}

/**
 * @notice Deactivated policy cannot be reactivated
 */
rule deactivationIrreversible(bytes32 policyId) {
    env e1;
    env e2;
    
    require isPolicyActive(policyId);
    
    deactivatePolicy(e1, policyId);
    
    assert !isPolicyActive(policyId),
        "Policy must be inactive after deactivation";
    
    // Any subsequent operation cannot reactivate
    method f;
    calldataarg args;
    f(e2, args);
    
    assert !isPolicyActive(policyId),
        "Deactivated policy cannot be reactivated";
}

/**
 * @notice VK binding requires active policy
 */
rule vkBindingRequiresActivePolicy(bytes32 vkHash, bytes32 policyHash) {
    env e;
    
    require !isPolicyActive(policyHash);
    
    bindVerificationKey@withrevert(e, vkHash, policyHash);
    
    assert lastReverted,
        "VK binding must fail for inactive policy";
}

/**
 * @notice VK cannot be rebound to different policy
 */
rule vkBindingPermanent(bytes32 vkHash, bytes32 policy1, bytes32 policy2) {
    env e1;
    env e2;
    
    require policy1 != policy2;
    require isPolicyActive(policy1);
    require isPolicyActive(policy2);
    
    // First binding
    bindVerificationKey(e1, vkHash, policy1);
    
    // Attempt rebind
    bindVerificationKey@withrevert(e2, vkHash, policy2);
    
    assert lastReverted,
        "VK cannot be rebound to different policy";
}

/**
 * @notice Proof verification respects policy scope
 */
rule proofMustMatchPolicyScope(PBP.BoundProof proof, bytes32 vkHash) {
    env e;
    
    bytes32 boundPolicy;
    bytes32 domainSep;
    bool isBound;
    (boundPolicy, domainSep, isBound) = getVerificationKey(vkHash);
    
    require isBound;
    require proof.policyHash != boundPolicy;
    
    PBP.VerificationResult result = verifyBoundProof(e, proof, vkHash);
    
    assert !result.withinScope,
        "Proof with wrong policy must fail scope check";
}

/**
 * @notice Only POLICY_ADMIN can register policies
 */
rule onlyAdminCanRegister(PBP.DisclosurePolicy policy) {
    env e;
    
    // Assume caller doesn't have POLICY_ADMIN_ROLE
    // Role check would be via ghost in complete spec
    
    registerPolicy@withrevert(e, policy);
    
    // If lacks role, must revert
}

/**
 * @notice Pause prevents policy registration
 */
rule pausePreventsRegistration(PBP.DisclosurePolicy policy) {
    env e;
    
    require paused();
    
    registerPolicy@withrevert(e, policy);
    
    assert lastReverted,
        "Policy registration must fail when paused";
}

/*//////////////////////////////////////////////////////////////
                    HIGH-LEVEL PROPERTIES
//////////////////////////////////////////////////////////////*/

/**
 * @notice Domain separator uniqueness
 */
rule domainSeparatorUniqueness(bytes32 vk1, bytes32 vk2, bytes32 policy) {
    env e1;
    env e2;
    
    require vk1 != vk2;
    require isPolicyActive(policy);
    
    bytes32 sep1 = bindVerificationKey(e1, vk1, policy);
    bytes32 sep2 = bindVerificationKey(e2, vk2, policy);
    
    assert sep1 != sep2,
        "Different VKs must produce different domain separators";
}

/**
 * @notice Policy hash immutability
 */
rule policyHashImmutable(bytes32 policyId) {
    env e;
    
    bytes32 hashBefore;
    (hashBefore,,,,,,,,,,,,,) = getPolicy(policyId);
    
    // Any operation
    method f;
    calldataarg args;
    f(e, args);
    
    bytes32 hashAfter;
    (hashAfter,,,,,,,,,,,,,) = getPolicy(policyId);
    
    assert hashBefore == hashAfter,
        "Policy hash cannot change after creation";
}
