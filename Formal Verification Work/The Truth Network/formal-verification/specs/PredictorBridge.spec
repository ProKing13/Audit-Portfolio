
methods {
    // ─── envfree views ───
    function paused()                       external returns (bool)     envfree;
    function owner()                        external returns (address)  envfree;
    function isAuthor(uint256)              external returns (bool)     envfree;
    function authorIsActive(uint256)        external returns (bool)     envfree;
    function isUsedLower(uint32)            external returns (bool)     envfree;
    function isPublishedRootHash(bytes32)   external returns (bool)     envfree;
    function relayerBalance(address)        external returns (int256)   envfree;
    function numActiveAuthors()             external returns (uint256)  envfree;
    function nextAuthorId()                 external returns (uint256)  envfree;
    function deriveT2PublicKey(address)     external returns (bytes32)  envfree;

    // ─── owner-gated mutators ───
    function pause()                        external;
    function unpause()                      external;
    function registerRelayer(address)       external;
    function deregisterRelayer(address)     external;
    function renounceOwnership()            external;

    // ─── fund-flow entrypoints (env-dependent) ───
    function lift(address,bytes32,uint256)  external;
    function permitLift(address,bytes32,uint256,uint256,uint8,bytes32,bytes32) external;
    function predictionMarketLift(address,uint256) external;
    function predictionMarketPermitLift(uint256,uint256,uint8,bytes32,bytes32) external;
    function predictionMarketRecipientLift(address,bytes32,uint256) external;
    function relayerLift(uint256,uint256,address,uint8,bytes32,bytes32,bool) external;
    function relayerLower(uint256,bytes,bool) external;
    function claimLower(bytes)              external;
    function revertLower(bytes)             external;
    function addAuthor(bytes,bytes32,uint256,uint32,bytes) external;
    function removeAuthor(bytes32,bytes,uint256,uint32,bytes) external;
    function publishRoot(bytes32,uint256,uint32,bytes) external;

    // ─── external-call summaries ───
   
    function _.transfer(address,uint256)                                          external => NONDET;
    function _.transferFrom(address,address,uint256)                              external => NONDET;
    function _.balanceOf(address)                                                 external => NONDET;
    function _.allowance(address,address)                                         external => NONDET;
    function _.permit(address,address,uint256,uint256,uint8,bytes32,bytes32)      external => NONDET;
    function _.swap(address,bool,int256,uint160,bytes)                            external => NONDET;
    function _.withdraw(uint256)                                                  external => NONDET;
    function _.isSanctioned(address)                                              external => NONDET;
    function _.latestAnswer()                                                     external => NONDET;
    function _.proxiableUUID() external => NONDET;
    function SafeERC20.safeTransfer(address,address,uint256) internal => NONDET;
    function SafeERC20.safeTransferFrom(address,address,address,uint256) internal => NONDET;


    function PredictorBridge._verifyConfirmations(bool,bytes32,bytes calldata) internal => NONDET;
    function PredictorBridge._authorizeUpgrade(address) internal => NONDET;
}

// =====================================================================
// 0. Ghost-tracked storage — lock reads to consistent values across calls.
// =====================================================================

ghost mapping(bytes32 => bool) isPublishedRootHashGhost;

hook Sload bool v isPublishedRootHash[KEY bytes32 r] {
    require isPublishedRootHashGhost[r] == v;
}

hook Sstore isPublishedRootHash[KEY bytes32 r] bool newValue (bool oldValue) {
    require oldValue == true => newValue == true;
    isPublishedRootHashGhost[r] = newValue;
}

ghost mapping(address => mathint) relayerBalanceGhost;

hook Sload int256 v relayerBalance[KEY address r] {
    require relayerBalanceGhost[r] == to_mathint(v);
}

hook Sstore relayerBalance[KEY address r] int256 newValue (int256 oldValue) {
    require newValue >= 0;
    relayerBalanceGhost[r] = to_mathint(newValue);
}

// =====================================================================
// 1. Access-control rules
// =====================================================================

// rule_pause_onlyOwner — only owner() may call pause()
rule rule_pause_onlyOwner(env e) {
    require e.msg.value == 0;
    pause@withrevert(e);
    assert lastReverted || e.msg.sender == owner();
}

// rule_unpause_onlyOwner — only owner() may call unpause()
rule rule_unpause_onlyOwner(env e) {
    require e.msg.value == 0;
    unpause@withrevert(e);
    assert lastReverted || e.msg.sender == owner();
}

// rule_registerRelayer_onlyOwner — only owner() may register a relayer
rule rule_registerRelayer_onlyOwner(env e, address relayer) {
    require e.msg.value == 0;
    registerRelayer@withrevert(e, relayer);
    assert lastReverted || e.msg.sender == owner();
}

// rule_deregisterRelayer_onlyOwner — only owner() may deregister a relayer
rule rule_deregisterRelayer_onlyOwner(env e, address relayer) {
    require e.msg.value == 0;
    deregisterRelayer@withrevert(e, relayer);
    assert lastReverted || e.msg.sender == owner();
}

// rule_upgradeToAndCall_onlyOwner — UUPS upgrade gated on owner()
rule rule_upgradeToAndCall_onlyOwner(env e, address newImpl, bytes data) {
    require e.msg.value == 0;
    require e.msg.sender != owner();
    upgradeToAndCall@withrevert(e, newImpl, data);
    assert lastReverted;
}

// =====================================================================
// 2. Ownership-disablement behaviour
// =====================================================================

// rule_renounceOwnership_alwaysReverts — ownership cannot be renounced
rule rule_renounceOwnership_alwaysReverts(env e) {
    renounceOwnership@withrevert(e);
    assert lastReverted;
}

// =====================================================================
// 3. Pause-gating rules — every fund-moving entrypoint reverts when paused
// =====================================================================

rule rule_lift_revertsWhenPaused(env e, address token, bytes32 t2PubKey, uint256 amount) {
    require paused();
    lift@withrevert(e, token, t2PubKey, amount);
    assert lastReverted;
}

rule rule_permitLift_revertsWhenPaused(
    env e, address token, bytes32 t2PubKey, uint256 amount,
    uint256 deadline, uint8 v, bytes32 r, bytes32 s
) {
    require paused();
    permitLift@withrevert(e, token, t2PubKey, amount, deadline, v, r, s);
    assert lastReverted;
}

rule rule_predictionMarketLift_revertsWhenPaused(env e, address token, uint256 amount) {
    require paused();
    predictionMarketLift@withrevert(e, token, amount);
    assert lastReverted;
}

rule rule_predictionMarketRecipientLift_revertsWhenPaused(env e, address token, bytes32 t2PubKey, uint256 amount) {
    require paused();
    predictionMarketRecipientLift@withrevert(e, token, t2PubKey, amount);
    assert lastReverted;
}

rule rule_relayerLift_revertsWhenPaused(
    env e, uint256 gasCost, uint256 amount, address user,
    uint8 v, bytes32 r, bytes32 s, bool triggerRefund
) {
    require paused();
    relayerLift@withrevert(e, gasCost, amount, user, v, r, s, triggerRefund);
    assert lastReverted;
}

rule rule_claimLower_revertsWhenPaused(env e, bytes lowerProof) {
    require paused();
    claimLower@withrevert(e, lowerProof);
    assert lastReverted;
}

rule rule_revertLower_revertsWhenPaused(env e, bytes lowerProof) {
    require paused();
    revertLower@withrevert(e, lowerProof);
    assert lastReverted;
}

rule rule_relayerLower_revertsWhenPaused(env e, uint256 gasCost, bytes lowerProof, bool triggerRefund) {
    require paused();
    relayerLower@withrevert(e, gasCost, lowerProof, triggerRefund);
    assert lastReverted;
}

rule rule_addAuthor_revertsWhenPaused(
    env e, bytes t1PubKey, bytes32 t2PubKey, uint256 expiry, uint32 t2TxId, bytes confirmations
) {
    require paused();
    addAuthor@withrevert(e, t1PubKey, t2PubKey, expiry, t2TxId, confirmations);
    assert lastReverted;
}

rule rule_removeAuthor_revertsWhenPaused(
    env e, bytes32 t2PubKey, bytes t1PubKey, uint256 expiry, uint32 t2TxId, bytes confirmations
) {
    require paused();
    removeAuthor@withrevert(e, t2PubKey, t1PubKey, expiry, t2TxId, confirmations);
    assert lastReverted;
}

rule rule_publishRoot_revertsWhenPaused(
    env e, bytes32 rootHash, uint256 expiry, uint32 t2TxId, bytes confirmations
) {
    require paused();
    publishRoot@withrevert(e, rootHash, expiry, t2TxId, confirmations);
    assert lastReverted;
}

// =====================================================================
// 4. State-transition rules — pause flips the paused() flag
// =====================================================================

rule rule_pause_transitionsToTrue(env e) {
    require !paused();
    pause@withrevert(e);
    assert !lastReverted => paused();
}

rule rule_unpause_transitionsToFalse(env e) {
    require paused();
    unpause@withrevert(e);
    assert !lastReverted => !paused();
}

// =====================================================================
// 5. Replay-protection monotonicity 
// =====================================================================

// rule_isPublishedRootHash_monotone — once published, the bit stays set
rule rule_isPublishedRootHash_monotone(env e, method f, bytes32 root) filtered {
    f -> f.selector != sig:upgradeToAndCall(address,bytes).selector
} {
    bool wasPublished = isPublishedRootHash(root);
    calldataarg args;
    f@withrevert(e, args);
    bool callReverted = lastReverted;
    bool isPublished = isPublishedRootHash(root);
    assert !callReverted => (wasPublished => isPublished);
}


// =====================================================================
// 6. Author counter monotonicity (initialize and upgrade excluded)
// =====================================================================

rule rule_nextAuthorId_monotone(env e, method f) filtered {
    f -> f.selector != sig:upgradeToAndCall(address,bytes).selector
      && f.selector != sig:initialize(address[],bytes32[],bytes32[],bytes32[],address).selector
} {
    uint256 before = nextAuthorId();
    calldataarg args;
    f@withrevert(e, args);
    bool callReverted = lastReverted;
    uint256 after_ = nextAuthorId();
    assert !callReverted => after_ >= before;
}

// =====================================================================
// 7. Author lifecycle floor: removeAuthor cannot violate MIN_AUTHORS = 4
// =====================================================================

rule rule_removeAuthor_preservesMinAuthors(
    env e, bytes32 t2PubKey, bytes t1PubKey, uint256 expiry, uint32 t2TxId, bytes confirmations
) {
    require numActiveAuthors() <= 256;
    removeAuthor@withrevert(e, t2PubKey, t1PubKey, expiry, t2TxId, confirmations);
    assert !lastReverted => numActiveAuthors() >= 4;
}

// =====================================================================
// 8. Relayer sentinel transitions
// =====================================================================

// rule_registerRelayer_setsSentinel — successful register sets balance 0 → 1
rule rule_registerRelayer_setsSentinel(env e, address relayer) {
    require relayerBalance(relayer) == 0;
    require e.msg.sender == owner();
    require relayer != 0;
    require e.msg.value == 0;
    registerRelayer@withrevert(e, relayer);
    assert !lastReverted;
    assert relayerBalance(relayer) == 1;
}

// rule_deregisterRelayer_zeroesBalance — successful deregister zeroes balance
rule rule_deregisterRelayer_zeroesBalance(env e, address relayer) {
    require relayerBalance(relayer) > 0;
    require e.msg.sender == owner();
    require e.msg.value == 0;
    deregisterRelayer@withrevert(e, relayer);
    bool ok = !lastReverted;
    assert ok => relayerBalance(relayer) == 0;
}

// invariant_relayerBalance_nonNegative — balance never goes below zero
invariant invariant_relayerBalance_nonNegative(address r)
    relayerBalance(r) >= 0
    filtered { f -> f.selector != sig:upgradeToAndCall(address,bytes).selector }
