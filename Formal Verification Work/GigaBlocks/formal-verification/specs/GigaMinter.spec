
methods {
    // INft.safeMint — out of scope; return value (tokenId) only feeds an event.
    function _.safeMint(string, address, string[9]) external => NONDET;
    // ERC721 receiver callback fired inside the out-of-scope Nft._safeMint; no
    // effect on GigaMinter storage → eliminated by summary.
    function _.onERC721Received(address, address, uint256, bytes) external => NONDET;

    // GigaMinter public getters — envfree so rules can read state without an env.
    function owner() external returns (address) envfree;
    function pendingOwner() external returns (address) envfree;
    function baseFee() external returns (uint256) envfree;
    function donationReceiver() external returns (address) envfree;
    function totalDonations() external returns (uint256) envfree;
    function totalBaseFeeCollected() external returns (uint256) envfree;
    function isBuyingPaused() external returns (bool) envfree;
    function schoolNft() external returns (address) envfree;
}


definition isExcludedParametric(method f) returns bool =
    f.selector == sig:multicall(bytes[]).selector ||
    f.selector == sig:batchMintNft(string[], address[], string[9][]).selector;


rule rule_conservation_buyNft_splitExact(
    string schoolId, address to, string[9] values
) {
    env e;
    uint256 feeBefore  = baseFee();
    uint256 donBefore  = totalDonations();
    uint256 baseBefore = totalBaseFeeCollected();

    buyNft@withrevert(e, schoolId, to, values);
    bool reverted = lastReverted;

    require !reverted;

    uint256 donAfter  = totalDonations();
    uint256 baseAfter = totalBaseFeeCollected();

    assert to_mathint(donAfter)  == to_mathint(donBefore)  + (to_mathint(e.msg.value) - to_mathint(feeBefore));
    assert to_mathint(baseAfter) == to_mathint(baseBefore) + to_mathint(feeBefore);
}


rule rule_conservation_buyNft_deltaSumEqualsValue(
    string schoolId, address to, string[9] values
) {
    env e;
    uint256 donBefore  = totalDonations();
    uint256 baseBefore = totalBaseFeeCollected();

    buyNft@withrevert(e, schoolId, to, values);
    require !lastReverted;

    uint256 donAfter  = totalDonations();
    uint256 baseAfter = totalBaseFeeCollected();

    assert (to_mathint(donAfter) - to_mathint(donBefore))
         + (to_mathint(baseAfter) - to_mathint(baseBefore))
         == to_mathint(e.msg.value);
}

ghost mathint g_forwarded {
    init_state axiom g_forwarded == 0;
}

hook Sstore currentContract.totalDonations uint256 newVal (uint256 oldVal) {
    g_forwarded = g_forwarded + (to_mathint(newVal) - to_mathint(oldVal));
}
hook Sstore currentContract.totalBaseFeeCollected uint256 newVal (uint256 oldVal) {
    g_forwarded = g_forwarded + (to_mathint(newVal) - to_mathint(oldVal));
}

invariant inv_totals_equal_forwarded()
    to_mathint(totalDonations()) + to_mathint(totalBaseFeeCollected()) == g_forwarded
    filtered { f -> f.selector != sig:multicall(bytes[]).selector }

rule rule_value_buyNft_noHold(
    string schoolId, address to, string[9] values
) {
    env e;
    require donationReceiver() != currentContract;
    require nativeBalances[currentContract] == 0;
    require e.msg.sender != currentContract;

    buyNft@withrevert(e, schoolId, to, values);
    require !lastReverted;

    assert nativeBalances[currentContract] == 0;
}

rule rule_value_onlyBuyNftAddsEth(method f) filtered {
    f -> !isExcludedParametric(f)
} {
    env e;
    calldataarg args;
    require e.msg.sender != currentContract;
    uint256 balBefore = nativeBalances[currentContract];

    f(e, args);

    uint256 balAfter = nativeBalances[currentContract];
    assert balAfter > balBefore =>
        f.selector == sig:buyNft(string, address, string[9]).selector;
}

rule rule_access_mintNft_onlyOwner(
    string schoolId, address to, string[9] values
) {
    env e;
    address ownerBefore = owner();
    mintNft@withrevert(e, schoolId, to, values);
    assert e.msg.sender != ownerBefore => lastReverted;
}

rule rule_access_batchMintNft_onlyOwner(
    string[] schoolIds, address[] tos, string[9][] values
) {
    env e;
    address ownerBefore = owner();
    batchMintNft@withrevert(e, schoolIds, tos, values);
    assert e.msg.sender != ownerBefore => lastReverted;
}

rule rule_access_baseFee_onlyOwnerSetter(uint256 newFee) {
    env e;
    address ownerBefore = owner();
    setBaseFee@withrevert(e, newFee);
    assert e.msg.sender != ownerBefore => lastReverted;
}

rule rule_access_donationReceiver_onlyOwnerSetter(address newReceiver) {
    env e;
    address ownerBefore = owner();
    setDonationReceiver@withrevert(e, newReceiver);
    assert e.msg.sender != ownerBefore => lastReverted;
}

rule rule_access_ownership_onlyOwner(address newOwner) {
    env e;
    address ownerBefore = owner();
    transferOwnership@withrevert(e, newOwner);
    assert e.msg.sender != ownerBefore => lastReverted;
}
rule rule_access_renounceOwnership_onlyOwner() {
    env e;
    address ownerBefore = owner();
    renounceOwnership@withrevert(e);
    assert e.msg.sender != ownerBefore => lastReverted;
}

rule rule_own_acceptOwnership_onlyPending() {
    env e;
    address pendingBefore = pendingOwner();
    acceptOwnership@withrevert(e);
    bool reverted = lastReverted;
    assert e.msg.sender != pendingBefore => reverted;
    assert !reverted => (owner() == e.msg.sender && pendingOwner() == 0);
}


rule rule_mono_totalsNeverDecrease(method f) filtered {
    f -> !isExcludedParametric(f)
} {
    env e;
    calldataarg args;
    uint256 donBefore  = totalDonations();
    uint256 baseBefore = totalBaseFeeCollected();

    f(e, args);

    assert totalDonations()        >= donBefore;
    assert totalBaseFeeCollected() >= baseBefore;
}

rule rule_state_totals_onlyBuyNft(method f) filtered {
    f -> !isExcludedParametric(f)
} {
    env e;
    calldataarg args;
    uint256 donBefore  = totalDonations();
    uint256 baseBefore = totalBaseFeeCollected();

    f(e, args);

    assert (totalDonations() != donBefore || totalBaseFeeCollected() != baseBefore)
        => f.selector == sig:buyNft(string, address, string[9]).selector;
}

rule rule_access_pause_onlyOwnerSetter(bool v) {
    env e;
    address ownerBefore = owner();
    updateBuyingStatus@withrevert(e, v);
    assert e.msg.sender != ownerBefore => lastReverted;
}

rule rule_pause_buyNftRevertsWhenPaused(
    string schoolId, address to, string[9] values
) {
    env e;
    require isBuyingPaused(); // justified: this rule characterises the paused state.
    buyNft@withrevert(e, schoolId, to, values);
    assert lastReverted;
}

rule rule_pause_adminMintNotGated(
    string schoolId, address to, string[9] values
) {
    env e;
    require isBuyingPaused();        // paused
    require e.msg.sender == owner(); // owner drives the admin mint
    require e.msg.value == 0;        // mintNft is non-payable
    mintNft@withrevert(e, schoolId, to, values);
    satisfy !lastReverted;
}

rule rule_pause_setterSetsExactValue(bool v) {
    env e;
    updateBuyingStatus@withrevert(e, v);
    require !lastReverted;
    assert isBuyingPaused() == v;
}

rule rule_access_buyNft_noEscalation(
    string schoolId, address to, string[9] values
) {
    env e;
    address ownerBefore    = owner();
    address pendingBefore  = pendingOwner();
    uint256 feeBefore      = baseFee();
    address receiverBefore = donationReceiver();
    bool    pausedBefore   = isBuyingPaused();

    buyNft@withrevert(e, schoolId, to, values);
    require !lastReverted;

    assert owner()            == ownerBefore;
    assert pendingOwner()     == pendingBefore;
    assert baseFee()          == feeBefore;
    assert donationReceiver() == receiverBefore;
    assert isBuyingPaused()   == pausedBefore;
}

rule rule_state_owner_onlyAcceptOrRenounce(method f) filtered {
    f -> !isExcludedParametric(f)
} {
    env e;
    calldataarg args;
    address ownerBefore = owner();

    f(e, args);

    assert owner() != ownerBefore =>
        f.selector == sig:acceptOwnership().selector ||
        f.selector == sig:renounceOwnership().selector;
}

rule rule_state_pendingOwner_sinks(method f) filtered {
    f -> !isExcludedParametric(f)
} {
    env e;
    calldataarg args;
    address pendingBefore = pendingOwner();

    f(e, args);

    assert pendingOwner() != pendingBefore =>
        f.selector == sig:transferOwnership(address).selector ||
        f.selector == sig:acceptOwnership().selector ||
        f.selector == sig:renounceOwnership().selector;
}

rule rule_state_schoolNft_immutable(method f) filtered {
    f -> !isExcludedParametric(f)
} {
    env e;
    calldataarg args;
    address before = schoolNft();

    f(e, args);

    assert schoolNft() == before;
}


rule rule_buyNft_revertsWhenUnderfunded(
    string schoolId, address to, string[9] values
) {
    env e;
    require !isBuyingPaused();
    require e.msg.value < baseFee();
    buyNft@withrevert(e, schoolId, to, values);
    assert lastReverted;
}
