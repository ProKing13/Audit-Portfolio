
using Escrow as escrow;

methods {
    // ---- Escrow's own view functions (envfree so rules can read them without env) ----
    function nftAddress() external returns (address) envfree;
    function owner() external returns (address) envfree;
    function pendingOwner() external returns (address) envfree;

    // ---- out-of-scope external callees: summarized, never linked ----
    function _.safeTransferFrom(address, address, uint256) external => NONDET;          // escrowed NFT out (transferSchoolNft / bulk)
    function _.transferFrom(address, address, uint256) external => NONDET;              // inherited transferERC721 (arbitrary token)
    function _.approve(address, uint256) external => NONDET;                            // inherited approveERC721
    function _.setApprovalForAll(address, bool) external => NONDET;                     // inherited approveERC721ForAll
    function _.onERC721Received(address, address, uint256, bytes) external => NONDET;   // recipient callback (untrusted)
}

function escrowEth() returns mathint {
    return nativeBalances[currentContract];
}

definition isParametricTarget(method f) returns bool =
    f.selector != sig:bulkTransferSchoolNft(address[],uint256[]).selector
    && !f.isView;

rule rule_access_withdraw_onlyOwner(env e, address to, uint256 amount) {
    address ownerBefore = owner();
    withdraw@withrevert(e, to, amount);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call withdraw";
}

rule rule_access_transferSchoolNft_onlyOwner(env e, address to, uint256 tokenId) {
    address ownerBefore = owner();
    transferSchoolNft@withrevert(e, to, tokenId);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call transferSchoolNft";
}

rule rule_access_bulkTransferSchoolNft_onlyOwner(env e, address[] tos, uint256[] tokenIds) {
    address ownerBefore = owner();
    bulkTransferSchoolNft@withrevert(e, tos, tokenIds);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call bulkTransferSchoolNft";
}

rule rule_access_transferERC721_onlyOwner(env e, address from, address token, address to, uint256 tokenId) {
    address ownerBefore = owner();
    transferERC721@withrevert(e, from, token, to, tokenId);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call transferERC721";
}

rule rule_access_approveERC721_onlyOwner(env e, address token, address spender, uint256 tokenId) {
    address ownerBefore = owner();
    approveERC721@withrevert(e, token, spender, tokenId);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call approveERC721";
}

rule rule_access_approveERC721ForAll_onlyOwner(env e, address token, address spender, bool approved) {
    address ownerBefore = owner();
    approveERC721ForAll@withrevert(e, token, spender, approved);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call approveERC721ForAll";
}

rule rule_access_ownership_onlyOwner_escrow(env e, address newOwner) {
    address ownerBefore = owner();
    transferOwnership@withrevert(e, newOwner);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call transferOwnership";
}
rule rule_access_renounceOwnership_onlyOwner_escrow(env e) {
    address ownerBefore = owner();
    renounceOwnership@withrevert(e);
    assert e.msg.sender != ownerBefore => lastReverted,
        "non-owner must not be able to call renounceOwnership";
}

rule rule_own_acceptOwnership_onlyPending_escrow(env e) {
    address pendingBefore = pendingOwner();
    acceptOwnership@withrevert(e);
    bool reverted = lastReverted;
    // only the pending owner may finalize the handoff
    assert (!reverted) => e.msg.sender == pendingBefore,
        "acceptOwnership must succeed only for the current pendingOwner";
    // and on success ownership moves to the caller, pending is cleared
    assert (!reverted) => (owner() == e.msg.sender && pendingOwner() == 0),
        "acceptOwnership success must set owner=caller and clear pendingOwner";
}

rule rule_isolation_ethDecreaseOnlyOwnerWithdraw(env e, method f, calldataarg args)
    filtered { f -> isParametricTarget(f) }
{
    // justified: the contract never calls itself externally, so msg.sender==self is
    // not a real protocol state and would spuriously credit the balance.
    require e.msg.sender != currentContract;

    mathint before = escrowEth();
    f@withrevert(e, args);
    bool reverted = lastReverted;

    // On any successful call by a non-owner, escrow ETH must not have decreased.
    assert (!reverted && e.msg.sender != owner()) => escrowEth() >= before,
        "a non-owner call must not decrease escrow ETH balance";
}

rule rule_value_withdrawExactDebit(env e, address to, uint256 amount) {
    require to != currentContract;

    mathint before = escrowEth();
    withdraw@withrevert(e, to, amount);
    bool reverted = lastReverted;

    assert !reverted => escrowEth() == before - to_mathint(amount),
        "successful withdraw(to,amount) with to != self must debit exactly amount";
}

rule rule_value_withdrawCannotOverdraw(env e, address to, uint256 amount) {
    require to != currentContract;
    mathint before = escrowEth();
    withdraw@withrevert(e, to, amount);
    bool reverted = lastReverted;
    // If the requested amount exceeds the balance, the send must fail (whole tx reverts).
    assert (to_mathint(amount) > before) => reverted,
        "withdraw must revert when amount exceeds escrow balance (no overdraw)";
}


rule rule_value_ethIncreaseOnlyViaReceive(env e, method f, calldataarg args)
    filtered {
        f -> isParametricTarget(f)
             && !f.isFallback
    }
{
    // justified: contract does not call itself externally.
    require e.msg.sender != currentContract;

    mathint before = escrowEth();
    f@withrevert(e, args);
    bool reverted = lastReverted;

    assert !reverted => escrowEth() <= before,
        "no entry other than receive() may increase escrow ETH balance";
}

rule rule_value_receiveAddsExact(env e, method f, calldataarg args)
    filtered { f -> f.isFallback }
{
    // justified: self-send is not a real deposit flow and would net zero.
    require e.msg.sender != currentContract;

    mathint before = escrowEth();
    f@withrevert(e, args);
    bool reverted = lastReverted;

    assert !reverted => escrowEth() == before + to_mathint(e.msg.value),
        "successful receive() (fallback) must increase escrow ETH by exactly msg.value";
}

rule rule_access_onERC721Received_noEscalation(env e, address operator, address from, uint256 tokenId, bytes data) {
    address ownerBefore   = owner();
    address pendingBefore = pendingOwner();
    address nftBefore     = nftAddress();
    mathint ethBefore     = escrowEth();

    bytes4 ret = onERC721Received(e, operator, from, tokenId, data);

    assert owner() == ownerBefore
        && pendingOwner() == pendingBefore
        && nftAddress() == nftBefore,
        "onERC721Received must not change owner / pendingOwner / nftAddress";
    // it moves no ETH out (does not decrease escrow balance)
    assert escrowEth() >= ethBefore,
        "onERC721Received must not decrease escrow ETH balance";
    // magic selector: IERC721Receiver.onERC721Received.selector == 0x150b7a02
    assert ret == to_bytes4(0x150b7a02),
        "onERC721Received must return the IERC721Receiver magic selector";
}

rule rule_access_receive_noEscalation(env e, method f, calldataarg args)
    filtered { f -> f.isFallback }
{
    address ownerBefore   = owner();
    address pendingBefore = pendingOwner();
    address nftBefore     = nftAddress();

    f@withrevert(e, args);

    assert !lastReverted => (
        owner() == ownerBefore
        && pendingOwner() == pendingBefore
        && nftAddress() == nftBefore
    ), "receive must not change owner / pendingOwner / nftAddress";
}

rule rule_state_owner_onlyAcceptOrRenounce_escrow(env e, method f, calldataarg args)
    filtered { f -> !f.isView }
{
    address ownerBefore = owner();
    f@withrevert(e, args);
    assert owner() != ownerBefore => (
        f.selector == sig:acceptOwnership().selector
        || f.selector == sig:renounceOwnership().selector
    ), "owner() may change only via acceptOwnership or renounceOwnership";
}

rule rule_state_pendingOwner_sinks_escrow(env e, method f, calldataarg args)
    filtered { f -> !f.isView }
{
    address pendingBefore = pendingOwner();
    f@withrevert(e, args);
    assert pendingOwner() != pendingBefore => (
        f.selector == sig:transferOwnership(address).selector
        || f.selector == sig:acceptOwnership().selector
        || f.selector == sig:renounceOwnership().selector
    ), "pendingOwner() may change only via transferOwnership / acceptOwnership / renounceOwnership";
}

rule rule_state_nftAddress_immutable(env e, method f, calldataarg args)
    filtered { f -> !f.isView }
{
    address before = nftAddress();
    f@withrevert(e, args);
    assert nftAddress() == before,
        "nftAddress must never change after construction (no setter exists)";
}


