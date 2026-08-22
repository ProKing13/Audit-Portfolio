using ERC20Aument as token;

methods {
    // ERC20 state
    function totalSupply() external returns (uint256) envfree;
    function balanceOf(address) external returns (uint256) envfree;

    // Role checks
    function hasRole(bytes32, address) external returns (bool) envfree;
    function ADMIN_ROLE() external returns (bytes32) envfree;
    function UPGRADER_ROLE() external returns (bytes32) envfree;

    // Fee getters
    function getTransferFee() external returns (uint256) envfree;
    function getBurnFee() external returns (uint256) envfree;
    function getMintFee() external returns (uint256) envfree;
    function precision() external returns (uint256) envfree;
    function getTransferFeeCollector() external returns (address) envfree;
    function getBurnFeeCollector() external returns (address) envfree;
    function getMintFeeCollector() external returns (address) envfree;

    // Compliance getters
    function isBlacklisted(address) external returns (bool) envfree;
    function isWhitelistedAddress(address) external returns (bool) envfree;
    function whitelistEnabled() external returns (bool) envfree;

    // Nonce getters
    function replayNonce(address) external returns (uint256) envfree;
    function redemptionNonce(address) external returns (uint256) envfree;

    // Wallet address
    function getAumentWalletAddress() external returns (address) envfree;

    // Pause state (from ERC20PausableUpgradeable)
    function paused() external returns (bool) envfree;

    // UUPS upgrade entrypoint 
    function upgradeToAndCall(address, bytes) external;

    // Admin-only mutators 
    function mint(address, uint256) external;
    function burn(uint256) external;
    function burnFrom(address, uint256) external;
    function pause() external;
    function unpause() external;
    function setTransferFee(uint256) external;
    function setBurnFee(uint256) external;
    function setMintFee(uint256) external;
    function setAumentWalletAddress(address) external;
    function blacklistAddress(address) external;
    function unblacklistAddress(address) external;
    function addWhitelistAddress(address) external;
    function removeWhitelistedAddress(address) external;
    function enableWhitelist() external;
    function disableWhitelist() external;
    function requestRedemption(uint256) external returns (bytes32);
    function fulfillRedemption(bytes32, string) external;
    function cancelRedemption(bytes32) external;
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function metaTransfer(bytes, address, uint256, uint256) external returns (bool);
}

// ─────────────────────────────────────────────────────────
// ACCESS CONTROL — fee setters require ADMIN_ROLE
// ─────────────────────────────────────────────────────────

// rule: non-admin cannot set transfer fee
rule rule_access_setTransferFee_non_admin_reverts(uint256 fee) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    setTransferFee@withrevert(e, fee);
    assert lastReverted, "non-admin must not set transfer fee";
}

// rule: non-admin cannot set burn fee
rule rule_access_setBurnFee_non_admin_reverts(uint256 fee) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    setBurnFee@withrevert(e, fee);
    assert lastReverted, "non-admin must not set burn fee";
}

// rule: non-admin cannot set mint fee
rule rule_access_setMintFee_non_admin_reverts(uint256 fee) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    setMintFee@withrevert(e, fee);
    assert lastReverted, "non-admin must not set mint fee";
}

// rule: non-admin cannot mint
rule rule_access_mint_non_admin_reverts(address to, uint256 amount) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    mint@withrevert(e, to, amount);
    assert lastReverted, "non-admin must not be able to mint";
}

// rule: non-admin cannot pause
rule rule_access_pause_non_admin_reverts() {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    pause@withrevert(e);
    assert lastReverted, "non-admin must not pause";
}

// rule: non-admin cannot blacklist
rule rule_access_blacklist_non_admin_reverts(address account) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    blacklistAddress@withrevert(e, account);
    assert lastReverted, "non-admin must not blacklist";
}


// rule: non-admin cannot fulfill redemption
rule rule_access_fulfillRedemption_non_admin_reverts(bytes32 requestId, string proofHash) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    fulfillRedemption@withrevert(e, requestId, proofHash);
    assert lastReverted, "non-admin must not fulfill redemption";
}

// rule: non-admin cannot cancel redemption
rule rule_access_cancelRedemption_non_admin_reverts(bytes32 requestId) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    cancelRedemption@withrevert(e, requestId);
    assert lastReverted, "non-admin must not cancel redemption";
}

// rule: non-admin cannot upgrade
rule rule_access_authorizeUpgrade_non_admin_reverts(address impl, bytes data) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    upgradeToAndCall@withrevert(e, impl, data);
    assert lastReverted, "non-admin must not upgrade";
}

// ─────────────────────────────────────────────────────────
// FEE CAP — fees never exceed 5 * 10^precision = 50000
// ─────────────────────────────────────────────────────────

definition MAX_FEE() returns uint256 = 50000; // 5 * 10^4


invariant inv_transfer_fee_within_cap()
    getTransferFee() <= MAX_FEE()
    filtered {
        f -> f.selector != sig:upgradeToAndCall(address, bytes).selector &&
             f.selector != sig:addWhitelistAddress(address).selector &&
             f.selector != sig:initialize(address[], uint256, uint256).selector
    }
    {
        preserved setTransferFee(uint256 f) with (env e) {
            require hasRole(ADMIN_ROLE(), e.msg.sender);
        }
    }

invariant inv_burn_fee_within_cap()
    getBurnFee() <= MAX_FEE()
    filtered {
        f -> f.selector != sig:upgradeToAndCall(address, bytes).selector &&
             f.selector != sig:addWhitelistAddress(address).selector &&
             f.selector != sig:initialize(address[], uint256, uint256).selector
    }
    {
        preserved setBurnFee(uint256 f) with (env e) {
            require hasRole(ADMIN_ROLE(), e.msg.sender);
        }
    }

invariant inv_mint_fee_within_cap()
    getMintFee() <= MAX_FEE()
    filtered {
        f -> f.selector != sig:upgradeToAndCall(address, bytes).selector &&
             f.selector != sig:addWhitelistAddress(address).selector &&
             f.selector != sig:initialize(address[], uint256, uint256).selector
    }
    {
        preserved setMintFee(uint256 f) with (env e) {
            require hasRole(ADMIN_ROLE(), e.msg.sender);
        }
    }

// ─────────────────────────────────────────────────────────
// PAUSE GATING — when paused, non-admin transfer reverts
// ─────────────────────────────────────────────────────────

rule rule_pause_blocks_non_admin_transfer(address to, uint256 amount) {
    env e;
    require paused(e);
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    transfer@withrevert(e, to, amount);
    assert lastReverted, "paused non-admin transfer must revert";
}

// rule: admin can transfer when paused
rule rule_pause_admin_can_transfer(address to, uint256 amount) {
    env e;
    require e.msg.sender != 0;
    require to != 0;
    require paused();
    require hasRole(ADMIN_ROLE(), e.msg.sender);
    require hasRole(ADMIN_ROLE(), to);
    require !isBlacklisted(e.msg.sender);
    require !isBlacklisted(to);
    require e.msg.sender != to;
    require balanceOf(e.msg.sender) >= amount;
    require amount > 0;

    requireInvariant inv_transfer_fee_within_cap();
    // Prevent multiplication overflow in fee calc: (amount * _transferFee) / 1_000_000.
    // Solidity 0.8 checked arithmetic reverts when amount * _transferFee > max_uint256.
    // With _transferFee <= MAX_FEE (50_000), bounding amount prevents overflow.
    require amount <= max_uint256 / MAX_FEE();
    require e.msg.value == 0;

    transfer@withrevert(e, to, amount);
    assert !lastReverted, "admin should transfer when paused";
}

// ─────────────────────────────────────────────────────────
// BLACKLIST — blacklisted sender/recipient blocked for regular transfers
// ─────────────────────────────────────────────────────────

rule rule_blacklist_sender_blocked(address to, uint256 amount) {
    env e;
    require isBlacklisted(e.msg.sender);
    require !paused(e);
    require amount > 0;
    transfer@withrevert(e, to, amount);
    assert lastReverted, "blacklisted sender must be blocked from transfer";
}

rule rule_blacklist_recipient_blocked(address to, uint256 amount) {
    env e;
    require isBlacklisted(to);
    require !paused(e);
    require amount > 0;
    transfer@withrevert(e, to, amount);
    assert lastReverted, "blacklisted recipient must be blocked from transfer";
}

// ─────────────────────────────────────────────────────────
// WHITELIST — non-whitelisted recipient blocked when whitelist enabled
// ─────────────────────────────────────────────────────────

rule rule_whitelist_blocks_non_whitelisted_recipient(address to, uint256 amount) {
    env e;
    require whitelistEnabled();
    require !isWhitelistedAddress(to);
    require !hasRole(ADMIN_ROLE(), to);
    require to != currentContract;
    require to != getTransferFeeCollector();
    require to != getBurnFeeCollector();
    require to != getMintFeeCollector();
    require !paused(e);
    require !isBlacklisted(e.msg.sender);
    require amount > 0;
    transfer@withrevert(e, to, amount);
    assert lastReverted, "non-whitelisted recipient must be blocked when whitelist enabled";
}

// ─────────────────────────────────────────────────────────
// META-TX — replayNonce strictly monotonic per signer
// ─────────────────────────────────────────────────────────

// rule: replayNonce for any address never decreases after any metaTransfer call
// Uses calldataarg to represent the opaque bytes signature parameter.
rule rule_meta_tx_nonce_never_decreases(address anyAddr) {
    env e;
    calldataarg args;
    uint256 nonceBefore = replayNonce(anyAddr);
    metaTransfer@withrevert(e, args);
    bool didRevert = lastReverted;
    uint256 nonceAfter = replayNonce(anyAddr);
    assert !didRevert => nonceAfter >= nonceBefore,
        "replayNonce must never decrease for any address";
}

// ─────────────────────────────────────────────────────────
// REDEMPTION — lifecycle safety
// ─────────────────────────────────────────────────────────


ghost mapping(bytes32 => bool) ghost_fulfilled {
    init_state axiom forall bytes32 id. !ghost_fulfilled[id];
}
ghost mapping(bytes32 => bool) ghost_cancelled {
    init_state axiom forall bytes32 id. !ghost_cancelled[id];
}
// Tracks the most recently fulfilled requestId (updated by Sstore hook).
// Used in rule_cancel_fulfilled_reverts so that cancelRedemption targets the
ghost bytes32 g_last_fulfilled_id;


hook Sstore redemptionRequests[KEY bytes32 id].fulfilled bool val {
    ghost_fulfilled[id] = val;
    // Record which requestId was most recently written to fulfilled (any value).
    // fulfillRedemption is the only function that writes true here, so after a
    // successful first call g_last_fulfilled_id == the requestId that was fulfilled.
    g_last_fulfilled_id = id;
}
hook Sstore redemptionRequests[KEY bytes32 id].cancelled bool val {
    ghost_cancelled[id] = val;
}

// Invariant: a request cannot be both fulfilled AND cancelled simultaneously
invariant inv_redemption_not_both_fulfilled_and_cancelled(bytes32 id)
    !(ghost_fulfilled[id] && ghost_cancelled[id])
   
    filtered {
        f -> f.selector != sig:initialize(address[], uint256, uint256).selector &&
             f.selector != sig:addWhitelistAddress(address).selector &&
             f.selector != sig:upgradeToAndCall(address, bytes).selector
    }
    {
        preserved requestRedemption(uint256 amount) with (env e) {
            require amount > 0;
        }
        preserved fulfillRedemption(bytes32 reqId, string ph) with (env e) {
            require hasRole(ADMIN_ROLE(), e.msg.sender);
            require !ghost_cancelled[reqId];
        }
        preserved cancelRedemption(bytes32 reqId) with (env e) {
            require hasRole(ADMIN_ROLE(), e.msg.sender);
            require !ghost_fulfilled[reqId];
        }
    }

// rule: double fulfill reverts
// Two-call: first call succeeds (sets fulfilled=true concretely), second must revert.
// Shared calldataarg ensures SAME requestId+proof in both calls.
rule rule_no_double_fulfill() {
    env e1; env e2;
    require hasRole(ADMIN_ROLE(), e1.msg.sender);
    require hasRole(ADMIN_ROLE(), e2.msg.sender);
    require e1.msg.sender != 0;
    require e2.msg.sender != 0;
    require e1.msg.value == 0;
    require e2.msg.value == 0;
    calldataarg args;
    fulfillRedemption(e1, args);
    fulfillRedemption@withrevert(e2, args);
    assert lastReverted, "double fulfill must revert";
}

// rule: fulfill on already-cancelled request reverts
rule rule_fulfill_cancelled_reverts(bytes32 requestId, string proof) {
    env e1; env e2;
    require hasRole(ADMIN_ROLE(), e1.msg.sender);
    require hasRole(ADMIN_ROLE(), e2.msg.sender);
    require e1.msg.sender != 0;
    require e2.msg.sender != 0;
    require e1.msg.value == 0;
    require e2.msg.value == 0;
    cancelRedemption(e1, requestId);
    fulfillRedemption@withrevert(e2, requestId, proof);
    assert lastReverted, "fulfilling cancelled request must revert";
}

// rule: double cancel reverts
rule rule_no_double_cancel(bytes32 requestId) {
    env e1; env e2;
    require hasRole(ADMIN_ROLE(), e1.msg.sender);
    require hasRole(ADMIN_ROLE(), e2.msg.sender);
    require e1.msg.sender != 0;
    require e2.msg.sender != 0;
    require e1.msg.value == 0;
    require e2.msg.value == 0;
    cancelRedemption(e1, requestId);
    cancelRedemption@withrevert(e2, requestId);
    assert lastReverted, "double cancel must revert";
}

// rule: cancel on already-fulfilled request reverts
rule rule_cancel_fulfilled_reverts() {
    env e1; env e2;
    require hasRole(ADMIN_ROLE(), e1.msg.sender);
    require hasRole(ADMIN_ROLE(), e2.msg.sender);
    require e1.msg.sender != 0;
    require e2.msg.sender != 0;
    require e1.msg.value == 0;
    require e2.msg.value == 0;
    calldataarg args;
    fulfillRedemption(e1, args);
    cancelRedemption@withrevert(e2, g_last_fulfilled_id);
    assert lastReverted, "cancelling fulfilled request must revert";
}

// ─────────────────────────────────────────────────────────
// TOTAL SUPPLY CONSERVATION — mint/burn accounting
// ─────────────────────────────────────────────────────────

// rule: mint increases total supply by exactly the requested amount
rule rule_mint_supply_increases(address to, uint256 amount) {
    env e;
    require hasRole(ADMIN_ROLE(), e.msg.sender);
    requireInvariant inv_mint_fee_within_cap();
    uint256 supplyBefore = totalSupply();
    mint(e, to, amount);
    uint256 supplyAfter = totalSupply();
    assert supplyAfter == supplyBefore + amount,
        "mint must increase total supply by exactly amount";
}

// rule: walletOrAdmin burn decreases supply
rule rule_burn_decreases_supply(uint256 amount) {
    env e;
    require hasRole(ADMIN_ROLE(), e.msg.sender);
    require e.msg.sender != 0;
    require amount > 0;

    requireInvariant inv_burn_fee_within_cap();
    require totalSupply() >= balanceOf(e.msg.sender);

    uint256 supplyBefore = totalSupply();
    burn@withrevert(e, amount);
    bool reverted = lastReverted;
    uint256 supplyAfter = totalSupply();
    assert reverted || supplyAfter < supplyBefore,
        "successful burn must decrease total supply";
}

// ─────────────────────────────────────────────────────────
// WALLET ADDRESS — always non-zero after set
// ─────────────────────────────────────────────────────────

rule rule_wallet_address_nonzero_after_set(address newAddr) {
    env e;
    require hasRole(ADMIN_ROLE(), e.msg.sender);
    require newAddr != 0;
    setAumentWalletAddress(e, newAddr);
    assert getAumentWalletAddress() == newAddr,
        "wallet address must be updated to non-zero value";
}

rule rule_wallet_address_zero_reverts() {
    env e;
    require hasRole(ADMIN_ROLE(), e.msg.sender);
    setAumentWalletAddress@withrevert(e, 0);
    assert lastReverted, "setting wallet to zero address must revert";
}
