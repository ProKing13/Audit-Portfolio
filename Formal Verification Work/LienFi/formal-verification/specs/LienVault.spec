// LienVault.spec — Certora CVL formal verification spec
// Contract: LienVault
// Solc: 0.8.28 / Hardhat build

using LienVault as lienVault;

methods {
    // admin / config
    function initialize(address, address, address, address, address) external;
    function setMarketplace(address) external;
    function setFeeManager(address) external;
    function pause() external;
    function unpause() external;
    function transferOwnership(address) external;

    // marketplace-role
    function lockNFT(uint256, address) external;
    function unlockNFT(uint256, address) external;
    function setFeeVersion(uint256, uint256) external;
    function setPurchasePrice(uint256, uint256) external;

    // operator / admin
    function redeemLien(uint256, uint128) external;
    function forceFeeVersion(uint256, uint256, string) external;

    // liquidity
    function addLiquidity(uint256) external;
    function removeLiquidity(uint256, address) external;
    function removeFullLiquidity(address) external;

    // views
    function marketplace() external returns (address) envfree;
    function feeVersionByTokenId(uint256) external returns (uint256) envfree;
    function purchasePriceByTokenId(uint256) external returns (uint256) envfree;
    function hasPurchasePriceByTokenId(uint256) external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function paused() external returns (bool) envfree;
    function lienNFT() external returns (address) envfree;
    function paymentToken() external returns (address) envfree;

    // role constants (pure, no env needed)
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function MARKETPLACE_ROLE() external returns (bytes32) envfree;
}

// ─── Role constants ────────────────────────────────────────────────────────────

definition DEFAULT_ADMIN_ROLE_DEF() returns bytes32 =
    to_bytes32(0);

// ─── Access Control: lockNFT ──────────────────────────────────────────────────

/// Non-marketplace cannot call lockNFT
rule rule_access_only_marketplace_lock(env e, uint256 tokenId, address owner_) {
    require !hasRole(MARKETPLACE_ROLE(), e.msg.sender);
    lockNFT@withrevert(e, tokenId, owner_);
    assert lastReverted, "Only MARKETPLACE_ROLE must be able to call lockNFT";
}

/// Non-marketplace cannot call unlockNFT
rule rule_access_only_marketplace_unlock(env e, uint256 tokenId, address newOwner) {
    require !hasRole(MARKETPLACE_ROLE(), e.msg.sender);
    unlockNFT@withrevert(e, tokenId, newOwner);
    assert lastReverted, "Only MARKETPLACE_ROLE must be able to call unlockNFT";
}

/// Non-marketplace cannot call setFeeVersion
rule rule_access_only_marketplace_set_fee_version(env e, uint256 tokenId, uint256 feeVersion) {
    require !hasRole(MARKETPLACE_ROLE(), e.msg.sender);
    setFeeVersion@withrevert(e, tokenId, feeVersion);
    assert lastReverted, "Only MARKETPLACE_ROLE must be able to call setFeeVersion";
}

/// Non-marketplace cannot call setPurchasePrice
rule rule_access_only_marketplace_set_purchase_price(env e, uint256 tokenId, uint256 price) {
    require !hasRole(MARKETPLACE_ROLE(), e.msg.sender);
    setPurchasePrice@withrevert(e, tokenId, price);
    assert lastReverted, "Only MARKETPLACE_ROLE must be able to call setPurchasePrice";
}

// ─── Access Control: redeemLien ───────────────────────────────────────────────

/// Non-operator, non-admin cannot call redeemLien
rule rule_access_only_operator_redeem(env e, uint256 tokenId, uint128 val) {
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    redeemLien@withrevert(e, tokenId, val);
    assert lastReverted, "Only OPERATOR_ROLE or DEFAULT_ADMIN_ROLE can call redeemLien";
}

// ─── Access Control: admin-only functions ────────────────────────────────────

/// Non-admin cannot call setMarketplace
rule rule_access_only_admin_set_marketplace(env e, address mp) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setMarketplace@withrevert(e, mp);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call setMarketplace";
}

/// Non-admin cannot call setFeeManager
rule rule_access_only_admin_set_fee_manager(env e, address fm) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setFeeManager@withrevert(e, fm);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call setFeeManager";
}

/// Non-admin cannot removeLiquidity
rule rule_access_only_admin_remove_liquidity(env e, uint256 amount, address to) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    removeLiquidity@withrevert(e, amount, to);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call removeLiquidity";
}

/// Non-admin cannot forceFeeVersion
rule rule_access_only_admin_force_fee_version(env e, uint256 tokenId, uint256 fv, string reason) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    forceFeeVersion@withrevert(e, tokenId, fv, reason);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call forceFeeVersion";
}

// ─── Pause gating ─────────────────────────────────────────────────────────────

/// lockNFT reverts when vault is paused
rule rule_pause_blocks_lock(env e, uint256 tokenId, address owner_) {
    require paused();
    lockNFT@withrevert(e, tokenId, owner_);
    assert lastReverted, "lockNFT must revert when paused";
}

/// unlockNFT reverts when vault is paused
rule rule_pause_blocks_unlock(env e, uint256 tokenId, address newOwner) {
    require paused();
    unlockNFT@withrevert(e, tokenId, newOwner);
    assert lastReverted, "unlockNFT must revert when paused";
}

/// redeemLien reverts when vault is paused
rule rule_pause_blocks_redeem(env e, uint256 tokenId, uint128 val) {
    require paused();
    redeemLien@withrevert(e, tokenId, val);
    assert lastReverted, "redeemLien must revert when paused";
}

// ─── hasPurchasePriceByTokenId monotonicity ───────────────────────────────────

/// Once hasPurchasePriceByTokenId is true, it stays true after any call
rule rule_has_purchase_price_monotone(env e, uint256 tokenId, method f)  filtered {
         f -> f.selector != sig:upgradeToAndCall(address, bytes).selector
    } {
    require hasPurchasePriceByTokenId(tokenId);
     
    calldataarg args;
    f(e, args);
    assert hasPurchasePriceByTokenId(tokenId),
        "hasPurchasePriceByTokenId must not go from true to false";
}

// ─── setPurchasePrice integrity ───────────────────────────────────────────────

/// After setPurchasePrice, both the price and the flag are updated correctly
rule rule_set_purchase_price_updates_state(env e, uint256 tokenId, uint256 price) {
    require hasRole(MARKETPLACE_ROLE(), e.msg.sender);
    setPurchasePrice(e, tokenId, price);
    assert purchasePriceByTokenId(tokenId) == price,
        "purchasePriceByTokenId must equal price after setPurchasePrice";
    assert hasPurchasePriceByTokenId(tokenId),
        "hasPurchasePriceByTokenId must be true after setPurchasePrice";
}

// ─── forceFeeVersion zero reverts ────────────────────────────────────────────

/// forceFeeVersion with feeVersion == 0 must revert
rule rule_force_fee_version_zero_reverts(env e, uint256 tokenId, string reason) {
    require hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    forceFeeVersion@withrevert(e, tokenId, 0, reason);
    assert lastReverted, "forceFeeVersion(0) must revert";
}

// ─── setMarketplace zero address rejected ─────────────────────────────────────

/// setMarketplace reverts with zero address
rule rule_set_marketplace_zero_reverts(env e) {
    require hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setMarketplace@withrevert(e, 0);
    assert lastReverted, "setMarketplace(0) must revert";
}

// ─── Pause / unpause access ───────────────────────────────────────────────────

/// Non-guardian, non-admin cannot pause
rule rule_access_only_guardian_pause(env e) {
    require !hasRole(GUARDIAN_ROLE(), e.msg.sender);
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    pause@withrevert(e);
    assert lastReverted, "Only GUARDIAN_ROLE or DEFAULT_ADMIN_ROLE can pause";
}

/// Non-admin cannot unpause
rule rule_access_only_admin_unpause(env e) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    unpause@withrevert(e);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE can unpause";
}
