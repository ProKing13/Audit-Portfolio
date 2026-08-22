// LienMarketplace.spec — Certora CVL formal verification spec
// Contract: LienMarketplace
// Solc: 0.8.28 / Hardhat build

using LienMarketplace as marketplace;
using LienVault as lienVault;
using LienNFT as lienNFT;
using FeeManager as feeManager;

methods {
    // user entrypoints
    function listNFT(uint256, uint256) external;
    function buyNFT(uint256, uint256, uint256, uint256, uint256, uint256, bytes) external;
    function cancelListing(uint256) external;

    // admin / config
    function initialize(address, address, address, address, address, address, address) external;
    function setFeeManager(address) external;
    function setPriceSigner(address) external;
    function setSellerSurcharge(uint256, uint256) external;
    function pause() external;
    function unpause() external;
    function adminCancelListing(uint256) external;
    function transferOwnership(address) external;

    // views
    function listings(uint256) external returns (
        uint256, address, address, uint256, bool, uint256
    ) envfree;
    function usedSignatures(bytes32) external returns (bool) envfree;
    function priceSigner() external returns (address) envfree;
    function paused() external returns (bool) envfree;
    function hasRole(bytes32, address) external returns (bool) envfree;
    function getListingSeller(uint256) external returns (address);
    function getListingSellerRaw(uint256) external returns (address) envfree;

    // role constant selectors 
    function GUARDIAN_ROLE() external returns (bytes32) envfree;
    function OPERATOR_ROLE() external returns (bytes32) envfree;
    function VAULT_ROLE() external returns (bytes32) envfree;

    // LienVault (linked via conf link directive)
    function lienVault.hasPurchasePriceByTokenId(uint256) external returns (bool) envfree;
    function lienVault.purchasePriceByTokenId(uint256) external returns (uint256) envfree;

    // LienNFT (linked via conf link directive)
    function lienNFT.isListed(uint256) external returns (bool) envfree;
    function lienNFT.ownerOf(uint256) external returns (address) envfree;

    // FeeManager (linked via conf link directive)
    function feeManager.currentFeeVersion() external returns (uint256) envfree;
    function feeManager.treasury() external returns (address) envfree;
}

// ─── Role constants ────────────────────────────────────────────────────────────

definition DEFAULT_ADMIN_ROLE_DEF() returns bytes32 =
    to_bytes32(0);


// ─── Pause gating ─────────────────────────────────────────────────────────────

/// listNFT reverts when marketplace is paused
rule rule_pause_blocks_list(env e, uint256 tokenId, uint256 surcharge) {
    require paused();
    listNFT@withrevert(e, tokenId, surcharge);
    assert lastReverted, "listNFT must revert when paused";
}

/// buyNFT reverts when marketplace is paused
rule rule_pause_blocks_buy(env e, uint256 tokenId, uint256 lienPrice, uint256 maturity, uint256 deadline, uint256 baseValue, uint256 feeVersion) {
    require paused();
    bytes buySignature;
    buyNFT@withrevert(e, tokenId, lienPrice, maturity, deadline, baseValue, feeVersion, buySignature);
    assert lastReverted, "buyNFT must revert when paused";
}

/// cancelListing reverts when marketplace is paused
rule rule_pause_blocks_cancel(env e, uint256 tokenId) {
    require paused();
    cancelListing@withrevert(e, tokenId);
    assert lastReverted, "cancelListing must revert when paused";
}

// ─── Access Control ───────────────────────────────────────────────────────────

/// Only VAULT_ROLE can call adminCancelListing
rule rule_access_admin_cancel_vault_only(env e, uint256 tokenId) {
    require !hasRole(VAULT_ROLE(), e.msg.sender);
    adminCancelListing@withrevert(e, tokenId);
    assert lastReverted, "Only VAULT_ROLE must be able to call adminCancelListing";
}

/// Only DEFAULT_ADMIN_ROLE can call setFeeManager
rule rule_access_only_admin_set_fee_manager(env e, address fm) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setFeeManager@withrevert(e, fm);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call setFeeManager";
}

/// Only operator or admin can call setPriceSigner
rule rule_access_only_operator_set_price_signer(env e, address signer) {
    require !hasRole(OPERATOR_ROLE(), e.msg.sender);
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setPriceSigner@withrevert(e, signer);
    assert lastReverted, "Only OPERATOR_ROLE or DEFAULT_ADMIN_ROLE can call setPriceSigner";
}

/// Only DEFAULT_ADMIN_ROLE can call setSellerSurcharge
rule rule_access_only_admin_set_surcharge(env e, uint256 tokenId, uint256 surcharge) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setSellerSurcharge@withrevert(e, tokenId, surcharge);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call setSellerSurcharge";
}

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

// ─── Listing state: cancelListing ────────────────────────────────────────────

/// After cancelListing, listing becomes inactive
rule rule_listing_inactive_after_cancel(env e, uint256 tokenId) {
    uint256 tid; address seller; address buyer; uint256 price; bool isActiveBefore; uint256 surcharge;
    (tid, seller, buyer, price, isActiveBefore, surcharge) = listings(tokenId);
    require isActiveBefore;
    require seller == e.msg.sender;
    require !paused();
    cancelListing(e, tokenId);
    uint256 tid2; address seller2; address buyer2; uint256 price2; bool isActiveAfter; uint256 surcharge2;
    (tid2, seller2, buyer2, price2, isActiveAfter, surcharge2) = listings(tokenId);
    assert !isActiveAfter,
        "Listing must be inactive after cancelListing";
}

/// Only the original seller can cancel their listing; others revert
rule rule_cancel_only_by_seller(env e, uint256 tokenId) {
    uint256 tid; address seller; address buyer; uint256 price; bool isActive; uint256 surcharge;
    (tid, seller, buyer, price, isActive, surcharge) = listings(tokenId);
    require isActive;
    require e.msg.sender != seller;
    require !paused();
    cancelListing@withrevert(e, tokenId);
    assert lastReverted, "Only the listing seller can cancel";
}

/// Cancelling an inactive listing reverts
rule rule_cancel_inactive_listing_reverts(env e, uint256 tokenId) {
    uint256 tid; address seller; address buyer; uint256 price; bool isActive; uint256 surcharge;
    (tid, seller, buyer, price, isActive, surcharge) = listings(tokenId);
    require !isActive;
    require !paused();
    cancelListing@withrevert(e, tokenId);
    assert lastReverted, "cancelListing must revert when listing is inactive";
}

// ─── Listing state: buyNFT ────────────────────────────────────────────────────

/// buyNFT on an inactive listing must revert
rule rule_buy_inactive_listing_reverts(env e, uint256 tokenId, uint256 lienPrice, uint256 maturity, uint256 deadline, uint256 baseValue, uint256 feeVersion) {
    uint256 tid; address seller; address buyer; uint256 price; bool isActive; uint256 surcharge;
    (tid, seller, buyer, price, isActive, surcharge) = listings(tokenId);
    require !isActive;
    require !paused();
    bytes buySignature;
    buyNFT@withrevert(e, tokenId, lienPrice, maturity, deadline, baseValue, feeVersion, buySignature);
    assert lastReverted, "buyNFT must revert when listing is not active";
}

// ─── priceSigner zero address rejected ───────────────────────────────────────

/// setPriceSigner reverts with zero address
rule rule_set_price_signer_zero_reverts(env e) {
    require hasRole(OPERATOR_ROLE(), e.msg.sender) || hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setPriceSigner@withrevert(e, 0);
    assert lastReverted, "setPriceSigner(0) must revert";
}

// ─── setFeeManager zero address rejected ─────────────────────────────────────

/// setFeeManager reverts with zero address
rule rule_set_fee_manager_zero_reverts(env e) {
    require hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setFeeManager@withrevert(e, 0);
    assert lastReverted, "setFeeManager(0) must revert";
}

// ─── adminCancelListing marks listing inactive ────────────────────────────────

/// adminCancelListing (by VAULT_ROLE) makes listing inactive
rule rule_admin_cancel_deactivates_listing(env e, uint256 tokenId) {
    require hasRole(VAULT_ROLE(), e.msg.sender);
    adminCancelListing(e, tokenId);
    uint256 tid; address seller; address buyer; uint256 price; bool isActiveAfter; uint256 surcharge;
    (tid, seller, buyer, price, isActiveAfter, surcharge) = listings(tokenId);
    assert !isActiveAfter,
        "adminCancelListing must mark the listing inactive";
}

// ─── getListingSeller / getListingSellerRaw return zero for inactive listings ──

/// getListingSellerRaw returns address(0) when listing is inactive
rule rule_get_seller_raw_returns_zero_when_inactive(env e, uint256 tokenId) {
    uint256 tid; address seller; address buyer; uint256 price; bool isActive; uint256 surcharge;
    (tid, seller, buyer, price, isActive, surcharge) = listings(tokenId);
    require !isActive;
    assert getListingSellerRaw(tokenId) == 0,
        "getListingSellerRaw must return address(0) for inactive listings";
}

/// getListingSeller returns address(0) when no purchase price exists (pre-sale).
rule rule_get_seller_returns_zero_when_no_purchase_price(env e, uint256 tokenId) {
    require !lienVault.hasPurchasePriceByTokenId(tokenId);
    address result = getListingSeller(e, tokenId);
    assert result == 0,
        "getListingSeller must return address(0) when no purchase price is on the vault";
}
