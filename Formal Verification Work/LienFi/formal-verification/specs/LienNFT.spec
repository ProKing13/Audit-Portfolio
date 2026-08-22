// LienNFT.spec — Certora CVL formal verification spec
// Contract: LienNFT
// Solc: 0.8.28 / Hardhat build

using LienNFT as lienNFT;

methods {
    // admin
    function initialize(address) external;
    function setLienVault(address) external;
    function addMinter(address) external;
    function removeMinter(address) external;
    function transferOwnership(address) external;
    function updateTokenURI(uint256, string) external;

    // minting
    function mintLien(address, ILienNFT.LienDetails) external returns (uint256);
    function bulkMintLiens(address, ILienNFT.LienDetails[]) external returns (uint256[]);

    // vault-only
    function setListedStatus(uint256, bool) external;
    function burnLien(uint256) external;
    function updateRedemptionValue(uint256, uint128) external;
    function setRedemptionType(uint256, string) external;

    // views
    function nextTokenId() external returns (uint256) envfree;
    function lienVault() external returns (address) envfree;
    function isListed(uint256) external returns (bool) envfree;
    function ownerOfSafe(uint256) external returns (address) envfree;
    function getRedemptionValue(uint256) external returns (uint256) envfree;
    function lienDetails(uint256) external returns (ILienNFT.LienDetails) envfree;

    // OZ ERC721 / AccessControl
    function hasRole(bytes32, address) external returns (bool) envfree;
    function ownerOf(uint256) external returns (address) envfree;

    // role constants
    function MINTER_ROLE() external returns (bytes32) envfree;
    function VAULT_ROLE() external returns (bytes32) envfree;
}

// ─── Role constant definitions ─────────────────────────────────────────────────

definition DEFAULT_ADMIN_ROLE_DEF() returns bytes32 =
    to_bytes32(0);

// ─── Ghost: mirror nextTokenId for monotonicity tracking ─────────────────────

ghost mathint ghostNextTokenId {
    init_state axiom ghostNextTokenId == 0;
}

hook Sstore nextTokenId uint256 newVal {
    ghostNextTokenId = newVal;
}




rule rule_next_token_id_once_set_stays_positive(env e, method f)
    filtered {
        f -> f.selector != sig:initialize(address).selector
          && f.selector != sig:upgradeToAndCall(address, bytes).selector
    }
{
    require nextTokenId() >= 1;   // pre-condition: initialized state
    calldataarg args;
    f(e, args);
    assert nextTokenId() >= 1,
        "nextTokenId must never drop below 1 once initialized";
}

// ─── Access Control Rules ─────────────────────────────────────────────────────

/// Only MINTER_ROLE can mint; non-minter call reverts
rule rule_access_only_minter_can_mint(env e) {
    ILienNFT.LienDetails lienData;
    address recipient;
    require !hasRole(MINTER_ROLE(), e.msg.sender);
    mintLien@withrevert(e, recipient, lienData);
    assert lastReverted, "Only MINTER_ROLE must be able to call mintLien";
}

/// Only VAULT_ROLE can setListedStatus; non-vault call reverts
rule rule_access_only_vault_sets_listed(env e, uint256 tokenId, bool status) {
    require !hasRole(VAULT_ROLE(), e.msg.sender);
    setListedStatus@withrevert(e, tokenId, status);
    assert lastReverted, "Only VAULT_ROLE must be able to call setListedStatus";
}

/// Only VAULT_ROLE can burnLien; non-vault call reverts
rule rule_access_only_vault_burns(env e, uint256 tokenId) {
    require !hasRole(VAULT_ROLE(), e.msg.sender);
    burnLien@withrevert(e, tokenId);
    assert lastReverted, "Only VAULT_ROLE must be able to call burnLien";
}

/// Only VAULT_ROLE can updateRedemptionValue
rule rule_access_only_vault_updates_redemption_value(env e, uint256 tokenId, uint128 val) {
    require !hasRole(VAULT_ROLE(), e.msg.sender);
    updateRedemptionValue@withrevert(e, tokenId, val);
    assert lastReverted, "Only VAULT_ROLE must be able to call updateRedemptionValue";
}

/// Only DEFAULT_ADMIN_ROLE can set vault
rule rule_access_only_admin_sets_vault(env e, address vault) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setLienVault@withrevert(e, vault);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call setLienVault";
}

/// Only DEFAULT_ADMIN_ROLE can addMinter
rule rule_access_only_admin_adds_minter(env e, address account) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    addMinter@withrevert(e, account);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call addMinter";
}

/// Only DEFAULT_ADMIN_ROLE can updateTokenURI
rule rule_access_only_admin_updates_uri(env e, uint256 tokenId, string newURI) {
    require !hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    updateTokenURI@withrevert(e, tokenId, newURI);
    assert lastReverted, "Only DEFAULT_ADMIN_ROLE must be able to call updateTokenURI";
}

// ─── nextTokenId monotonicity ──────────────────────────────────────────────────

/// nextTokenId strictly increases by exactly 1 after mintLien
rule rule_next_token_id_monotone(env e) {
    ILienNFT.LienDetails lienData;
    address recipient;
    uint256 before = nextTokenId();
    mintLien(e, recipient, lienData);
    uint256 after_ = nextTokenId();
    assert after_ == before + 1,
        "nextTokenId must increase by exactly 1 per mint";
}

/// nextTokenId never decreases from non-mint operations.
/// Excludes:
///   - mintLien          : legitimately increments by 1 (covered by rule_next_token_id_monotone)
///   - bulkMintLiens     : also increments (multiple mints)
///   - initialize        : one-time setup that resets nextTokenId to 1 from an uninitialized state
///   - upgradeToAndCall  : UUPS upgrade — Certora HAVOCs storage after delegatecall to new impl
rule rule_next_token_id_never_decreases(env e, method f) filtered {
    f -> f.selector != sig:mintLien(address, ILienNFT.LienDetails).selector
      && f.selector != sig:bulkMintLiens(address, ILienNFT.LienDetails[]).selector
      && f.selector != sig:initialize(address).selector
      && f.selector != sig:upgradeToAndCall(address, bytes).selector
} {
    uint256 before = nextTokenId();
    calldataarg args;
    f(e, args);
    uint256 after_ = nextTokenId();
    assert after_ >= before,
        "nextTokenId must never decrease";
}

// ─── setListedStatus integrity ────────────────────────────────────────────────

/// isListed reflects the status set by setListedStatus
rule rule_listed_status_set_correctly(env e, uint256 tokenId, bool status) {
    require hasRole(VAULT_ROLE(), e.msg.sender);
    setListedStatus(e, tokenId, status);
    assert isListed(tokenId) == status,
        "isListed must equal the status passed to setListedStatus";
}

// ─── burnLien irreversibility ─────────────────────────────────────────────────

/// After burnLien, ownerOfSafe returns address(0) for that tokenId
rule rule_burn_clears_owner(env e, uint256 tokenId) {
    require hasRole(VAULT_ROLE(), e.msg.sender);
    require ownerOfSafe(tokenId) != 0;
    burnLien(e, tokenId);
    assert ownerOfSafe(tokenId) == 0,
        "After burnLien, ownerOfSafe must return address(0)";
}

// ─── setLienVault zero address rejected ──────────────────────────────────────

/// setLienVault reverts with zero address input
rule rule_set_vault_zero_reverts(env e) {
    require hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    setLienVault@withrevert(e, 0);
    assert lastReverted, "setLienVault(0) must revert";
}

// ─── mint recipient non-zero ─────────────────────────────────────────────────

/// mintLien reverts when recipient is zero address
rule rule_mint_zero_recipient_reverts(env e) {
    ILienNFT.LienDetails lienData;
    require hasRole(MINTER_ROLE(), e.msg.sender);
    mintLien@withrevert(e, 0, lienData);
    assert lastReverted, "mintLien to zero address must revert";
}

// ─── Upgrade access ──────────────────────────────────────────────────────────

/// transferOwnership reverts with zero address
rule rule_transfer_ownership_zero_reverts(env e) {
    require hasRole(DEFAULT_ADMIN_ROLE_DEF(), e.msg.sender);
    transferOwnership@withrevert(e, 0);
    assert lastReverted, "transferOwnership(0) must revert";
}
