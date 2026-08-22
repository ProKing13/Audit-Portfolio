// FeeManager.spec — Certora CVL formal verification spec
// Contract: FeeManager
// Solc: 0.8.28 / Hardhat build

using FeeManager as feeManager;

methods {
    function createFeeConfig(IFeeManager.FeeConfig) external returns (uint256) optional;
    function updateTreasury(address) external optional;
    function getFeeConfig(uint256) external returns (IFeeManager.FeeConfig) envfree;
    function feeScheduleHash(uint256) external returns (bytes32) envfree;
    function currentFeeVersion() external returns (uint256) envfree;
    function treasury() external returns (address) envfree;
    function owner() external returns (address) envfree;
    function pendingOwner() external returns (address) envfree;
}

// ─── Invariants ───────────────────────────────────────────────────────────────

/// treasury is never zero address after any operation
invariant treasury_never_zero()
    treasury() != 0
    {
        preserved with (env e) {
            require treasury() != 0;
        }
    }



// ─── Access Control Rules ─────────────────────────────────────────────────────

/// Only the owner can call createFeeConfig; non-owner calls revert
rule rule_access_only_owner_creates_config(env e) {
    IFeeManager.FeeConfig config;
    address o = owner();
    require e.msg.sender != o;
    createFeeConfig@withrevert(e, config);
    assert lastReverted, "Non-owner must not be able to call createFeeConfig";
}

/// Only the owner can call updateTreasury; non-owner calls revert
rule rule_access_only_owner_updates_treasury(env e, address newTreasury) {
    address o = owner();
    require e.msg.sender != o;
    updateTreasury@withrevert(e, newTreasury);
    assert lastReverted, "Non-owner must not be able to call updateTreasury";
}

// ─── Fee Version Monotonicity ──────────────────────────────────────────────────

/// currentFeeVersion strictly increases by exactly 1 on createFeeConfig
rule rule_fee_version_monotone(env e) {
    IFeeManager.FeeConfig config;
    uint256 versionBefore = currentFeeVersion();
    createFeeConfig(e, config);
    uint256 versionAfter = currentFeeVersion();
    assert versionAfter == versionBefore + 1,
        "currentFeeVersion must increase by exactly 1 on createFeeConfig";
}

/// currentFeeVersion never decreases from any non-create call
rule rule_fee_version_never_decreases(env e, method f) filtered {
    f -> f.selector != sig:createFeeConfig(IFeeManager.FeeConfig).selector
} {
    uint256 versionBefore = currentFeeVersion();
    calldataarg args;
    f(e, args);
    uint256 versionAfter = currentFeeVersion();
    assert versionAfter == versionBefore,
        "currentFeeVersion must not change except via createFeeConfig";
}

// ─── Treasury Rules ────────────────────────────────────────────────────────────

/// updateTreasury with zero address reverts
rule rule_treasury_zero_address_reverts(env e) {
    updateTreasury@withrevert(e, 0);
    assert lastReverted, "updateTreasury(0) must revert";
}

/// treasury is updated correctly after updateTreasury
rule rule_treasury_updated_correctly(env e, address newTreasury) {
    require newTreasury != 0;
    require e.msg.sender == owner();
    updateTreasury(e, newTreasury);
    assert treasury() == newTreasury, "Treasury must equal newTreasury after update";
}

// ─── BPS Validation ────────────────────────────────────────────────────────────

/// createFeeConfig reverts when any bps field exceeds 10_000
rule rule_bps_exceeds_denominator_reverts(env e) {
    IFeeManager.FeeConfig config;
    require e.msg.sender == owner();
    // Certora will explore cases where any field > 10000
    require config.saleFeeBps > 10000 ||
            config.saleServicerFeeBps > 10000 ||
            config.interestFeeBps > 10000 ||
            config.interestServicerFeeBps > 10000 ||
            config.foreclosureFeeBps > 10000 ||
            config.preSaleProfitSharingBps > 10000;
    createFeeConfig@withrevert(e, config);
    assert lastReverted, "createFeeConfig must revert when any bps > 10_000";
}

/// After createFeeConfig, every stored bps field is ≤ 10_000
rule rule_bps_within_bounds_after_create(env e) {
    IFeeManager.FeeConfig config;
    require e.msg.sender == owner();
    uint256 version = createFeeConfig(e, config);
    IFeeManager.FeeConfig stored = getFeeConfig(version);
    assert stored.saleFeeBps <= 10000 &&
           stored.saleServicerFeeBps <= 10000 &&
           stored.interestFeeBps <= 10000 &&
           stored.interestServicerFeeBps <= 10000 &&
           stored.foreclosureFeeBps <= 10000 &&
           stored.preSaleProfitSharingBps <= 10000,
        "All bps fields must be ≤ 10_000 after createFeeConfig";
}

// ─── getFeeConfig Revert Behavior ─────────────────────────────────────────────

/// getFeeConfig reverts for a version that has never been created.
rule rule_get_config_unknown_reverts() {
    uint256 version;
    feeScheduleHash@withrevert(version);
    require lastReverted;
    getFeeConfig@withrevert(version);
    assert lastReverted, "getFeeConfig must revert for unknown version";
}

/// getFeeConfig does NOT revert for a version that was just created
rule rule_get_config_known_succeeds(env e) {
    IFeeManager.FeeConfig config;
    require e.msg.sender == owner();
    // ensure bps valid so createFeeConfig doesn't revert
    require config.saleFeeBps <= 10000 &&
            config.saleServicerFeeBps <= 10000 &&
            config.interestFeeBps <= 10000 &&
            config.interestServicerFeeBps <= 10000 &&
            config.foreclosureFeeBps <= 10000 &&
            config.preSaleProfitSharingBps <= 10000;
    uint256 version = createFeeConfig(e, config);
    getFeeConfig@withrevert(version);
    assert !lastReverted, "getFeeConfig must not revert for a known version";
}

/// feeScheduleHash is non-zero for a created version
rule rule_fee_hash_non_zero_after_create(env e) {
    IFeeManager.FeeConfig config;
    require e.msg.sender == owner();
    require config.saleFeeBps <= 10000 &&
            config.saleServicerFeeBps <= 10000 &&
            config.interestFeeBps <= 10000 &&
            config.interestServicerFeeBps <= 10000 &&
            config.foreclosureFeeBps <= 10000 &&
            config.preSaleProfitSharingBps <= 10000;
    uint256 version = createFeeConfig(e, config);
    assert feeScheduleHash(version) != to_bytes32(0),
        "feeScheduleHash must be non-zero for a created version";
}
