using ERC20Aument as token;

methods {
    function hasRole(bytes32, address) external returns (bool) envfree;
    function ADMIN_ROLE()              external returns (bytes32) envfree;
    function addWhitelistAddress(address) external;
}

// rule: non-admin cannot add an address to the whitelist
rule rule_access_addWhitelist_non_admin_reverts(address account) {
    env e;
    require !hasRole(ADMIN_ROLE(), e.msg.sender);
    addWhitelistAddress@withrevert(e, account);
    assert lastReverted, "non-admin must not add to whitelist";
}
