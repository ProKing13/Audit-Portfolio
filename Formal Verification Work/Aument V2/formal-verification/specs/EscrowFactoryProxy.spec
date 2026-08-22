using EscrowFactoryProxy as factory;

methods {
    function deployAndCloseEscrow(bytes, bytes32, address, bool) external;
    function ADMIN_ROLE() external returns (bytes32) envfree;
}

// ─────────────────────────────────────────────────────────
// ACCESS CONTROL — a revert path must exist for the hasRole=false branch
// ─────────────────────────────────────────────────────────

rule rule_factory_revert_path_reachable(
    bytes bytecode,
    bytes32 salt,
    address userAddress,
    bool loanPaid
) {
    env e;
    deployAndCloseEscrow@withrevert(e, bytecode, salt, userAddress, loanPaid);
    satisfy lastReverted;
}


rule rule_factory_success_path_reachable(
    bytes bytecode,
    bytes32 salt,
    address userAddress,
    bool loanPaid
) {
    env e;
    deployAndCloseEscrow@withrevert(e, bytecode, salt, userAddress, loanPaid);
    satisfy !lastReverted;
}
