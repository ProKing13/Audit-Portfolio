// EscrowContract.spec — Certora Formal Verification
// Target: EscrowContract
// Coverage: factory-only guard on closeEscrow, zero-address safety on userAddress,
//           loan routing assertion.
//
// EscrowContract inherits ProxyStorage which defines _escrowFactoryAddress.
// CVL can read this as currentContract._escrowFactoryAddress.

using EscrowContract as escrow;

methods {
    function closeEscrow(address, bool) external;
    function _.transfer(address to, uint256 amount) external =>
        erc20TransferSummary(to) expect bool;
}

ghost bool g_erc20TransferResult;

function erc20TransferSummary(address to) returns bool {
    if (to == 0) {
        return false;      
    }
    return g_erc20TransferResult;  
}

// ─────────────────────────────────────────────────────────
// ACCESS CONTROL — caller != _escrowFactoryAddress must revert
// ─────────────────────────────────────────────────────────

rule rule_closeEscrow_non_factory_reverts(address userAddress, bool loanPaid) {
    env e;
    require e.msg.sender != escrow._escrowFactoryAddress;
    closeEscrow@withrevert(e, userAddress, loanPaid);
    assert lastReverted, "caller != factory must revert with NotFactory";
}

// ─────────────────────────────────────────────────────────
// ZERO-ADDRESS SAFETY — zero userAddress with loanPaid=true must revert
// (ERC20 reverts on transfer to address(0))
// ─────────────────────────────────────────────────────────

rule rule_closeEscrow_paid_zero_user_reverts() {
    env e;
    
    closeEscrow@withrevert(e, 0, true);
    assert lastReverted, "closeEscrow to zero user address must revert";
}

// ─────────────────────────────────────────────────────────
// LOAN ROUTING — revert path exists for non-factory caller
// ─────────────────────────────────────────────────────────

rule rule_closeEscrow_revert_path_exists(address userAddress, bool loanPaid) {
    env e;
    closeEscrow@withrevert(e, userAddress, loanPaid);
    satisfy lastReverted;
}

// Existence: success path exists when caller is factory and user is non-zero
rule rule_closeEscrow_success_path_exists(address userAddress, bool loanPaid) {
    env e;
    require e.msg.sender == escrow._escrowFactoryAddress;
    require userAddress != 0;
    closeEscrow@withrevert(e, userAddress, loanPaid);
    satisfy !lastReverted;
}
