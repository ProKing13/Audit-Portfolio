using AumentWalletContract as wallet;

methods {
    function withdrawAnyToken(address, address, uint256) external returns (bool);
    function withdrawEther(address, uint256) external;
    function proxyCallWithValue(bytes, address, uint256) external;
    function proxyCallWithoutValue(bytes, address) external;
}


// rule: withdrawEther to zero address reverts
rule rule_withdrawEther_zero_recipient_reverts(uint256 amount) {
    env e;
    withdrawEther@withrevert(e, 0, amount);
    assert lastReverted, "withdrawEther to zero address must revert";
}

// rule: withdrawEther reverts when amount exceeds contract balance
rule rule_withdrawEther_insufficient_balance_reverts(address recipient, uint256 amount) {
    env e;
    require recipient != 0;
    require e.msg.value == 0;
    require amount > 0;
    require nativeBalances[currentContract] < amount;
    withdrawEther@withrevert(e, recipient, amount);
    assert lastReverted, "withdrawEther must revert when balance insufficient";
}

// rule: withdrawAnyToken to zero token address reverts
rule rule_withdrawAnyToken_zero_token_reverts(address recipient, uint256 amount) {
    env e;
    withdrawAnyToken@withrevert(e, 0, recipient, amount);
    assert lastReverted, "withdrawAnyToken with zero token address must revert";
}

// rule: withdrawAnyToken to zero recipient reverts
rule rule_withdrawAnyToken_zero_recipient_reverts(address token, uint256 amount) {
    env e;
    withdrawAnyToken@withrevert(e, token, 0, amount);
    assert lastReverted, "withdrawAnyToken with zero recipient must revert";
}

// rule: proxyCallWithValue to zero address reverts
rule rule_proxyCallWithValue_zero_target_reverts(bytes data, uint256 value) {
    env e;
    proxyCallWithValue@withrevert(e, data, 0, value);
    assert lastReverted, "proxyCallWithValue to zero address must revert";
}

// rule: proxyCallWithoutValue to zero address reverts
rule rule_proxyCallWithoutValue_zero_target_reverts(bytes data) {
    env e;
    proxyCallWithoutValue@withrevert(e, data, 0);
    assert lastReverted, "proxyCallWithoutValue to zero address must revert";
}
