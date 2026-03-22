## Table of Contents

- 🔴 **H-01.** [Double-Transfer Vulnerability in Repay Function: Fund Loss and DoS](#h-01)
- 🔴 **H-02.** [Protocol Fees Deducted During `burn` Are Not Transferred, Leading to Accounting Discrepancies and Revenue Diversion](#h-02)

---

<a id="h-01"></a>

## 🔴 **H-01 - Double-Transfer Vulnerability in Repay Function: Fund Loss and DoS**

### Summary

The repay function in AlchemistV3.sol incorrectly transfers the entire repayment amount to both the transmuter and the protocol fee receiver, instead of only sending the fee portion to the fee receiver. This creates either a double-spend vulnerability or a complete denial of service for the repay functionality.

### Finding Description

In the `repay` function, there's a critical accounting error in how protocol fees are handled. The function correctly calculates and deducts the fee from the user's collateral balance but then incorrectly transfers the entire repayment amount ( `creditToYield` ) to both the transmuter and the protocol fee receiver.

**Link:** `https://cantina.xyz/code/e68909e6-3491-4a94-a707-ecf0c89cf72a/src/AlchemistV3.sol?lines=488,488`

The issue is in these lines:

```javascript
// Debt is subject to protocol fee similar to redemptions
account.collateralBalance -= (creditToYield * protocolFee) / BPS;

_subDebt(recipientTokenId, credit);

// Transfer the repaid tokens to the transmuter.
TokenUtils.safeTransferFrom(yieldToken, msg.sender, transmuter, creditToYield);
TokenUtils.safeTransfer(yieldToken, protocolFeeReceiver, creditToYield);
```

### Initial Code Snippet

```javascript
// Transfer the repaid tokens to the transmuter.
TokenUtils.safeTransferFrom(yieldToken, msg.sender, transmuter, creditToYield);
TokenUtils.safeTransfer(yieldToken, protocolFeeReceiver, creditToYield);
```

### Description Text

The function deducts the fee from the user's collateral but it transfers the entire `creditToYield` amount to both the transmuter and the protocol fee receiver, instead of only transferring the fee portion to the fee receiver.

### Impact Explanation

This vulnerability has two possible impacts depending on the contract's state:

1.  **Double-spend vulnerability:** If the contract has enough yield tokens, it will transfer the entire repayment amount twice - once to the transmuter and once to the fee receiver. This means the fee receiver gets the entire repayment amount instead of just the fee portion.
2.  **Denial of Service:** If the contract doesn't have enough yield tokens (which is the more likely scenario), the second transfer will revert, making the entire repay function unusable. This completely breaks a core protocol function.

### Likelihood Explanation

The likelihood of this issue occurring is HIGH. The repay function is a core protocol function that will be regularly used by users to repay their debt. Every single call to this function will either result in complete amount transfer to protocol fee receiver or transaction failure, depending on the contract's token balance.

### Proof of Concept

**Dourble spending PoC:**

```javascript
function testRepayBug() external {
    // Set a protocol fee (5%)
    uint256 protocolFee = 500; // 5% in BPS
    vm.prank(alOwner);
    alchemist.setProtocolFee(protocolFee);

    uint256 amount = 100e18;

    // Setup user position
    vm.startPrank(address(0xbeef));
    SafeERC20.safeApprove(address(fakeYieldToken), address(alchemist), amount + 100e18);
    alchemist.deposit(amount, address(0xbeef), 0);
    uint256 tokenId = AlchemistNFTHelper.getFirstTokenId(address(0xbeef), address(alchemistNFT));
    alchemist.mint(tokenId, amount / 2, address(0xbeef));

    vm.roll(block.number + 1);

    // Get balances before repay
    uint256 preBalanceTransmuter = fakeYieldToken.balanceOf(address(transmuterLogic));
    uint256 preBalanceFeeReceiver = fakeYieldToken.balanceOf(alchemist.protocolFeeReceiver());
    uint256 preBalanceUser = fakeYieldToken.balanceOf(address(0xbeef));

    // Calculate expected fee
    uint256 repayAmount = amount / 4; // 25e18

    // Repay debt
    SafeERC20.safeApprove(address(fakeYieldToken), address(alchemist), repayAmount);
    alchemist.repay(repayAmount, tokenId);
    vm.stopPrank();

    // Get balances after repay
    uint256 postBalanceTransmuter = fakeYieldToken.balanceOf(address(transmuterLogic));
    uint256 postBalanceFeeReceiver = fakeYieldToken.balanceOf(alchemist.protocolFeeReceiver());
    uint256 postBalanceUser = fakeYieldToken.balanceOf(address(0xbeef));

    assertEq(
        postBalanceFeeReceiver - preBalanceFeeReceiver,
        repayAmount, // Should be expectedFee
        "Fee receiver incorrectly received the full repayment amount instead of just the fee"
    );

    assertEq(
        postBalanceTransmuter - preBalanceTransmuter,
        repayAmount,
        "Transmuter should receive the repayment amount"
    );

    // User paid the correct amount
    assertEq(
        preBalanceUser - postBalanceUser,
        repayAmount,
        "User should pay exactly the repay amount"
    );

    console.log("Double transfer bug: Total tokens transferred:", repayAmount * 2);
    console.log("Expected total transfer (without fee):", repayAmount);
}
```

**Denial of service PoC:**

```javascript
    function testRepayDenialOfService() external {
        // Set a protocol fee (5%)
        uint256 protocolFee = 500; // 5% in BPS
        vm.prank(alOwner);
        alchemist.setProtocolFee(protocolFee);

        uint256 amount = 100e18;

        // Setup user position
        vm.startPrank(address(0xbeef));
        SafeERC20.safeApprove(address(fakeYieldToken), address(alchemist), amount + 100e18);
        alchemist.deposit(amount, address(0xbeef), 0);
        uint256 tokenId = AlchemistNFTHelper.getFirstTokenId(address(0xbeef), address(alchemistNFT));
        alchemist.mint(tokenId, amount / 2, address(0xbeef));

        vm.roll(block.number + 1);
        vm.stopPrank(); // Stop the current prank before starting a new one

        // Ensure the contract has no tokens to demonstrate the DoS scenario
        // This simulates a real scenario where the contract wouldn't have tokens to transfer. As in real scenario after some repay the contract balance is going to be zero.
        uint256 contractBalance = fakeYieldToken.balanceOf(address(alchemist));
        vm.startPrank(address(alchemist));
        fakeYieldToken.transfer(address(0xdead), contractBalance);
        vm.stopPrank();

        // Try to repay - this should revert because the contract can't transfer tokens it doesn't have
        vm.startPrank(address(0xbeef));
        uint256 repayAmount = amount / 4; // 25e18
        SafeERC20.safeApprove(address(fakeYieldToken), address(alchemist), repayAmount);

        // The transaction should revert due to the second transfer failing
        vm.expectRevert();
        alchemist.repay(repayAmount, tokenId);
        vm.stopPrank();

        console.log("Repay function is unusable (DoS) when contract has insufficient tokens");
    }
```

**Test output:**

```javascript
[PASS] testRepayBug() (gas: 684888)
Logs:
  Double transfer bug: Total tokens transferred: 50000000000000000000
  Expected total transfer (without fee): 25000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 52.23ms (2.97ms CPU time)
```

**Results of tests:**

```javascript
Ran 1 test for src/test/AlchemistV3.t.sol:AlchemistV3Test
[PASS] testRepayDenialOfService() (gas: 674300)
Logs:
  Repay function is unusable (DoS) when contract has insufficient tokens

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 38.68ms (9.75ms CPU time)
```

---

<a id="h-02"></a>

## 🔴 **H-02 - Protocol Fees Deducted During `burn` Are Not Transferred, Leading to Accounting Discrepancies and Revenue Diversion**


### Summary

Protocol fees collected during debt repayment via the `burn` function are deducted from user collateral balances but are never transferred to the protocol fee receiver, resulting in accounting discrepancies.

### Finding Description

In the `burn` function of AlchemistV3.sol, when users repay their debt by burning synthetic tokens, a protocol fee is correctly deducted from the user's collateral balance but is never transferred to the protocol fee receiver:

**URL Link:** `https://cantina.xyz/code/e68909e6-3491-4a94-a707-ecf0c89cf72a/src/AlchemistV3.sol?lines=447,447`

```javascript
// Debt is subject to protocol fee similar to redemptions
_accounts[recipientId].collateralBalance -= convertDebtTokensToYield(credit) * protocolFee / BPS;
```

This creates an accounting discrepancy where the contract's actual token balance becomes larger than the sum of all user collateral balances. The deducted fees remain in the AlchemistV3 contract but are not properly accounted for, essentially creating "phantom" collateral.

While these accumulated fees can indirectly benefit the system by providing additional liquidity for redemptions through the Transmuter, they are not properly attributed to the protocol fee receiver as intended by the protocol's design.

### Impact Explanation

This vulnerability has medium impact as it affects the protocol's financial accounting and revenue distribution:

1. **Protocol Fee Diversion**: Fees that should go to the protocol fee receiver instead remain in the AlchemistV3 contract, diverting revenue from its intended destination.
2. **Accounting Inconsistency**: Creates a growing discrepancy between internal accounting (sum of user collateral balances) and the contract's actual token balance.
3. **Deposit Cap Limitation**: As "phantom" collateral accumulates, it counts against the deposit cap, potentially limiting new deposits unnecessarily.
4. **Transparency Issues**: The protocol's fee collection metrics would be inaccurate, as fees from burns are not properly attributed.

### Likelihood Explanation

This issue will occur with 100% certainty every time a user burns synthetic tokens to repay debt. As the `burn` function will be frequently used, making the likelihood of impact very high. The issue compounds over time as more users repay debt through burning.

### Proof of Concept

```javascript
function testBurnProtocolFeeNotTransferred() external {
    // Set a protocol fee (5%)
    uint256 protocolFee = 500; // 5% in BPS (basis points)
    vm.prank(alOwner);
    alchemist.setProtocolFee(protocolFee);

    uint256 amount = 100e18;

    // Setup user position
    vm.startPrank(address(0xbeef));
    SafeERC20.safeApprove(address(fakeYieldToken), address(alchemist), amount + 100e18);

    // Get initial contract balance before deposit
    uint256 initialContractBalance = fakeYieldToken.balanceOf(address(alchemist));

    alchemist.deposit(amount, address(0xbeef), 0);
    uint256 tokenId = AlchemistNFTHelper.getFirstTokenId(address(0xbeef), address(alchemistNFT));

    alchemist.mint(tokenId, amount / 2, address(0xbeef));

    vm.roll(block.number + 1);

    // Get balance before burn
    uint256 preBalanceContract = fakeYieldToken.balanceOf(address(alchemist));
    uint256 preBalanceFeeReceiver = fakeYieldToken.balanceOf(alchemist.protocolFeeReceiver());

    // Burn debt tokens
    SafeERC20.safeApprove(address(alToken), address(alchemist), amount / 2);
    alchemist.burn(amount / 2, tokenId);
    vm.stopPrank();

    // Get final balances after burn
    uint256 finalBalanceContract = fakeYieldToken.balanceOf(address(alchemist));
    uint256 finalBalanceFeeReceiver = fakeYieldToken.balanceOf(alchemist.protocolFeeReceiver());

    // Verify fee was NOT transferred to protocol fee receiver
    assertEq(
        finalBalanceFeeReceiver - preBalanceFeeReceiver,
        0,
        "Fee was incorrectly transferred to protocol fee receiver"
    );
    console.log(" Fee was NOT transferred to protocol fee receiver");

    // Verify the fee remains in the contract
    assertEq(
        finalBalanceContract,
        preBalanceContract,
        "Contract balance should remain unchanged"
    );

}
```

**Result:**

```javascript
Ran 1 test for src/test/AlchemistV3.t.sol:AlchemistV3Test
[PASS] testBurnProtocolFeeNotTransferred() (gas: 540851)
Logs:
  Fee was NOT transferred to protocol fee receiver

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 46.36ms (2.48ms CPU time)
```

### Recommendation

Modify the `burn` function to properly transfer the fee to the protocol fee receiver
