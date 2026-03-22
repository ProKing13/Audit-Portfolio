## Table of Contents

- 🟡 **M-01.** [Pendle PT Oracle Decimal Precision Mismatch Leading to Collateral Overvaluation](#m-01)
- 🟡 **M-02.** [Lack of slippage protection in liquidations exposes liquidators to losses](#m-02)
- 🟡 **M-03.** [WStable Contract Invariant Break in `isSaving=true` Mode](#m-03)
- 🟡 **M-04.** [Liquidation fee calculated on entire repayment amount instead of liquidator profit](#m-04)

---

<a id="m-01"></a>
## 🟡 **M-01 - Pendle PT Oracle Decimal Precision Mismatch Leading to Collateral Overvaluation**

### Summary

The `OraclePendlePT` contract incorrectly assumes that Pendle's oracle function `getPtToSyRate()` always returns values in 1e18 decimals, which is not true for all Pendle markets. This can lead to significant overvaluation of PT tokens used as collateral, allowing users to borrow more than they should and potentially causing bad debt for the protocol.
Same bug on [Notional contest](https://solodit.cyfrin.io/issues/m-12-pendleptoracle_getptrate-isnt-correct-for-some-market-sherlock-notional-exponent-git)

### Root Cause

The root cause  is in the [latestAnswer()](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Oracles/Pendle/OraclePendlePT.sol#L37) function of `OraclePendlePT.sol` at line [45](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Oracles/Pendle/OraclePendlePT.sol#L45):

```javascript
return (oracle.getPtToSyRate(address(_params.pendleMarket), uint32(_params.duration)) * underlyingPrice) / 1e18;
```

This code makes the incorrect assumption that `getPtToSyRate()` always returns values with 1e18 decimal precision. However, for certain Pendle markets, this function returns values with different decimal precision (e.g., 1e20 or higher). The hardcoded division by `1e18` fails to account for markets where the rate is returned with different decimal precision.


### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. An attacker identifies a Pendle market used by Tangent where `getPtToSyRate()` returns non-1e18 decimals (e.g., 1e20)
2. They acquire PT tokens from this market, which are accepted as collateral in Tangent's `BasicERC20Market`
3. They deposit these PT tokens as collateral in Tangent Finance
4. Due to the oracle bug, their collateral is valued at up to 100x its actual value (if precision is 1e20)
5. They borrow the maximum amount of USG against this overvalued collateral
6. They never repay the loan, leaving the protocol with bad debt
7. If many users exploit this or the market conditions change, the protocol could face significant insolvency


### Impact

1. **Collateral Overvaluation**: PT tokens can be valued at up to 100x their actual value
2. **Excessive Borrowing**: Users can borrow significantly more USG than their collateral should allow
3. **Undercollateralized Positions**: Positions that appear healthy may actually be severely undercollateralized
5. **Financial Loss**: The protocol could lose substantial funds if exploited


### PoC

_No response_

### Mitigation

Consider a way to properly handle the decimal precision returned by `getPtToSyRate()`.




<a id="m-02"></a>
## 🟡 **M-02 - Lack of slippage protection in liquidations exposes liquidators to losses**

### Summary

The liquidation mechanism in Tangent protocol lacks a slippage protection mechanism for liquidators, exposing them to potential losses. The protocol does not verify that liquidators receive sufficient value to cover their costs, making liquidations risky and potentially unprofitable. Their is minUSGOut paramter on liquidate function but that only check the value which is gotten from the swaping LP or other token on zapproxy it is not for checking the liquidator expectation(profit)

### Root Cause

The liquidation function does not include any slippage protection that liquidators can set their expectation on liquidating the borrower. The protocol allows liquidations to proceed even when they result in a loss for the liquidator:


There is no slippage protection for liquidation in liquidate function
[liquidate function](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Market/abstract/MarketExternalActions.sol#L214)
```javascript
  function liquidate(address account, uint256 collatToLiquidate, uint256 minUSGOut, ZapStruct calldata liquidationCall)external nonReentrant updateRewards(account) {
        (uint256 newDebtIndex, uint256 collatBalance, uint256 _userDebtShares, uint256 userDebt_) = _preLiquidate(account);
        // Can liquidate only if the health ratio is below 1
        require(_healthRatio(userDebt_, collatBalance, true) < 1 ether, NotLiquidablePosition());

        (uint256 collatLiquidated, uint256 debtRepaid, uint256 fee, uint256 newUserDebtShares) = _liquidate(
            LiquidateInput({
                account: account,
                collatToLiquidate: collatToLiquidate,
                minUSGOut: minUSGOut,
                newDebtIndex: newDebtIndex,
                _collateralBalance: collatBalance,
                _totalCollateral: totalCollateral,
                _userDebtShares: _userDebtShares,
                _totalDebtShares: totalDebtShares,
                userDebt: userDebt_
            }),
            liquidationCall
        );

        emit Liquidate(account, debtRepaid, newUserDebtShares, fee, collatLiquidated, liquidationCall.router);
    }

```
Here below in _postliquidate it only check the minUSGOut from the swap on zapProxy. which is not slippage protection for liquidation
[function _postliquidate](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Market/abstract/MarketCore.sol#L462)

```javascript
    function _postLiquidate(uint256 collatAmountToLiquidate, uint256 USGToBurn, uint256 minUSGOut, ZapStruct calldata liquidationCall) internal {
        IZappingProxy _zappingProxy = zappingProxy;
        // Withdraw the collateral from the underlying protocol if needed and
        // Transfer it to the caller when there is no liquidator passed in parameter
        // If a liquidator is passed, we send the collateral to the Zapping Proxy that will handle the selling of the collateral.
        _transferCollateralWithdraw(liquidationCall.router != address(0) ? address(_zappingProxy) : msg.sender, collatAmountToLiquidate);
        // When liquidator is not zero, it allows to the LiquidatorProxy to receive the collateral.
        // Then, if needed, liquidator will allow the custom Liquidator to sell the collateral for USG in the same transaction.
        if (liquidationCall.router != address(0)) {
            _zappingProxy.zapProxy(collatToken, usg, minUSGOut, msg.sender, liquidationCall);
        }

        // Burns USG from the sender.
        // The debt has to be on the caller of the transaction.
        // In case a liquidator is passed in parameter, it needs to send it back to the sender of the tx.
        _burnUSG(msg.sender, USGToBurn);
    }
```

### Internal Pre-conditions

- A position becomes liquidatable (health ratio < 1)
- Liquidator performs liquidation, paying debt + fee


### External Pre-conditions

- Volatile market conditions causing collateral value to fluctuate


### Attack Path

1. A liquidator identifies a liquidatable position 
2. The liquidator initiates a liquidation, paying debt + fee
3. Liquidator receive  collateral less than the amount paid as there is fee + debt repayment
4. The transaction succeeds despite being unprofitable for the liquidator
5. The liquidator suffers a loss with no protection mechanism to prevent it


### Impact

- Liquidators can suffer unexpected losses with no protection
- Reduced incentive to perform liquidations, potentially leading to bad debt accumulation
- Protocol stability at risk due to lack of reliable liquidation mechanism
- Liquidators must manually calculate profitability with no protocol-level safeguards
- Both direct and zap liquidations are affected 


### PoC


### Mitigation

Add a slippage protection paramter to liquidate function.





<a id="m-03"></a>
## 🟡 **M-03 - WStable Contract Invariant Break in `isSaving=true` Mode**

### Summary

The `WStable` contract breaks the 1:1 invariant between vault shares and WStable tokens when using the `isSaving=true` mode. When yield accrues in the underlying ERC4626 vault between mint and burn operations, users permanently lose a portion of their vault shares, with the loss percentage directly proportional to the yield accrual.



### Root Cause


The root cause is an asymmetric conversion logic between the `mint` and `burn` functions when `isSaving=true`, specifically when user shares have already accrued yield:

1. In [mint(amountIn, receiver, true)](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Tokens/WStable.sol#L44):
   - User provides vault shares (`amountIn`) that have already accrued yield
   - Contract converts these yield-bearing shares to assets using `previewMint(amountIn)`
   - User receives  WStable tokens equal to the asset value(as asset value is more then shares already), capturing the accrued yield

2. In [burn(amount, receiver, true)](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Tokens/WStable.sol#L80):
   - User provides WStable tokens (`amount`) representing assets
   - Contract converts assets back to shares using `previewWithdraw(amount)`
   - User receives vault shares

When additional yield accrues between these operations, the share-to-asset ratio increases further, causing users to receive fewer shares than they initially deposited. This asymmetric conversion creates a permanent loss of shares for users, as the contract fails to account for the fact that the user's original shares already had accrued yield at the time of deposit.



Invariant from README : `Users are always able to withdraw 1:1 their deposits NB : This one is not completely true. Because of rounding, it can even be false. The consequence of this is that the last user to withdraw its WStable will not be able to burn everything but everything - numberOfBurnSinceCreation * 1wei. This is mitigated because we'll mint in the WStable few K$ to initiate the associated LP that we'll never remove. So we have a lot of room before this error occurs.`

### Internal Pre-conditions

- User must use the `isSaving=true` mode in both `mint` and `burn` functions
- The user's shares must have already accrued some yield before deposit
- Additional yield must accrue in the vault between the user's mint and burn operations


### External Pre-conditions

.

### Attack Path

1. User has vault shares that have already accrued yield (ratio 1:1.1)
   - Each share is worth 1.1 assets due to previous yield accrual

2. User deposits these yield-bearing vault shares using `mint(shares, user, true)`
   - User transfers `X` vault shares to the contract
   - Contract calculates asset value: `assets = vault.previewMint(X)` = `X * 1.1`
   - User receives `X * 1.1` amount of WStable tokens

3. Additional yield accrues in the underlying vault (this happens naturally over time)
   - Share-to-asset ratio increases from 1:1.1 to 1:1.2 (where each share is now worth 1.2 assets)

4. User burns WStable tokens using `burn(assets, user, true)`
   - User burns `X * 1.1` amount of WStable tokens
   - Contract calculates share value: `shares = vault.previewWithdraw(X * 1.1)` = `(X * 1.1) / 1.2` = `X * 0.9167`
   - User receives `X * 0.9167` amount of vault shares, which is less than the original `X`

5. Result: User has permanently lost vault shares (8.33% loss)


### Impact

- **Loss of user funds**: Users permanently lose a portion of their vault shares proportional to the yield accrual
- In our test scenario, a user lost 8.33% of their shares when the share-to-asset ratio changed from 1:1.1 to 1:1.2
- This issue affects all users who use the `isSaving=true` mode, which is specifically designed for share-based operations


### PoC

Place this file at **WStables** folder of test and run this command to run test ` forge test --mt "test_InvariantBreak_Scenario" -vv`

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../contexts/MarketDeploymentContext.sol";


contract wUSDE_InvariantBreak is MarketDeploymentContext {
    IERC20 stable = AddrClassicERC20.USDe;
    IERC4626 saving = AddrERC4626.sUSDe;

  
    function test_InvariantBreak_Scenario() external {
        
        vm.startPrank(address(this));
        deal(address(stable), address(this), 10000 ether);
        stable.approve(address(saving), 10000 ether);
        saving.deposit(10000 ether, address(this)); // Get shares at 1:1 ratio
        vm.stopPrank();

        // Step 2: Accrue yield to create exactly 1 : 1.1 ratio
        uint256 currentShares = saving.totalSupply();
        uint256 targetAssetsFor11 = (currentShares * 11) / 10; // 1.1 ratio
        console.log("currentShares : ", currentShares);
        console.log("targetAsetsFor11 : ", targetAssetsFor11);
        deal(address(stable), address(saving), targetAssetsFor11);
        skip(1 days);

        uint256 ratio11 = saving.previewRedeem(1 ether);
        console.log("After first yield: 1 share = %s assets (exactly 1:1.1 ratio)", ratio11);
        
        // Verify we have approximately 1.1 ratio 
        assertApproxEqRel(ratio11, 1100000000000000000, 1e16, "Ratio should be approximately 1.1");

        // Step 3: Giving user 1000 vault shares (now at 1:1.1 ratio)
        uint256 vaultShares = 1000 ether;
        vm.startPrank(address(this));
        saving.transfer(usr1, vaultShares);
        vm.stopPrank();

        uint256 initialShares = saving.balanceOf(usr1);
        console.log("User gets 1000 vault shares (worth %s assets at 1:1.1 ratio)", saving.previewRedeem(initialShares));

        // Step 4: User deposits 1000 vault shares using WStable contract
        vm.startPrank(usr1);
        saving.approve(address(wUSDE), vaultShares);
        wUSDE.mint(vaultShares, usr1, true);
        vm.stopPrank();

        uint256 wStableReceived = wUSDE.balanceOf(usr1);
        console.log("WStable tokens received: %s", wStableReceived);
        console.log("Expected: 1000 * 1.1 = 1100 (exactly 1100000000000000000000)");
        
        assertApproxEqRel(wStableReceived, 1100000000000000000000, 1e16, "Should receive approximately 1100 WStable tokens");

        // Step 5: Accrue more yield to create 1:1.2 ratio
        uint256 targetAssetsFor12 = (saving.totalSupply() * 12) / 10; // 1.2 ratio
        console.log("targetAssetsFor12: " , targetAssetsFor12);
        deal(address(stable), address(saving), targetAssetsFor12);
        skip(1 days);

        uint256 ratio12 = saving.previewRedeem(1 ether);
        console.log("After second yield: 1 share = %s assets (exactly 1:1.2 ratio)", ratio12);
        
        assertApproxEqRel(ratio12, 1200000000000000000, 1e16, "Ratio should be approximately 1.2");

        // Step 6: User burns WStable tokens using WStable contract
        vm.startPrank(usr1);
        wUSDE.burn(wStableReceived, usr1, true);
        vm.stopPrank();

        uint256 finalShares = saving.balanceOf(usr1);
        uint256 sharesLost = initialShares - finalShares;
        uint256 lossPercentage = (sharesLost * 100) / initialShares;
        
        console.log("Final user vault shares: %s", finalShares);
        console.log("Expected: 1100 / 1.2 = 916.67 (exactly 916666666666666666667)");
        console.log("Shares lost: %s", sharesLost);
        console.log("Loss percentage: %s%%", lossPercentage);
        console.log("Expected loss: 83.33 shares (8.33%%)");
        
        // Verifying we get approximately 916.67 shares back 
        assertApproxEqRel(finalShares, 916666666666666666667, 1e16, "Should receive approximately 916.67 shares");
        assertApproxEqRel(sharesLost, 83333333333333333333, 1e16, "Should lose approximately 83.33 shares");

        // The invariant is broken: user deposited more shares than they got back
        assertLt(finalShares, initialShares, "User should have fewer shares than they started with");
        assertGt(sharesLost, 0, "User should have lost shares due to invariant break");
        assertGt(lossPercentage, 5, "Loss should be significant (>5%) to clearly demonstrate the issue");
        
        console.log("INVARIANT BROKEN: Deposited %s shares, got back %s shares", initialShares, finalShares);
    }
}

```

**Output of test:**
```javascript 

Ran 1 test for test/unit/WStables/wUSDE_InvariantBreak.t.sol:wUSDE_InvariantBreak
[PASS] test_InvariantBreak_Scenario() (gas: 731009)
Logs:
  currentShares :  4404337623717191315390233149
  targetAsetsFor11 :  4844771386088910446929256463
  After first yield: 1 share = 1099999999999999999 assets (exactly 1:1.1 ratio)
  User gets 1000 vault shares (worth 1099999999999999999999 assets at 1:1.1 ratio)
  WStable tokens received: 1100000000000000000000
  Expected: 1000 * 1.1 = 1100 (exactly 1100000000000000000000)
  targetAssetsFor12:  5285205148460629578468279778
  After second yield: 1 share = 1199999999999999999 assets (exactly 1:1.2 ratio)
  Final user vault shares: 916666666666666666667
  Expected: 1100 / 1.2 = 916.67 (exactly 916666666666666666667)
  Shares lost: 83333333333333333333
  Loss percentage: 8%
  Expected loss: 83.33 shares (8.33%)
  INVARIANT BROKEN: Deposited 1000000000000000000000 shares, got back 916666666666666666667 shares

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.34s (5.24ms CPU time)
```


### Mitigation

**Share-Based Accounting**: Track shares instead of assets when `isSaving=true`



---
<a id="m-04"></a>
## 🟡 **M-04 - Liquidation fee calculated on entire repayment amount instead of liquidator profit**

### Summary

The liquidation fee in Tangent protocol is incorrectly calculated based on the entire debt amount being repaid, rather than the liquidator's profit. This design flaw makes many liquidations unprofitable, discouraging liquidators and potentially leading to protocol insolvency due to accumulation of bad debt.

same issue on [Sentiment V2 Contest on Sherlock](https://github.com/sherlock-audit/2024-08-sentiment-v2-judging/issues/91)


### Root Cause

In the [_liquidate](https://github.com/sherlock-audit/2025-08-usg-tangent/blob/main/tangent-contracts/src/USG/Market/abstract/MarketCore.sol#L408) function of `MarketCore.sol`, the liquidation fee is calculated as a percentage of the entire debt amount being repaid, regardless of the liquidator's actual profit:

```javascript
 function _liquidate(LiquidateInput memory liquidateInput, ZapStruct calldata liquidateCall) internal returns (uint256, uint256, uint256, uint256) {
        uint256 collatAmountToLiquidate = liquidateInput.collatToLiquidate;

        _verifyCollatInputNotZero(liquidateInput.collatToLiquidate);

        uint256 debtSharesToRemove;
        uint256 USGToRepay;

        // Liquidate all
        if (collatAmountToLiquidate >= liquidateInput._collateralBalance) {
            collatAmountToLiquidate = liquidateInput._collateralBalance;
            USGToRepay = liquidateInput.userDebt;
            debtSharesToRemove = liquidateInput._userDebtShares;
        }
        // Liquidate partial
        else {
            USGToRepay = (collatAmountToLiquidate * liquidateInput.userDebt) / liquidateInput._collateralBalance;
            debtSharesToRemove = _convertToShares(USGToRepay, liquidateInput.newDebtIndex);

            // Ensure that the remaining debt is bigger than a minimum in order to leave profitable liquidation
            _verifyMinimumDebt(liquidateInput.userDebt - USGToRepay);
        }

        uint256 newUserDebtShares = liquidateInput._userDebtShares - debtSharesToRemove;
        // Modify the collateral balance, the user debt and the total debt
        _updateCollatAndDebts(
            liquidateInput.account,
            liquidateInput._collateralBalance - collatAmountToLiquidate,
            liquidateInput._totalCollateral - collatAmountToLiquidate,
            newUserDebtShares,
            liquidateInput._totalDebtShares - debtSharesToRemove
        );

---->>        uint256 fee = _mulDiv(USGToRepay, liquidationFee, DENOMINATOR);

        _postLiquidate(collatAmountToLiquidate, USGToRepay + fee, liquidateInput.minUSGOut, liquidateCall);

        if (fee != 0) {
            _mintUSG(usg, controlTower.feeTreasury(), fee);
        }

        return (collatAmountToLiquidate, USGToRepay, fee, newUserDebtShares);
    }

```

This means liquidators must pay a fee even when there is minimal or no profit, making liquidations financially unattractive or even resulting in losses.

### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. A position becomes liquidatable
2. A liquidator attempts to liquidate the position
3. The liquidator must pay: debt amount + liquidation fee 
4. The liquidator receives: collateral worth slightly more than the debt
5. If the collateral value minus debt is less than the fee, the liquidator loses money
6. Rational liquidators avoid such unprofitable liquidations
7. Bad debt accumulates in the protocol as underwater positions remain unliquidated


### Impact

- Liquidators lose money on positions where profit margin < liquidation fee
- Reduced incentive to perform liquidations, especially for positions with collateral value close to debt
- Potential accumulation of bad debt in the protocol
- Protocol insolvency risk due to unliquidated underwater positions


### PoC

_No response_

### Mitigation

Calculate the liquidation fee based on the liquidator's profit rather than the entire repayment(debt) amount
