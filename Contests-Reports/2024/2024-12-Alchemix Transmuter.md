## Table of Contents

- 🟡 **M-01.** [Incorrect Asset Valuation Due to Direct Addition of WETH and alETH Balances](#m-01)

---

<a id="m-01"></a>
## 🟡 **M-01 - Incorrect Asset Valuation Due to Direct Addition of WETH and alETH Balances**

### Summary

The strategy incorrectly calculates total assets by directly adding WETH and alETH balances without proper conversion, leading to inaccurate share price calculations and potential accounting issues.

### Vulnerability Details

The vulnerability exists in multiple functions where WETH and alETH balances are added directly:

**1. In `balanceDeployed()`:**

```javascript
1 function balanceDeployed() public view returns (uint256) {
2 @>>>   return transmuter.getUnexchangedBalance(address(this)) +
3            underlying.balanceOf(address(this)) +   // WETH balance
4            asset.balanceOf(address(this));         // alETH balance
5 }
```

**1. In `_harvestAndReport()`:**

```javascript
1 function _harvestAndReport() internal override returns (uint256 _totalAssets) {
2     uint256 unexchanged = transmuter.getUnexchangedBalance(address(this));
3     uint256 underlyingBalance = underlying.balanceOf(address(this));
4 @>>>    _totalAssets = unexchanged + asset.balanceOf(address(this)) + underlyingBalance;
5 }
```

The issue arises because:
1. WETH and alETH have different market values
2. alETH typically trades at a discount to WETH
3. Direct addition assumes 1:1 value which is incorrect

### Impact

1. **Incorrect Total Assets Reporting**
    * Strategy reports inflated/deflated total assets
    * Share price calculations become inaccurate
2. **Example Scenario:**

```javascript
1  Strategy State:
2  - 10 WETH in underlying balance
3  - 15 alETH in asset balance
4  - 20 alETH in unexchanged balance
5  - Market: 1 WETH = 1.05 alETH
6
7  Current Calculation:
8  Total = 10 + 15 + 20 = 45 units
9
10 Correct Calculation:
11 WETH in alETH = 10 * 1.05 = 10.5
12 Total = 10.5 + 15 + 20 = 45.5 units
```

### Tools Used

* Manual Review

### Recommendations

1. **Implement Price Conversion of WETH to alETH:**
2. **Add Price Oracle Integration:**
