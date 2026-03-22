## Table of Contents

- 🟡 **M-01.** [Cross-Chain USDC Decimal Mismatch Leads to Reward Reduction to Almost Zero](#m-01)

---

<a id="m-01"></a>
## 🟡 **M-01 - Cross-Chain USDC Decimal Mismatch Leads to Reward Reduction to Almost Zero**


### Summary

Cashback rewards are calculated using a hardcoded decimal conversion that assumes USDC always has 6 decimals. However, on BNB Chain, USDC has 18 decimals, resulting in users receiving almost zero rewards. This completely breaks the protocol's economic incentives on BNB Chain and renders the cashback system effectively useless.


### Root Cause

The root cause is in the [_convertToUSDCPrecisio](https://github.com/sherlock-audit/2025-09-super-dca/blob/main/super-dca-cashback/src/SuperDCACashback.sol#L184) function which hardcodes a conversion from 18 decimals to 6 decimals by dividing by 1e12:

```javascript
function _convertToUSDCPrecision(uint256 amount) internal pure returns (uint256 convertedAmount) {
    convertedAmount = amount / 1e12;
}
```

This function fails to account for the fact that USDC has different decimal implementations across chains:
- Ethereum, Polygon, Arbitrum, Base, Optimism: 6 decimals
- BNB Chain: 18 decimals
[USDC on BNB chain](https://bscscan.com/address/0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d#readProxyContract#F3)



### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. User creates a DCA trade on BNB Chain with flow rate of 1 token/second (1e18 wei/s)
2. Trade runs for 1 day (86,400 seconds), spending 86,400 tokens
3. User expects 0.5% cashback: 432 USDC
4. When claiming, the conversion happens:
   - 432e18 wei (correct for 18 decimal USDC)
   - Divided by 1e12 → 432e6 wei
   - On BNB Chain, 432e6 wei = 0.000000432 USDC
5. User receives 0.000000432 USDC instead of 432 USDC


### Impact

1. **Business Impact**: Protocol will be non-viable on BNB Chain
2. **Economic Failure**: Users receive almost zero rewards
3. **Protocol Viability**: The cashback incentive system completely fails


### PoC

_No response_

### Mitigation

The _convertToUSDCPrecision function should dynamically determine USDC decimals

