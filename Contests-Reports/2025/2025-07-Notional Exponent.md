## Table of Contents

- 🟡 **M-01.** [Lack of minimum deposit check](#m-01)
- 🟡 **M-02.** [USDT Compatibility Issue in `_enterOrMigrate` Function Prevents Position Entry](#m-02)

---

<a id="m-01"></a>
## 🟡 **M-01 - Lack of minimum deposit check**

### Summary

Notional Exponent protocol lacks a minimum position size check in the `enterPosition` function of the `AbstractLendingRouter` contract, allowing the creation of economically unliquidatable positions that could lead to protocol insolvency.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L79

### Root Cause

The `enterPosition` function in `AbstractLendingRouter` does not enforce a minimum deposit or position size, allowing users to create arbitrarily small positions that may cost more in gas to liquidate than the value that can be recovered.

### Internal Pre-conditions

- The `enterPosition` function in `AbstractLendingRouter` accepts any non-zero deposit amount
- No minimum threshold check exists anywhere in the position creation flow
- The protocol's liquidation mechanism assumes positions are large enough to be economically viable to liquidate

### External Pre-conditions

- Small positions become undercollateralized due to market fluctuations
- Liquidators act rationally and won't perform liquidations that cost more in gas than they can recover

### Attack Path

1. A user creates many small positions through the `enterPosition` function with minimal collateral
2. Market conditions change, making these positions undercollateralized
3. Liquidation would cost more in gas than the potential profit from liquidation
4. Rational liquidators avoid liquidating these positions
5. The protocol accumulates bad debt from these economically unliquidatable positions

### Impact

- Accumulation of bad debt in the protocol
- Protocol resources tied up in positions that cannot be economically liquidated
- Gradual protocol insolvency if many such positions exist over time
- Degradation of the protocol's financial health and sustainability

### PoC

_No response_

### Mitigation

Implement a minimum position size requirement in the `enterPosition` function in `AbstractLendingRouter.sol`.


<a id="m-02"></a>
## 🟡 **M-02 - USDT Compatibility Issue in `_enterOrMigrate` Function Prevents Position Entry**


### Summary

The `_enterOrMigrate` function in AbstractLendingRouter has a compatibility issue with non-standard ERC20 tokens like USDT. In the `else` branch, it uses a direct `approve` call without handling tokens that don't return a boolean value as required by the ERC20 standard.

https://github.com/sherlock-audit/2025-06-notional-exponent/blob/main/notional-v4/src/routers/AbstractLendingRouter.sol#L222

### Root Cause

The root cause is using a standard `ERC20(asset).approve(vault, assetAmount)` call for non-standard tokens like USDT. USDT's `approve` function doesn't return a boolean value as required by the ERC20 standard, causing the call to fail at the ABI level when trying to decode a non-existent return value.

### Internal Pre-conditions

- The contract must be executing the `_enterOrMigrate` function
- The `migrateFrom` parameter must be `address(0)`, triggering the `else` branch
- The `asset` parameter must be a non-standard ERC20 token like USDT that doesn't return a boolean from its `approve` function

### External Pre-conditions

- A user must be attempting to enter a position with USDT or another non-standard ERC20 token
- The transaction must not be a migration (which would use the `checkApprove` function instead)

### Attack Path

1. A user calls `enterPosition` with USDT as the asset
2. The call flows to `_enterPosition` and then to `_enterOrMigrate`
3. Since `migrateFrom` is `address(0)`, execution enters the `else` branch
4. `ERC20(asset).approve(vault, assetAmount)` is called with USDT
5. The USDT approve function executes but doesn't return a boolean value
6. The transaction reverts when trying to decode the non-existent return value

### Impact

- Users cannot enter positions using USDT or other non-standard ERC20 tokens that don't return boolean values from approve
- This effectively blocks a significant portion of the DeFi ecosystem from using the protocol
- The protocol loses potential users and liquidity from USDT, which is one of the largest stablecoins by market cap

### PoC

_No response_

### Mitigation

Replace the direct `approve` call with the `checkApprove`.
