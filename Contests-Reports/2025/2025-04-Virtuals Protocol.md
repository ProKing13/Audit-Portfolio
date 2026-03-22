## Table of Contents

- 🟡 **M-01.** [Lack of Slippage Protection and Deadline Enforcement in `buy` Function](#m-01)
- 🟡 **M-02.** [Lack of Slippage Protection When Adding Liquidity in `_executeApplication` Function](#m-02)

---

<a id="m-01"></a>
## 🟡 **M-01 - Lack of Slippage Protection and Deadline Enforcement in `buy` Function**

**Author:** pro_king · **Severity:** Medium

### Finding description and impact

The `buy` function in the Bonding contract allows users to purchase tokens without any built-in slippage protection or deadline enforcement. This means that users may receive significantly fewer tokens than expected if the price changes between transaction submission and execution, especially during periods of high volatility or if the transaction is delayed. Additionally, without a deadline parameter, transactions can be executed at any time after submission, further increasing the risk of unfavorable execution due to market movements or manipulation.

### Mitigation

* Add Slippage Protection
* Add Deadline Parameter

### Links to affected code

* `Bonding.sol#L318`


<a id="m-02"></a>
## 🟡 **M-02 - Lack of Slippage Protection When Adding Liquidity in `_executeApplication` Function**

**Author:** pro_king · **Severity:** Medium

### Finding description and impact

In the `_executeApplication` function of the `AgentFactoryV4` contract, when adding liquidity to a Uniswap V2 pool for a custom token, the function calls `addLiquidity` with the minimum amounts (`amountAMin` and `amountBMin`) both set to zero. This means the transaction will proceed regardless of how much slippage occurs, potentially resulting in significant value loss if the pool's price moves unfavorably between transaction submission and execution. Users are thus forced to add liquidity without any slippage protection.

### Recommended mitigation steps

* Add Slippage Parameters

### Links to affected code

* `AgentFactoryV4.sol#L205`
