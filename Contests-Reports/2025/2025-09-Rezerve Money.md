## Table of Contents

- 🔴 **H-01.** [Front-Running Attack in Position Trading Allows Theft of Buyer Funds](#h-01)
- 🔴 **H-02.** [Anyone can increase a position's declared value, causing fund loss and DoS attack](#h-02)
- 🔴 **H-03.** [Incorrect Conversion Price Calculation in AppConvertibles Contract](#h-03)
- 🟡 **M-01.** [Refunded ETH Will Be Stuck in BridgeL2 Contract](#m-01)
- 🟡 **M-02.** [Incorrect Initialization Order in BridgeL2 Constructor Breaks Cross-Chain Communication](#m-02)

---

<a id="h-01"></a>
## 🔴 **H-01 - Front-Running Attack in Position Trading Allows Theft of Buyer Funds**

### Summary

A position owner can front-run a buyer's transaction to extract nearly all value from a position while still receiving the full purchase price(declaredValue). This attack allowing a malicious seller to split their position to retain most tokens, then artificially inflate the declared value back to the original amount. When the buyer's transaction executes, they pay full price but receive a nearly worthless position.

### Root Cause


 The [splitPosition](https://github.com/sherlock-audit/2025-08-rezerve-money/blob/main/code/contracts/core/AppStaking.sol#L370) function correctly splits both values proportionally, but `increaseAmount` allows arbitrary increases to declared value without requiring proportional token increases. The `buyPosition` function only checks the declared value when determining price, not considering whether this value reasonably reflects the actual tokens in the position.


### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. Alice owns position tokenId 1 with 1000 RZR and declared value of 1300 RZR
2. Bob submits a transaction to call `buyPosition(1)` with 1300 RZR approved
3. Alice sees Bob's transaction in the mempool and front-runs with:
   - Calls `splitPosition(1, 0.01e18, alice)` to split 99% of tokens to a new position, leaving only 10 RZR in tokenId 1
   - Position 1 now has 10 RZR with declared value of 13 RZR (1% of original)
   - Calls `increaseAmount(1, 0, 1287)` to increase declared value back to 1300 RZR
4. Bob's transaction executes, transferring his full 1300 RZR to Alice
5. Bob receives tokenId 1 containing only 10 RZR instead of the expected 1000 RZR


### Impact

1. **Direct financial loss**: Buyers lose nearly all of their investment (paying 1300 RZR for a 10 RZR position)
2. **Market breakdown**: The position trading system becomes unusable as rational buyers will avoid purchasing positions
3. **Protocol reputation damage**: Users will lose trust in the protocol's economic mechanisms


### PoC

_No response_

### Mitigation

Add a check in `buyPosition` to ensure the price is reasonable given the position's token amount or add a paramter of minOut so buyer can specify that how much is he going  to receive


<a id="h-02"></a>
## 🔴 **H-02 - Anyone can increase a position's declared value, causing fund loss and DoS attack**

### Summary

The `increaseAmount` function in `AppStaking.sol` allows any user (not just the position owner) to arbitrarily increase the declared value of any staking position. This creates two severe vulnerabilities: (1) position owners can lose their staked funds through excessive taxation, and (2) the `buyPosition` function can be DoS as the DeclaredValue is very big so no one will buy the position.


### Root Cause

The [increaseAmount](https://github.com/sherlock-audit/2025-08-rezerve-money/blob/main/code/contracts/core/AppStaking.sol#L312) function lacks proper access control. It doesn't verify that `msg.sender` is the owner of the position being modified, allowing anyone to call this function on any position. This is particularly dangerous because increasing the declared value requires no token payment but dramatically increases the position's tax rate and DeclaredValue.


### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. Attacker identifies a target position (either to drain funds or prevent purchase)
2. Attacker calls `increaseAmount` with:
   - `tokenId` = target position ID
   - `additionalAmount` = 0 (no tokens required)
   - `addtionalDeclaredValue` = extremely large value (malicous user consider to only remain position.amount > 0 after tax after this malicous tx so to pass the last check of increaseAmount function)
3. The position's `taxPerSecond` is dramatically increased
4. For fund draining:
   - When position owner interacts with their position, `_updateReward(tokenId)` is called
   - This triggers `_collectStreamingTaxInternal`, which calculates a massive tax amount
   - The tax drains most or all of the position's staked amount
5. For DoS attack:
   - The position's `declaredValue` becomes astronomically high
   - Any buyer attempting to use `buyPosition` must pay this declared value
   - This makes the position effectively impossible to purchase


### Impact

1. **Financial Loss**: Position owners can lose their entire staked amount through excessive taxation when they interact with their position. Since `_updateReward` is called in most position interactions, users can't avoid this tax.

2. **Market Disruption**: The `buyPosition` function can be rendered unusable for targeted positions because the declaredValue is so much big then position.amount so no one will buy this position. Same attack can be done for any position wihtout any loss for malicous user(attacker). 


### PoC

_No response_

### Mitigation

Add proper access control to ensure only the position owner can increase the declared value


<a id="h-03"></a>
## 🔴 **H-03 - Incorrect Conversion Price Calculation in AppConvertibles Contract**

### Summary

The `AppConvertibles.sol` contract contains a vulnerability in the `getOfferings` function that incorrectly calculates the conversion price and amount when staking tokens. The function applies the premium to the loan token's price instead of the RZR token's price, resulting in economically absurd conversion rates, especially for high-value tokens like WBTC. This causes users staking high-value tokens to receive virtually no RZR tokens upon conversion, leading to significant financial loss.


### Root Cause

The root cause is a fundamental design flaw in the [getOfferings](https://github.com/sherlock-audit/2025-08-rezerve-money/blob/main/code/contracts/core/AppConvertibles.sol#L361) function ([lines 376 and 377](https://github.com/sherlock-audit/2025-08-rezerve-money/blob/main/code/contracts/core/AppConvertibles.sol#L376C7-L377C70)):

```solidity
conversionPrice = price * (1e18 + premium) / 1e18;
conversionAmount = amountLoanScaled * 1e18 / conversionPrice;
```

The function incorrectly uses the loan token's price (`price`) as the base for calculating the conversion price, instead of the RZR token's price. Additionally, it fails to account for the USD value of the staked tokens when calculating the conversion amount.


### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. A user stakes a high-value token like WBTC (1 WBTC = $50,000) with a 30-day lock duration
2. The `getOfferings` function calculates the conversion price as $50,000 * 1.2959 = $64,795 per RZR
3. The conversion amount is calculated as 1e18 / 64795e18 = 0.000015 RZR
4. The user later attempts to convert their position, expecting to receive RZR tokens proportional to their $50,000 stake
5. The user receives only 0.000015 RZR tokens, worth virtually nothing compared to their initial stake


### Impact

1. **Massive Value Loss**: Users staking high-value tokens like WBTC would lose nearly all of their investment value upon conversion, receiving only a tiny fraction of the expected RZR tokens.

2. **Economic Inconsistency**: The same USD value in different tokens yields drastically different RZR amounts:
   - $50,000 in WBTC → 0.000015 RZR (virtually nothing)
   - $1,000 in DAI → 771 RZR (reasonable amount)

3. **Protocol Instability**: The fundamental economic model of the protocol is broken, undermining trust and potentially leading to protocol failure.


### PoC


The vulnerability can be demonstrated with the following test that compares staking WBTC vs DAI, to run the test `forge test --match-test "test_Stake_BothTokens_30Days" -vv`:

```javascript
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./BaseTest.sol";
import "../../contracts/core/AppConvertibles.sol";
import "../../contracts/mocks/MockOracleV2.sol";
import "../../contracts/mocks/MockWBTC.sol";
import "../../contracts/mocks/MockERC20.sol";

contract CombinedStakeTest is BaseTest {
    AppConvertibles public convertibles;
    MockWBTC public wbtcToken;
    MockERC20 public daiToken;
    MockOracleV2 public mockTwapOracle;
    MockOracleV2 public mockWBTCOracle;
    MockOracleV2 public mockDAIOracle;

    uint256 public constant LOCK_DURATION = 30 days;

    function setUp() public {
        setUpBaseTest();

        vm.startPrank(owner);

        // Deploy WBTC token with 8 decimals
        wbtcToken = new MockWBTC();

        // Deploy DAI token with 18 decimals (standard DAI)
        daiToken = new MockERC20("Dai Stablecoin", "DAI");

        // Deploy mock TWAP oracle
        mockTwapOracle = new MockOracleV2(0, 1e18, address(app)); // RZR price = $1

        // Deploy separate oracles for each token
        mockWBTCOracle = new MockOracleV2(0, 50000e18, address(wbtcToken)); // WBTC price = $50,000
        mockDAIOracle = new MockOracleV2(0, 1e18, address(daiToken)); // DAI price = $1

        // Register WBTC in the AppOracle with $50,000 price
        appOracle.updateOracle(address(wbtcToken), address(mockWBTCOracle), 3600);
        
        // Register DAI in the AppOracle with $1 price
        appOracle.updateOracle(address(daiToken), address(mockDAIOracle), 3600);

        // Deploy AppConvertibles
        convertibles = new AppConvertibles();
        convertibles.initialize(address(app), address(appOracle), address(mockTwapOracle), address(authority));

        // Enable tokens with premium values
        convertibles.enableToken(wbtcToken, 0.1e18, 0.3e18, 0.05e18, 0.15e18, 10000000e18); // 10-30% premium, 5-15% interest
        convertibles.enableToken(daiToken, 0.1e18, 0.3e18, 0.05e18, 0.15e18, 10000000e18); // 10-30% premium, 5-15% interest

        // Add convertibles to policy
        authority.addPolicy(address(convertibles));

        vm.stopPrank();
    }

    function test_Stake_BothTokens_30Days() public {
        console.log("=== Combined Stake Test ===");
        console.log("Testing both WBTC and DAI with 30 days lock duration");

        // ===== WBTC STAKE TEST =====
        uint256 wbtcAmount = 1e8; // 1 WBTC (8 decimals)
        
        console.log("=== WBTC Stake Test ===");
        console.log("Amount:", wbtcAmount, "WBTC");
        console.log("Lock Duration:", LOCK_DURATION);
        
        // Mint WBTC to user1
        wbtcToken.mint(user1, wbtcAmount);
        
        // Stake WBTC
        vm.startPrank(user1);
        wbtcToken.approve(address(convertibles), wbtcAmount);
        
        (uint256 wbtcTokenId, uint256 wbtcConversionPrice, uint256 wbtcConversionAmount, uint256 wbtcFixedInterestRate, uint256 wbtcFixedInterestRateAmount, uint256 wbtcStakingPower) = 
            convertibles.stake(wbtcToken, wbtcAmount, LOCK_DURATION, user1);

        console.log("=== After WBTC Stake ===");
        console.log("Token ID:", wbtcTokenId);
        console.log("Conversion Price:", wbtcConversionPrice);
        console.log("Conversion Amount:", wbtcConversionAmount);
        console.log("Fixed Interest Rate:", wbtcFixedInterestRate);
        console.log("Fixed Interest Rate Amount:", wbtcFixedInterestRateAmount);
        console.log("Staking Power:", wbtcStakingPower);
        console.log("User1 WBTC balance:", wbtcToken.balanceOf(user1));
        console.log("Contract WBTC balance:", wbtcToken.balanceOf(address(convertibles)));

        // WBTC Assertions
        assertEq(wbtcTokenId, 1);
        assertEq(convertibles.lastId(), 1);
        assertGt(wbtcConversionPrice, 0);
        assertGt(wbtcConversionAmount, 0);
        assertGt(wbtcFixedInterestRate, 0);
        assertEq(wbtcFixedInterestRateAmount, 0);
        assertGt(wbtcStakingPower, 0);
        assertEq(convertibles.ownerOf(wbtcTokenId), user1);

        // ===== DAI STAKE TEST =====
        uint256 daiAmount = 1000e18; // 1000 DAI (18 decimals)

        console.log("=== DAI Stake Test ===");
        console.log("Amount:", daiAmount, "DAI");
        console.log("Lock Duration:", LOCK_DURATION);

        // Mint DAI to user2
        daiToken.mint(user2, daiAmount);
        
        // Stake DAI
        vm.startPrank(user2);
        daiToken.approve(address(convertibles), daiAmount);
        (uint256 daiTokenId, uint256 daiConversionPrice, uint256 daiConversionAmount, uint256 daiFixedInterestRate, uint256 daiFixedInterestRateAmount, uint256 daiStakingPower) = 
            convertibles.stake(daiToken, daiAmount, LOCK_DURATION, user2);
        vm.stopPrank();

        console.log("=== After DAI Stake ===");
        console.log("Token ID:", daiTokenId);
        console.log("Conversion Price:", daiConversionPrice);
        console.log("Conversion Amount:", daiConversionAmount);
        console.log("Fixed Interest Rate:", daiFixedInterestRate);
        console.log("Fixed Interest Rate Amount:", daiFixedInterestRateAmount);
        console.log("Staking Power:", daiStakingPower);
        console.log("User2 DAI balance:", daiToken.balanceOf(user2));
        console.log("Contract DAI balance:", daiToken.balanceOf(address(convertibles)));

        // DAI Assertions
        assertEq(daiTokenId, 2);
        assertEq(convertibles.lastId(), 2);
        assertGt(daiConversionPrice, 0);
        assertGt(daiConversionAmount, 0);
        assertGt(daiFixedInterestRate, 0);
        assertEq(daiFixedInterestRateAmount, 0);
        assertGt(daiStakingPower, 0);
        assertEq(convertibles.ownerOf(daiTokenId), user2);
        
        // Final assertions
        console.log("=== Final State ===");
        console.log("Total convertible:", convertibles.totalConvertible());
        console.log("Last ID:", convertibles.lastId());
        console.log("WBTC total staked:", convertibles.totalStaked(address(wbtcToken)));
        console.log("DAI total staked:", convertibles.totalStaked(address(daiToken)));
        
        assertEq(convertibles.lastId(), 2);
        assertEq(convertibles.totalStaked(address(wbtcToken)), 1e8);
        assertEq(convertibles.totalStaked(address(daiToken)), 1000e18);
    }
}
```
MockWBTC contract:
```javascript
// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./MockERC20.sol";

contract MockWBTC is MockERC20 {
    constructor() MockERC20("Wrapped Bitcoin", "WBTC") {
        // WBTC has 8 decimals, not 18
        decimals_ = 8;
    }

    function decimals() public view override returns (uint8) {
        return 8;
    }
}

```
**Test Output:**
```javascript

Ran 1 test for test/foundry/CombinedStakeTest.t.sol:CombinedStakeTest
[PASS] test_Stake_BothTokens_30Days() (gas: 1248707)
Logs:
  === Combined Stake Test ===
  Testing both WBTC and DAI with 30 days lock duration
  === WBTC Stake Test ===
  Amount: 100000000 WBTC
  Lock Duration: 2592000
  price 50000000000000000000000
  getOfferings 0xa217C4fd524c3f2BABf88F6ebA577E64D5DE3752 100000000 2592000
  amountLoanScaled 1000000000000000000
  price 50000000000000000000000
  Premuium:  295890410958904109
  Staking Power:  20547945205479452
  === After WBTC Stake ===
  Token ID: 1
  Conversion Price: 64794520547945205450000
  Conversion Amount: 15433403805496
  Fixed Interest Rate: 52054794520547945
  Fixed Interest Rate Amount: 0
  Staking Power: 20547945205479452
  User1 WBTC balance: 0
  Contract WBTC balance: 100000000
  === DAI Stake Test ===
  Amount: 1000000000000000000000 DAI
  Lock Duration: 2592000
  price 1000000000000000000
  getOfferings 0xD474a3B8125Bf812917f5F7D61EdaBE876CaE3ef 1000000000000000000000 2592000
  amountLoanScaled 1000000000000000000000
  price 1000000000000000000
  Premuium:  295890410958904109
  Staking Power:  20547945205479452054
  === After DAI Stake ===
  Token ID: 2
  Conversion Price: 1295890410958904109
  Conversion Amount: 771670190274841437982
  Fixed Interest Rate: 52054794520547945
  Fixed Interest Rate Amount: 0
  Staking Power: 20547945205479452054
  User2 DAI balance: 0
  Contract DAI balance: 1000000000000000000000
  === Final State ===
  Total convertible: 771670205708245243478
  Last ID: 2
  WBTC total staked: 100000000
  DAI total staked: 1000000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 44.76ms (7.16ms CPU time)
```


### Mitigation


The vulnerability should be fixed by modifying the `getOfferings` function to:


```diff
  function getOfferings(IERC20 loanToken, uint256 amountLoan, uint256 lockDuration)
        public
        view
        returns (uint256 conversionPrice, uint256 conversionAmount, uint256 fixedInterestRate)
    {
        console.log("getOfferings", address(loanToken), amountLoan, lockDuration);
        uint256 amountLoanScaled = _scaleAmount(loanToken, amountLoan);
        console.log("amountLoanScaled", amountLoanScaled);
        uint256 price = _getPrice(loanToken);
        console.log("price", price);
        Variables memory _vars = _variables[loanToken];

+         uint256 rzrPrice = _getTwapPrice();
        // console.log("rzrPrice, ", rzrPrice);

        // calculate the conversion premium; longer duration means lower premium
        uint256 premium =
            _scale(_vars.maxConversionPremium, _vars.minConversionPremium, MAX_LOCK_DURATION - lockDuration);
-        conversionPrice = price * (1e18 + premium) / 1e18;
-        conversionAmount = amountLoanScaled * 1e18 / conversionPrice;
+         conversionPrice = rzrPrice * (1e18 + premium) / 1e18;
+         uint256 usdValue = amountLoanScaled * price / 1e18;
+         conversionAmount = usdValue * 1e18 / conversionPrice;


        // calculate the fixed interest rate; longer duration means higher fixed interest rate
        fixedInterestRate = _scale(_vars.maxFixedInterestRate, _vars.minFixedInterestRate, lockDuration);
    }

```

**Test Output After Fix:**
```javascript
Ran 1 test for test/foundry/CombinedStakeTest.t.sol:CombinedStakeTest
[PASS] test_Stake_BothTokens_30Days() (gas: 1267363)
Logs:
  === Combined Stake Test ===
  Testing both WBTC and DAI with 30 days lock duration
  === WBTC Stake Test ===
  Amount: 100000000 WBTC
  Lock Duration: 2592000
  price 50000000000000000000000
  getOfferings 0xa217C4fd524c3f2BABf88F6ebA577E64D5DE3752 100000000 2592000
  amountLoanScaled 1000000000000000000
  price 50000000000000000000000
  Premuium:  295890410958904109
  Staking Power:  20547945205479452
  === After WBTC Stake ===
  Token ID: 1
  Conversion Price: 1295890410958904109
  Conversion Amount: 38583509513742071899144
  Fixed Interest Rate: 52054794520547945
  Fixed Interest Rate Amount: 0
  Staking Power: 20547945205479452
  User1 WBTC balance: 0
  Contract WBTC balance: 100000000
  === DAI Stake Test ===
  Amount: 1000000000000000000000 DAI
  Lock Duration: 2592000
  price 1000000000000000000
  getOfferings 0xD474a3B8125Bf812917f5F7D61EdaBE876CaE3ef 1000000000000000000000 2592000
  amountLoanScaled 1000000000000000000000
  price 1000000000000000000
  Premuium:  295890410958904109
  Staking Power:  20547945205479452054
  === After DAI Stake ===
  Token ID: 2
  Conversion Price: 1295890410958904109
  Conversion Amount: 771670190274841437982
  Fixed Interest Rate: 52054794520547945
  Fixed Interest Rate Amount: 0
  Staking Power: 20547945205479452054
  User2 DAI balance: 0
  Contract DAI balance: 1000000000000000000000
  === Final State ===
  Total convertible: 39355179704016913337126
  Last ID: 2
  WBTC total staked: 100000000
  DAI total staked: 1000000000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 45.86ms (7.93ms CPU time)
```
**Analysis of Test Output**
The test results confirm that the fix is working correctly:

### WBTC (8 decimals, $50,000):
- **Price**: 50000000000000000000000 (50000e18 = $50,000)
- **Premium**: 295890410958904109 (29.59%)
- **Conversion Price**: 1295890410958904109 (≈$1.30 per RZR)
- **Conversion Amount**: 38583509513742071899144 (≈38,583 RZR)

### DAI (18 decimals, $1,000):
- **Price**: 1000000000000000000 (1e18 = $1)
- **Premium**: 295890410958904109 (29.59%)
- **Conversion Price**: 1295890410958904109 (≈$1.30 per RZR)
- **Conversion Amount**: 771670190274841437982 (≈771.67 RZR)


<a id="m-01"></a>
## 🟡 **M-01 - Refunded ETH Will Be Stuck in BridgeL2 Contract**

### Summary

The BridgeL2 contract has a design flaw where it can receive ETH through its `receive()` function and LayerZero refunds but provides no mechanism to withdraw or utilize this accumulated ETH. This results in permanently locked ETH in the contract, causing a gradual loss of value for the protocol.


### Root Cause

BridgeL2 contract can't withdraw ETH that is refunded by LayerZero, it will be stuck permanetly in this contract.In [flushToL1()](https://github.com/sherlock-audit/2025-08-rezerve-money/blob/main/code/contracts/periphery/bridge/BridgeL2.sol#L72) function the refund address is address(this) but the BridgeL2 (means address(this)) doesn't have any way to use or withdraw this ETH which cause stuck of ETH forever.


```javascript
   function flushToL1() external payable onlyExecutor {
        uint256 balance = IERC20(address(rzr)).balanceOf(address(this));
        rzr.send{value: msg.value}(
            SendParam({
                dstEid: MAINNET_EID,
                to: bytes32(uint256(uint160(BRIDGE_MAINNET))),
                amountLD: balance,
                minAmountLD: balance,
                extraOptions: "",
                composeMsg: "",
                oftCmd: ""
            }),
            MessagingFee({nativeFee: msg.value, lzTokenFee: 0}),
  @>>>          address(this)
        );
    }
```


### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

This is not an attack vector but a design flaw:
1. Executor calls `flushToL1()` with `msg.value` ETH for fees
2. LayerZero calculates actual fee needed, which is less than `msg.value`
3. Excess ETH is refunded to `address(this)` (the BridgeL2 contract)
4. ETH accumulates in the contract with no way to recover or use it
5. Over time, significant value becomes permanently locked


### Impact

- **Financial Loss**: ETH becomes permanently locked in the contract
- **Value Leakage**: Protocol gradually loses value that could be used for operations
- **Inefficiency**: Executor pay more gas than necessary as accumulated ETH cannot be utilized


### PoC

_No response_

### Mitigation

Change the refund address to msg.sender(Executor)


<a id="m-02"></a>
## 🟡 **M-02 - Incorrect Initialization Order in BridgeL2 Constructor Breaks Cross-Chain Communication**

### Summary

The `BridgeL2` contract contains a  initialization order problem in its [constructor](https://github.com/sherlock-audit/2025-08-rezerve-money/blob/main/code/contracts/periphery/bridge/BridgeL2.sol#L45). The contract calls `_setPeer(READ_CHANNEL, ...)` before initializing `READ_CHANNEL` with the provided `_readChannel` parameter. This causes the peer to be set for channel `0` (the default value) instead of the intended channel, breaking the cross-chain message routing mechanism.


### Root Cause

The root cause is an incorrect ordering of operations in the constructor. The `READ_CHANNEL` state variable is used before it is initialized with its intended value. As default value for uint is 0 so `_setPeer` is called with channel `0` instead of the intended `_readChannel` value.


### Internal Pre-conditions

.

### External Pre-conditions

.

### Attack Path

1. The contract is deployed with a specific `_readChannel` value
2. During construction, `_setPeer` is called with channel `0` instead of `_readChannel`
3. Later, when `syncRate()` is called, messages are sent to `READ_CHANNEL` (which is set to `_readChannel`)
4. However, the contract is only configured to receive on channel `0`
5. This mismatch causes cross-chain messages to be undeliverable or ignored


### Impact

- Rate synchronization from L1 to L2 will fail
- Cross-chain messages will not be properly routed
- The bridge contract becomes non-functional for its primary purpose
- The entire cross-chain integration between L1 and L2 is compromised


### PoC

_No response_

### Mitigation

Fix the initialization order in the constructor to ensure `READ_CHANNEL` is set before calling `_setPeer`
