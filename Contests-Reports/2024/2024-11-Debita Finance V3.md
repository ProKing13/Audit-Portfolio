## Table of Contents

- 🔴 **H-01.** [NFTs Can Get Permanently Stuck in buyOrder Contract Due to Incorrect Transfer Destination](#h-01)
- 🟡 **M-02.** [Silent Return in `updateFunds()` Causes Partial State Updates Leading to Incentive Accounting Inconsistencies](#m-02)

---

<a id="h-01"></a>
## 🔴 **H-01 - NFTs Can Get Permanently Stuck in buyOrder Contract Due to Incorrect Transfer Destination**


### Summary
The `buyOrder::sellNFT` function in buyOrder.sol transfers NFTs to the contract address (`address(this)`) instead of the buyer's address (`buyInformation.owner`), potentially leading to permanently stuck NFTs.
https://github.com/sherlock-audit/2024-11-debita-finance-v3/blob/main/Debita-V3-Contracts/contracts/buyOrders/buyOrder.sol#L92

### Root Cause
The function incorrectly transfers veNFT tokens to the contract address instead of the intended buyer's address, creating a risk of NFT loss due to:
1. NFT stuck in contract instead to be transferred to buyer

### Internal Pre-conditions
- Buy order must be active
- Available amount must be greater than 0
- Contract must have proper NFT handling capabilities

### External Pre-conditions
- Seller must own the veNFT
- Seller must have approved the contract
- veNFT must exist and be transferable

### Attack Path
1. Seller calls `sellNFT` with valid receiptID
2. NFT gets transferred to contract address
3. Contract has no mechanism to transfer NFT to actual buyer
4. NFT becomes permanently stuck in contract
5. If contract self-destructs, NFT becomes permanently inaccessible

### Impact
- Permanent loss of valuable NFTs
- Users lose access to their veNFT tokens
- No recovery mechanism available
- Financial loss for users
- Platform reputation damage

### PoC
```javascript
function setUp() public {
    factory = new buyOrderFactory(address(new BuyOrder()));
    usdc = new ERC20Mock();
    veNFT = new MockVeNFR();

    buyer = address(1);
    seller = address(2);

    // Give buyer enough USDC (use BUY_AMOUNT constant)
    usdc.mint(buyer, BUY_AMOUNT);

    // Setup mock NFT
    veNFT.mint(seller, 123);

    console.log("=== Initial Setup ===");
    console.log("Buyer address:", buyer);
    console.log("Seller address:", seller);
    console.log("Initial Buyer USDC Balance:", usdc.balanceOf(buyer));
    console.log("Initial NFT Owner:", veNFT.ownerOf(123));
}

function testNFTLockupVulnerability() public {
    console.log("\n=== Starting NFT Lockup Test ===");

    // 1. Approve USDC spending
    vm.startPrank(buyer);
    usdc.approve(address(factory), BUY_AMOUNT);
    console.log("Buyer approved USDC spending");

    // 2. Create buy order
    buyOrder = factory.createBuyOrder(address(usdc), address(veNFT), BUY_AMOUNT, RATIO);
    console.log("Buy order created at:", buyOrder);
    vm.stopPrank();

    console.log("\n=== Pre-Sale State ===");
    console.log("Buy Order USDC Balance:", usdc.balanceOf(buyOrder));
    console.log("Buyer USDC Balance:", usdc.balanceOf(buyer));
    console.log("NFT Owner:", veNFT.ownerOf(123));

    // 3. Seller approves and sells NFT
    vm.startPrank(seller);
    veNFT.approve(buyOrder, 123);
    console.log("Seller approved NFT transfer");

    BuyOrder(buyOrder).sellNFT(123);
    console.log("Seller executed sellNFT function");
    vm.stopPrank();

    console.log("\n=== Post-Sale State ===");
    console.log("NFT is now owned by:", veNFT.ownerOf(123));
    console.log("Seller USDC Balance:", usdc.balanceOf(seller));
    console.log("Buyer USDC Balance:", usdc.balanceOf(buyer));

    // Verify NFT is stuck
    assertEq(veNFT.ownerOf(123), buyOrder);
    console.log("\n=== Vulnerability Confirmed ===");
    console.log("NFT is stuck in contract:", veNFT.ownerOf(123));

    // Verify USDC transfers
    uint256 expectedAmount = LOCKED_AMOUNT * RATIO / 1e18;
    uint256 expectedFee = (expectedAmount * factory.sellFee()) / 10000;
    assertEq(usdc.balanceOf(seller), expectedAmount - expectedFee);
    assertEq(usdc.balanceOf(factory.feeAddress()), expectedFee);

    console.log("\n=== Final State ===");
    console.log("Final Seller USDC:", usdc.balanceOf(seller));
    console.log("Protocol Fee:", usdc.balanceOf(factory.feeAddress()));
    console.log("Final Buyer USDC:", usdc.balanceOf(buyer));

    console.log("\n=== Vulnerability Summary ===");
    console.log("1. NFT is permanently locked in contract");
    console.log("2. Buyer paid but received nothing");
    console.log("3. Seller got paid ");
    console.log("4. No recovery mechanism exists");
}
```
**Test output:** 
```javascript
[PASS] testNFTLockupVulnerability() (gas: 637414)
Logs:
  === Initial Setup ===
  Buyer address: 0x0000000000000000000000000000000000000001
  Seller address: 0x0000000000000000000000000000000000000002
  Initial Buyer USDC Balance: 2000000000000000000000
  Initial NFT Owner: 0x0000000000000000000000000000000000000002
  
=== Starting NFT Lockup Test ===
  Buyer approved USDC spending
  Buy order created at: 0xffD4505B3452Dc22f8473616d50503bA9E1710Ac
  
=== Pre-Sale State ===
  Buy Order USDC Balance: 2000000000000000000000
  Buyer USDC Balance: 0
  NFT Owner: 0x0000000000000000000000000000000000000002
  Seller approved NFT transfer
  Seller executed sellNFT function
  
=== Post-Sale State ===
  NFT is now owned by: 0xffD4505B3452Dc22f8473616d50503bA9E1710Ac
  Seller USDC Balance: 995000000000000000000
  Buyer USDC Balance: 0
  
=== Vulnerability Confirmed ===
  NFT is stuck in contract: 0xffD4505B3452Dc22f8473616d50503bA9E1710Ac
  
=== Final State ===
  Final Seller USDC: 995000000000000000000
  Protocol Fee: 5000000000000000000
  Final Buyer USDC: 0
  
=== Vulnerability Summary ===
  1. NFT is permanently locked in contract
  2. Buyer paid but received nothing
  3. Seller got paid
  4. No recovery mechanism exists

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 3.45ms (1.10ms CPU time)
```

### Mitigation
```diff

function sellNFT(uint receiptID) public {
    require(buyInformation.isActive, "Buy order is not active");
    require(buyInformation.availableAmount > 0, "Buy order is not available");
    
    // Transfer NFT directly to buyer instead of contract
-   IERC721(buyInformation.wantedToken).transferFrom(
-       msg.sender,
-       address(this),
-       receiptID
-   );
+   IERC721(buyInformation.wantedToken).transferFrom(
+       msg.sender,
+       buyInformation.owner,
+       receiptID
+   );
    
    // ... rest of the function ...
}
```

Key changes:
1. Transfer NFT directly to buyer's address
2. Remove unnecessary contract holding of NFT
3. Ensure proper NFT delivery to intended recipient

---

<a id="m-02"></a>
## 🟡 **M-02 - Silent Return in `updateFunds()` Causes Partial State Updates Leading to Incentive Accounting Inconsistencies**


### Summary
The `DebitaIncentives::updateFunds` function in DebitaIncentives.sol silently returns when encountering an invalid pair, causing partial state updates and breaking incentive accounting. This leads to some lenders' funds not being properly tracked in the incentive system.
https://github.com/sherlock-audit/2024-11-debita-finance-v3/blob/main/Debita-V3-Contracts/contracts/DebitaIncentives.sol#L306

### Root Cause
The function uses a simple `return` statement instead of reverting when an invalid pair is detected, causing the function to exit prematurely after processing only some of the lenders, leaving the remaining valid lenders unprocessed.

### Internal Pre-conditions
- Function called by Aggregator contract
- Multiple lenders in the input array
- At least one valid pair before an invalid pair

### External Pre-conditions
- Aggregator must have proper permissions
- Valid lender addresses provided
- Valid offer information available

### Attack Path
1. Aggregator calls updateFunds with multiple lenders
2. First lender has valid pair - processed successfully
3. Second lender has invalid pair - function returns silently
4. Third and subsequent lenders (even with valid pairs) - never processed
5. State updates remain incomplete

### Impact
- Inconsistent incentive accounting
- Loss of rewards for valid lenders
- Incorrect total lending amounts
- Skewed reward distributions
- Platform's incentive mechanism compromised



### Mitigation
```diff
function updateFunds(
    infoOfOffers[] memory informationOffers,
    address collateral,
    address[] memory lenders,
    address borrower
) public onlyAggregator {
    for (uint i = 0; i < lenders.length; i++) {
        bool validPair = isPairWhitelisted[informationOffers[i].principle][collateral];
-       if (!validPair) {
-           return;
-       }
+       require(validPair, "Invalid pair");
        
        // ... rest of the function ...
    }
}
```

The fix replaces the silent return with a require statement to:
1. Prevent partial updates
2. Ensure all valid pairs are processed
3. Maintain consistent incentive accounting
4. Make failures visible and traceable
