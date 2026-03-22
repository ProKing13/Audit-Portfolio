## Table of Contents

- 🔴 **H-01.** [Unauthorized Token Claims Possible Due to Missing Caller Validation in `claim()` Function](#h-01)

---

<a id="h-01"></a>
## 🔴 **H-01 - Unauthorized Token Claims Possible Due to Missing Caller Validation in `claim()` Function**


### Summary

The `claim` function in VVVVCTokenDistributor allows any address to claim tokens on behalf of a KYC'd address, where tokens are sent to the caller (msg.sender) instead of the legitimate KYC address. This creates a critical vulnerability where attackers can steal tokens meant for legitimate users if they obtain a valid signature.
The `claim()` function in VVVVCTokenDistributor contract is vulnerable to front-running attacks, allowing attackers to steal tokens intended for legitimate users by submitting transactions with higher gas prices and using the same valid claim parameters.
https://github.com/sherlock-audit/2024-11-vvv-exchange-update/blob/main/vvv-platform-smart-contracts/contracts/vc/VVVVCTokenDistributor.sol#L106

### Root Cause

The core issue stems from two design flaws:
1. No validation between msg.sender and kycAddress
2. Tokens are sent to msg.sender instead of kycAddress
This allows anyone to use valid claim parameters and receive tokens meant for others.

### Internal Pre-conditions

- Valid signature for a KYC address exists
- Nonce is unused
- Claim is not paused
- Project tokens are available in proxy wallets

### External Pre-conditions

- Access to mempool to observe pending transactions
- Ability to submit transactions with higher gas prices
- Sufficient gas to execute the front-running transaction

### Attack Path

1. **Initial Observation**
   - Attacker monitors the mempool for pending claim transactions
   - Identifies a transaction with valid claim parameters and signature
   - Notes the victim's KYC address and claim details
2. **Parameter Extraction**
   - Extracts the valid signature from the pending transaction
   - Captures all claim parameters including:
     - KYC address
     - Project token address
     - Proxy wallet addresses
     - Token amounts
     - Valid nonce
     - Signature
3. **Attack Execution**
   - Attacker prepares their own transaction using the extracted parameters
   - Sets themselves (attacker address) as msg.sender
   - Submits transaction with higher gas price to front-run victim's transaction
4. **Claim Processing**
   - Contract validates the signature (passes as it's legitimate)
   - Contract checks nonce (passes as it's first use)
   - Contract processes the claim
   - Tokens are transferred to attacker's address (msg.sender)
5. **Attack Completion**
   - Attacker successfully receives tokens
   - Victim's original transaction fails due to used nonce
   - Tokens are permanently lost to the attacker

### Impact

- Direct theft of user tokens
- No recovery mechanism
- Core functionality compromised
- Financial loss for legitimate users
- Undermines trust in platform

### PoC

_No response_

### Mitigation

Implement one of these fixes:
1. Require msg.sender to be the KYC address:
```javascript
function claim(ClaimParams memory _params) public {
    require(msg.sender == _params.kycAddress, "Caller not KYC address");
    // ... rest of function
}
```
2. Send tokens to KYC address instead of caller:
```javascript
projectToken.safeTransferFrom(
    _params.projectTokenProxyWallets[i],
    _params.kycAddress,  // Send to KYC address instead of msg.sender
    _params.tokenAmountsToClaim[i]
);
```
3. Add authorization system:

```javascript
require(
    isAuthorizedClaimer(msg.sender, _params.kycAddress),
    "Not authorized"
);
```
