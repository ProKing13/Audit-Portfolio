## Table of Contents

- 🔴 **H-01.** [Unclaimable Rewards for Multi-Epoch Distributions Due to `Already Claimed` Requirement Causing Stuck Rewards](#h-01)

---

<a id="h-01"></a>
## 🔴 **H-01 - Unclaimable Rewards for Multi-Epoch Distributions Due to `Already Claimed` Requirement Causing Stuck Rewards**


### Summary

In the `GammaRewarder::handleProofResult` function, a `require` statement (`require(claim.amount == 0, "Already claimed reward.");`) checks if the `claim.amount` is zero before allowing a user to claim rewards. If a user is eligible for rewards that exceed `distributionAmountPerEpoch`, the initial claim will record the full `claim.amount`, making subsequent claims impossible for the same `distributionId`. This issue restricts the user's ability to receive rewards across multiple epochs or full amount if his rewards amount is greater than `distributionAmountPerEpoch`, effectively locking any remaining rewards after the first claim. As a result, eligible rewards spanning multiple epochs cannot be accessed fully, leading to unclaimable rewards.

https://github.com/sherlock-audit/2024-10-gamma-rewarder/blob/475f7fbd0f7c2717ed585a67632e9a675b51c306/GammaRewarder/contracts/GammaRewarder.sol#L187

### Root Cause

In `GammaRewarder::handleProofResult` is not allowing again claiming for reaming reward amount.

### Internal Pre-conditions

1. The request for claiming is going to be approved already by BrevisApp and ready for distribution and claim.

### External Pre-conditions

_No response_

### Attack Path

1. The `handleProofResult` function is invoked by the BrevisApp.
2. When users attempt to claim their reward, there may be cases where their claimable amount exceeds the `distributionAmountPerEpoch`. Due to this limitation, users cannot claim the full amount in a single transaction. However, if they attempt to claim partially, they will be unable to receive the remaining amount in subsequent claims. This issue arises because the system prevents further claims by any user who has already claimed any portion of their reward, as determined by the condition `require(claim.amount == 0 , "Already claimed reward.");` checking prior claim status.

### Impact

Users eligible for rewards exceeding `distributionAmountPerEpoch` cannot receive their remaining rewards after the first claim, leading to significant loss of eligible tokens across multiple epochs. This restriction directly affects the claim mechanism and deprives users of their entitled rewards in a multi-epoch distribution. Loss of funds for user who's reward are exceeding `distributionAmountPerEpoch`.

### PoC

```javascript
function handleProofResult(bytes32, bytes32 _vkHash, bytes calldata _appCircuitOutput) internal override {
    require(vkHashes[_vkHash], "invalid vk");

    (
        address userAddress,
        address lpTokenAddress,
        uint64 startBlock,
        uint64 endBlock,
        bytes32 distributionId,
        address rewardTokenAddress,
        uint248 distributionAmountPerEpoch,
        uint248 totalRewardAmount
    ) = decodeOutput(_appCircuitOutput);

    DistributionParameters memory params = distributions[distributionId];
    require(startBlock < endBlock && (endBlock - startBlock) % blocksPerEpoch == 0, "Claim period must be valid");
    require(startBlock >= params.startBlockNumber && endBlock <= params.endBlockNumber, "Claim range out of bounds");
    require(lpTokenAddress == params.hypervisor && rewardTokenAddress == params.rewardToken && distributionId == params.distributionId, "Invalid distribution parameters");
    require(totalRewardAmount > 0, "Rewards do not exist for you.");

    CumulativeClaim memory claim = claimed[userAddress][rewardTokenAddress][distributionId];

    require(claim.amount == 0, "Already claimed reward.");

    claim.startBlock = startBlock;
    claim.endBlock = endBlock;
    claim.amount = totalRewardAmount;
    claimed[userAddress][rewardTokenAddress][distributionId] = claim;

    IERC20(rewardTokenAddress).safeTransfer(userAddress, totalRewardAmount);
    emit Claimed(userAddress, distributionId, rewardTokenAddress, startBlock, endBlock, totalRewardAmount);
}
```

### Mitigation

To enable users to claim rewards across multiple epochs, consider implementing a mechanism to track cumulative claims or introduce per-epoch tracking for `claim.amount`.
