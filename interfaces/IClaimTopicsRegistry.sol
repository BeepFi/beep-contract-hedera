// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ==================== CLAIM TOPICS REGISTRY ====================

interface IClaimTopicsRegistry {
    function addClaimTopic(uint256 _claimTopic) external;
    function removeClaimTopic(uint256 _claimTopic) external;
    function getClaimTopics() external view returns (uint256[] memory);
}
