// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ==================== TRUSTED ISSUERS REGISTRY ====================
import { IIdentity } from "./IIdentity.sol";

interface ITrustedIssuersRegistry {
    function addTrustedIssuer(address _trustedIssuer, address _issuerIdentity, uint256[] calldata _claimTopics) external;
    function removeTrustedIssuer(address _trustedIssuer) external;
    function updateIssuerClaimTopics(address _trustedIssuer, uint256[] calldata _claimTopics) external;
    function getTrustedIssuers() external view returns (address[] memory);
    function getTrustedIssuersForClaimTopic(uint256 _claimTopic) external view returns (address[] memory);
    function isTrustedIssuer(address _issuer) external view returns (bool);
    function hasClaimTopic(address _issuer, uint256 _claimTopic) external view returns (bool);
    function getTrustedIssuerClaimTopics(address _trustedIssuer) external view returns (uint256[] memory);
    function getTrustedIssuerIdentity(address _trustedIssuer) external view returns (IIdentity);
}
