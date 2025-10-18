// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ==================== IDENTITY (ONCHAINID) INTERFACE ====================
interface IIdentity {
    function keyHasPurpose(bytes32 key, uint256 purpose) external view returns (bool);
    function addClaim(
        uint256 topic,
        uint256 scheme,
        address issuer,
        bytes calldata signature,
        bytes calldata data,
        string calldata uri
    ) external returns (bytes32);
    function removeClaim(address user, bytes32 claimId) external returns (bool);
    function getClaim(bytes32 claimId)
        external
        view
        returns (
            uint256 topic,
            uint256 scheme,
            address issuer,
            bytes memory signature,
            bytes memory data,
            string memory uri
        );
    function getClaimIdsByTopic(address user, uint256 topic) external view returns (bytes32[] memory);
}