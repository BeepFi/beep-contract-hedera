// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ==================== IDENTITY (ONCHAINID) INTERFACE ====================
interface IIdentity {
    function getClaim(bytes32 _claimId) external view returns (
        uint256 topic,
        uint256 scheme,
        address issuer,
        bytes memory signature,
        bytes memory data,
        string memory uri
    );
    function getClaimIdsByTopic(uint256 _topic) external view returns (bytes32[] memory);
    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes calldata _signature,
        bytes calldata _data,
        string calldata _uri
    ) external returns (bytes32);
    function removeClaim(bytes32 _claimId) external returns (bool);
    function keyHasPurpose(bytes32 _key, uint256 _purpose) external view returns (bool);
}