// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IIdentity} from "../interfaces/IIdentity.sol";

contract MockIdentity is IIdentity {
    mapping(bytes32 => Claim) public claims;
    mapping(uint256 => bytes32[]) public claimIdsByTopic;

    struct Claim {
        uint256 topic;
        uint256 scheme;
        address issuer;
        bytes signature;
        bytes data;
        string uri;
    }

    function addClaim(
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes calldata _signature,
        bytes calldata _data,
        string calldata _uri
    ) external override returns (bytes32) {
        bytes32 claimId = keccak256(abi.encode(_topic, _issuer));
        claims[claimId] = Claim(_topic, _scheme, _issuer, _signature, _data, _uri);
        claimIdsByTopic[_topic].push(claimId);
        return claimId;
    }

    function removeClaim(bytes32 _claimId) external override returns (bool) {
        Claim memory claim = claims[_claimId];
        require(claim.issuer != address(0), "Claim does not exist");
        
        // Remove claim from storage
        delete claims[_claimId];
        
        // Remove claimId from claimIdsByTopic
        bytes32[] storage claimIds = claimIdsByTopic[claim.topic];
        for (uint256 i = 0; i < claimIds.length; i++) {
            if (claimIds[i] == _claimId) {
                claimIds[i] = claimIds[claimIds.length - 1];
                claimIds.pop();
                break;
            }
        }
        return true;
    }

    function getClaimIdsByTopic(uint256 _topic) external view override returns (bytes32[] memory) {
        return claimIdsByTopic[_topic];
    }

    function getClaim(bytes32 _claimId)
        external
        view
        override
        returns (uint256 topic, uint256 scheme, address issuer, bytes memory signature, bytes memory data, string memory uri)
    {
        Claim memory claim = claims[_claimId];
        return (claim.topic, claim.scheme, claim.issuer, claim.signature, claim.data, claim.uri);
    }

    function keyHasPurpose(bytes32, uint256) external pure override returns (bool) {
        return true; // Simplified for testing
    }
}
