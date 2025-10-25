// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IIdentity} from "../interfaces/IIdentity.sol";

contract MockIdentity is IIdentity {
    struct Claim {
        uint256 topic;
        uint256 scheme;
        address issuer;
        bytes signature;
        bytes data;
        string uri;
    }

    mapping(bytes32 => Claim) public claims;
    mapping(address => mapping(uint256 => bytes32[])) public claimIdsByUserAndTopic;
    mapping(bytes32 => uint256) private keyPurposes;

    function addKey(bytes32 _key, uint256 _purpose, uint256 /*_keyType*/) external {
        keyPurposes[_key] = _purpose;
    }

    function keyHasPurpose(bytes32 _key, uint256 _purpose) external view override returns (bool) {
        return keyPurposes[_key] == _purpose;
    }

    function addClaim(
        address user,
        uint256 _topic,
        uint256 _scheme,
        address _issuer,
        bytes calldata _signature,
        bytes calldata _data,
        string calldata _uri
    ) external override returns (bytes32) {
        require(user != address(0), "Invalid user address");
        bytes32 claimId = keccak256(abi.encode(_issuer, _topic, user, _data));
        claims[claimId] = Claim(_topic, _scheme, _issuer, _signature, _data, _uri);
        claimIdsByUserAndTopic[user][_topic].push(claimId);
        return claimId;
    }

    function removeClaim(address _user, bytes32 _claimId) external override returns (bool) {
        Claim memory claim = claims[_claimId];
        require(claim.issuer != address(0), "Claim does not exist");

        // Remove claim from storage
        delete claims[_claimId];

        // Remove claimId from claimIdsByUserAndTopic
        bytes32[] storage claimIds = claimIdsByUserAndTopic[_user][claim.topic];
        for (uint256 i = 0; i < claimIds.length; i++) {
            if (claimIds[i] == _claimId) {
                claimIds[i] = claimIds[claimIds.length - 1];
                claimIds.pop();
                break;
            }
        }
        return true;
    }

    function getClaimIdsByTopic(address _user, uint256 _topic) external view override returns (bytes32[] memory) {
        return claimIdsByUserAndTopic[_user][_topic];
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
}
