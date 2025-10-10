// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IIdentityRegistryStorage} from "../interfaces/IIdentityRegistryStorage.sol";
import {IClaimTopicsRegistry} from "../interfaces/IClaimTopicsRegistry.sol";
import {ITrustedIssuersRegistry} from "../interfaces/ITrustedIssuersRegistry.sol";
import {IIdentity} from "../interfaces/IIdentity.sol";
import {AccessControl} from "../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

contract MockClaimTopicsRegistry is IClaimTopicsRegistry {
    uint256[] public topics;

    function addClaimTopic(uint256 _claimTopic) external override {
        topics.push(_claimTopic);
    }

    function removeClaimTopic(uint256 _claimTopic) external override {
        for (uint256 i = 0; i < topics.length; i++) {
            if (topics[i] == _claimTopic) {
                topics[i] = topics[topics.length - 1];
                topics.pop();
                break;
            }
        }
    }

    function getClaimTopics() external view override returns (uint256[] memory) {
        return topics;
    }
}
