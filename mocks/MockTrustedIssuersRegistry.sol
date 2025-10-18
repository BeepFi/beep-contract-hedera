// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITrustedIssuersRegistry} from "../interfaces/ITrustedIssuersRegistry.sol";
import {IIdentity} from "../interfaces/IIdentity.sol";

contract MockTrustedIssuersRegistry is ITrustedIssuersRegistry {
    mapping(uint256 => address[]) public issuers; // Maps claim topics to issuers
    mapping(address => uint256[]) public issuerClaimTopics; // Maps issuers to their claim topics
    mapping(address => IIdentity) public issuerIdentities; // Maps issuers to their identities
    address[] public trustedIssuers; // List of trusted issuers

    function addTrustedIssuer(address _trustedIssuer, address _issuerIdentity, uint256[] calldata _claimTopics) external override {
        require(_trustedIssuer != address(0), "Invalid issuer address");
        require(!isTrustedIssuer(_trustedIssuer), "Issuer already exists");

        trustedIssuers.push(_trustedIssuer);
        issuerIdentities[_trustedIssuer] = IIdentity(_issuerIdentity);
        for (uint256 i = 0; i < _claimTopics.length; i++) {
            issuers[_claimTopics[i]].push(_trustedIssuer);
            issuerClaimTopics[_trustedIssuer].push(_claimTopics[i]);
        }
    }

    function removeTrustedIssuer(address _issuer) external override {
        require(isTrustedIssuer(_issuer), "Issuer not found");
        
        // Remove from trustedIssuers list
        for (uint256 i = 0; i < trustedIssuers.length; i++) {
            if (trustedIssuers[i] == _issuer) {
                trustedIssuers[i] = trustedIssuers[trustedIssuers.length - 1];
                trustedIssuers.pop();
                break;
            }
        }
        
        // Remove from issuerClaimTopics and issuers mappings
        uint256[] memory claimTopics = issuerClaimTopics[_issuer];
        for (uint256 i = 0; i < claimTopics.length; i++) {
            address[] storage issuerList = issuers[claimTopics[i]];
            for (uint256 j = 0; j < issuerList.length; j++) {
                if (issuerList[j] == _issuer) {
                    issuerList[j] = issuerList[issuerList.length - 1];
                    issuerList.pop();
                    break;
                }
            }
        }
        delete issuerClaimTopics[_issuer];
    }

    function getTrustedIssuers() external view override returns (address[] memory) {
        return trustedIssuers;
    }

    function isTrustedIssuer(address _issuer) public view override returns (bool) {
        for (uint256 i = 0; i < trustedIssuers.length; i++) {
            if (trustedIssuers[i] == _issuer) {
                return true;
            }
        }
        return false;
    }

    function hasClaimTopic(address _issuer, uint256 _claimTopic) external view override returns (bool) {
        uint256[] memory claimTopics = issuerClaimTopics[_issuer];
        for (uint256 i = 0; i < claimTopics.length; i++) {
            if (claimTopics[i] == _claimTopic) {
                return true;
            }
        }
        return false;
    }

    function getTrustedIssuerClaimTopics(address _trustedIssuer) external view override returns (uint256[] memory) {
        return issuerClaimTopics[_trustedIssuer];
    }

    function getTrustedIssuersForClaimTopic(uint256 _claimTopic) external view override returns (address[] memory) {
        return issuers[_claimTopic];
    }

    function getTrustedIssuerIdentity(address _issuer) external view override returns (IIdentity) {
        return issuerIdentities[_issuer];
    }

    function setIssuerIdentity(address _issuer, address _identity) external {
        issuerIdentities[_issuer] = IIdentity(_identity);
    }

    function updateIssuerClaimTopics(address _trustedIssuer, uint256[] calldata _claimTopics) external override {
        require(isTrustedIssuer(_trustedIssuer), "Issuer not found");
        
        // Clear existing claim topics
        uint256[] memory oldTopics = issuerClaimTopics[_trustedIssuer];
        for (uint256 i = 0; i < oldTopics.length; i++) {
            address[] storage issuerList = issuers[oldTopics[i]];
            for (uint256 j = 0; j < issuerList.length; j++) {
                if (issuerList[j] == _trustedIssuer) {
                    issuerList[j] = issuerList[issuerList.length - 1];
                    issuerList.pop();
                    break;
                }
            }
        }
        delete issuerClaimTopics[_trustedIssuer];
        
        // Add new claim topics
        for (uint256 i = 0; i < _claimTopics.length; i++) {
            issuers[_claimTopics[i]].push(_trustedIssuer);
            issuerClaimTopics[_trustedIssuer].push(_claimTopics[i]);
        }
    }
}