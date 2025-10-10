// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IIdentityRegistryStorage} from "../interfaces/IIdentityRegistryStorage.sol";
import {IClaimTopicsRegistry} from "../interfaces/IClaimTopicsRegistry.sol";
import {ITrustedIssuersRegistry} from "../interfaces/ITrustedIssuersRegistry.sol";
import {IIdentity} from "../interfaces/IIdentity.sol";
import {AccessControl} from "../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

// Mock contracts for dependencies
contract MockIdentityRegistryStorage is IIdentityRegistryStorage {
    mapping(address => address) public identities;
    mapping(address => uint16) public countries;
    mapping(address => bool) public containsIdentity;

    event IdentityRegistered(address indexed investorAddress, address indexed identity);
    event IdentityRemoved(address indexed investorAddress, address indexed identity);
    event IdentityUpdated(address indexed oldIdentity, address indexed newIdentity);
    event CountryUpdated(address indexed investorAddress, uint16 indexed country);

    function addIdentityToStorage(address _userAddress, address _identity, uint16 _country) external override {
        identities[_userAddress] = _identity;
        countries[_userAddress] = _country;
        containsIdentity[_userAddress] = true;
        emit IdentityRegistered(_userAddress, _identity);
    }

    function removeIdentityFromStorage(address _userAddress) external override {
        address identity = identities[_userAddress];
        delete identities[_userAddress];
        delete countries[_userAddress];
        delete containsIdentity[_userAddress];
        emit IdentityRemoved(_userAddress, identity);
    }

    function modifyStoredIdentity(address _userAddress, address _identity) external override {
        address oldIdentity = identities[_userAddress];
        identities[_userAddress] = _identity;
        emit IdentityUpdated(oldIdentity, _identity);
    }

    function modifyStoredInvestorCountry(address _userAddress, uint16 _country) external override {
        countries[_userAddress] = _country;
        emit CountryUpdated(_userAddress, _country);
    }

    function contains(address _userAddress) external view override returns (bool) {
        return containsIdentity[_userAddress];
    }

    function storedIdentity(address _userAddress) external view override returns (address) {
        return identities[_userAddress];
    }

    function storedInvestorCountry(address _userAddress) external view override returns (uint16) {
        return countries[_userAddress];
    }
}
