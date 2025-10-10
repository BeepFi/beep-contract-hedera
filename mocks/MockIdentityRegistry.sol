// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IIdentityRegistry} from "../src/ERC3643.sol";

contract MockIdentityRegistry is IIdentityRegistry {
    // Mapping to store verification status for addresses
    mapping(address => bool) private _isVerified;
    // Mapping to store identity addresses
    mapping(address => address) private _identity;
    // Mapping to store investor country codes
    mapping(address => uint16) private _investorCountry;
    // Mock addresses for registries
    address private _claimTopicsRegistry;
    address private _identityRegistryStorage;
    address private _trustedIssuersRegistry;

    // Events for debugging and tracking
    event VerificationSet(address indexed userAddress, bool isVerified);
    event IdentitySet(address indexed userAddress, address identityAddress);
    event InvestorCountrySet(address indexed userAddress, uint16 country);
    event IdentityRegistered(address indexed userAddress, address indexed identity);
    event IdentityRemoved(address indexed userAddress, address indexed identity);
    event IdentityUpdated(address indexed oldIdentity, address indexed newIdentity);
    event CountryUpdated(address indexed userAddress, uint16 indexed country);
    event ClaimTopicsRegistrySet(address indexed claimTopicsRegistry);
    event IdentityStorageSet(address indexed identityStorage);
    event TrustedIssuersRegistrySet(address indexed trustedIssuersRegistry);

    // Function to set verification status (for testing)
    function setVerificationStatus(address userAddress, bool verified) external {
        _isVerified[userAddress] = verified;
        emit VerificationSet(userAddress, verified);
    }

    // Function to set identity (for testing)
    function setIdentity(address userAddress, address identityAddress) external {
        _identity[userAddress] = identityAddress;
        emit IdentitySet(userAddress, identityAddress);
    }

    // Function to set investor country (for testing)
    function setInvestorCountry(address userAddress, uint16 country) external {
        _investorCountry[userAddress] = country;
        emit InvestorCountrySet(userAddress, country);
    }

    // IIdentityRegistry interface implementations

    /**
     * @notice Register a new identity for a user
     * @param _userAddress Wallet address of the user
     * @param _identityAddress ONCHAINID contract address
     * @param _country Country code (ISO 3166-1 numeric)
     */
    function registerIdentity(
        address _userAddress,
        address _identityAddress,
        uint16 _country
    ) external override {
        require(_userAddress != address(0), "Invalid user address");
        require(_identityAddress != address(0), "Invalid identity address");
        require(_identity[_userAddress] == address(0), "Identity already registered");

        _identity[_userAddress] = _identityAddress;
        _investorCountry[_userAddress] = _country;
        _isVerified[_userAddress] = true; // Assume verified for mock purposes

        emit IdentityRegistered(_userAddress, _identityAddress);
    }

    /**
     * @notice Register multiple identities in batch
     */
    function batchRegisterIdentity(
        address[] calldata _userAddresses,
        address[] calldata _identityAddresses,
        uint16[] calldata _countries
    ) external override {
        require(
            _userAddresses.length == _identityAddresses.length &&
            _identityAddresses.length == _countries.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < _userAddresses.length; i++) {
            require(_userAddresses[i] != address(0), "Invalid user address");
            require(_identityAddresses[i] != address(0), "Invalid identity address");
            require(_identity[_userAddresses[i]] == address(0), "Identity already registered");

            _identity[_userAddresses[i]] = _identityAddresses[i];
            _investorCountry[_userAddresses[i]] = _countries[i];
            _isVerified[_userAddresses[i]] = true; // Assume verified for mock purposes

            emit IdentityRegistered(_userAddresses[i], _identityAddresses[i]);
        }
    }

    /**
     * @notice Remove an identity from the registry
     */
    function deleteIdentity(address _userAddress) external override {
        require(_identity[_userAddress] != address(0), "Identity not registered");

        address identityAddress = _identity[_userAddress];
        delete _identity[_userAddress];
        delete _investorCountry[_userAddress];
        delete _isVerified[_userAddress];

        emit IdentityRemoved(_userAddress, identityAddress);
    }

    /**
     * @notice Update an existing identity
     */
    function updateIdentity(
        address _userAddress,
        address _identityAddress
    ) external override {
        require(_identity[_userAddress] != address(0), "Identity not registered");
        require(_identityAddress != address(0), "Invalid identity address");

        address oldIdentity = _identity[_userAddress];
        _identity[_userAddress] = _identityAddress;

        emit IdentityUpdated(oldIdentity, _identityAddress);
    }

    /**
     * @notice Update user's country
     */
    function updateCountry(
        address _userAddress,
        uint16 _country
    ) external override {
        require(_identity[_userAddress] != address(0), "Identity not registered");

        _investorCountry[_userAddress] = _country;

        emit CountryUpdated(_userAddress, _country);
    }

    /**
     * @notice Update identity registry storage
     */
    function setIdentityRegistryStorage(
        address newIdentityRegistryStorage
    ) external override {
        require(newIdentityRegistryStorage != address(0), "Invalid address");
        _identityRegistryStorage = newIdentityRegistryStorage;
        emit IdentityStorageSet(newIdentityRegistryStorage);
    }

    /**
     * @notice Update claim topics registry
     */
    function setClaimTopicsRegistry(
        address newClaimTopicsRegistry
    ) external override {
        require(newClaimTopicsRegistry != address(0), "Invalid address");
        _claimTopicsRegistry = newClaimTopicsRegistry;
        emit ClaimTopicsRegistrySet(newClaimTopicsRegistry);
    }

    /**
     * @notice Update trusted issuers registry
     */
    function setTrustedIssuersRegistry(
        address newTrustedIssuersRegistry
    ) external override {
        require(newTrustedIssuersRegistry != address(0), "Invalid address");
        _trustedIssuersRegistry = newTrustedIssuersRegistry;
        emit TrustedIssuersRegistrySet(newTrustedIssuersRegistry);
    }

    /**
     * @notice Check if address is in registry
     */
    function contains(address _userAddress) external view override returns (bool) {
        return _identity[_userAddress] != address(0);
    }

    /**
     * @notice Get identity address for user
     */
    function identity(address _userAddress) external view override returns (address) {
        return _identity[_userAddress];
    }

    /**
     * @notice Get country for user
     */
    function investorCountry(address _userAddress) external view override returns (uint16) {
        return _investorCountry[_userAddress];
    }

    /**
     * @notice Check if a user's identity is verified
     */
    function isVerified(address _userAddress) external view override returns (bool) {
        return _isVerified[_userAddress];
    }
}
