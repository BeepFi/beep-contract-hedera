// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IIdentityRegistry {
    function registerIdentity(address _userAddress, address _identity, uint16 _country) external;
    function deleteIdentity(address _userAddress) external;
    function setIdentityRegistryStorage(address _identityRegistryStorage) external;
    function setClaimTopicsRegistry(address _claimTopicsRegistry) external;
    function setTrustedIssuersRegistry(address _trustedIssuersRegistry) external;
    function updateCountry(address _userAddress, uint16 _country) external;
    function updateIdentity(address _userAddress, address _identity) external;
    function batchRegisterIdentity(
        address[] calldata _userAddresses,
        address[] calldata _identities,
        uint16[] calldata _countries
    ) external;
    function contains(address _userAddress) external view returns (bool);
    function isVerified(address _userAddress) external view returns (bool);
    function identity(address _userAddress) external view returns (address);
    function investorCountry(address _userAddress) external view returns (uint16);
}
