// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AccessControl } from "../lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

/**
 * @title IdentityRegistryStorage
 * @notice Stores identity mappings for the Identity Registry
 * @dev Separated storage pattern for upgradeability
 */

interface IIdentityRegistryStorage {
    function addIdentityToStorage(address _userAddress, address _identity, uint16 _country) external;
    function removeIdentityFromStorage(address _userAddress) external;
    function modifyStoredIdentity(address _userAddress, address _identity) external;
    function modifyStoredInvestorCountry(address _userAddress, uint16 _country) external;
    function storedIdentity(address _userAddress) external view returns (address);
    function storedInvestorCountry(address _userAddress) external view returns (uint16);
    function contains(address _userAddress) external view returns (bool);
}
