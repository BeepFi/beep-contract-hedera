// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {IIdentityRegistry} from "./ERC3643.sol";
import {IIdentityRegistryStorage} from "../interfaces/IIdentityRegistryStorage.sol";
import {IClaimTopicsRegistry} from "../interfaces/IClaimTopicsRegistry.sol";
import {ITrustedIssuersRegistry} from "../interfaces/ITrustedIssuersRegistry.sol";
import {IIdentity} from "../interfaces/IIdentity.sol";

/**
 * @title IdentityRegistry
 * @notice Production implementation of ERC3643 Identity Registry
 * @dev Manages investor identities, KYC/AML verification, and compliance
 */
contract IdentityRegistry is IIdentityRegistry, AccessControl {
    // ==================== ROLES ====================
    bytes32 public constant AGENT_ROLE = keccak256("AGENT_ROLE");

    // ==================== STATE VARIABLES ====================

    // Core registry components
    IIdentityRegistryStorage public identityStorage;
    IClaimTopicsRegistry public claimTopicsRegistry;
    ITrustedIssuersRegistry public trustedIssuersRegistry;

    // ==================== EVENTS ====================

    event ClaimTopicsRegistrySet(address indexed claimTopicsRegistry);
    event IdentityStorageSet(address indexed identityStorage);
    event TrustedIssuersRegistrySet(address indexed trustedIssuersRegistry);
    event IdentityRegistered(address indexed investorAddress, address indexed identity);
    event IdentityRemoved(address indexed investorAddress, address indexed identity);
    event IdentityUpdated(address indexed oldIdentity, address indexed newIdentity);
    event CountryUpdated(address indexed investorAddress, uint16 indexed country);

    // ==================== CONSTRUCTOR ====================

    constructor(address _identityRegistryStorage, address _claimTopicsRegistry, address _trustedIssuersRegistry) {
        require(_identityRegistryStorage != address(0), "Invalid storage address");
        require(_claimTopicsRegistry != address(0), "Invalid claim topics address");
        require(_trustedIssuersRegistry != address(0), "Invalid issuers address");

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(AGENT_ROLE, msg.sender);

        identityStorage = IIdentityRegistryStorage(_identityRegistryStorage);
        claimTopicsRegistry = IClaimTopicsRegistry(_claimTopicsRegistry);
        trustedIssuersRegistry = ITrustedIssuersRegistry(_trustedIssuersRegistry);

        emit IdentityStorageSet(_identityRegistryStorage);
        emit ClaimTopicsRegistrySet(_claimTopicsRegistry);
        emit TrustedIssuersRegistrySet(_trustedIssuersRegistry);
    }

    // ==================== IDENTITY MANAGEMENT ====================

    /**
     * @notice Register a new identity for a user
     * @param _userAddress Wallet address of the user
     * @param _identity ONCHAINID contract address
     * @param _country Country code (ISO 3166-1 numeric)
     */
    function registerIdentity(address _userAddress, address _identity, uint16 _country)
        external
        override
        onlyRole(AGENT_ROLE)
    {
        require(_userAddress != address(0), "Invalid user address");
        require(_identity != address(0), "Invalid identity address");
        require(!identityStorage.contains(_userAddress), "Identity already registered");

        identityStorage.addIdentityToStorage(_userAddress, _identity, _country);

        emit IdentityRegistered(_userAddress, _identity);
    }

    /**
     * @notice Register multiple identities in batch
     */
    function batchRegisterIdentity(
        address[] calldata _userAddresses,
        address[] calldata _identities,
        uint16[] calldata _countries
    ) external override onlyRole(AGENT_ROLE) {
        require(
            _userAddresses.length == _identities.length && _identities.length == _countries.length,
            "Array length mismatch"
        );

        for (uint256 i = 0; i < _userAddresses.length; i++) {
            require(_userAddresses[i] != address(0), "Invalid user address");
            require(_identities[i] != address(0), "Invalid identity address");
            require(!identityStorage.contains(_userAddresses[i]), "Identity already registered");

            identityStorage.addIdentityToStorage(_userAddresses[i], _identities[i], _countries[i]);

            emit IdentityRegistered(_userAddresses[i], _identities[i]);
        }
    }

    /**
     * @notice Remove an identity from the registry
     */
    function deleteIdentity(address _userAddress) external override onlyRole(AGENT_ROLE) {
        require(identityStorage.contains(_userAddress), "Identity not registered");

        address identityAddress = identityStorage.storedIdentity(_userAddress);
        identityStorage.removeIdentityFromStorage(_userAddress);

        emit IdentityRemoved(_userAddress, identityAddress);
    }

    /**
     * @notice Update an existing identity
     */
    function updateIdentity(address _userAddress, address _identity) external override onlyRole(AGENT_ROLE) {
        require(identityStorage.contains(_userAddress), "Identity not registered");
        require(_identity != address(0), "Invalid identity address");

        address oldIdentity = identityStorage.storedIdentity(_userAddress);
        identityStorage.modifyStoredIdentity(_userAddress, _identity);

        emit IdentityUpdated(oldIdentity, _identity);
    }

    /**
     * @notice Update user's country
     */
    function updateCountry(address _userAddress, uint16 _country) external override onlyRole(AGENT_ROLE) {
        require(identityStorage.contains(_userAddress), "Identity not registered");

        identityStorage.modifyStoredInvestorCountry(_userAddress, _country);

        emit CountryUpdated(_userAddress, _country);
    }

    // ==================== VERIFICATION ====================

    /**
     * @notice Check if a user's identity is verified
     * @dev Verification requires valid claims from trusted issuers
     */
    function isVerified(address _userAddress) external view override returns (bool) {
        if (!identityStorage.contains(_userAddress)) {
            return false;
        }

        address identityAddress = identityStorage.storedIdentity(_userAddress);
        if (identityAddress == address(0)) {
            return false;
        }

        // Get required claim topics
        uint256[] memory claimTopics = claimTopicsRegistry.getClaimTopics();
        if (claimTopics.length == 0) {
            return true; // No claims required
        }

        // Check each required claim topic
        for (uint256 i = 0; i < claimTopics.length; i++) {
            if (!_hasValidClaim(IIdentity(identityAddress), claimTopics[i])) {
                return false;
            }
        }

        return true;
    }

    /**
     * @notice Check if identity has a valid claim for a topic
     * @dev Internal function to verify claims with trusted issuers
     */
    function _hasValidClaim(IIdentity _identity, uint256 _claimTopic) internal view returns (bool) {
        // Get trusted issuers for this claim topic
        address[] memory issuers = trustedIssuersRegistry.getTrustedIssuersForClaimTopic(_claimTopic);

        if (issuers.length == 0) {
            return false;
        }

        // Check if identity has claim from any trusted issuer
        for (uint256 i = 0; i < issuers.length; i++) {
            bytes32[] memory claimIds = _identity.getClaimIdsByTopic(_claimTopic);

            for (uint256 j = 0; j < claimIds.length; j++) {
                (uint256 topic,, address issuer, bytes memory sig, bytes memory data,) = _identity.getClaim(claimIds[j]);

                // Verify claim is from trusted issuer and signature is valid
                if (issuer == issuers[i] && topic == _claimTopic) {
                    if (_verifyClaimSignature(_identity, _claimTopic, issuer, sig, data)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @notice Verify claim signature
     * @dev Validates that the claim was signed by the issuer
     */
    function _verifyClaimSignature(
        IIdentity _identity,
        uint256 _claimTopic,
        address _issuer,
        bytes memory _signature,
        bytes memory _data
    ) internal view returns (bool) {
        // Encode data for first keccak256
        bytes memory encodedData = abi.encode(address(_identity), _claimTopic, _data);
        bytes32 dataHash;

        // Use inline assembly for keccak256
        assembly {
            let dataPtr := add(encodedData, 32)
            let dataLength := mload(encodedData)
            dataHash := keccak256(dataPtr, dataLength)
        }

        // Prepare prefixed message for second keccak256
        bytes memory prefixedData = abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash);
        bytes32 prefixedHash;

        // Use inline assembly for second keccak256
        assembly {
            let prefixedPtr := add(prefixedData, 32)
            let prefixedLength := mload(prefixedData)
            prefixedHash := keccak256(prefixedPtr, prefixedLength)
        }

        address recoveredSigner = _recoverSigner(prefixedHash, _signature);

        // Check if recovered signer has CLAIM_SIGNER_KEY on issuer identity
        IIdentity issuerIdentity = trustedIssuersRegistry.getTrustedIssuerIdentity(_issuer);
        return issuerIdentity.keyHasPurpose(keccak256(abi.encode(recoveredSigner)), 3); // 3 = CLAIM_SIGNER_KEY
    }

    /**
     * @notice Recover signer from signature
     */
    function _recoverSigner(bytes32 _hash, bytes memory _signature) internal pure returns (address) {
        require(_signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature version");

        return ecrecover(_hash, v, r, s);
    }

    // ==================== VIEW FUNCTIONS ====================

    /**
     * @notice Check if address is in registry
     */
    function contains(address _userAddress) external view override returns (bool) {
        return identityStorage.contains(_userAddress);
    }

    /**
     * @notice Get identity address for user
     */
    function identity(address _userAddress) external view override returns (address) {
        return identityStorage.storedIdentity(_userAddress);
    }

    /**
     * @notice Get country for user
     */
    function investorCountry(address _userAddress) external view override returns (uint16) {
        return identityStorage.storedInvestorCountry(_userAddress);
    }

    // ==================== ADMIN FUNCTIONS ====================

    /**
     * @notice Update identity registry storage
     */
    function setIdentityRegistryStorage(address _identityRegistryStorage)
        external
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_identityRegistryStorage != address(0), "Invalid address");
        identityStorage = IIdentityRegistryStorage(_identityRegistryStorage);
        emit IdentityStorageSet(_identityRegistryStorage);
    }

    /**
     * @notice Update claim topics registry
     */
    function setClaimTopicsRegistry(address _claimTopicsRegistry) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_claimTopicsRegistry != address(0), "Invalid address");
        claimTopicsRegistry = IClaimTopicsRegistry(_claimTopicsRegistry);
        emit ClaimTopicsRegistrySet(_claimTopicsRegistry);
    }

    /**
     * @notice Update trusted issuers registry
     */
    function setTrustedIssuersRegistry(address _trustedIssuersRegistry)
        external
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(_trustedIssuersRegistry != address(0), "Invalid address");
        trustedIssuersRegistry = ITrustedIssuersRegistry(_trustedIssuersRegistry);
        emit TrustedIssuersRegistrySet(_trustedIssuersRegistry);
    }
}
