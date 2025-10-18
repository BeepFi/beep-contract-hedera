// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2, Vm} from "forge-std/Test.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {MockIdentityRegistryStorage} from "../mocks/MockIdentityRegistryStorage.sol";
import {MockClaimTopicsRegistry} from "../mocks/MockClaimTopicsRegistry.sol";
import {MockTrustedIssuersRegistry} from "../mocks/MockTrustedIssuersRegistry.sol";
import {MockIdentity} from "../mocks/MockIdentity.sol";

contract IdentityRegistryTest is Test {
    IdentityRegistry public identityRegistry;
    MockIdentityRegistryStorage public identityStorage;
    MockClaimTopicsRegistry public claimTopicsRegistry;
    MockTrustedIssuersRegistry public trustedIssuersRegistry;
    MockIdentity public identity;

    address public admin = address(0x1);
    address public agent = address(0x2);
    address public user1 = address(0x3);
    address public user2 = address(0x4);
    address public issuer = address(0x5);

    uint16 constant COUNTRY_CODE = 840; // USA
    uint256 constant CLAIM_TOPIC = 1;

    bytes32 constant AGENT_ROLE = keccak256("AGENT_ROLE");
    bytes32 constant DEFAULT_ADMIN_ROLE = 0x00;

    event IdentityRegistered(address indexed investorAddress, address indexed identity);
    event IdentityRemoved(address indexed investorAddress, address indexed identity);
    event IdentityUpdated(address indexed oldIdentity, address indexed newIdentity);
    event CountryUpdated(address indexed investorAddress, uint16 indexed country);
    event IdentityStorageSet(address indexed identityStorage);
    event ClaimTopicsRegistrySet(address indexed claimTopicsRegistry);
    event TrustedIssuersRegistrySet(address indexed trustedIssuersRegistry);

    function setUp() public {
        vm.startPrank(admin);
        identityStorage = new MockIdentityRegistryStorage();
        claimTopicsRegistry = new MockClaimTopicsRegistry();
        trustedIssuersRegistry = new MockTrustedIssuersRegistry();
        identity = new MockIdentity();

        identityRegistry = new IdentityRegistry(
            address(identityStorage), address(claimTopicsRegistry), address(trustedIssuersRegistry)
        );

        // Grant roles
        identityRegistry.grantRole(AGENT_ROLE, agent);
        identityRegistry.grantRole(DEFAULT_ADMIN_ROLE, admin);

        // Setup trusted issuer
        uint256[] memory topics = new uint256[](1);
        topics[0] = CLAIM_TOPIC;
        trustedIssuersRegistry.addTrustedIssuer(issuer, address(identity), topics);

        vm.stopPrank();

        // Verify setup
        assertEq(address(identityRegistry.identityStorage()), address(identityStorage), "Identity storage not set");
        assertEq(
            address(identityRegistry.claimTopicsRegistry()),
            address(claimTopicsRegistry),
            "Claim topics registry not set"
        );
        assertEq(
            address(identityRegistry.trustedIssuersRegistry()),
            address(trustedIssuersRegistry),
            "Trusted issuers registry not set"
        );
        assertTrue(identityRegistry.hasRole(DEFAULT_ADMIN_ROLE, admin), "Admin role not assigned");
        assertTrue(identityRegistry.hasRole(AGENT_ROLE, agent), "Agent role not assigned");
    }

    function testInitializeRegistries() public {
        vm.prank(admin);
        vm.expectEmit(true, false, false, true);
        emit IdentityStorageSet(address(identityStorage));
        vm.expectEmit(true, false, false, true);
        emit ClaimTopicsRegistrySet(address(claimTopicsRegistry));
        vm.expectEmit(true, false, false, true);
        emit TrustedIssuersRegistrySet(address(trustedIssuersRegistry));

        IdentityRegistry newRegistry = new IdentityRegistry(
            address(identityStorage), address(claimTopicsRegistry), address(trustedIssuersRegistry)
        );

        assertEq(address(newRegistry.identityStorage()), address(identityStorage), "Identity storage not initialized");
        assertEq(
            address(newRegistry.claimTopicsRegistry()),
            address(claimTopicsRegistry),
            "Claim topics registry not initialized"
        );
        assertEq(
            address(newRegistry.trustedIssuersRegistry()),
            address(trustedIssuersRegistry),
            "Trusted issuers registry not initialized"
        );
        assertTrue(newRegistry.hasRole(DEFAULT_ADMIN_ROLE, admin), "Admin role not assigned in constructor");
        assertTrue(newRegistry.hasRole(AGENT_ROLE, admin), "Agent role not assigned in constructor");
    }

    function testRegisterIdentity() public {
        vm.prank(agent);
        vm.expectEmit(true, true, false, true);
        emit IdentityRegistered(user1, address(identity));
        identityRegistry.registerIdentity(user1, address(identity), COUNTRY_CODE);

        assertTrue(identityRegistry.contains(user1), "User1 not registered");
        assertEq(identityRegistry.identity(user1), address(identity), "User1 identity incorrect");
        assertEq(identityRegistry.investorCountry(user1), COUNTRY_CODE, "User1 country incorrect");
    }

    function testBatchRegisterIdentity() public {
        address[] memory users = new address[](2);
        address[] memory identities = new address[](2);
        uint16[] memory countries = new uint16[](2);
        users[0] = user1;
        users[1] = user2;
        identities[0] = address(identity);
        identities[1] = address(identity);
        countries[0] = COUNTRY_CODE;
        countries[1] = COUNTRY_CODE;

        vm.prank(agent);
        vm.expectEmit(true, true, false, true);
        emit IdentityRegistered(user1, address(identity));
        vm.expectEmit(true, true, false, true);
        emit IdentityRegistered(user2, address(identity));
        identityRegistry.batchRegisterIdentity(users, identities, countries);

        assertTrue(identityRegistry.contains(user1), "User1 not registered");
        assertTrue(identityRegistry.contains(user2), "User2 not registered");
        assertEq(identityRegistry.identity(user1), address(identity), "User1 identity incorrect");
        assertEq(identityRegistry.identity(user2), address(identity), "User2 identity incorrect");
        assertEq(identityRegistry.investorCountry(user1), COUNTRY_CODE, "User1 country incorrect");
        assertEq(identityRegistry.investorCountry(user2), COUNTRY_CODE, "User2 country incorrect");
    }

    function testDeleteIdentity() public {
        vm.startPrank(agent);
        identityRegistry.registerIdentity(user1, address(identity), COUNTRY_CODE);

        vm.expectEmit(true, true, false, true);
        emit IdentityRemoved(user1, address(identity));
        identityRegistry.deleteIdentity(user1);

        assertFalse(identityRegistry.contains(user1), "User1 should not be registered");
        assertEq(identityRegistry.identity(user1), address(0), "User1 identity not cleared");
        assertEq(identityRegistry.investorCountry(user1), 0, "User1 country not cleared");
        vm.stopPrank();
    }

    function testUpdateIdentity() public {
        vm.startPrank(agent);
        identityRegistry.registerIdentity(user1, address(identity), COUNTRY_CODE);

        MockIdentity newIdentity = new MockIdentity();
        vm.expectEmit(true, true, false, true);
        emit IdentityUpdated(address(identity), address(newIdentity));
        identityRegistry.updateIdentity(user1, address(newIdentity));

        assertEq(identityRegistry.identity(user1), address(newIdentity), "User1 identity not updated");
        assertTrue(identityRegistry.contains(user1), "User1 should still be registered");
        assertEq(identityRegistry.investorCountry(user1), COUNTRY_CODE, "User1 country should remain unchanged");
        vm.stopPrank();
    }

    function testUpdateCountry() public {
        vm.startPrank(agent);
        identityRegistry.registerIdentity(user1, address(identity), COUNTRY_CODE);

        uint16 newCountry = 124; // Canada
        vm.expectEmit(true, true, false, true);
        emit CountryUpdated(user1, newCountry);
        identityRegistry.updateCountry(user1, newCountry);

        assertEq(identityRegistry.investorCountry(user1), newCountry, "User1 country not updated");
        assertTrue(identityRegistry.contains(user1), "User1 should still be registered");
        assertEq(identityRegistry.identity(user1), address(identity), "User1 identity should remain unchanged");
        vm.stopPrank();
    }

    function testIsVerifiedWithNoClaimTopics() public {
        vm.prank(agent);
        identityRegistry.registerIdentity(user1, address(identity), COUNTRY_CODE);
        assertTrue(identityRegistry.isVerified(user1), "User1 should be verified with no claim topics");
    }

    function testSetIdentityRegistryStorage() public {
        vm.startPrank(admin);
        MockIdentityRegistryStorage newStorage = new MockIdentityRegistryStorage();
        vm.expectEmit(true, false, false, true, address(identityRegistry));
        emit IdentityStorageSet(address(newStorage));
        identityRegistry.setIdentityRegistryStorage(address(newStorage));
        assertEq(address(identityRegistry.identityStorage()), address(newStorage), "Identity storage not updated");
        vm.stopPrank();
    }

    function testSetClaimTopicsRegistry() public {
        vm.startPrank(admin);
        MockClaimTopicsRegistry newRegistry = new MockClaimTopicsRegistry();
        vm.expectEmit(true, false, false, true, address(identityRegistry));
        emit ClaimTopicsRegistrySet(address(newRegistry));
        identityRegistry.setClaimTopicsRegistry(address(newRegistry));
        assertEq(
            address(identityRegistry.claimTopicsRegistry()), address(newRegistry), "Claim topics registry not updated"
        );
        vm.stopPrank();
    }

    function testSetTrustedIssuersRegistry() public {
        vm.startPrank(admin);
        MockTrustedIssuersRegistry newRegistry = new MockTrustedIssuersRegistry();
        vm.expectEmit(true, false, false, true, address(identityRegistry));
        emit TrustedIssuersRegistrySet(address(newRegistry));
        identityRegistry.setTrustedIssuersRegistry(address(newRegistry));
        assertEq(
            address(identityRegistry.trustedIssuersRegistry()),
            address(newRegistry),
            "Trusted issuers registry not updated"
        );
        vm.stopPrank();
    }

    // Helper function to sign claim
    function signClaim(bytes32 _claimId) internal view returns (bytes memory) {
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _claimId));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(uint256(uint160(issuer)), prefixedHash);
        return abi.encodePacked(r, s, v);
    }
}
