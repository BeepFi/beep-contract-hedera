// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ERC3643} from "../src/ERC3643.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {IdentityRegistryStorage} from "../src/IdentityRegistryStorage.sol";
import {ClaimTopicsRegistry} from "../src/ClaimTopicsRegistry.sol";
import {TrustedIssuersRegistry} from "../src/TrustedIssuersRegistry.sol";
import {Compliance} from "../src/Compliance.sol";
import {Identity} from "../src/Identity.sol";

contract ERC3643Script is Script {
    // Helper function to convert bytes32 to hexadecimal string
    function bytes32ToString(bytes32 _bytes32) public pure returns (string memory) {
        bytes memory chars = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            bytes1 char = _bytes32[i];
            uint8 hi = uint8(char) / 16;
            uint8 lo = uint8(char) % 16;
            chars[i * 2] = hi < 10 ? bytes1(hi + 48) : bytes1(hi + 87);
            chars[i * 2 + 1] = lo < 10 ? bytes1(lo + 48) : bytes1(lo + 87);
        }
        return string(abi.encodePacked("0x", chars));
    }

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("HEDERA_PRIVATE_KEY");
        address admin = vm.addr(deployerPrivateKey);
        uint256 agentPrivateKey = vm.envUint("AGENT_PRIVATE_KEY");
        address agent = vm.addr(agentPrivateKey);
        uint256 pauserPrivateKey = vm.envUint("PAUSER_PRIVATE_KEY");
        address pauser = vm.addr(pauserPrivateKey);
        uint256 userPrivateKey = vm.envUint("USER_PRIVATE_KEY");
        address userAddress = vm.addr(userPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        IdentityRegistryStorage identityStorage = new IdentityRegistryStorage();
        console.log("IdentityRegistryStorage deployed to:", address(identityStorage));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        ClaimTopicsRegistry claimTopicsRegistry = new ClaimTopicsRegistry();
        console.log("ClaimTopicsRegistry deployed to:", address(claimTopicsRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        TrustedIssuersRegistry trustedIssuersRegistry = new TrustedIssuersRegistry();
        console.log("TrustedIssuersRegistry deployed to:", address(trustedIssuersRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        IdentityRegistry identityRegistry = new IdentityRegistry(
            address(identityStorage), address(claimTopicsRegistry), address(trustedIssuersRegistry)
        );
        console.log("IdentityRegistry deployed to:", address(identityRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        Compliance compliance = new Compliance(address(identityRegistry));
        console.log("Compliance deployed to:", address(compliance));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        Identity identity = new Identity(admin);
        console.log("Identity contract deployed to:", address(identity));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bytes32 agentKey = keccak256(abi.encode(agent));
        if (!identity.keyHasPurpose(agentKey, 3)) {
            identity.addKey(agentKey, 3, 1);
            console.log("Added agent as CLAIM_SIGNER_KEY:", agent);
        } else {
            console.log("Agent already has CLAIM_SIGNER_KEY:", agent);
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        string memory name = "Tokenized Naira";
        string memory symbol = "bNGN";

        ERC3643 bNgn = new ERC3643(name, symbol, address(identityRegistry), address(compliance));
        console.log("ERC3643 (bNGN) deployed to:", address(bNgn));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.grantRole(bNgn.DEFAULT_ADMIN_ROLE(), admin);
        console.log("Granted DEFAULT_ADMIN_ROLE to:", admin);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.grantRole(bNgn.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.grantRole(bNgn.PAUSER_ROLE(), pauser);
        console.log("Granted PAUSER_ROLE to:", pauser);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        bNgn.setAuditorStatus(admin, true);
        console.log("Set auditor status for admin:", admin);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        identityStorage.grantRole(identityStorage.REGISTRY_ROLE(), address(identityRegistry));
        console.log("Granted REGISTRY_ROLE to IdentityRegistry:", address(identityRegistry));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        identityRegistry.grantRole(identityRegistry.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent, "for IdentityRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        claimTopicsRegistry.grantRole(claimTopicsRegistry.MANAGER_ROLE(), admin);
        console.log("Granted MANAGER_ROLE to:", admin, "for ClaimTopicsRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        trustedIssuersRegistry.grantRole(trustedIssuersRegistry.MANAGER_ROLE(), admin);
        console.log("Granted MANAGER_ROLE to:", admin, "for TrustedIssuersRegistry");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        compliance.grantRole(compliance.AGENT_ROLE(), agent);
        console.log("Granted AGENT_ROLE to:", agent, "for Compliance");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        compliance.bindToken(address(bNgn));
        console.log("Compliance bound to ERC3643 token at:", address(bNgn));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        claimTopicsRegistry.addClaimTopic(1);
        console.log("Added claim topic: KYC (1)");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        claimTopicsRegistry.addClaimTopic(2);
        console.log("Added claim topic: AML (2)");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        compliance.setComplianceLimits(1_000_000 * 10 ** 18, 10_000_000 * 10 ** 18, 100_000_000 * 10 ** 18, 0);
        console.log("Set compliance limits: daily=1M, monthly=10M, maxBalance=100M, minHoldingPeriod=0");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Register agent's identity
        if (identityRegistry.identity(agent) == address(0)) {
            identityRegistry.registerIdentity(agent, address(identity), 234);
            console.log("Registered identity for agent:", agent, "with identity contract:", address(identity));
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        uint256[] memory issuerTopics = new uint256[](2);
        issuerTopics[0] = 1;
        issuerTopics[1] = 2;
        trustedIssuersRegistry.addTrustedIssuer(agent, address(identity), issuerTopics);
        console.log("Added trusted issuer (agent):", agent, "for topics KYC and AML");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        address[] memory trustedIssuersKyc = trustedIssuersRegistry.getTrustedIssuersForClaimTopic(1);
        console.log("Trusted issuers for KYC (1):", trustedIssuersKyc.length > 0 ? trustedIssuersKyc[0] : address(0));
        address[] memory trustedIssuersAml = trustedIssuersRegistry.getTrustedIssuersForClaimTopic(2);
        console.log("Trusted issuers for AML (2):", trustedIssuersAml.length > 0 ? trustedIssuersAml[0] : address(0));
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        if (identityRegistry.identity(userAddress) == address(0)) {
            identityRegistry.registerIdentity(userAddress, address(identity), 234);
            console.log("Registered identity for user:", userAddress, "with identity contract:", address(identity));
        } else {
            console.log("User already registered with identity:", identityRegistry.identity(userAddress));
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        if (identityRegistry.identity(admin) == address(0)) {
            identityRegistry.registerIdentity(admin, address(identity), 234);
            console.log("Registered identity for admin:", admin, "with identity contract:", address(identity));
        } else {
            console.log("Admin already registered with identity:", identityRegistry.identity(admin));
        }
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        // Add KYC/AML claims for admin (signed by agent, called by admin)
        console.log("Adding KYC/AML claims for admin, signed by agent");
        // KYC claim
        bytes32 kycClaimId = keccak256(abi.encode(agent, uint256(1), admin));
        bytes memory kycData = "KYC verified";
        bytes memory kycEncodedData = abi.encode(address(identity), uint256(1), kycData);
        bytes32 kycDataHash = keccak256(kycEncodedData);
        bytes32 kycPrefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", kycDataHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPrivateKey, kycPrefixedHash);
        bytes memory kycSignature = abi.encodePacked(r, s, v);
        identity.addClaim(1, 1, agent, kycSignature, kycData, "");
        console.log("Added KYC claim for admin, claimId:", bytes32ToString(kycClaimId));

        // AML claim
        bytes32 amlClaimId = keccak256(abi.encode(agent, uint256(2), admin));
        bytes memory amlData = "AML verified";
        bytes memory amlEncodedData = abi.encode(address(identity), uint256(2), amlData);
        bytes32 amlDataHash = keccak256(amlEncodedData);
        bytes32 amlPrefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", amlDataHash));
        (v, r, s) = vm.sign(agentPrivateKey, amlPrefixedHash);
        bytes memory amlSignature = abi.encodePacked(r, s, v);
        identity.addClaim(2, 1, agent, amlSignature, amlData, "");
        console.log("Added AML claim for admin, claimId:", bytes32ToString(amlClaimId));

        // Debug: Check claims
        bytes32[] memory kycClaimIds = identity.getClaimIdsByTopic(admin, 1);
        console.log("KYC claim count for admin:", kycClaimIds.length);
        if (kycClaimIds.length > 0) {
            console.log("KYC claim ID:", bytes32ToString(kycClaimIds[0]));
        }
        bytes32[] memory amlClaimIds = identity.getClaimIdsByTopic(admin, 2);
        console.log("AML claim count for admin:", amlClaimIds.length);
        if (amlClaimIds.length > 0) {
            console.log("AML claim ID:", bytes32ToString(amlClaimIds[0]));
        }

        // Debug: Check verification status
        bool isAdminVerified = identityRegistry.isVerified(admin);
        console.log("Admin verification status:", isAdminVerified);
        require(isAdminVerified, "Admin not verified");

        // Mint tokens
        uint256 reserveAmount = vm.envUint("INITIAL_RESERVE_PROOF");
        bNgn.submitReserveProof(reserveAmount * 10 ** 18, 0, "ipfs://QmbFMke1KXqnYy1Y8bW8z1kY5Qz1Y8bW8z1kY5Qz1Y8bW8");
        console.log("Submitted reserve proof by admin:", reserveAmount, "NGN fiat-backed");
        uint256 mintAmount = reserveAmount * 10 ** 18;
        console.log("Minting", mintAmount / 10 ** 18, "bNGN to admin:", admin);
        bNgn.mint(admin, mintAmount);
        console.log("Admin bNGN balance:", bNgn.balanceOf(admin) / 10 ** 18);
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();

        vm.stopBroadcast();
    }
}
