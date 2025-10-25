// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {Identity} from "../src/Identity.sol";

/**
 * @title UserOnboardingScript
 * @notice Automated script for onboarding new users to bNGN system with a new Identity contract per user
 * @dev Deploys a new Identity contract, registers identity, and issues KYC/AML claims
 *
 * USAGE:
 * 1. Set environment variables:
 *    - AGENT_PRIVATE_KEY: Agent's private key (has signing authority)
 *    - NEW_USER_ADDRESS: Address of user to onboard
 *    - IDENTITY_REGISTRY: IdentityRegistry contract address
 *    - USER_COUNTRY_CODE: ISO 3166-1 numeric code (234 for Nigeria)
 *    - KYC_VERIFICATION_DATA: JSON string with KYC proof
 *    - AML_VERIFICATION_DATA: JSON string with AML proof
 *
 * 2. Run: forge script script/UserOnboarding.s.sol:UserOnboardingScript --rpc-url $RPC_URL --broadcast
 */
contract UserOnboardingScript is Script {
    IdentityRegistry public identityRegistry;
    Identity public userIdentity; // New Identity contract for the user
    address public agent;
    uint256 public agentPrivateKey;
    address public newUserAddress;
    uint16 public userCountryCode;
    string public kycData;
    string public amlData;
    uint256 constant KYC_TOPIC = 1;
    uint256 constant AML_TOPIC = 2;
    uint256 constant CLAIM_SCHEME_ECDSA = 1;

    function run() external {
        loadEnvironmentVariables();
        vm.startBroadcast(agentPrivateKey);
        console.log("\n=== STARTING USER ONBOARDING PROCESS ===\n");
        verifyPrerequisites();
        deployUserIdentity();
        registerUserIdentity();
        issueKycClaim();
        issueAmlClaim();
        verifyUserStatus();
        console.log("\n=== USER ONBOARDING COMPLETED ===\n");
        console.log("New Identity Contract:", address(userIdentity));
        vm.stopBroadcast();
    }

    function loadEnvironmentVariables() internal {
        console.log("Loading configuration...");
        agentPrivateKey = vm.envUint("AGENT_PRIVATE_KEY");
        agent = vm.addr(agentPrivateKey);
        console.log("Agent address:", agent);
        newUserAddress = vm.envAddress("NEW_USER_ADDRESS");
        console.log("New user address:", newUserAddress);
        address identityRegistryAddr = vm.envAddress("IDENTITY_REGISTRY");
        identityRegistry = IdentityRegistry(identityRegistryAddr);
        console.log("IdentityRegistry:", address(identityRegistry));
        userCountryCode = uint16(vm.envUint("USER_COUNTRY_CODE"));
        console.log("Country code:", userCountryCode);
        kycData = vm.envString("KYC_VERIFICATION_DATA");
        amlData = vm.envString("AML_VERIFICATION_DATA");
        console.log("\n");
    }

    function verifyPrerequisites() internal view {
        console.log("Step 1: Verifying prerequisites...");
        bytes32 agentRole = identityRegistry.AGENT_ROLE();
        require(identityRegistry.hasRole(agentRole, agent), "Agent does not have AGENT_ROLE in IdentityRegistry");
        console.log("  [OK] Agent has AGENT_ROLE");
        require(!identityRegistry.contains(newUserAddress), "User already registered");
        console.log("  [OK] User not yet registered");
        console.log("\n");
    }

    function deployUserIdentity() internal {
        console.log("Step 2: Deploying new Identity contract for user...");
        console.log("  User:", newUserAddress);
        userIdentity = new Identity(newUserAddress);
        console.log("  New Identity contract deployed to:", address(userIdentity));
        // Grant agent CLAIM_SIGNER_KEY (purpose 3) on the new Identity contract
        userIdentity.addKey(keccak256(abi.encode(agent)), 3, 1);
        console.log("  [OK] Granted CLAIM_SIGNER_KEY to agent:", agent);
        require(userIdentity.keyHasPurpose(keccak256(abi.encode(agent)), 3), "Agent CLAIM_SIGNER_KEY not set");
        console.log("  [VERIFIED] Agent has CLAIM_SIGNER_KEY");
        console.log("\n");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();
    }

    function registerUserIdentity() internal {
        console.log("Step 3: Registering user identity...");
        console.log("  User:", newUserAddress);
        console.log("  Identity contract:", address(userIdentity));
        console.log("  Country:", userCountryCode);
        identityRegistry.registerIdentity(newUserAddress, address(userIdentity), userCountryCode);
        console.log("  [SUCCESS] User registered in IdentityRegistry");
        require(identityRegistry.contains(newUserAddress), "Registration failed");
        require(identityRegistry.identity(newUserAddress) == address(userIdentity), "Identity mismatch");
        require(identityRegistry.investorCountry(newUserAddress) == userCountryCode, "Country mismatch");
        console.log("  [VERIFIED] Registration successful");
        console.log("\n");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();
    }

    function issueKycClaim() internal {
        console.log("Step 4: Issuing KYC claim...");
        console.log("  Verification data:", kycData);
        bytes memory kycSignature = createClaimSignature(KYC_TOPIC, bytes(kycData), newUserAddress);
        bytes32 expectedClaimId = keccak256(abi.encode(agent, KYC_TOPIC, newUserAddress, bytes(kycData)));
        console.log("  Expected Claim ID:", bytes32ToString(expectedClaimId));
        bytes32 claimId = userIdentity.addClaim(
            newUserAddress, KYC_TOPIC, CLAIM_SCHEME_ECDSA, agent, kycSignature, bytes(kycData), ""
        );
        console.log("  [SUCCESS] KYC claim issued");
        console.log("  Claim ID:", bytes32ToString(claimId));
        bytes32[] memory kycClaims = userIdentity.getClaimIdsByTopic(newUserAddress, KYC_TOPIC);
        console.log("  KYC claims found:", kycClaims.length);
        for (uint256 i = 0; i < kycClaims.length; i++) {
            console.log("  Claim ID:", bytes32ToString(kycClaims[i]));
        }
        require(kycClaims.length > 0, "KYC claim not found");
        console.log("  [VERIFIED] KYC claim stored");
        console.log("\n");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();
    }

    function issueAmlClaim() internal {
        console.log("Step 5: Issuing AML claim...");
        console.log("  Verification data:", amlData);
        bytes memory amlSignature = createClaimSignature(AML_TOPIC, bytes(amlData), newUserAddress);
        bytes32 claimId = userIdentity.addClaim(
            newUserAddress, AML_TOPIC, CLAIM_SCHEME_ECDSA, agent, amlSignature, bytes(amlData), ""
        );
        console.log("  [SUCCESS] AML claim issued");
        console.log("  Claim ID:", bytes32ToString(claimId));
        bytes32[] memory amlClaims = userIdentity.getClaimIdsByTopic(newUserAddress, AML_TOPIC);
        require(amlClaims.length > 0, "AML claim not found");
        console.log("  [VERIFIED] AML claim stored");
        console.log("\n");
        vm.pauseGasMetering();
        vm.sleep(2000);
        vm.resumeGasMetering();
    }

    function verifyUserStatus() internal view {
        console.log("Step 6: Verifying user status...");
        bool isVerified = identityRegistry.isVerified(newUserAddress);
        if (isVerified) {
            console.log("  [SUCCESS] User is VERIFIED");
            console.log("  User can now receive and transfer bNGN tokens");
        } else {
            console.log("  [FAILED] User verification incomplete");
            console.log("  User cannot transact bNGN tokens yet");
            revert("User verification failed");
        }
        console.log("\n--- USER PROFILE ---");
        console.log("Address:", newUserAddress);
        console.log("Identity Contract:", identityRegistry.identity(newUserAddress));
        console.log("Country Code:", identityRegistry.investorCountry(newUserAddress));
        console.log("Verification Status:", isVerified ? "VERIFIED" : "NOT VERIFIED");
        bytes32[] memory kycClaims = userIdentity.getClaimIdsByTopic(newUserAddress, KYC_TOPIC);
        bytes32[] memory amlClaims = userIdentity.getClaimIdsByTopic(newUserAddress, AML_TOPIC);
        console.log("KYC Claims:", kycClaims.length);
        console.log("AML Claims:", amlClaims.length);
        console.log("-------------------\n");
    }

    function createClaimSignature(uint256 topic, bytes memory data, address user)
        internal
        view
        returns (bytes memory)
    {
        bytes memory encodedData = abi.encode(agent, topic, user, data);
        bytes32 dataHash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, encodedData)
            dataHash := keccak256(ptr, mload(encodedData))
            mstore(0x40, add(ptr, mload(encodedData)))
        }
        bytes32 prefixedHash;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19Ethereum Signed Message:\n32")
            mstore(add(ptr, 52), dataHash)
            prefixedHash := keccak256(ptr, 84)
            mstore(0x40, add(ptr, 84))
        }
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPrivateKey, prefixedHash);
        return abi.encodePacked(r, s, v);
    }

    function bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
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
}

/**
 * @title BatchUserOnboardingScript
 * @notice Onboard multiple users in a single script execution
 * @dev Gas-efficient batch processing for KYC operations
 *
 * USAGE:
 * 1. Create users.json file with user data or set USERS_JSON env var:
 * [
 *   {
 *     "address": "0x742d35Cc6...",
 *     "countryCode": 234,
 *     "kycData": "KYC verified - NIN: 12345678901",
 *     "amlData": "AML clear - No sanctions matches"
 *   },
 *   ...
 * ]
 *
 * 2. Set environment variables:
 *    - AGENT_PRIVATE_KEY
 *    - IDENTITY_REGISTRY
 *    - IDENTITY_CONTRACT
 *    - USERS_JSON (JSON string or file path with user data)
 *
 * 3. Run: forge script script/UserOnboarding.s.sol:BatchUserOnboardingScript --rpc-url $RPC_URL --broadcast
 */
contract BatchUserOnboardingScript is Script {
    IdentityRegistry public identityRegistry;
    Identity public sharedIdentity;
    address public agent;
    uint256 public agentPrivateKey;

    struct UserData {
        address userAddress;
        uint16 countryCode;
        string kycData;
        string amlData;
    }

    uint256 constant KYC_TOPIC = 1;
    uint256 constant AML_TOPIC = 2;
    uint256 constant CLAIM_SCHEME_ECDSA = 1;

    function run() external {
        agentPrivateKey = vm.envUint("AGENT_PRIVATE_KEY");
        agent = vm.addr(agentPrivateKey);
        address identityRegistryAddr = vm.envAddress("IDENTITY_REGISTRY");
        identityRegistry = IdentityRegistry(identityRegistryAddr);
        address sharedIdentityAddr = vm.envAddress("IDENTITY_CONTRACT");
        sharedIdentity = Identity(sharedIdentityAddr);
        UserData[] memory users = loadUsersFromEnv();
        vm.startBroadcast(agentPrivateKey);
        console.log("\n=== BATCH USER ONBOARDING ===");
        console.log("Agent:", agent);
        console.log("Total users:", users.length);
        console.log("\n");
        uint256 successCount = 0;
        uint256 skipCount = 0;
        for (uint256 i = 0; i < users.length; i++) {
            console.log(
                string(
                    abi.encodePacked(
                        "--- Processing user ", vm.toString(i + 1), " of ", vm.toString(users.length), " ---"
                    )
                )
            );
            bool success = onboardUser(users[i]);
            if (success) {
                successCount++;
                console.log("[SUCCESS]\n");
            } else {
                skipCount++;
                console.log("[SKIPPED]\n");
            }
            if (i < users.length - 1) {
                vm.pauseGasMetering();
                vm.sleep(2000);
                vm.resumeGasMetering();
            }
        }
        console.log("\n=== BATCH ONBOARDING SUMMARY ===");
        console.log("Total processed:", users.length);
        console.log("Successfully onboarded:", successCount);
        console.log("Skipped (already registered):", skipCount);
        console.log("===============================\n");
        vm.stopBroadcast();
    }

    function loadUsersFromEnv() internal view returns (UserData[] memory) {
        string memory usersJson = vm.envString("USERS_JSON");
        bytes memory encodedUsers = vm.parseJson(usersJson);
        UserData[] memory users = abi.decode(encodedUsers, (UserData[]));
        return users;
    }

    function onboardUser(UserData memory user) internal returns (bool) {
        console.log("  User:", user.userAddress);
        console.log("  Country:", user.countryCode);
        if (identityRegistry.contains(user.userAddress)) {
            console.log("  [INFO] User already registered");
            bool verified = identityRegistry.isVerified(user.userAddress);
            console.log("  [INFO] Verification status:", verified ? "VERIFIED" : "NOT VERIFIED");
            return false;
        }
        identityRegistry.registerIdentity(user.userAddress, address(sharedIdentity), user.countryCode);
        console.log("  [OK] Identity registered");
        bytes memory kycSig = createClaimSignature(KYC_TOPIC, bytes(user.kycData), user.userAddress);
        sharedIdentity.addClaim(user.userAddress, KYC_TOPIC, CLAIM_SCHEME_ECDSA, agent, kycSig, bytes(user.kycData), "");
        console.log("  [OK] KYC claim issued");
        bytes memory amlSig = createClaimSignature(AML_TOPIC, bytes(user.amlData), user.userAddress);
        sharedIdentity.addClaim(user.userAddress, AML_TOPIC, CLAIM_SCHEME_ECDSA, agent, amlSig, bytes(user.amlData), "");
        console.log("  [OK] AML claim issued");
        bool isVerified = identityRegistry.isVerified(user.userAddress);
        console.log("  [VERIFY] Status:", isVerified ? "VERIFIED" : "NOT VERIFIED");
        if (!isVerified) {
            console.log("  [ERROR] Verification failed!");
            revert("User verification failed");
        }
        return true;
    }

    function createClaimSignature(uint256 topic, bytes memory data, address user)
        internal
        view
        returns (bytes memory)
    {
        bytes memory encodedData = abi.encode(agent, topic, user, data);
        bytes32 dataHash = keccak256(encodedData);
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPrivateKey, prefixedHash);
        return abi.encodePacked(r, s, v);
    }
}

/**
 * @title RevokeUserAccessScript
 * @notice Revoke KYC/AML claims for users (compliance enforcement)
 * @dev Used when user fails re-verification or for regulatory actions
 *
 * USAGE:
 * Set env vars: AGENT_PRIVATE_KEY, IDENTITY_CONTRACT, USER_TO_REVOKE
 * Run: forge script script/UserOnboarding.s.sol:RevokeUserAccessScript --rpc-url $RPC_URL --broadcast
 */
contract RevokeUserAccessScript is Script {
    Identity public sharedIdentity;
    IdentityRegistry public identityRegistry; // Added missing state variable
    address public agent;
    uint256 public agentPrivateKey;
    address public userToRevoke;

    uint256 constant KYC_TOPIC = 1;
    uint256 constant AML_TOPIC = 2;

    function run() external {
        // Load configuration
        agentPrivateKey = vm.envUint("AGENT_PRIVATE_KEY");
        agent = vm.addr(agentPrivateKey);

        address identityRegistryAddr = vm.envAddress("IDENTITY_REGISTRY");
        identityRegistry = IdentityRegistry(identityRegistryAddr);

        address sharedIdentityAddr = vm.envAddress("IDENTITY_CONTRACT");
        sharedIdentity = Identity(sharedIdentityAddr);

        userToRevoke = vm.envAddress("USER_TO_REVOKE");

        vm.startBroadcast(agentPrivateKey);

        console.log("\n=== REVOKING USER ACCESS ===");
        console.log("Agent:", agent);
        console.log("User:", userToRevoke);
        console.log("\n");

        // Get existing claims
        bytes32[] memory kycClaims = sharedIdentity.getClaimIdsByTopic(userToRevoke, KYC_TOPIC);
        bytes32[] memory amlClaims = sharedIdentity.getClaimIdsByTopic(userToRevoke, AML_TOPIC);

        console.log("KYC claims to revoke:", kycClaims.length);
        console.log("AML claims to revoke:", amlClaims.length);

        // Remove KYC claims
        for (uint256 i = 0; i < kycClaims.length; i++) {
            sharedIdentity.removeClaim(userToRevoke, kycClaims[i]);
            console.log("  [OK] Removed KYC claim", i + 1);
        }

        // Remove AML claims
        for (uint256 i = 0; i < amlClaims.length; i++) {
            sharedIdentity.removeClaim(userToRevoke, amlClaims[i]);
            console.log("  [OK] Removed AML claim", i + 1);
        }

        console.log("\n[SUCCESS] User access revoked");
        console.log("User can no longer transact bNGN tokens\n");

        vm.stopBroadcast();
    }
}

/**
 * @title VerifyUserStatusScript
 * @notice Check verification status of one or more users
 * @dev Read-only script for testing purposes
 *
 * USAGE:
 * Set env vars: IDENTITY_REGISTRY, IDENTITY_CONTRACT, CHECK_USER_ADDRESS
 * Run: forge script script/UserOnboarding.s.sol:VerifyUserStatusScript --rpc-url $RPC_URL
 */
contract VerifyUserStatusScript is Script {
    IdentityRegistry public identityRegistry;
    Identity public sharedIdentity;

    function run() external {
        address identityRegistryAddr = vm.envAddress("IDENTITY_REGISTRY");
        identityRegistry = IdentityRegistry(identityRegistryAddr);

        address sharedIdentityAddr = vm.envAddress("IDENTITY_CONTRACT");
        sharedIdentity = Identity(sharedIdentityAddr);

        address userAddress = vm.envAddress("CHECK_USER_ADDRESS");

        console.log("\n=== USER VERIFICATION STATUS ===\n");

        checkUserStatus(userAddress);

        console.log("\n================================\n");
    }

    function checkUserStatus(address user) internal view {
        console.log("User Address:", user);

        // Check if registered
        bool isRegistered = identityRegistry.contains(user);
        console.log("Registered:", isRegistered ? "YES" : "NO");

        if (!isRegistered) {
            console.log("Status: NOT ONBOARDED");
            return;
        }

        // Get identity contract
        address identityAddr = identityRegistry.identity(user);
        console.log("Identity Contract:", identityAddr);

        // Get country
        uint16 country = identityRegistry.investorCountry(user);
        console.log("Country Code:", country);

        // Check claims
        bytes32[] memory kycClaims = sharedIdentity.getClaimIdsByTopic(user, 1);
        bytes32[] memory amlClaims = sharedIdentity.getClaimIdsByTopic(user, 2);

        console.log("\nClaims:");
        console.log("  KYC Claims:", kycClaims.length);
        console.log("  AML Claims:", amlClaims.length);

        // Check verification
        bool isVerified = identityRegistry.isVerified(user);
        console.log("\nVerification Status:", isVerified ? unicode"VERIFIED ✓" : unicode"NOT VERIFIED ✗");

        if (isVerified) {
            console.log("Status: CAN TRANSACT bNGN");
        } else {
            console.log("Status: CANNOT TRANSACT bNGN");

            if (kycClaims.length == 0) {
                console.log("Reason: Missing KYC claim");
            }
            if (amlClaims.length == 0) {
                console.log("Reason: Missing AML claim");
            }
        }
    }
}
