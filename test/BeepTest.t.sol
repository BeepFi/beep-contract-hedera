// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {BeepContract} from "../src/BeepContract.sol";
import {MockERC20} from "../src/MockERC20.sol";

contract BeepContractTest is Test {
    BeepContract beep;
    address admin = address(0x1);
    address user1 = address(0x2);
    address user2 = address(0x3);
    address token1 = address(0x4);
    address token2 = address(0x5);
    address[] supportedTokens;
    string[] supportedProtocols;
    uint64 defaultTimeoutHeight = 100;

    // Mock ERC20 for testing
    MockERC20 mockToken1;
    MockERC20 mockToken2;

    function setUp() public {
        vm.startPrank(admin);
        supportedTokens = new address[](2);
        supportedTokens[0] = token1;
        supportedTokens[1] = token2;
        supportedProtocols = new string[](1);
        supportedProtocols[0] = "protocol1";
        
        mockToken1 = new MockERC20("Token1", "T1", 18);
        mockToken2 = new MockERC20("Token2", "T2", 18);
        supportedTokens[0] = address(mockToken1);
        supportedTokens[1] = address(mockToken2);
        
        beep = new BeepContract(supportedTokens, supportedProtocols, defaultTimeoutHeight);
        vm.stopPrank();

        // Fund users with tokens
        mockToken1.mint(user1, 1000 ether);
        mockToken2.mint(user1, 1000 ether);
        mockToken1.mint(user2, 1000 ether);
        mockToken2.mint(user2, 1000 ether);
    }

    function testConstructor() public view {
        assertEq(beep.getConfig().admin, admin);
        assertEq(beep.getConfig().supportedTokens.length, 2);
        assertEq(beep.getConfig().supportedProtocols.length, 1);
        assertEq(beep.getConfig().defaultTimeoutHeight, defaultTimeoutHeight);
    }

    function testCreateIntentWithNativeToken() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory inputTokens = new BeepContract.BeepCoin[](1);
        inputTokens[0] = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 1 ether
        });
        BeepContract.ExpectedToken[] memory outputTokens = new BeepContract.ExpectedToken[](1);
        outputTokens[0] = BeepContract.ExpectedToken({
            token: address(mockToken1),
            isNative: false,
            amount: 100,
            targetAddress: user1
        });
        BeepContract.BeepCoin memory tip = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 0.1 ether
        });

        uint256 fee = beep.calculateFee(BeepContract.Priority.Normal);
        string memory id = beep.createIntent{value: 1.1 ether + fee}(
            inputTokens,
            outputTokens,
            0,
            tip,
            false,
            BeepContract.Priority.Normal,
            false
        );

        BeepContract.Intent memory intent = beep.getIntent(id);
        assertEq(intent.creator, user1);
        assertEq(intent.inputTokens.length, 1);
        assertEq(intent.outputTokens.length, 1);
        assertEq(uint8(intent.status), uint8(BeepContract.IntentStatus.Active));
        assertEq(intent.tip.amount, 0.1 ether);
        vm.stopPrank();
    }

    function testCreateIntentWithERC20() public {
        vm.startPrank(user1);
        mockToken1.approve(address(beep), 100);
        BeepContract.BeepCoin[] memory inputTokens = new BeepContract.BeepCoin[](1);
        inputTokens[0] = BeepContract.BeepCoin({
            token: address(mockToken1),
            isNative: false,
            amount: 100
        });
        BeepContract.ExpectedToken[] memory outputTokens = new BeepContract.ExpectedToken[](1);
        outputTokens[0] = BeepContract.ExpectedToken({
            token: address(mockToken2),
            isNative: false,
            amount: 100,
            targetAddress: user1
        });
        BeepContract.BeepCoin memory tip = BeepContract.BeepCoin({
            token: address(mockToken1),
            isNative: false,
            amount: 10
        });

        mockToken1.approve(address(beep), 110);
        uint256 fee = beep.calculateFee(BeepContract.Priority.Normal);
        string memory id = beep.createIntent{value: fee}(
            inputTokens,
            outputTokens,
            0,
            tip,
            false,
            BeepContract.Priority.Normal,
            false
        );

        assertEq(beep.getIntent(id).creator, user1);
        vm.stopPrank();
    }

    function testFillIntent() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory inputTokens = new BeepContract.BeepCoin[](1);
        inputTokens[0] = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 1 ether
        });
        BeepContract.ExpectedToken[] memory outputTokens = new BeepContract.ExpectedToken[](1);
        outputTokens[0] = BeepContract.ExpectedToken({
            token: address(mockToken1),
            isNative: false,
            amount: 100,
            targetAddress: user1
        });
        BeepContract.BeepCoin memory tip = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 0.1 ether
        });

        uint256 fee = beep.calculateFee(BeepContract.Priority.Normal);
        string memory id = beep.createIntent{value: 1.1 ether + fee}(
            inputTokens,
            outputTokens,
            0,
            tip,
            false,
            BeepContract.Priority.Normal,
            false
        );
        vm.stopPrank();

        vm.startPrank(user2);
        mockToken1.approve(address(beep), 100);
        uint256 balanceBefore = mockToken1.balanceOf(user2);
        beep.fillIntent{value: fee}(id, false, false);
        assertEq(uint8(beep.getIntent(id).status), uint8(BeepContract.IntentStatus.Completed));
        assertEq(beep.getIntent(id).executor, user2);
        assertEq(mockToken1.balanceOf(user2), balanceBefore - 100);
        vm.stopPrank();
    }

    function testCancelIntent() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory inputTokens = new BeepContract.BeepCoin[](1);
        inputTokens[0] = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 1 ether
        });
        BeepContract.ExpectedToken[] memory outputTokens = new BeepContract.ExpectedToken[](1);
        outputTokens[0] = BeepContract.ExpectedToken({
            token: address(mockToken1),
            isNative: false,
            amount: 100,
            targetAddress: user1
        });
        BeepContract.BeepCoin memory tip = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 0.1 ether
        });

        uint256 fee = beep.calculateFee(BeepContract.Priority.Normal);
        string memory id = beep.createIntent{value: 1.1 ether + fee}(
            inputTokens,
            outputTokens,
            0,
            tip,
            false,
            BeepContract.Priority.Normal,
            false
        );

        uint256 balanceBefore = user1.balance;
        beep.cancelIntent{value: fee}(id, false);
        assertEq(uint8(beep.getIntent(id).status), uint8(BeepContract.IntentStatus.Cancelled));
        assertEq(user1.balance, balanceBefore + 1.1 ether);
        vm.stopPrank();
    }

    function testWithdrawExpiredIntent() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory inputTokens = new BeepContract.BeepCoin[](1);
        inputTokens[0] = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 1 ether
        });
        BeepContract.ExpectedToken[] memory outputTokens = new BeepContract.ExpectedToken[](1);
        outputTokens[0] = BeepContract.ExpectedToken({
            token: address(mockToken1),
            isNative: false,
            amount: 100,
            targetAddress: user1
        });
        BeepContract.BeepCoin memory tip = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 0.1 ether
        });

        uint256 fee = beep.calculateFee(BeepContract.Priority.Normal);
        string memory id = beep.createIntent{value: 1.1 ether + fee}(
            inputTokens,
            outputTokens,
            10,
            tip,
            false,
            BeepContract.Priority.Normal,
            false
        );
        vm.stopPrank();

        vm.roll(block.number + 11); // Move past timeout
        vm.startPrank(user1);
        uint256 balanceBefore = user1.balance;
        beep.withdrawIntentFund{value: fee}(id, false);
        assertEq(uint8(beep.getIntent(id).status), uint8(BeepContract.IntentStatus.Expired));
        assertEq(user1.balance, balanceBefore + 1.1 ether);
        vm.stopPrank();
    }

    function testDepositToWallet() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory tokens = new BeepContract.BeepCoin[](2);
        tokens[0] = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 1 ether
        });
        tokens[1] = BeepContract.BeepCoin({
            token: address(mockToken1),
            isNative: false,
            amount: 100
        });

        mockToken1.approve(address(beep), 100);
        beep.depositToWallet{value: 1 ether}(tokens);
        BeepContract.BeepCoin[] memory balances = beep.getWalletBalance(user1);
        assertEq(balances.length, 2);
        assertEq(balances[0].amount, 1 ether);
        assertEq(balances[1].amount, 100);
        vm.stopPrank();
    }

    function testTransferFromWallet() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory tokens = new BeepContract.BeepCoin[](1);
        tokens[0] = BeepContract.BeepCoin({
            token: address(mockToken1),
            isNative: false,
            amount: 100
        });
        mockToken1.approve(address(beep), 100);
        beep.depositToWallet(tokens);

        uint256 balanceBefore = mockToken1.balanceOf(user2);
        beep.transferFromWallet(user2, tokens);
        assertEq(mockToken1.balanceOf(user2), balanceBefore + 100);
        vm.stopPrank();
    }

    function testUpdateAdmin() public {
        vm.startPrank(admin);
        address newAdmin = address(0x6);
        beep.updateAdmin(newAdmin);
        assertEq(beep.getConfig().admin, newAdmin);
        vm.stopPrank();
    }

    function testFailUnauthorizedAdminUpdate() public {
        vm.startPrank(user1);
        vm.expectRevert(BeepContract.Unauthorized.selector);
        beep.updateAdmin(user2);
        vm.stopPrank();
    }

    function testFailInsufficientMsgValue() public {
        vm.startPrank(user1);
        BeepContract.BeepCoin[] memory inputTokens = new BeepContract.BeepCoin[](1);
        inputTokens[0] = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 1 ether
        });
        BeepContract.ExpectedToken[] memory outputTokens = new BeepContract.ExpectedToken[](1);
        outputTokens[0] = BeepContract.ExpectedToken({
            token: address(mockToken1),
            isNative: false,
            amount: 100,
            targetAddress: user1
        });
        BeepContract.BeepCoin memory tip = BeepContract.BeepCoin({
            token: address(0),
            isNative: true,
            amount: 0.1 ether
        });

        vm.expectRevert(BeepContract.InsufficientMsgValue.selector);
        beep.createIntent{value: 0.5 ether}(inputTokens, outputTokens, 0, tip, false, BeepContract.Priority.Normal, false);
        vm.stopPrank();
    }
}
