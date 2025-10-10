// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ICompliance} from "../src/ERC3643.sol";

contract MockCompliance is ICompliance {
    // Mapping to store transfer permissions
    mapping(address => mapping(address => mapping(uint256 => bool))) private _canTransfer;
    // Mapping to store bound tokens
    mapping(address => bool) private _boundTokens;
    // Mapping to store token agents
    mapping(address => bool) private _tokenAgents;
    // Struct to track transfer/creation/destruction events
    struct Operation {
        address from;
        address to;
        uint256 amount;
        uint256 timestamp;
    }

    // Arrays to store operations
    Operation[] public transfers;
    Operation[] public creations;
    Operation[] public destructions;

    // Events for debugging
    event CanTransferSet(address indexed from, address indexed to, uint256 amount, bool allowed);
    event Transferred(address indexed from, address indexed to, uint256 amount);
    event Created(address indexed to, uint256 amount);
    event Destroyed(address indexed from, uint256 amount);
    event TokenBound(address indexed token);
    event TokenUnbound(address indexed token);
    event TokenAgentSet(address indexed agent, bool isAgent);

    // Function to set transfer permission (for testing)
    function setCanTransfer(address from, address to, uint256 amount, bool allowed) external {
        _canTransfer[from][to][amount] = allowed;
        emit CanTransferSet(from, to, amount, allowed);
    }

    // Function to set token agent status (for testing)
    function setTokenAgent(address agentAddress, bool isAgent) external {
        _tokenAgents[agentAddress] = isAgent;
        emit TokenAgentSet(agentAddress, isAgent);
    }

    // ICompliance interface implementations

    /**
     * @notice Check if a transfer is allowed
     * @param _from Sender address
     * @param _to Receiver address
     * @param _amount Amount to transfer
     * @return bool Whether the transfer is allowed
     */
    function canTransfer(address _from, address _to, uint256 _amount) external view override returns (bool) {
        return _canTransfer[_from][_to][_amount];
    }

    /**
     * @notice Record a transfer operation
     * @param _from Sender address
     * @param _to Receiver address
     * @param _amount Amount transferred
     */
    function transferred(address _from, address _to, uint256 _amount) external override {
        transfers.push(Operation({
            from: _from,
            to: _to,
            amount: _amount,
            timestamp: block.timestamp
        }));
        emit Transferred(_from, _to, _amount);
    }

    /**
     * @notice Record a token creation operation
     * @param _to Receiver address
     * @param _amount Amount created
     */
    function created(address _to, uint256 _amount) external override {
        creations.push(Operation({
            from: address(0),
            to: _to,
            amount: _amount,
            timestamp: block.timestamp
        }));
        emit Created(_to, _amount);
    }

    /**
     * @notice Record a token destruction operation
     * @param _from Sender address
     * @param _amount Amount destroyed
     */
    function destroyed(address _from, uint256 _amount) external override {
        destructions.push(Operation({
            from: _from,
            to: address(0),
            amount: _amount,
            timestamp: block.timestamp
        }));
        emit Destroyed(_from, _amount);
    }

    /**
     * @notice Bind a token to the compliance contract
     * @param _token Token address to bind
     */
    function bindToken(address _token) external override {
        require(_token != address(0), "Invalid token address");
        require(!_boundTokens[_token], "Token already bound");

        _boundTokens[_token] = true;
        emit TokenBound(_token);
    }

    /**
     * @notice Unbind a token from the compliance contract
     * @param _token Token address to unbind
     */
    function unbindToken(address _token) external override {
        require(_token != address(0), "Invalid token address");
        require(_boundTokens[_token], "Token not bound");

        _boundTokens[_token] = false;
        emit TokenUnbound(_token);
    }

    /**
     * @notice Check if an address is a token agent
     * @param _agentAddress Address to check
     * @return bool Whether the address is a token agent
     */
    function isTokenAgent(address _agentAddress) external view override returns (bool) {
        return _tokenAgents[_agentAddress];
    }

    /**
     * @notice Check if a token is bound to the compliance contract
     * @param _token Token address to check
     * @return bool Whether the token is bound
     */
    function isTokenBound(address _token) external view override returns (bool) {
        return _boundTokens[_token];
    }

    // Helper functions to inspect operations (for testing)
    function getTransferCount() external view returns (uint256) {
        return transfers.length;
    }

    function getCreationCount() external view returns (uint256) {
        return creations.length;
    }

    function getDestructionCount() external view returns (uint256) {
        return destructions.length;
    }
}
