// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ICompliance {
    function canTransfer(address _from, address _to, uint256 _amount) external view returns (bool);
    function transferred(address _from, address _to, uint256 _amount) external;
    function created(address _to, uint256 _amount) external;
    function destroyed(address _from, uint256 _amount) external;
    function bindToken(address _token) external;
    function unbindToken(address _token) external;
    function isTokenAgent(address _agentAddress) external view returns (bool);
    function isTokenBound(address _token) external view returns (bool);
}