// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

event TokenBound(address _token);

event TokenUnbound(address _token);

interface IERC3643Compliance {
    function bindToken(address _token) external;
    function unbindToken(address _token) external;
    function transferred(address _from, address _to, uint256 _amount) external;
    function created(address _to, uint256 _amount) external;
    function destroyed(address _from, uint256 _amount) external;
    function canTransfer(address _from, address _to, uint256 _amount) external view returns (bool);
    function isTokenBound(address _token) external view returns (bool);
    function getTokenBound() external view returns (address);
}
