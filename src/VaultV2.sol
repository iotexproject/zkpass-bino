// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VaultV2 is Ownable, ReentrancyGuard {
    using Address for address payable;

    error ExistsClaimer(address account);
    error NonClaimer(address account);

    event AddClaimer(address indexed claimer);
    event RemoveClaimer(address indexed claimer);
    event Claim(address indexed claimer, address indexed token, address indexed account, uint256 amount);

    mapping(address => bool) public claimer;

    constructor() Ownable(msg.sender) {}

    function addClaimer(address _claimer) external onlyOwner {
        if (claimer[_claimer]) {
            revert ExistsClaimer(_claimer);
        }

        claimer[_claimer] = true;
        emit AddClaimer(_claimer);
    }

    function removeClaimer(address _claimer) external onlyOwner {
        if (!claimer[_claimer]) {
            revert NonClaimer(_claimer);
        }

        claimer[_claimer] = false;
        emit RemoveClaimer(_claimer);
    }

    function claim(address _token, address _recipient, uint256 _amount) external nonReentrant {
        if (!claimer[msg.sender]) {
            revert NonClaimer(msg.sender);
        }
        if (_token == address(0)) {
            payable(_recipient).sendValue(_amount);
        } else {
            (bool success, ) = _token.call(abi.encodeWithSignature("transfer(address,uint256)", _recipient, _amount));
            require(success, "Vault: transfer failed");
        }
        emit Claim(msg.sender, _token, _recipient, _amount);
    }

    function withdraw() external onlyOwner {
        payable(msg.sender).sendValue(address(this).balance);
    }

    function withdrawToken(address _token) external onlyOwner {
        (bool success, ) = _token.call(abi.encodeWithSignature("transfer(address,uint256)", msg.sender, IERC20(_token).balanceOf(address(this))));
        require(success, "Vault: transfer failed");
    }

    receive() external payable {}
}
