// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is Ownable, ReentrancyGuard {
    using Address for address payable;

    error ExistsClaimer(address account);
    error NonClaimer(address account);

    event AddClaimer(address indexed claimer);
    event RemoveClaimer(address indexed claimer);
    event Claim(address indexed claimer, address indexed account, uint256 amount);

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

    function claim(address _recipient, uint256 _amount) external nonReentrant {
        if (!claimer[msg.sender]) {
            revert NonClaimer(msg.sender);
        }

        payable(_recipient).sendValue(_amount);
        emit Claim(msg.sender, _recipient, _amount);
    }

    function withdraw() external onlyOwner {
        payable(msg.sender).sendValue(address(this).balance);
    }

    receive() external payable {}
}
