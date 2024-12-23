// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

interface IVault {
    function claim(address _recipient, uint256 _amount) external;
}

contract VerifingClaimer is Ownable {
    using ECDSA for bytes32;

    error InvalidEndTimestamp();
    error ZeroAddress();
    error ClaimEnded();
    error ClaimedAccount(address account);
    error ClaimedProof();
    error InvalidRewardProof();
    error InvalidValidator(address validator);

    event ChangeValidator(address indexed validator);
    event Claim(address indexed account, uint256 amount);

    IVault public immutable vault;
    bytes32 public immutable rewardRoot;
    uint256 public immutable endTimestamp;
    address public validator;
    mapping(address => bool) public claimedAccount;
    mapping(bytes32 => bool) public claimedProof;

    constructor(address _vault, address _validator, bytes32 _root, uint256 _endTimestamp) Ownable(msg.sender) {
        if (_endTimestamp < block.timestamp) {
            revert InvalidEndTimestamp();
        }

        vault = IVault(_vault);
        validator = _validator;
        rewardRoot = _root;
    }

    function changeValidator(address _validator) external onlyOwner {
        if (_validator == address(0)) {
            revert ZeroAddress();
        }

        validator = _validator;
        emit ChangeValidator(_validator);
    }

    function claim(
        address _account,
        bool _doubleCheck,
        uint256 _amount,
        bytes calldata signature,
        bytes32[] calldata _rewardProof
    ) external {
        if (endTimestamp < block.timestamp) {
            revert ClaimEnded();
        }
        if (claimedAccount[_account]) {
            revert ClaimedAccount(_account);
        }
        bytes32 node = keccak256(abi.encodePacked(_account, _doubleCheck, _amount));
        if (_doubleCheck) {
            address _validator = node.recover(signature);
            if (_validator != validator) {
                revert InvalidValidator(_validator);
            }
        }
        if (!MerkleProof.verify(_rewardProof, rewardRoot, node)) {
            revert InvalidRewardProof();
        }

        claimedAccount[_account] = true;
        vault.claim(_account, _amount);
        emit Claim(_account, _amount);
    }
}
