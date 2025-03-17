// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Proof} from "./zkpass/Common.sol";
import {ProofVerifier} from "./zkpass/ProofVerifier.sol";

interface IVaultV2 {
    function claim(address _token, address _recipient, uint256 _amount) external;
}

contract VerifingClaimerV2 is Ownable {
    using ECDSA for bytes32;

    error InvalidEndTimestamp();
    error ZeroAddress();
    error ClaimEnded();
    error ClaimedAccount(address account);
    error ClaimedZkId(bytes32 zkId);
    error InvalidRewardProof();
    error InvalidValidator(address validator);
    error InvalidZKPassProof();

    event EndTimestampExtended(uint256 endTimestamp);
    event ChangeValidator(address indexed validator);
    event Claim(address indexed token, address indexed account, uint256 amount);

    IVaultV2 public immutable vault;
    bytes32 public immutable rewardRoot;
    uint256 public endTimestamp;
    address public validator;
    address public proofVerifier;
    address public rewardToken;
    mapping(address => bool) public claimedAccount;
    mapping(bytes32 => bool) public claimedZkId;

    constructor(address _vault, address _validator, address _proofVerifier, address _token, bytes32 _root, uint256 _endTimestamp) Ownable(msg.sender) {
        vault = IVaultV2(_vault);
        validator = _validator;
        proofVerifier = _proofVerifier;
        rewardToken = _token;
        rewardRoot = _root;
        endTimestamp = _endTimestamp;
    }

    function extendEndTimestamp(uint256 _endTimestamp) external onlyOwner {
        if (_endTimestamp < endTimestamp) {
            revert InvalidEndTimestamp();
        }

        endTimestamp = _endTimestamp;
        emit EndTimestampExtended(_endTimestamp);
    }

    function changeValidator(address _validator) external onlyOwner {
        if (_validator == address(0)) {
            revert ZeroAddress();
        }

        validator = _validator;
        emit ChangeValidator(_validator);
    }

    function claim(
        bool _doubleCheck,
        uint256 _amount,
        bytes calldata signature,
        bytes32[] calldata _rewardProof,
        Proof calldata _zkPassProof
    ) external {
        if (endTimestamp < block.timestamp) {
            revert ClaimEnded();
        }
        address _account = _zkPassProof.recipient;
        bytes32 _zkId = _zkPassProof.uHash;
        if (claimedAccount[_account]) {
            revert ClaimedAccount(_account);
        }
        if (_zkId != 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470) {
            if (claimedZkId[_zkId]) {
                revert ClaimedZkId(_zkId);
            }
            claimedZkId[_zkId] = true;
        }
        bytes32 node = keccak256(abi.encodePacked(_account, _doubleCheck, _amount));
        if (_doubleCheck) {
            address _validator = node.recover(signature);
            if (_validator != validator) {
                revert InvalidValidator(_validator);
            }
            if (!ProofVerifier(proofVerifier).verify(_zkPassProof)) {
                revert InvalidZKPassProof();
            }
        }
        if (!MerkleProof.verify(_rewardProof, rewardRoot, node)) {
            revert InvalidRewardProof();
        }

        claimedAccount[_account] = true;
        vault.claim(rewardToken, _account, _amount);
        emit Claim(rewardToken, _account, _amount);
    }
}
