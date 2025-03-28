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

    error ZeroAddress();
    error ClaimEnded(uint256 projectId);
    error ClaimedAccount(uint256 projectId, address account);
    error ClaimedZkId(uint256 projectId, bytes32 zkId);
    error InvalidProjectId(uint256 projectId);
    error InvalidEndTimestamp();
    error InvalidRewardProof();
    error InvalidValidator(address validator);
    error InvalidZKPassProof();

    event EndTimestampExtended(uint256 projectId, uint256 endTimestamp);
    event ChangeValidator(address indexed validator);
    event Claim(address indexed token, uint256 indexed projectId, address indexed account, uint256 amount);

    IVaultV2 public immutable vault;
    uint256 public nextProjectId;
    address public validator;
    address public proofVerifier;
    mapping(uint256 => bytes32) private rewardRoots;
    mapping(uint256 => uint256) private endTimestamps;
    mapping(uint256 => address) private rewardTokens;
    mapping(uint256 => mapping(address => bool)) private claimedAccounts;
    mapping(uint256 => mapping(bytes32 => bool)) private claimedZkIds;

    constructor(address _vault, address _validator, address _proofVerifier) Ownable(msg.sender) {
        vault = IVaultV2(_vault);
        validator = _validator;
        proofVerifier = _proofVerifier;
        nextProjectId = 1;
    }

    function addProject(address _token, bytes32 _root, uint256 _endTimestamp) external onlyOwner returns (uint256 projectId_) {
        if (_token == address(0)) {
            revert ZeroAddress();
        }
        if (_endTimestamp < block.timestamp) {
            revert InvalidEndTimestamp();
        }
        projectId_ = nextProjectId++;
        rewardTokens[projectId_] = _token;
        rewardRoots[projectId_] = _root;
        endTimestamps[projectId_] = _endTimestamp;
    }

    function extendEndTimestamp(uint256 _projectId, uint256 _endTimestamp) external onlyOwner {
        uint256 curr = endTimestamps[_projectId];
        if (curr == 0) {
            revert InvalidProjectId(_projectId);
        }
        if (_endTimestamp < curr) {
            revert InvalidEndTimestamp();
        }

        endTimestamps[_projectId] = _endTimestamp;
        emit EndTimestampExtended(_projectId, _endTimestamp);
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
        uint256 _projectId,
        uint256 _amount,
        bytes calldata signature,
        bytes32[] calldata _rewardProof,
        Proof calldata _zkPassProof
    ) external {
        uint256 curr = endTimestamps[_projectId];
        if (curr == 0) {
            revert InvalidProjectId(_projectId);
        }
        if (curr < block.timestamp) {
            revert ClaimEnded(_projectId);
        }
        address _account = _zkPassProof.recipient;
        bytes32 _zkId = _zkPassProof.uHash;
        if (claimedAccounts[_projectId][_account]) {
            revert ClaimedAccount(_projectId, _account);
        }
        if (_zkId != 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470) {
            if (claimedZkIds[_projectId][_zkId]) {
                revert ClaimedZkId(_projectId, _zkId);
            }
            claimedZkIds[_projectId][_zkId] = true;
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
        if (!MerkleProof.verify(_rewardProof, rewardRoots[_projectId], node)) {
            revert InvalidRewardProof();
        }

        address token = rewardTokens[_projectId];
        claimedAccounts[_projectId][_account] = true;
        vault.claim(token, _account, _amount);
        emit Claim(token, _projectId, _account, _amount);
    }

    function rewardRoot(uint256 projectId) public view returns (bytes32) {
        return rewardRoots[projectId];
    }

    function endTimestamp(uint256 projectId) public view returns (uint256) {
        return endTimestamps[projectId];
    }

    function rewardToken(uint256 projectId) public view returns (address) {
        return rewardTokens[projectId];
    }

    function claimedAccount(uint256 projectId, address account) public view returns (bool) {
        return claimedAccounts[projectId][account];
    }

    function claimedZkId(uint256 projectId, bytes32 zkId) public view returns (bool) {
        return claimedZkIds[projectId][zkId];
    }
}
