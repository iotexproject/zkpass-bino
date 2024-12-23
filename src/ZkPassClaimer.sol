// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

import "./zkpass/IVerifier.sol";

interface IVault {
    function claim(address _recipient, uint256 _amount) external;
}

contract ZkPassClaimer {
    error InvalidEndTimestamp();
    error ClaimEnded();
    error ClaimedAccount(address account);
    error ClaimedProof();
    error InvalidRewardProof();
    error InvalidZkProof();

    event Claim(bytes32 proofKey, address indexed account, uint256 amount);

    IVault public immutable vault;
    IVerifier public immutable verifier;
    bytes32 public immutable rewardRoot;
    uint256 public endTimestamp;
    mapping(address => bool) public claimedAccount;
    mapping(bytes32 => bool) public claimedProof;

    constructor(address _vault, address _verifier, bytes32 _root, uint256 _endTimestamp) {
        if (_endTimestamp < block.timestamp) {
            revert InvalidEndTimestamp();
        }

        vault = IVault(_vault);
        verifier = IVerifier(_verifier);
        rewardRoot = _root;
    }

    function proofKey(Proof calldata _proof) public pure returns (bytes32) {
        return keccak256(abi.encode(_proof.taskId, _proof.schemaId, _proof.validator));
    }

    function claim(Proof calldata _zkProof, address _account, uint256 _amount, bytes32[] calldata _rewardProof)
        external
    {
        if (endTimestamp < block.timestamp) {
            revert ClaimEnded();
        }
        if (claimedAccount[_account]) {
            revert ClaimedAccount(_account);
        }
        bytes32 zkProofKey = proofKey(_zkProof);
        if (claimedProof[zkProofKey]) {
            revert ClaimedProof();
        }

        if (!verifier.verify(_zkProof)) {
            revert InvalidZkProof();
        }
        bytes32 node = keccak256(abi.encodePacked(_account, _amount));
        if (!MerkleProof.verify(_rewardProof, rewardRoot, node)) {
            revert InvalidRewardProof();
        }

        claimedAccount[_account] = true;
        claimedProof[zkProofKey] = true;
        vault.claim(_account, _amount);
        emit Claim(zkProofKey, _account, _amount);
    }
}
