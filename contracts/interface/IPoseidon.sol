// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPoseidon {
    function poseidon(uint256[2] calldata) external pure returns (uint256);

    function poseidon(bytes32[2] calldata) external pure returns (bytes32);
}
