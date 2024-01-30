// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Bn254 } from "./Bn254.sol";

library Domain {
    using Bn254 for uint256;

    // Note: decide by circuit size
    uint64 constant public SIZE = 2 ** 20;

    // Domain generators
    uint256 constant public GENERATOR = 0x26125da10a0ed06327508aba06d1e303ac616632dbed349f53422da953337857;
    uint256 constant public INV_GENERATOR = 0x100c332d2100895fab6473bc2c51bfca521f45cb3baca6260852a8fde26c91f3;

    error OutOfRange(uint256 index);

    function element(uint256 index) internal view returns (uint256) {
        if (index == 0) {
            return 1;
        } else if (index == 1) {
            return GENERATOR;
        } else if (index > 1 && index < SIZE - 1) {
            return GENERATOR.pow(index);
        } else if (index == SIZE - 1) {
            return INV_GENERATOR;
        } else {
            revert OutOfRange(index);
        }
    }

    function evaluateLagrangePoly(uint256 _element, uint256 zhEval, uint256 tau) internal view returns (uint256) {
        uint256 numerator = zhEval.mul(_element);
        uint256 domimator = tau.sub(_element).mul(SIZE);
        return domimator.inverse().mul(numerator);
    }

    function evaluateVanishingPoly(uint256 tau) internal view returns (uint256) {
        return tau.pow(SIZE).sub(1);
    }
}