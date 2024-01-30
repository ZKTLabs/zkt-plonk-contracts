// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Bn254 {
    uint256 constant private Q_MOD = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant private R_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant private BN254_B_COEFF = 3;

    struct G1Affine {
        uint256 x;
        uint256 y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Affine {
        uint256[2] x;
        uint256[2] y;
    }

    function isScalar(uint256 self) internal pure returns (bool) {
        return self < R_MOD;
    }

    function negate(uint256 self) internal pure returns (uint256) {
        if (self == 0) {
            return 0;
        } else {
            unchecked {
                return R_MOD - self;
            }
        }
    }

    function inverse(uint256 self) internal view returns (uint256) {
        assert(self > 0);
        return pow(self, R_MOD - 2);
    }

    function add(uint256 self, uint256 other) internal pure returns (uint256) {
        return addmod(self, other, R_MOD);
    }

    function sub(uint256 self, uint256 other) internal pure returns (uint256) {
        return addmod(self, R_MOD - other, R_MOD);
    }

    function mul(uint256 self, uint256 other) internal pure returns (uint256) {
        return mulmod(self, other, R_MOD);
    }

    function pow(uint256 self, uint256 power) internal view returns (uint256) {
        bool success;
        uint256[1] memory result;
        uint256[6] memory input = [32, 32, 32, self, power, R_MOD];
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        assert(success);
        return result[0];
    }

    function isG1Affine(G1Affine memory self) internal pure returns (bool) {
        if (self.x == 0 && self.y == 0) {
            return true;
        }
        // check encoding
        if (self.x >= Q_MOD || self.y >= Q_MOD) {
            return false;
        }
        // check on curve
        uint256 lhs = mulmod(self.y, self.y, Q_MOD); // y^2
        uint256 rhs = mulmod(self.x, self.x, Q_MOD); // x^2
        rhs = mulmod(rhs, self.x, Q_MOD); // x^3
        rhs = addmod(rhs, BN254_B_COEFF, Q_MOD); // x^3 + b
        return lhs == rhs;
    }

    function copy(G1Affine memory self, G1Affine memory other) internal pure {
        self.x = other.x;
        self.y = other.y;
    }

    function clone(G1Affine memory self) internal pure returns (G1Affine memory result) {
        return G1Affine(self.x, self.y);
    }

    function negate(G1Affine memory self) internal pure returns (G1Affine memory result) {
        // The prime q in the base field F_q for G1
        if (self.y == 0) {
            assert(self.x == 0);
        } else {
            result.x = self.x;
            unchecked {
                result.y = Q_MOD - self.y;
            }
        }
    }

    function negateAssign(G1Affine memory self) internal pure {
        // The prime q in the base field F_q for G1
        if (self.y == 0) {
            assert(self.x == 0);
        } else {
            unchecked {
                self.y = Q_MOD - self.y;
            }
        }
    }

    function add(G1Affine memory p1, G1Affine memory p2) internal view returns (G1Affine memory r) {
        addInto(p1, p2, r);
        return r;
    }

    function addAssign(G1Affine memory p1, G1Affine memory p2) internal view {
        addInto(p1, p2, p1);
    }

    function addInto(
        G1Affine memory p1,
        G1Affine memory p2,
        G1Affine memory dest
    ) internal view {
        if (p2.x == 0 && p2.y == 0) {
            // we add zero, nothing happens
            dest.x = p1.x;
            dest.y = p1.y;
            return;
        } else if (p1.x == 0 && p1.y == 0) {
            // we add into zero, and we add non-zero point
            dest.x = p2.x;
            dest.y = p2.y;
            return;
        } else {
            uint256[4] memory input;
            input[0] = p1.x;
            input[1] = p1.y;
            input[2] = p2.x;
            input[3] = p2.y;

            bool success;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := staticcall(gas(), 0x06, input, 0x80, dest, 0x40)
            }
            assert(success);
        }
    }

    function sub(G1Affine memory p1, G1Affine memory p2) internal view returns (G1Affine memory r) {
        subInto(p1, p2, r);
        return r;
    }

    function subAssign(G1Affine memory p1, G1Affine memory p2) internal view {
        subInto(p1, p2, p1);
    }

    function subInto(G1Affine memory p1, G1Affine memory p2, G1Affine memory dest) internal view {
        if (p2.x == 0 && p2.y == 0) {
            // we subtracted zero, nothing happens
            dest.x = p1.x;
            dest.y = p1.y;
        } else if (p1.x == 0 && p1.y == 0) {
            // we subtract from zero, and we subtract non-zero point
            dest.x = p2.x;
            unchecked {
                dest.y = Q_MOD - p2.y;
            }
        } else {
            uint256[4] memory input;
            input[0] = p1.x;
            input[1] = p1.y;
            input[2] = p2.x;
            unchecked {
                input[3] = Q_MOD - p2.y;
            }

            bool success;
            // solhint-disable-next-line no-inline-assembly
            assembly {
                success := staticcall(gas(), 0x06, input, 0x80, dest, 0x40)
            }
            assert(success);
        }
    }

    function mul(G1Affine memory p, uint256 s) internal view returns (G1Affine memory r) {
        mulInto(p, s, r);
    }

    function mulAssign(G1Affine memory p, uint256 s) internal view {
        mulInto(p, s, p);
    }

    function mulInto(G1Affine memory p, uint256 s, G1Affine memory dest) internal view {
        uint256[3] memory input;
        input[0] = p.x;
        input[1] = p.y;
        input[2] = s;

        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 0x07, input, 0x60, dest, 0x40)
        }
        assert(success);
    }

    function pairing(G1Affine[] memory g1, G2Affine[] memory g2) internal view returns (bool) {
        assert(g1.length == g2.length);
        uint256 elements = g1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        unchecked {
            for (uint256 i = 0; i < elements; i++) {
                input[i * 6 + 0] = g1[i].x;
                input[i * 6 + 1] = g1[i].y;
                input[i * 6 + 2] = g2[i].x[0];
                input[i * 6 + 3] = g2[i].x[1];
                input[i * 6 + 4] = g2[i].y[0];
                input[i * 6 + 5] = g2[i].y[1];
            }
        }

        uint256[1] memory out;
        bool success;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            success := staticcall(gas(), 0x08, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        }
        assert(success);
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(
        G1Affine memory a1,
        G2Affine memory a2,
        G1Affine memory b1,
        G2Affine memory b2
    ) internal view returns (bool) {
        G1Affine[] memory g1 = new G1Affine[](2);
        G2Affine[] memory g2 = new G2Affine[](2);
        unchecked {
            g1[0] = a1;
            g1[1] = b1;
            g2[0] = a2;
            g2[1] = b2;
        }
        return pairing(g1, g2);
    }
}