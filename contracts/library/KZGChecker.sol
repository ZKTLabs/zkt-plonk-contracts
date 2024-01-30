// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Bn254 } from "./Bn254.sol";

library KZGChecker {
    using Bn254 for uint256;
    using Bn254 for Bn254.G1Affine;

    error MismatchedLength(uint256 left, uint256 right);

    function G() internal pure returns (Bn254.G1Affine memory) {
        return Bn254.G1Affine(
            0x16ec48c31f874dba2a3b3f74107bf12ad45c8353f403778a8e5d17df25e07cdf,
            0x20f2c5686fccbfad42ac39b7d2dfa5d241b2e423ddb6a5d05060bed389bfbc63
        );
    }

    function H() internal pure returns (Bn254.G2Affine memory) {
        return Bn254.G2Affine(
            [
                0x2e693da4ee4ba44597b16c46bd7868b0196ec9a5952aca0b0dfb5112fc7df1b4,
                0x070a5ebd1d20576e40620c6540f1d90e521b72c428638fd60a421a13755009b6
            ],
            [
                0x1bd168767b435f84330377d4d5699a086b13322ef3f1d1a7b568c26813caca8d,
                0x2c7cbaad2b912db234378ede551853f07a82f342fe67e6916a32c4d7df2cd6bc
            ]
        );
    }

    function BetaH() internal pure returns (Bn254.G2Affine memory) {
        return Bn254.G2Affine(
            [
                0x28962b931459b7877c4e7b7088a8975508b6d4a1d1e3df25f12425c27eb863bf,
                0x0d7708b73042ffc2dcdf512c47d109002ccb7e16bdf2cfe78250d22135eff87a
            ],
            [
                0x03f8e37e8944bc55a584c53c833feb0c8f99f6f8691617c7324d4b4bbab5b947,
                0x2e8abb48266164ee1e81d725fb34efb2bcac51bea317c3244014c47b6f218107
            ]
        );
    }

    function check(
        uint256 point,
        uint256 eval,
        Bn254.G1Affine memory opening,
        Bn254.G1Affine memory commitment
    ) internal view returns (bool) {
        Bn254.G1Affine memory g = G();
        Bn254.G2Affine memory h = H();
        Bn254.G2Affine memory betaH = BetaH();

        g.mulAssign(eval);
        g.subAssign(commitment);
        g.subAssign(opening.mul(point));

        return Bn254.pairingProd2(opening, betaH, g, h);
    }

    function batchCheck(
        uint256 challenge,
        uint256[] memory points,
        uint256[] memory evals,
        Bn254.G1Affine[] memory openings,
        Bn254.G1Affine[] memory commitments
    ) internal view returns (bool) {
        if (points.length != evals.length) {
            revert MismatchedLength(points.length, evals.length);
        }
        if (points.length != openings.length) {
            revert MismatchedLength(points.length, openings.length);
        }
        if (points.length != commitments.length) {
            revert MismatchedLength(points.length, commitments.length);
        }
        
        Bn254.G1Affine memory g = G();
        Bn254.G2Affine memory h = H();
        Bn254.G2Affine memory betaH = BetaH();

        uint256 tmpFr;
        uint256 u = 1;
        Bn254.G1Affine memory partA = Bn254.G1Affine(0, 0);
        Bn254.G1Affine memory partB = Bn254.G1Affine(0, 0);
        Bn254.G1Affine memory tmpG1 = Bn254.G1Affine(0, 0);
        for (uint256 i = 0; i < points.length; i++) {
            tmpG1.copy(openings[i]);
            tmpG1.mulAssign(u);
            partA.addAssign(tmpG1);

            tmpFr = u.mul(evals[i]);
            tmpG1.copy(g);
            tmpG1.mulAssign(tmpFr);
            partB.addAssign(tmpG1);
            tmpG1.copy(commitments[i]);
            tmpG1.mulAssign(u);
            partB.subAssign(tmpG1);

            tmpFr = u.mul(points[i]);
            tmpG1.copy(openings[i]);
            tmpG1.mulAssign(tmpFr);
            partB.subAssign(tmpG1);

            u = u.mul(challenge);
        }
        // Pairing check
        return Bn254.pairingProd2(partA, betaH, partB, h);
    }
}