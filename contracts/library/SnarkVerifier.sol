// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Bn254 } from "./Bn254.sol";
import { Domain } from "./Domain.sol";
import { KZGChecker } from "./KZGChecker.sol";
import { TranscriptProtocol } from "./TranscriptProtocol.sol";

library SnarkVerifier {
    using Bn254 for uint256;
    using Bn254 for Bn254.G1Affine;
    using TranscriptProtocol for TranscriptProtocol.Transcript;

    uint256 constant private K1 = 7;
    uint256 constant private K2 = 13; 

    error MismatchedLength(uint256 left, uint256 right);
    error InvalidPublicInput(uint256 index);

    struct Proof {
        // Wire Evaluations
        uint256 a;
        uint256 b;
        uint256 c;

        // Permutation Evaluations
        uint256 sigma1;
        uint256 sigma2;
        uint256 z1Next;

        // Lookup Evaluations
        uint256 qLookup;
        uint256 t;
        uint256 tNext;
        uint256 z2Next;
        uint256 h1Next;
        uint256 h2;

        // Commitments
        Bn254.G1Affine aComm;
        Bn254.G1Affine bComm;
        Bn254.G1Affine cComm;
        Bn254.G1Affine tComm;
        Bn254.G1Affine h1Comm;
        Bn254.G1Affine h2Comm;
        Bn254.G1Affine z1Comm;
        Bn254.G1Affine z2Comm;
        Bn254.G1Affine qLoComm;
        Bn254.G1Affine qMidComm;
        Bn254.G1Affine qHiComm;

        Bn254.G1Affine awOpening;
        Bn254.G1Affine sawOpening;
    }

    struct Challenges {
        uint256[5] alphas;
        uint256[8] etas;
        uint256 beta;
        uint256 gamma;
        uint256 delta;
        uint256 epsilon;
        uint256 xi;
        uint256 theta;
    }

    struct VerifierKey {
        // public input index list
        uint64[] piIndex;

        // Arithmetic vk
        Bn254.G1Affine qM;
        Bn254.G1Affine qL;
        Bn254.G1Affine qR;
        Bn254.G1Affine qO;
        Bn254.G1Affine qC;

        // Permutation vk
        Bn254.G1Affine sigma1;
        Bn254.G1Affine sigma2;
        Bn254.G1Affine sigma3;

        // Lookup vk
        Bn254.G1Affine qLookup;
        Bn254.G1Affine qTable;
    }

    function seedTranscript(
        VerifierKey memory vk,
        TranscriptProtocol.Transcript memory transcript
    ) internal pure {
        transcript.appendUint64(Domain.SIZE);
        transcript.appendG1(vk.qM);
        transcript.appendG1(vk.qL);
        transcript.appendG1(vk.qR);
        transcript.appendG1(vk.qO);
        transcript.appendG1(vk.qC);
        transcript.appendG1(vk.sigma1);
        transcript.appendG1(vk.sigma2);
        transcript.appendG1(vk.sigma3);
        transcript.appendG1(vk.qLookup);
        transcript.appendG1(vk.qTable);
    }

    function validatePublicInputs(
        VerifierKey memory vk,
        uint256[] memory publicInputs
    ) internal pure {
        if (vk.piIndex.length != publicInputs.length) {
            revert MismatchedLength(vk.piIndex.length, publicInputs.length);
        }
        for (uint256 i = 0; i < publicInputs.length; i++) {
            if (!publicInputs[i].isScalar()) {
                revert InvalidPublicInput(i);
            }
        }
    }

    function validateProof(Proof memory proof) internal pure {
        require(proof.a.isScalar(), "Proof: a is invalid");
        require(proof.b.isScalar(), "Proof: b is invalid");
        require(proof.c.isScalar(), "Proof: c is invalid");
        require(proof.sigma1.isScalar(), "Proof: sigma1 is invalid");
        require(proof.sigma2.isScalar(), "Proof: sigma2 is invalid");
        require(proof.z1Next.isScalar(), "Proof: z1Next is invalid");
        require(proof.qLookup.isScalar(), "Proof: qLookup is invalid");
        require(proof.t.isScalar(), "Proof: t is invalid");
        require(proof.tNext.isScalar(), "Proof: tNext is invalid");
        require(proof.z2Next.isScalar(), "Proof: z2Next is invalid");
        require(proof.h1Next.isScalar(), "Proof: h1Next is invalid");
        require(proof.h2.isScalar(), "Proof: h2 is invalid");

        require(proof.aComm.isG1Affine(), "Proof: aComm is invalid");
        require(proof.bComm.isG1Affine(), "Proof: bComm is invalid");
        require(proof.cComm.isG1Affine(), "Proof: cComm is invalid");
        require(proof.tComm.isG1Affine(), "Proof: tComm is invalid");
        require(proof.h1Comm.isG1Affine(), "Proof: h1Comm is invalid");
        require(proof.h2Comm.isG1Affine(), "Proof: h2Comm is invalid");
        require(proof.z1Comm.isG1Affine(), "Proof: z1Comm is invalid");
        require(proof.z2Comm.isG1Affine(), "Proof: z2Comm is invalid");
        require(proof.qLoComm.isG1Affine(), "Proof: qLoComm is invalid");
        require(proof.qMidComm.isG1Affine(), "Proof: qMidComm is invalid");
        require(proof.qHiComm.isG1Affine(), "Proof: qHiComm is invalid");
        require(proof.awOpening.isG1Affine(), "Proof: awOpening is invalid");
        require(proof.sawOpening.isG1Affine(), "Proof: sawOpening is invalid");
    }

    function generateChallenges(
        Proof memory proof,
        VerifierKey memory vk,
        uint256[] memory publicInputs
    ) internal pure returns (Challenges memory) {
        // build transcript
        TranscriptProtocol.Transcript memory transcript = TranscriptProtocol.newTranscript();
        seedTranscript(vk, transcript);

        transcript.appendScalarArray(publicInputs);
        transcript.appendG1(proof.aComm);
        transcript.appendG1(proof.bComm);
        transcript.appendG1(proof.cComm);
        transcript.appendG1(proof.tComm);
        transcript.appendG1(proof.h1Comm);
        transcript.appendG1(proof.h2Comm);
        // Compute challenge beta
        uint256 beta = transcript.challengeScalar();
        // Compute challenge gamma
        uint256 gamma = transcript.challengeScalar();
        // Compute challenge delta
        uint256 delta = transcript.challengeScalar();
        // Compute challenge epsilon
        uint256 epsilon = transcript.challengeScalar();

        transcript.appendG1(proof.z1Comm);
        transcript.appendG1(proof.z2Comm);
        // Compute challenge alpha
        uint256 alpha = transcript.challengeScalar();

        transcript.appendG1(proof.qLoComm);
        transcript.appendG1(proof.qMidComm);
        transcript.appendG1(proof.qHiComm);
        // Compute challenge xi
        uint256 xi = transcript.challengeScalar();

        transcript.appendScalar(proof.a);
        transcript.appendScalar(proof.b);
        transcript.appendScalar(proof.c);
        transcript.appendScalar(proof.sigma1);
        transcript.appendScalar(proof.sigma2);
        transcript.appendScalar(proof.z1Next);
        transcript.appendScalar(proof.qLookup);
        transcript.appendScalar(proof.t);
        transcript.appendScalar(proof.tNext);
        transcript.appendScalar(proof.z2Next);
        transcript.appendScalar(proof.h1Next);
        transcript.appendScalar(proof.h2);
        // Compute challenge eta
        uint256 eta = transcript.challengeScalar();

        transcript.appendG1(proof.awOpening);
        transcript.appendG1(proof.sawOpening);
        // Compute challenge theta
        uint256 theta = transcript.challengeScalar();

        // Expand alpha vector
        uint256[5] memory alphas;
        alphas[0] = alpha;
        for (uint256 i = 1; i < 5; i++) {
            alphas[i] = alphas[i - 1].mul(alpha);
        }
        // Expand etas vectors
        uint256[8] memory etas;
        etas[0] = eta;
        for (uint256 i = 1; i < 8; i++) {
            etas[i] = etas[i - 1].mul(eta);
        }

        return Challenges(alphas, etas, beta, gamma, delta, epsilon, xi, theta);
    }

    function computeLinearEvaluation(
        Proof memory proof,
        VerifierKey memory vk,
        uint256[] memory publicInputs,
        Challenges memory challenges,
        uint256 zhEval,
        uint256 firstLagrangeEval
    ) internal view returns (uint256) {
        // part 1: PI(xi)
        uint256 part1 = 0;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            uint256 lagrange = Domain.evaluateLagrangePoly(
                Domain.element(vk.piIndex[i]),
                zhEval,
                challenges.xi
            );
            part1 = part1.sub(lagrange.mul(publicInputs[i]));
        }

        // part 2: (a(ξ) + β*σ1(ξ) + γ) * (b(ξ) + β*σ2(ξ) + γ) * (c(ξ) + γ) * α * z1(ωξ)
        uint256 part2 = challenges.alphas[0]
            .mul(proof.z1Next)
            .mul(challenges.beta.mul(proof.sigma1).add(proof.a).add(challenges.gamma))
            .mul(challenges.beta.mul(proof.sigma2).add(proof.b).add(challenges.gamma))
            .mul(challenges.gamma.add(proof.c));

        // part 3: L_1(ξ) * α^2
        uint256 part3 = firstLagrangeEval.mul(challenges.alphas[1]);

        // part 4: α^3 * z2(ωξ) * (ε(1+δ) + δ * h2(ξ)) * (ε(1+δ) + h2(ξ) + δ * h1(ωξ))
        uint256 epsilonOnePlusDelta = challenges.delta.add(1).mul(challenges.epsilon);
        uint256 part4 = challenges.alphas[2]
            .mul(proof.z2Next)
            .mul(challenges.delta.mul(proof.h2).add(epsilonOnePlusDelta))
            .mul(challenges.delta.mul(proof.h1Next).add(proof.h2).add(epsilonOnePlusDelta));

        // part 5: L_1(z) * α^4
        uint256 part5 = firstLagrangeEval.mul(challenges.alphas[3]);

        return part1.add(part2).add(part3).add(part4).add(part5);
    }

    function computeBatchedEvaluations(
        Proof memory proof,
        Challenges memory challenges
    ) internal pure returns (uint256) {
        return challenges.etas[0].mul(proof.a)
            .add(challenges.etas[1].mul(proof.b))
            .add(challenges.etas[2].mul(proof.c))
            .add(challenges.etas[3].mul(proof.sigma1))
            .add(challenges.etas[4].mul(proof.sigma2))
            .add(challenges.etas[5].mul(proof.qLookup))
            .add(challenges.etas[6].mul(proof.t))
            .add(challenges.etas[7].mul(proof.h2));
    }

    function computeShiftedBatchedEvaluations(
        Proof memory proof,
        Challenges memory challenges
    ) internal pure returns (uint256) {
        return challenges.etas[0].mul(proof.z1Next)
            .add(challenges.etas[1].mul(proof.z2Next))
            .add(challenges.etas[2].mul(proof.tNext))
            .add(challenges.etas[3].mul(proof.h1Next));
    }

    function processArithLinearComm(
        Bn254.G1Affine memory commitment,
        Proof memory proof,
        VerifierKey memory vk
    ) internal view {
        Bn254.G1Affine memory tmpComm;

        vk.qM.mulInto(proof.a.mul(proof.b), tmpComm);
        commitment.addAssign(tmpComm);

        vk.qL.mulInto(proof.a, tmpComm);
        commitment.addAssign(tmpComm);

        vk.qR.mulInto(proof.b, tmpComm);
        commitment.addAssign(tmpComm);

        vk.qO.mulInto(proof.c, tmpComm);
        commitment.addAssign(tmpComm);

        commitment.addAssign(vk.qC);
    }

    function processPermLinearComm(
        Bn254.G1Affine memory commitment,
        Proof memory proof,
        VerifierKey memory vk,
        Challenges memory challenges,
        uint256 firstLagrangeEval
    ) internal view {
        Bn254.G1Affine memory tmpComm;

        // (a(ξ) + β*ξ + γ) * (b(ξ) + β*K1*ξ + γ) * (c(ξ) + β*K2*ξ + γ) * α + L_1(ξ) * α^2
        uint256 scalar = challenges.alphas[0]
            .mul(challenges.beta.mul(challenges.xi).add(proof.a).add(challenges.gamma))
            .mul(challenges.beta.mul(K1).mul(challenges.xi).add(proof.b).add(challenges.gamma))
            .mul(challenges.beta.mul(K2).mul(challenges.xi).add(proof.c).add(challenges.gamma))
            .add(firstLagrangeEval.mul(challenges.alphas[1]));
        proof.z1Comm.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);

        // -α * β * z1(ωξ) * (a(ξ) + β*σ1(ξ) + γ) * (b(ξ) + β*σ2(ξ) + γ)
        scalar = challenges.alphas[0]
            .mul(challenges.beta)
            .mul(proof.z1Next)
            .mul(challenges.beta.mul(proof.sigma1).add(proof.a).add(challenges.gamma))
            .mul(challenges.beta.mul(proof.sigma2).add(proof.b).add(challenges.gamma))
            .negate();
        vk.sigma3.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);
    }

    function processLookupLinearComm(
        Bn254.G1Affine memory commitment,
        Proof memory proof,
        VerifierKey memory vk,
        Challenges memory challenges,
        uint256 firstLagrangeEval
    ) internal view {
        Bn254.G1Affine memory tmpComm;

        // α^3 * (1+δ) * (ε + q_lookup(ξ)*c(ξ)) * (ε(1+δ) + t(ξ) + δ*t(ωξ)) + α^4 * L_1(ξ)
        uint256 onePlusDelta = challenges.delta.add(1);
        uint256 epsilonOnePlusDelta = challenges.epsilon.mul(onePlusDelta);
        uint256 scalar = challenges.alphas[2]
            .mul(onePlusDelta)
            .mul(proof.qLookup.mul(proof.c).add(challenges.epsilon))
            .mul(challenges.delta.mul(proof.tNext).add(proof.t).add(epsilonOnePlusDelta))
            .add(firstLagrangeEval.mul(challenges.alphas[3]));
        proof.z2Comm.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);

        // -α^3 * z2(ωξ) * (ε(1+δ) + h2(ξ) + δ * h1(ωξ))
        scalar = challenges.alphas[2]
            .mul(proof.z2Next)
            .mul(challenges.delta.mul(proof.h1Next).add(proof.h2).add(epsilonOnePlusDelta))
            .negate();
        proof.h1Comm.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);

        // α^5 * t(ξ)
        scalar = challenges.alphas[4].mul(proof.t);
        vk.qTable.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);
    }

    function processLinearComm(
        Bn254.G1Affine memory commitment,
        Proof memory proof,
        VerifierKey memory vk,
        Challenges memory challenges,
        uint256 zhEval,
        uint256 firstLagrangeEval
    ) internal view {
        processArithLinearComm(commitment, proof, vk);
        processPermLinearComm(commitment, proof, vk, challenges, firstLagrangeEval);
        processLookupLinearComm(commitment, proof, vk, challenges, firstLagrangeEval);

        Bn254.G1Affine memory tmpComm;
        uint256 scalar = zhEval.negate();
        uint256 xiExpNPlus2 = zhEval.add(1).mul(challenges.xi).mul(challenges.xi);
        proof.qLoComm.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);

        scalar = scalar.mul(xiExpNPlus2);
        proof.qMidComm.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);

        scalar = scalar.mul(xiExpNPlus2);
        proof.qHiComm.mulInto(scalar, tmpComm);
        commitment.addAssign(tmpComm);
    }

    function processBatchedComm(
        Bn254.G1Affine memory commitment,
        Proof memory proof,
        VerifierKey memory vk,
        Challenges memory challenges
    ) internal view {
        Bn254.G1Affine memory tmpComm;

        proof.aComm.mulInto(challenges.etas[0], tmpComm);
        commitment.addAssign(tmpComm);

        proof.bComm.mulInto(challenges.etas[1], tmpComm);
        commitment.addAssign(tmpComm);

        proof.cComm.mulInto(challenges.etas[2], tmpComm);
        commitment.addAssign(tmpComm);

        vk.sigma1.mulInto(challenges.etas[3], tmpComm);
        commitment.addAssign(tmpComm);

        vk.sigma2.mulInto(challenges.etas[4], tmpComm);
        commitment.addAssign(tmpComm);

        vk.qLookup.mulInto(challenges.etas[5], tmpComm);
        commitment.addAssign(tmpComm);

        proof.tComm.mulInto(challenges.etas[6], tmpComm);
        commitment.addAssign(tmpComm);

        proof.h2Comm.mulInto(challenges.etas[7], tmpComm);
        commitment.addAssign(tmpComm);
    }

    function verify(
        Proof memory proof,
        VerifierKey memory vk,
        uint256[] memory publicInputs
    ) internal view returns (bool) {
        // validate public inputs and proof
        validatePublicInputs(vk, publicInputs);
        validateProof(proof);

        // Compute challenges
        Challenges memory challenges = generateChallenges(proof, vk, publicInputs);

        // Compute vanishing polynomial evaluated at `ξ`
        uint256 zhEval = Domain.evaluateVanishingPoly(challenges.xi);
        // Compute the first Lagrange evaluation at `ξ`
        uint256 firstLagrangeEval = Domain.evaluateLagrangePoly(Domain.element(0), zhEval, challenges.xi);

        uint256[] memory evals = new uint256[](2);
        Bn254.G1Affine[] memory commitments = new Bn254.G1Affine[](2);

        // Compute linear evaluation
        uint256 linearEval = computeLinearEvaluation(proof, vk, publicInputs, challenges, zhEval, firstLagrangeEval);
        // Compute batched evaluation
        uint256 batchEval = computeBatchedEvaluations(proof, challenges);
        evals[0] = linearEval.add(batchEval);

        // Compute linear combination of commitments
        processLinearComm(commitments[0], proof, vk, challenges, zhEval, firstLagrangeEval);
        // Compute batched commitments
        processBatchedComm(commitments[0], proof, vk, challenges);

        // Compute evaluation of shifted
        evals[1] = computeShiftedBatchedEvaluations(proof, challenges);

        // Compute shifted commitments
        processBatchedComm(commitments[1], proof, vk, challenges);

        uint256[] memory points = new uint256[](2);
        points[0] = challenges.xi;
        points[1] = challenges.xi.mul(Domain.GENERATOR);

        Bn254.G1Affine[] memory openings = new Bn254.G1Affine[](2);
        openings[0] = proof.awOpening;
        openings[1] = proof.sawOpening;

        // KZG batch check
        return KZGChecker.batchCheck(
            challenges.theta,
            points,
            evals,
            openings,
            commitments
        );
    }
}

