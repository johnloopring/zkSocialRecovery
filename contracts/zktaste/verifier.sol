// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x2859770ab83aef9b6890c58d4d6966726230dffdd710a61d1e85f6919d3b349a), uint256(0x274ffb6091ea4b69a52bf399b6906c9dd04692b86009356fb9013b3e234769dc));
        vk.beta = Pairing.G2Point([uint256(0x03bf02d789335748a1830b352ee544cb17ac622996bed43e058d0bb7266316f4), uint256(0x29567fd80732d2d87a5367d7c72cf0b9ff05ab5f57b937294577483ca455fd56)], [uint256(0x0faa24d3c9ef528615f1e69295b514f6b5609984c55cd8cca31ba3ed8e847370), uint256(0x07fb77c96f3c418afdad684e16a155cdfe7d9fbe8ccdf4c67d9b3e70468ad580)]);
        vk.gamma = Pairing.G2Point([uint256(0x0b537b75ec61c019c06c043f0dba1a1027a7e2189a844ed93da6fab1aebdd967), uint256(0x15d54456642c24a9f7f588bfaca75dbe032680c9b1727a7cc9d354546fc3d727)], [uint256(0x15159b6f202aaa729725fd88db05fdfbeefb7d7f40ad3db73c14aa69e050fb83), uint256(0x0762a95e789bc9af874e14512681d67c2cedcf24220e57451b049434bd0e86ef)]);
        vk.delta = Pairing.G2Point([uint256(0x07950cea6f9ab7e06b59308a9a6f20ab7c50f3d4ba8ff68eff330739085059c4), uint256(0x275de07a91b5598fe3780baee99b0428f29ef6b88ca4c4d46fdb64b7c522cae6)], [uint256(0x024093816df51899aae3b92ef705636402349495e59d1f8139222f65d626d67b), uint256(0x2f9e855f7defbad54c917e7a65a655a3e039d78db49213b645fce2458c1af96b)]);
        vk.gamma_abc = new Pairing.G1Point[](25);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0b4e973a50ca5d12382b0e4cb424131b5bef4ded56d2742f8343ec347016c77a), uint256(0x15e96d344149bbe5c3fa0be410357cb1b47bfbe8ab78097837aa7f0b23b3b9be));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0123f7b2b062072f0974b6ebe7e6235ce38a2a1c955988ac53630d2f78fd7213), uint256(0x2c17ef4908c81e374da103e43b318c8c1fba809d8c1f7944eb32631e2a3e37b3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x010bed3e613ae9bd47a8650120f4e95333c8a2b890c89be851da04132577b1d5), uint256(0x1f667fdc15682c37f33e58980804112d0a232833156ac51edb879deb19f6bcf3));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x22a3c1c120016d44a28497a3c1a922349f09d42821502880a5ba58142825541a), uint256(0x233e740155776a0342a2f0cfcd1dc1e5d0e31ed7a7aa00d653064b7182074d97));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x26ab54277f429edac9e7a4ab0be7456d9fa1df82752d8783a073c72b538a42d0), uint256(0x0d6bd647efd2340685100cab62ab27a8a0de8294f1c99a92694f3d804fa15177));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2bfd9bce85393b765eaa35bc69d88694cf801c3fdbcbe129543aeafbd60fc6a1), uint256(0x19d8db3fe3047465e2b64e1421ae9d445e4e306b1d5ddf33f7e394c733968eba));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0013e1b1b325e4065465011f7961dccbee12f81da205e9406c8d95c2eb1a56d4), uint256(0x1b34bcad4a2dc26912f99f49714555350e61e28559682ad47fb98b2e18546bb4));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0f23c9bcd247b4477c84a10d01642750bc7f4be657b2f0b9e8ac08f5c19f54f4), uint256(0x165c9c9263688a62727637dd92c51cc9aad9c2bb24106dc2980a7458a0c35048));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x12ffc89831d397d729fa93cca11899d50504ce7c7bda55f17d251a65a83d9c25), uint256(0x17946d825735774cfdbc5d7f985695c91f9b607b58fd8e8c75e23072a7cb5552));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1dc05e52bc926838c86044d6bc9f36c6d2aafedeb38641623edf5b8f9c02fe60), uint256(0x0bdf84f7c25ebce3f12cf5a54fe70b8a114cab0fdd4a05b640a132e5ca9c4cf4));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1ede6072c778960bd61cb7b684ebb0e6005685f4dc8a9e5b1504127607d7cc50), uint256(0x1e90b9f2a49e41fd02a4cc7d1407c7879dc887cb6245c56511d5a1889c2aec9c));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x03e5a84f59f20e433d9963c75dbf04229687197d656ad7b8664c5b47fbeb776b), uint256(0x1130f091bb73dbfce7451637b27f6d7f4e097c146209ab7227ade059490839c0));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x050ee80a4f2e5e47b6bd7d42146eaac740a6c82a86af21f84264a3586f889a8b), uint256(0x240bcb25f9b9c498b7328526f38d430f73451bd0a95de18e26a9a784ba9781ba));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x066d793ef4be147b2eb6d65614fc3e7726e1fc33386a7aea4190f3435bf35e35), uint256(0x1071d800ddca400020b26286df8b378e800806959650f8603adc3ffc7ca9910d));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x16701e8debe9bc12cb760a44fb9aebef533c15b99b114885d95b05d6821d282f), uint256(0x175d34fe01443f44971c10f906408717f026f7a1e4795a8109e8fc70a9e021c1));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x27bcfac6fdd44d711e24abdafc9b3cb4040e845575c1aaa29f5014acc2bc2926), uint256(0x098a388a8534dd9257bdd100e2a7441224225d6cf3eef7cac98e6ce8c7de9717));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1bca7b59c0b55f2b0c365a7d42d6978525c7ad3635d4a9d80bca788940ba5188), uint256(0x002400b720eb74362d99622635c14dd07ff3efc497d142905f7679e310ca64b5));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x12f9d98833cdea491b2a7e6ac5bce6054dd0f2f83ff62349dec2cd976b46e6f4), uint256(0x1d7c913c3829f19592e687c97f10a5f5513fcade2a5d439813b604149ba9e257));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x02f001dd52012a06ff82d3a39e6ad9ec172d4d2debc4e09c465d4e64f9e51aa9), uint256(0x1c4710f42c43541ec36f5b4613758ac3b80f4b3a82ca2b9ca46bb09bb6548e49));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x023b23cb20d48df0e9c9a4cc376139ecb17a8c543ef556f02cf2e6490bbd3ca4), uint256(0x189848dec3c32c3a5aeac1a747e8df7602980350cb5a47924ea964f5897b5de0));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x11ee40b6fee01369672705341d5cefcaa53fd85bd73044d3ccf87bbcc549e528), uint256(0x175d183d67102e6ae0547f67710385259ba75cb878d889a292ad7640b33304bb));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x20e668146b53342eb8a3231aada7ce33725654b3f72cf38a671a55ca4ee9f943), uint256(0x23c17096456e03910933ed5b379ed2a63e7a2bf73e1521ff4b565bba69d60cde));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x019efa565391d67563666e07f04de4eceea398b3cc3c402110e6f106388a6a39), uint256(0x2d855e3384e6c9357685aad4717e576878a1df62206742112117c0d0148bec8e));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1dd5b9327a17e50727145837466bcc8bb4f7932e4458e129de675b05f90cc205), uint256(0x1337009077e098f329b7c56d297b7d32a15b8fea24842579b35e1d42695da41d));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2686f8a6572f6db871cfc077c331ac06722e32af9da663f2177ba7e510fd6fba), uint256(0x0f3cce9b9bf71b668e45063c32b158687e67b1cd4508ddd7dab8c863d1e2375a));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[24] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](24);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
