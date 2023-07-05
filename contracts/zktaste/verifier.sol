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
        vk.alpha = Pairing.G1Point(uint256(0x0ed7da9612d6298dfe2cd9757b19f5e3524ba91360a8acceaef7998627e2a887), uint256(0x2dff95606b6c2e4b387a49791cd767c74c246cfb19f34ba57e38a517cc0fe7f5));
        vk.beta = Pairing.G2Point([uint256(0x23ca3f21905fb33e2b867030319d3e7eae0a0b016f75a4881e66b2250e7b35df), uint256(0x06b9222095e3f7145e9cc013999b48c46328913b50e490decef01469941a567f)], [uint256(0x2d0b9e02b8c7e9d83ad458dd6e5e60b787b81d73c2340139efeb59aca3257895), uint256(0x1d0b59916bf697686940446dd8a6449ccdaf84b5553b6cea19e5593eeecc4c3e)]);
        vk.gamma = Pairing.G2Point([uint256(0x2c90b53c0e4d3be59bef8b5c1757ee42d6dc448af49d297f2f7d25dff5fd687d), uint256(0x202b7959f364641f123cb2a32f0a6880b985473dc1d7fbb3422552c90487904b)], [uint256(0x0b570d9ca029cd3a279085a58872fa1077e61d032e07d68830e30f6055152991), uint256(0x181dfc5939d3d9879510796ea16d3210270063103a3e385bf97f7b0455a11262)]);
        vk.delta = Pairing.G2Point([uint256(0x0cf422ab573175c96e430dcd3d981d4b309ae283ef948c0344f6f1c59e42dc57), uint256(0x0473666907b826677a9ebcf672a0005ee67e05ce28ee01ae8a7f57379d2f3ac1)], [uint256(0x1f3ab1bbfc276b0c5753d83d03be7816195f5343671a4221b9010c7985833207), uint256(0x0e9cc13af5ffc0211f3f88d321d9fd445dc66a2df87240fb09755e4354f528af)]);
        vk.gamma_abc = new Pairing.G1Point[](25);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2ba2670eb8d90113713fec2a85375e4660baff77c9884802c1101b28048eaeee), uint256(0x2286ea8220cb0ea2414140c2873c0e09bb67c611afa981700709ea4c82b51930));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2c3e750b24db4bce6caefc40ea7f74c655e79741efb32a91f83dc4bf073b8b3c), uint256(0x2ab3fbff06ba1c1b35f3c9e84f0cebd9207b02b3dcc766fbf8b081c3bcba2ec8));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x248883534667b2d703cb0c2c8a5c5e91caf02d807416ad5758697cc3e543ddad), uint256(0x2a834e425d16620a808e66c198add64d06e9fbed0de39126e9e8466cdfd7a456));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2298f5e0be109a2bb1d954a1b36dba308edaf86f949dd2998ba6df64f6478b18), uint256(0x005c947503c3188e5cca28c405a7e4e739b3616958144ff72ea48b8c4b71427f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x26c0f08f3a9babef0872d62bf910bd50a783cdc8b8c061f1af064fc7bf72517c), uint256(0x2b7c9966d3437f5103941198c68f26eda5e6979d876c84a6ffa54fd68964f58b));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x20aa9b894df421775bddb64ac96c2601636c954cdeef2e49e89a366e09406bb2), uint256(0x0cf873686ab3943f8ff3ed638ca8c943020c6f5fac248abc9acf994ef141b8d9));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1a040b6fb7679ed04e2909d900956edc55f58f789741761eaa34b53f9b8fa4b3), uint256(0x26eda9539e0e845fa19c3be6ec403c5b4dcb857c4d9268374d6e1b7a6259ba79));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x29f260b7ef5771b04edbb2337887e1685d74a9a8c51952191c11064b9665adb2), uint256(0x305853e9365ccd416083b0cfb9c337b2e079dc010a08becb5db0b8356760bc22));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1c7e01710f87f5e153682560fc4b77068e604a9cfef2f0e8797d6992dbb637a4), uint256(0x0fe098880c2e32010476edb82dac875594ecb634a86325be5eb02e2dc5edb34d));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x237672bcbe127202e1b581c5f006bef3fc6955b93397564702b487128ef74c0b), uint256(0x0632ba70fecf83b717f2d4c29b3e576f1780bcc526da2357a7758d76cfcda799));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x29b417e179b8d27c72f4a2c6b0f0c56ce70638ed873169f2c55589acd54aa70b), uint256(0x242011bfa58da58a8259eb466d17f0ffa380d36d16fc918c9f494262a126ec0f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x01e7dc7fe4e4ac8c4689c11467308c24a09d5046739599f6933706c36e15f81e), uint256(0x1a4a4250ca16a592bf2ab0e554d89319940ed9f603109dfe1d298443bc3bd372));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x261c33238f807fc659d6b9815c7105eb5b0d0dca49ec892ee985fb72f090c905), uint256(0x25d9835377be4b8c301799bb979df19d93449f481ef5bfe4a6b13fdc2fcdf4c3));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x28df923ccba966eafa3150a9d4fcaa58c59818f2fc23a90abc3f233fb8f55ff9), uint256(0x23e198cc5a95713370952ce6412299bd45d5f4f25d0887a4dffa8d65e3b53c81));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0d4ed6eb7a4f022543f01816763a241cdd03086d96c287ae42fde9d02ddbae68), uint256(0x171a1cf634c0a9bffdf8330293156915f8ddec9221349e16ec5f6a0e8d829470));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1fefeb97b74742b8cdf76c5f9100112b3be8474a58a128860e8874664bbc474b), uint256(0x270868048b10d5bd5d94f18391c3402e330802bcdfe2aa66f3c06e63613a9cc7));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0525b5d9a1aea6314e1a0b1101c6e3699604c13d37ce4d51a2c91aa1a651f702), uint256(0x1a876c1bf63427cd595680de4fa3fd9c09bbe3130c166680490eaa2f90736d67));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x14f1b61f64c30948c35712902ff2ca9c79aca6d98e0178ec735632f02e0ae28b), uint256(0x0e4bd11dd58e8667e27bb2429146c07848542f2e70579cb4e547a62f64485f98));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x26f6a626225f4cd45e8e49ce8c7b64602f4beaaeb2f53c24258ea0258a7fc728), uint256(0x03d6305e2c970d31bec4877159b9cc4d3dcd5f322c899bae0f20082959883586));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x22fbaef7e5fcd82653ce74eb8c24a9824a4ccc4c270f1d6e9aed5b7192b96233), uint256(0x144a9a6388515b3c482831a536648923faafbd5bd157f0823004e3001deaaa96));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x27462fe52eb153fda6062542ac6343cf2c4e896dde31da05ec9f330912be05dd), uint256(0x107d802938b7b2cc787ef10faf3a2e0ac248804741301880eeb1e291fa79c195));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1d7c91b030bca0b8006e9a202b5313bba32cc4cd0b7e4a6ae0871967ca4548c6), uint256(0x259749c4463b4ec6777180fc1fb637b02a8be10fbbbf3da0a200d4e714ae5dba));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1e3559b73affa9548d8e3a44c69cbd1286701339389a9426017f6e4da303bddd), uint256(0x08f432cba53e7997284270c6fa61b86390c0340e3adeab1603bb4b054980f462));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x16b2acd1d9d214896d35b97fc2166dd39c1bd8f4407e4eabacf1a572f8246f05), uint256(0x1f3536b36ba2ead2a1f4efa4c53aa6c1ed680730b47f4bccce88330317367e32));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x03cdd97c5cc06a67edef36043a2a077ce895937455db9acd2ebfbf0b6dc3b4cb), uint256(0x0a216349c551635f862c82ab086ac275b7589e6ce01f4da8ee653eb525c6304d));
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
