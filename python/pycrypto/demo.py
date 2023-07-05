import hashlib
from zokrates_pycrypto.eddsa import PrivateKey, PublicKey
from zokrates_pycrypto.field import FQ
from zokrates_pycrypto.utils import write_signature_for_zokrates_cli
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher


def write_compute_witeness_command(pk, sig, msg, path):
    sig_R, sig_S = sig
    # print(pk.p.compress().hex())
    args = ["zokrates compute-witness -a", sig_R.x, sig_R.y, sig_S, pk.p.x.n, pk.p.y.n]
    args = " ".join(map(str, args))

    M0 = msg.hex()[:64]
    M1 = msg.hex()[64:]
    b0 = [str(int(M0[i:i+8], 16)) for i in range(0,len(M0), 8)]
    b1 = [str(int(M1[i:i+8], 16)) for i in range(0,len(M1), 8)]
    args = args + " " + " ".join(b0 + b1)

    preimage = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000" + pk.p.compress().hex()) 
    personalisation = 'test'.encode("ascii")    
    point = PedersenHasher(personalisation).hash_bytes(preimage)
    digest = point.compress().hex()
    b2 = [str(int(digest[i:i+8], 16)) for i in range(0,len(digest), 8)]
    args = args + " " + " ".join(b2)

    # pk.compress

    with open(path, "w+") as file:
        for l in args:
            file.write(l)


if __name__ == "__main__":

    raw_msg = "This is my secret message"
    msg = hashlib.sha512(raw_msg.encode("utf-8")).digest()

    # sk = PrivateKey.from_rand()
    # Seeded for debug purpose
    # a = random
    key = FQ(1997011358982923168928344992199991480689546837621580239342656433234255379025)
    sk = PrivateKey(key)
    sig = sk.sign(msg)

    pk = PublicKey.from_private(sk)
    is_verified = pk.verify(sig, msg)
    print(is_verified)

    path = 'compute_witeness_command.sh'
    write_compute_witeness_command(pk, sig, msg, path)
