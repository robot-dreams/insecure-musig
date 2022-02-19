# insecure-musig

This repo demonstrates an attack against "InsecureMuSig", a modified version of [MuSig](https://eprint.iacr.org/2018/068) where the nonce commitment round is omitted. Equivalently, this is an attack against a modified version of [MuSig2](https://eprint.iacr.org/2020/1261) with the degenerate case `nu = 1`.

Although it might be feasible to use [Wagner's algorithm](https://www.iacr.org/archive/crypto2002/24420288/24420288.pdf), we instead use the approach from [On the (in)security of ROS](https://eprint.iacr.org/2020/945). This approach uses 256 concurrent signing sessions (one for each bit of the SHA256 challenge hash), and is extremely efficient: the running time is completely dominated by the time needed to actually complete the signing sessions.

The InsecureMuSig implementation is designed to be interoperable with BIP-340. In fact, the reference implementation of Schnorr signatures was copied directly from the [BIPs repo](https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py).

Note that the use of "xonly" points in BIP-340 significantly complicates the attack. We partially handle the complexity by regenerating/retrying until all attacker public keys/nonces have even y coordinate. The attack currently only works against an honest signer whose public key has even y coordinate, but in the future we can likely get around this by handling the two cases separately.

The attack itself can be found in [insecure_musig.py](insecure_musig.py); the function [`test_forgery`](https://github.com/robot-dreams/insecure-musig/blob/main/insecure_musig.py#L183) is a good entry point.
