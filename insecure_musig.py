#import pdb
import secrets

from insecure_musig_reference import *
from reference import *
from util import *

def forge_signature(honest_signer, honest_msg, forged_msg):
    X1 = honest_signer.get_pubkey()

    # Force even y coordinate in both adversary pubkey and aggregate pubkey
    while True:
        adversary = InsecureMuSigSigner()
        P = point_mul(G, int_from_bytes(adversary.seckey))
        if not has_even_y(P):
            continue
        X2 = adversary.get_pubkey()

        # Key aggregation
        pubkeys = [X1, X2]
        Q = key_agg_internal(pubkeys)
        if has_even_y(Q):
            break

    X = key_agg(pubkeys)
    a_1 = key_agg_coeff(pubkeys, X1)
    a_2 = key_agg_coeff(pubkeys, X2)

    # Target is a 256-bit value
    k_max = 256
    R_1 = [None] * k_max
    for k in range(k_max):
        print('gen_partial_pubnonce', k)
        R_1[k] = pointc(honest_signer.gen_partial_pubnonce(k))

    # Force even y coordinate in linear combination of honest signer's pubnonces
    while True:
        # Two choices of attacker-controlled aggregate nonces,
        # force even y coordinate in both
        while True:
            r_agg_0, R_agg_0 = nonce_gen()
            r_agg_1, R_agg_1 = nonce_gen()
            if has_even_y(pointc(R_agg_0)) and has_even_y(pointc(R_agg_1)):
                break

        # Two corresponding challenges for each signing session
        c_0 = [None] * k_max
        c_1 = [None] * k_max
        for k in range(k_max):
            # BIP0340 challenge hash uses x-only pubnonces, so remove first byte of R_agg_b
            c_0[k] = int_from_bytes(tagged_hash('BIP0340/challenge', R_agg_0[1:] + X + honest_msg)) % n
            c_1[k] = int_from_bytes(tagged_hash('BIP0340/challenge', R_agg_1[1:] + X + honest_msg)) % n
            # Only fails with negligible probability
            assert c_0[k] != c_1[k]
        print("generate c_0, c_1 done")

        # Coefficients in the linear combination
        alpha = [None] * k_max
        for k in range(k_max):
            # (c_1[k] - c_0[k])^(-1) mod n
            alpha[k] = pow(2, k, n) * pow(c_1[k] - c_0[k], n - 2, n) % n
        print("generate alpha done")

        # Nonce used in forgery
        R_star = infinity
        for k in range(k_max):
            print('point_add', k)
            R_star = point_add(R_star, point_mul(R_1[k], alpha[k]))
        if has_even_y(R_star):
            print("generate R_star done")
            break
        else:
            print("R_star has odd y, retrying")

    # Challenge used in forgery
    e = int_from_bytes(tagged_hash('BIP0340/challenge', bytes_from_point(R_star) + X + forged_msg)) % n
    print("generate e done")

    # The k-th bit of `target` determines whether the k-th partial signature
    # should use R_agg_0 or R_agg_1 as the aggregate nonce
    target = e
    for k in range(k_max):
        target = (target - alpha[k] * c_0[k]) % n
    print("generate target done")
    R_agg = [None] * k_max
    for k in range(k_max):
        if target & (1 << k) == 0:
            R_agg[k] = R_agg_0
        else:
            R_agg[k] = R_agg_1

    # Verify coefficients from ROS attack
    c = 0
    for k in range(k_max):
        e_k = int_from_bytes(tagged_hash('BIP0340/challenge', R_agg[k][1:] + X + honest_msg)) % n
        c = (c + alpha[k] * e_k) % n
    assert c == e
    print("linear combination matches challenge on forged_msg")

    # Get honest signer to generate partial signatures on valid messages,
    # across different sessions
    s_1 = [None] * k_max
    for k in range(k_max):
        print('gen_partial_sig', k)
        s_1[k] = int_from_bytes(honest_signer.gen_partial_sig(k, pubkeys, R_agg[k], honest_msg))
    print("generate partial signatures done")

    # The linear combination of the partial signatures from the honest signer
    # is equal to r_star + e * x_1 * a_1
    s = 0
    for k in range(k_max):
        s = (s + alpha[k] * s_1[k]) % n

    #pdb.set_trace()

    assert partial_sig_verify_internal(bytes_from_int(s), cbytes(R_star), cbytes(R_star), pubkeys, X1, forged_msg)
    print("partial sig verify success")

    # In order to convert this to a full signature, the only thing left
    # is to add the contribution from the adversary (without changing the
    # "aggregate nonce" R_star)
    x_2 = int_from_bytes(adversary.seckey)
    s = (s + e * x_2 * a_2) % n
    sig = bytes_from_point(R_star) + bytes_from_int(s)
    return pubkeys, sig

class InsecureMuSigSigner:
    def __init__(self, seckey=None):
        if seckey is None:
            seckey = secrets.token_bytes(32)
        self.seckey = seckey
        self.pubkey = pubkey_gen(self.seckey)
        self.secnonces = dict()
        self.seen_queries = set()

    def get_pubkey(self):
        return self.pubkey

    def gen_partial_pubnonce(self, k):
        assert k not in self.secnonces
        secnonce, pubnonce = nonce_gen()
        self.secnonces[k] = secnonce
        return pubnonce

    def gen_partial_sig(self, k, pubkeys, aggnonce, msg):
        assert k in self.secnonces
        #assert pubkey_gen(self.seckey) in pubkeys
        assert len(aggnonce) == 33
        assert len(msg) == 32

        secnonce = self.secnonces[k]
        #del self.secnonces[k]
        self.seen_queries.add((tuple(pubkeys), msg))

        return sign(secnonce, self.seckey, aggnonce, pubkeys, msg)

def test_basic():
    signer1 = InsecureMuSigSigner()
    signer2 = InsecureMuSigSigner()

    X1 = signer1.get_pubkey()
    X2 = signer2.get_pubkey()
    pubkeys = [X1, X2]
    agg_pubkey = key_agg(pubkeys)

    R1 = signer1.gen_partial_pubnonce(0)
    R2 = signer2.gen_partial_pubnonce(0)
    R = point_add(pointc(R1), pointc(R2))
    msg = b'msg signed by both Alice and Bob'

    aggnonce = cbytes_from_point(R)
    s1 = signer1.gen_partial_sig(0, pubkeys, aggnonce, msg)
    s2 = signer2.gen_partial_sig(0, pubkeys, aggnonce, msg)
    sig = bytes_from_point(R) + partial_sig_agg([s1, s2])

    assert schnorr_verify(msg, agg_pubkey, sig)

def test_forgery():
    # Force even y coordinate in honest signer's pubkey for now
    while True:
        honest_signer = InsecureMuSigSigner()
        P = point_mul(G, int_from_bytes(honest_signer.seckey))
        if has_even_y(P):
            break
    honest_msg = b'msg signed by both Alice and Bob'
    forged_msg = b'send all of Bob\'s coins to Alice'

    pubkeys, sig = forge_signature(honest_signer, honest_msg, forged_msg)
    assert honest_signer.get_pubkey() in pubkeys
    assert (tuple(pubkeys), forged_msg) not in honest_signer.seen_queries

    agg_pubkey = key_agg(pubkeys)
    assert schnorr_verify(forged_msg, agg_pubkey, sig)

if __name__ == '__main__':
    #test_basic()
    test_forgery()
