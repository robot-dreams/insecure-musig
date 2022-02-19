#import pdb
import secrets

from insecure_musig_reference import *
from reference import *
from util import *

# 256 concurrent signing sessions, one session per bit
k_max = 256

def gen_signer_even_y():
    while True:
        signer = InsecureMuSigSigner()
        x = int_from_bytes(signer.seckey)
        P = point_mul(G, x)
        if has_even_y(P):
            return signer

def gen_nonce_even_y():
    while True:
        r, R = nonce_gen()
        if has_even_y(pointc(R)):
            return r, R

def forge_signature(honest_signer, honest_msg, forged_msg):
    X1 = honest_signer.get_pubkey()

    # Force even y coordinate in both adversary pubkey and aggregate pubkey
    while True:
        adversary = gen_signer_even_y()
        X2 = adversary.get_pubkey()
        pubkeys = [X1, X2]
        Q = key_agg_internal(pubkeys)
        if has_even_y(Q):
            break

    mu_1 = key_agg_coeff(pubkeys, X1)
    mu_2 = key_agg_coeff(pubkeys, X2)

    # Start k_max concurrent signing sessions
    R_1 = [None] * k_max
    for k in range(k_max):
        print('gen_partial_pubnonce: point_mul', k)
        R_1[k] = pointc(honest_signer.gen_partial_pubnonce(k))
    print('gen_partial_pubnonce: done')

    # Loop forces even y coordinate in linear combination of honest signer's pubnonces
    # (i.e. final aggnonce used in forgery)
    while True:
        # Force even y coordinate in both choices of attacker-controlled
        # aggregate nonce
        _, R_agg_0 = gen_nonce_even_y()
        _, R_agg_1 = gen_nonce_even_y()

        # Two corresponding challenges for each signing session
        c_0 = [None] * k_max
        c_1 = [None] * k_max
        for k in range(k_max):
            # BIP0340 challenge hash uses x-only pubnonces, so remove first byte of R_agg_b
            c_0[k] = int_from_bytes(tagged_hash('BIP0340/challenge', R_agg_0[1:] + bytes_from_point(Q) + honest_msg)) % n
            c_1[k] = int_from_bytes(tagged_hash('BIP0340/challenge', R_agg_1[1:] + bytes_from_point(Q) + honest_msg)) % n
            # "Interpolation" fails if c_0[k] == c_1[k] but this only fails with negligible probability
            assert c_0[k] != c_1[k]

        # We can set the alpha linear combination of the challenge hashes equal to
        # any arbitrary value, just by choosing between R_agg_0 and R_agg_1 for each
        # of the k_max individual challenges
        alpha = [None] * k_max
        for k in range(k_max):
            # Modular inverse by raising to power of n - 2
            alpha[k] = pow(2, k, n) * pow(c_1[k] - c_0[k], n - 2, n) % n

        # R_star is the final aggnonce used in forgery
        R_star = infinity
        for k in range(k_max):
            print('generate R_star: point_add', k)
            R_star = point_add(R_star, point_mul(R_1[k], alpha[k]))

        if has_even_y(R_star):
            break
        else:
            print("generated R_star has odd y; retrying")

    # Challenge hash for forgery
    e = int_from_bytes(tagged_hash('BIP0340/challenge', bytes_from_point(R_star) + bytes_from_point(Q) + forged_msg)) % n

    # The k-th bit of `target` determines whether the k-th partial signature
    # should use R_agg_0 or R_agg_1 as the aggregate nonce
    target = e
    for k in range(k_max):
        target = (target - alpha[k] * c_0[k]) % n
    R_agg_choice = [None] * k_max
    for k in range(k_max):
        if target & (1 << k) == 0:
            R_agg_choice[k] = R_agg_0
        else:
            R_agg_choice[k] = R_agg_1

    # Verify that alpha linear combination of challenge hashes for honest messages
    # equals challenge hash for forgery
    c = 0
    for k in range(k_max):
        e_k = int_from_bytes(tagged_hash('BIP0340/challenge', R_agg_choice[k][1:] + bytes_from_point(Q) + honest_msg)) % n
        c = (c + alpha[k] * e_k) % n
    assert c == e

    # Get honest signer to generate partial signatures on valid messages,
    # across different sessions
    s_1 = [None] * k_max
    for k in range(k_max):
        print('gen_partial_sig', k)
        s_1[k] = int_from_bytes(honest_signer.gen_partial_sig(k, pubkeys, R_agg_choice[k], honest_msg))

    # The alpha linear combination of the partial signatures from the honest signer
    # is equal to r_star + e * x_1 * mu_1
    s = 0
    for k in range(k_max):
        s = (s + alpha[k] * s_1[k]) % n

    #pdb.set_trace()

    assert partial_sig_verify_internal(bytes_from_int(s), cbytes(R_star), cbytes(R_star), pubkeys, X1, forged_msg)
    print("partial_sig_verify successful")

    # Add contribution from adversary (without changing aggregate nonce R_star)
    # to convert partial signature into full signature
    x_2 = int_from_bytes(adversary.seckey)
    s = (s + e * x_2 * mu_2) % n
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
    # TODO: Handle honest signers with odd y as well
    honest_signer = gen_signer_even_y()
    honest_msg = b'msg signed by both Alice and Bob'
    forged_msg = b'send all of Bob\'s coins to Alice'

    pubkeys, sig = forge_signature(honest_signer, honest_msg, forged_msg)
    assert honest_signer.get_pubkey() in pubkeys
    assert (tuple(pubkeys), forged_msg) not in honest_signer.seen_queries

    agg_pubkey = key_agg(pubkeys)
    assert schnorr_verify(forged_msg, agg_pubkey, sig)
    print("schnorr_verify successful")

if __name__ == '__main__':
    #test_basic()
    test_forgery()
