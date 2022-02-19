from typing import Any, List, Optional, Tuple
import hashlib
import secrets

from reference import *

infinity = None

def cbytes(P: Point) -> bytes:
    a = b'\x02' if has_even_y(P) else b'\x03'
    return a + bytes_from_point(P)

def point_negate(P: Point) -> Point:
    if is_infinite(P):
        return P
    return (x(P), p - y(P))

def pointc(x: bytes) -> Point:
    P = lift_x(x[1:33])
    if x[0] == 2:
        return P
    elif x[0] == 3:
        return point_negate(P)
    assert False

def key_agg(pubkeys: List[bytes]) -> bytes:
    Q = key_agg_internal(pubkeys)
    return bytes_from_point(Q)

def key_agg_internal(pubkeys: List[bytes]) -> Point:
    u = len(pubkeys)
    Q = infinity
    for i in range(u):
        a_i = key_agg_coeff(pubkeys, pubkeys[i])
        P_i = lift_x(pubkeys[i])
        Q = point_add(Q, point_mul(P_i, a_i))
    assert not is_infinite(Q)
    return Q

def hash_keys(pubkeys: List[bytes]) -> bytes:
    return tagged_hash('KeyAgg list', b''.join(pubkeys))

def key_agg_coeff(pubkeys: List[bytes], pk: bytes) -> int:
    L = hash_keys(pubkeys)
    return int_from_bytes(tagged_hash('KeyAgg coefficient', L + pk)) % n

def nonce_gen() -> Tuple[bytes, bytes]:
    k = 1 + secrets.randbelow(n - 2)
    R = point_mul(G, k)
    pubnonce = cbytes(R)
    secnonce = bytes_from_int(k)
    return secnonce, pubnonce

def nonce_agg(pubnonces: List[bytes]) -> bytes:
    R = infinity
    for pubnonce in pubnonces:
        R = point_add(R, pointc(pubnonce))
    return cbytes(R)

def sign(secnonce: bytes, sk: bytes, aggnonce: bytes, pubkeys: List[bytes], msg: bytes) -> bytes:
    R = pointc(aggnonce)
    assert not is_infinite(R)
    Q = key_agg_internal(pubkeys)
    k_ = int_from_bytes(secnonce)
    assert 0 < k_ < n
    k = k_ if has_even_y(R) else n - k_
    d_ = int_from_bytes(sk)
    assert 0 < d_ < n
    P = point_mul(G, d_)
    d = n - d_ if has_even_y(P) != has_even_y(Q) else d_
    e = int_from_bytes(tagged_hash('BIP0340/challenge', bytes_from_point(R) + bytes_from_point(Q) + msg)) % n
    mu = key_agg_coeff(pubkeys, bytes_from_point(P))
    s = (k + e * mu * d) % n
    psig = bytes_from_int(s)
    pubnonce = cbytes(point_mul(G, k_))
    #assert partial_sig_verify_internal(psig, pubnonce, aggnonce, pubkeys, bytes_from_point(P), msg)
    return psig

def partial_sig_verify(psig: bytes, pubnonces: List[bytes], pubkeys: List[bytes], msg: bytes, i: int) -> bool:
    aggnonce = nonce_agg(pubnonces)
    return partial_sig_verify_internal(psig, pubnonces[i], aggnonce, pubkeys, pubkeys[i], msg)

def partial_sig_verify_internal(psig: bytes, pubnonce: bytes, aggnonce: bytes, pubkeys: List[bytes], pk: bytes, msg: bytes) -> bool:
    s = int_from_bytes(psig)
    assert s < n
    R = pointc(aggnonce)
    Q = key_agg_internal(pubkeys)
    R__ = pointc(pubnonce)
    R_ = R__ if has_even_y(R) else point_negate(R__)
    e = int_from_bytes(tagged_hash('BIP0340/challenge', bytes_from_point(R) + bytes_from_point(Q) + msg)) % n
    mu = key_agg_coeff(pubkeys, pk)
    P_ = lift_x(pk)
    P = P_ if has_even_y(Q) else point_negate(P_)
    return point_mul(G, s) == point_add(R_, point_mul(P, e * mu % n))

def test_sign_and_verify_random(iters):
    for i in range(iters):
        sk_1 = secrets.token_bytes(32)
        sk_2 = secrets.token_bytes(32)
        pk_1 = bytes_from_point(point_mul(G, int_from_bytes(sk_1)))
        pk_2 = bytes_from_point(point_mul(G, int_from_bytes(sk_2)))
        pubkeys = [pk_1, pk_2]

        secnonce_1, pubnonce_1 = nonce_gen()
        secnonce_2, pubnonce_2 = nonce_gen()
        pubnonces = [pubnonce_1, pubnonce_2]
        aggnonce = nonce_agg(pubnonces)

        msg = secrets.token_bytes(32)

        psig = sign(secnonce_1, sk_1, aggnonce, pubkeys, msg)
        assert partial_sig_verify(psig, pubnonces, pubkeys, msg, 0)

        # Wrong signer index
        assert not partial_sig_verify(psig, pubnonces, pubkeys, msg, 1)

        # Wrong message
        assert not partial_sig_verify(psig, pubnonces, pubkeys, secrets.token_bytes(32), 0)

if __name__ == '__main__':
    test_sign_and_verify_random(4)
