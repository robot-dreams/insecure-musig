from typing import List

from reference import *

def cbytes_from_point(P: Point) -> bytes:
    prefix = b'\x02' if has_even_y(P) else b'\x03'
    return prefix + bytes_from_point(P)

def point_from_cbytes(b: bytes) -> Point:
    prefix = b[:1]
    x, y = lift_x(b[1:])
    return (x, y) if prefix == b'\x02' else (x, p-y)

def point_negate(P: Point) -> Point:
    if is_infinite(P):
        return P
    return (x(P), p - y(P))

def xonly_point_agg(xonly_points: List[bytes]) -> Point:
    P = None # point at infinity
    for xonly_point in xonly_points:
        P = point_add(P, lift_x(xonly_point))
    return P

def xonly_int(b: bytes, P_agg: Point) -> int:
    k = int_from_bytes(b)
    if has_even_y(point_mul(G, k)) != has_even_y(P_agg):
        k = n - k
    return k

def partial_sig_agg(partial_sigs: List[bytes]) -> bytes:
    s = 0
    for partial_sig in partial_sigs:
        s = (s + int_from_bytes(partial_sig)) % n
    return bytes_from_int(s)
