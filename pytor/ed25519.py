"""
this code is a cleaned version of http://ed25519.cr.yp.to/python/ed25519.py
for python3

code released under the terms of the GNU Public License v3, copyleft 2015
yoochan
"""
import collections

Point = collections.namedtuple("Point", ["x", "y"])


class Ed25519:
    """
    Generate public key from private key secret hash
    """

    length = 256

    def __init__(self):
        self.q = 2 ** 255 - 19
        self.l = 2 ** 252 + 27742317777372353535851937790883648493
        self.d = -121665 * self.inverse(121666)

        self.i = pow(2, (self.q - 1) // 4, self.q)

        self.B = self.point(4 * self.inverse(5))

    def from_bytes(self, h):
        """ pick 32 bytes, return a 256 bit int """
        return int.from_bytes(h[0 : self.length // 8], "little", signed=False)

    def to_bytes(self, k):
        return k.to_bytes(self.length // 8, "little", signed=False)

    def public_key_from_hash(self, hash):
        c = self.outer(self.B, int.from_bytes(hash[:32], "little"))
        return self.point_to_bytes(c)

    def inverse(self, x):
        return pow(x, self.q - 2, self.q)

    def recover(self, y):
        """ given a value y, recover the preimage x """
        p = (y * y - 1) * self.inverse(self.d * y * y + 1)
        x = pow(p, (self.q + 3) // 8, self.q)
        if (x * x - p) % self.q != 0:
            x = (x * self.i) % self.q
        if x % 2 != 0:
            x = self.q - x
        return x

    def point(self, y):
        """ given a value y, recover x and return the corresponding P(x, y) """
        return Point(self.recover(y) % self.q, y % self.q)

    def inner(self, P, Q):
        """ inner product on the curve, between two points """
        x = (P.x * Q.y + Q.x * P.y) * self.inverse(
            1 + self.d * P.x * Q.x * P.y * Q.y
        )
        y = (P.y * Q.y + P.x * Q.x) * self.inverse(
            1 - self.d * P.x * Q.x * P.y * Q.y
        )
        return Point(x % self.q, y % self.q)

    def outer(self, P, n):
        """ outer product on the curve, between a point and a scalar """
        if n == 0:
            return Point(0, 1)
        Q = self.outer(P, n // 2)
        Q = self.inner(Q, Q)
        if n & 1:
            Q = self.inner(Q, P)
        return Q

    def point_to_bytes(self, P):
        return (P.y + ((P.x & 1) << 255)).to_bytes(self.length // 8, "little")
