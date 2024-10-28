#
# Please complete the following in Rust.
# 1: ZK knowledge proof
Please find the attached Python source file. Please implement the same primitive in Rust.
Please use any suitable from RustCrypto.
# Non-interactive Schnorr ZK DLOG Proof scheme with a Fiat-Shamir transformation
#

```python
import json
import secrets
import time
from hashlib import sha256
from typing import List

import ecdsa
from ecdsa.ellipticcurve import PointJacobi

from htss_ecdsa.common.serializers import (
    BigIntegerField,
    ECDSAPointField,
    SerializerField,
    StringField,
)

curve = ecdsa.SECP256k1
G = curve.generator
q = curve.order


def generate_random_number() -> int:
    return BigIntegerField().from_bytes(secrets.token_bytes(32))


class DLogProof:
    """
    Non-interactive Schnorr ZK DLOG Proof scheme with a Fiat-Shamir transformation
    """

    G = curve.generator
    q = curve.order

    def __init__(self, t: PointJacobi, s: int):
        self.t = t
        self.s = s

    def __eq__(self, other):
        assert type(other) is DLogProof, "Can only compare DLogProofs"

        return self.to_dict() == other.to_dict()

    def __ne__(self, other):
        return not self.__eq__(other)

    @staticmethod
    def _hash_points(sid: str, pid: int, points: List[PointJacobi]):
        string_field = StringField()
        bigint_field = BigIntegerField()
        point_field = ECDSAPointField()
        h = sha256()
        h.update(string_field.to_bytes(sid))
        h.update(bigint_field.to_bytes(pid))
        for point in points:
            h.update(point_field.to_bytes(point))
        digest = h.digest()
        return BigIntegerField().from_bytes(digest)

    @staticmethod
    def prove(sid: str, pid: int, x: int, y: PointJacobi, base_point: PointJacobi = G):
        """y = x*G"""
        r = generate_random_number()
        t = r * base_point
        c = DLogProof._hash_points(sid, pid, [base_point, y, t])
        s = (r + c * x) % DLogProof.q
        return DLogProof(t, s)

    def verify(self, sid: str, pid: int, y: PointJacobi, base_point: PointJacobi = G):
        c = self._hash_points(sid, pid, [base_point, y, self.t])
        lhs = self.s * base_point
        rhs = self.t + (y * c)
        return lhs == rhs

    def to_dict(self):
        return {
            "t": ECDSAPointField().serialize(self.t),
            "s": BigIntegerField().serialize(self.s),
        }

    def to_str(self):
        return json.dumps(self.to_dict())

    @staticmethod
    def from_dict(data):
        t = ECDSAPointField().deserialize(data["t"])
        s = BigIntegerField().deserialize(data["s"])
        return DLogProof(t, s)


class DLogProofField(SerializerField):
    def serialize(self, dlog_proof: DLogProof) -> dict:
        return dlog_proof.to_dict()

    def deserialize(self, data: dict) -> DLogProof:
        return DLogProof.from_dict(data)


if __name__ == "__main__":
    sid = "sid"
    pid = 1

    x = generate_random_number()
    print(x)
    y = x * G

    start_proof = time.time()
    dlog_proof = DLogProof.prove(sid, pid, x, y)
    print(
        "Proof computation time: {} ms".format(int((time.time() - start_proof) * 1000))
    )

    print("")
    print(dlog_proof.t.x(), dlog_proof.t.y())
    print(dlog_proof.s)

    start_verify = time.time()
    result = dlog_proof.verify(sid, pid, y)
    print(
        "Verify computation time: {} ms".format(
            int((time.time() - start_verify) * 1000)
        )
    )
    if result:
        print("DLOG proof is correct")
    else:
        print("DLOG proof is not correct")

```
