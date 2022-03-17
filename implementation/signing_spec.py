r"""Proof-of-concept implementation of DSSE on top of COSE.

This is effectively a minimal COSE implementation that conforms to the API of
DSSE, namely requiring a single protected "content type" header. The encoding is
CBOR for compatibility with COSE, though a JSON encoding is also possible.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0

The following example requires `pip3 install pycryptodome` and uses ecdsa.py in
the same directory as this file.

>>> import binascii, os, sys
>>> from pprint import pprint
>>> sys.path.insert(0, os.path.dirname(__file__))
>>> import ecdsa

>>> signer = ecdsa.Signer.construct(
...     curve='P-256',
...     d=97358161215184420915383655311931858321456579547487070936769975997791359926199,
...     point_x=46950820868899156662930047687818585632848591499744589407958293238635476079160,
...     point_y=5640078356564379163099075877009565129882514886557779369047442380624545832820)
>>> verifier = ecdsa.Verifier(signer.public_key)
>>> payloadType = 'http://example.com/HelloWorld'
>>> payload = b'hello world'

Signing example:

>>> signature_cbor = Sign(payloadType, payload, signer)
>>> binascii.hexlify(signature_cbor)
b'845821a103781d687474703a2f2f6578616d706c652e636f6d2f48656c6c6f576f726c64a04b68656c6c6f20776f726c64818340a1046836363330316262665840e21b0bbcbd129abfb39fba9026711a7521ce04d05449b9885a17230c6b6630f5e41c2770f3f01071de74ee3c7480a8cc011b1387840550f4c8ab333ac78434d7'

Verification example:

>>> result = Verify(signature_cbor, [('mykey', verifier)])
>>> pprint(result)
VerifiedPayload(payloadType='http://example.com/HelloWorld', payload=b'hello world', recognizedSigners=['mykey'])

PAE:

>>> sig_structure(payloadType, payload)
b'\x85ISignaturex\x1dhttp://example.com/HelloWorld@@Khello world'
"""

import binascii, dataclasses, io, struct

# Protocol requires Python 3.8+.
from typing import Iterable, List, Optional, Protocol, Tuple

import cbor


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes:
        """Returns the signature of `message`."""
        ...

    def keyid(self) -> Optional[str]:
        """Returns the ID of this key, or None if not supported."""
        ...


class Verifier(Protocol):
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Returns true if `message` was signed by `signature`."""
        ...

    def keyid(self) -> Optional[str]:
        """Returns the ID of this key, or None if not supported."""
        ...


# Collection of verifiers, each of which is associated with a name.
VerifierList = Iterable[Tuple[str, Verifier]]


@dataclasses.dataclass
class VerifiedPayload:
    payloadType: str
    payload: bytes
    recognizedSigners: List[str]  # List of names of signers


# COSE Common headers:
ALG = 1
CRIT = 2
CONTENT_TYPE = 3
KID = 4
IV = 5
PARTIAL_IV = 6
COUNTER_SIGNATURE = 7


def sig_structure(body_protected: bytes, payload: bytes) -> bytes:
    return cbor.encode([
        b'Signature',
        body_protected,
        b'',  # sign_protected
        b'',  # external_aad
        payload,
    ])


def Sign(payloadType: str, payload: bytes, signer: Signer) -> bytes:
    body_protected = cbor.encode({CONTENT_TYPE: payloadType})
    body_unprotected = {}
    sign_protected = b''
    sign_unprotected = {KID: signer.keyid()}
    return cbor.encode([
        body_protected, body_unprotected, payload,
        [[
            sign_protected,
            sign_unprotected,
            signer.sign(sig_structure(body_protected, payload)),
        ]]
    ])


def Verify(cbor_wrapper: bytes, verifiers: VerifierList) -> VerifiedPayload:
    wrapper = cbor.decode(cbor_wrapper)
    if not isinstance(wrapper, list) or len(wrapper) != 4:
        raise ValueError('Expected array of length 4: %r' % wrapper)
    body_protected, body_unprotected, payload, signatures = wrapper
    # TODO: check types
    to_be_signed = sig_structure(body_protected, payload)
    recognizedSigners = []
    for signature in signatures:
        sign_protected, sign_unprotected, sig = signature
        if sign_protected:
            raise ValueError('sign_protected expected to be empty')
        keyid = sign_unprotected.get('keyid')
        # TODO check types
        for name, verifier in verifiers:
            if (keyid is not None and verifier.keyid() is not None
                    and keyid != verifier.keyid()):
                continue
            if verifier.verify(to_be_signed, sig):
                recognizedSigners.append(name)
    if not recognizedSigners:
        raise ValueError('No valid signature found')
    headers = cbor.decode(body_protected)
    # TODO check types
    if len(headers) != 1 or CONTENT_TYPE not in headers:
        raise ValueError('Expected exactly one protected header (%d), got %r' %
                         (CONTENT_TYPE, headers))
    payloadType = headers[CONTENT_TYPE]
    return VerifiedPayload(payloadType, payload, recognizedSigners)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
