r"""Simple minimal implementation of CBOR.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0
"""

import io, struct

from typing import Tuple


class StructIO(io.BytesIO):
    def read_int(self, format: str) -> int:
        size = struct.calcsize(format)
        value = super().read(size)
        if len(value) != size:
            raise ValueError('unexpected EOF reached at pos %d' % self.tell())
        return struct.unpack(format, value)[0]


# CBOR Major type:
UNSIGNED_INT = 0
NEGATIVE_INT = 1
BYTE_STRING = 2
TEXT_STRING = 3
ARRAY = 4
MAP = 5


def _head(major: int, arg: int) -> bytes:
    if arg < 24:
        return struct.pack('>B', (major << 5) | arg)
    elif arg < 256:
        return struct.pack('>BB', (major << 5) | 24, arg)
    elif arg < 65536:
        return struct.pack('>BH', (major << 5) | 25, arg)
    elif arg < 4294967296:
        return struct.pack('>BI', (major << 5) | 26, arg)
    elif arg < 18446744073709551616:
        return struct.pack('>BQ', (major << 5) | 27, arg)
    else:
        raise ValueError('arg %d too big' % arg)


def _head_decode(b: StructIO) -> Tuple[int, int]:
    initial_byte = b.read_int('>B')
    major = initial_byte >> 5
    argtype = initial_byte & 0x1f
    if argtype < 24:
        return major, argtype
    if argtype == 24:
        return major, b.read_int('>B')
    if argtype == 25:
        return major, b.read_int('>H')
    if argtype == 26:
        return major, b.read_int('>I')
    if argtype == 27:
        return major, b.read_int('>Q')
    raise ValueError('Unexpected argtype %d at pos %d' % (argtype, b.tell()))


def encode(value) -> bytes:
    if isinstance(value, int):
        if value >= 0:
            return _head(UNSIGNED_INT, value)
        else:
            return _head(NEGATIVE_INT, -1 - value)
    if isinstance(value, bytes):
        return _head(BYTE_STRING, len(value)) + value
    if isinstance(value, str):
        b = value.encode('utf-8')
        return _head(TEXT_STRING, len(b)) + b
    if isinstance(value, list):
        return _head(ARRAY, len(value)) + b''.join([encode(x) for x in value])
    if isinstance(value, dict):
        items = [(encode(k), encode(v)) for k, v in value.items()]
        items.sort()
        return _head(MAP, len(value)) + b''.join([e for t in items for e in t])
    raise ValueError('unsupported type: %s' % type(value))


def _decode(b: StructIO):
    major, arg = _head_decode(b)
    if major == UNSIGNED_INT:
        return arg
    if major == NEGATIVE_INT:
        return -1 - arg
    if major == BYTE_STRING:
        return b.read(arg)
    if major == TEXT_STRING:
        return b.read(arg).decode('utf-8')
    if major == ARRAY:
        return [_decode(b) for i in range(arg)]
    if major == MAP:
        return {_decode(b): _decode(b) for i in range(arg)}
    raise ValueError('unsupported major type: %d' % major)


def decode(b: bytes):
    return _decode(StructIO(b))
