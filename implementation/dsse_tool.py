"""CLI to use DSSE.

Currently this only supports ECDSA with deterministic-rfc6979 and SHA256.

Copyright 2021 Google LLC.
SPDX-License-Identifier: Apache-2.0
"""

import argparse, os, sys
from Crypto.PublicKey import ECC
sys.path.insert(0, os.path.dirname(__file__))
import ecdsa, signing_spec


def verify(args):
    print('verify')
    with open(args.pubkey, 'rb') as f:
        public_key = ECC.import_key(f.read())
    verifier = ecdsa.Verifier(public_key)
    with open(args.envelope, 'rb') as f:
        envelope = f.read()
    result = signing_spec.Verify(envelope, [('key', verifier)])
    if args.raw:
        print(result.payload, end='')
    else:
        print('payloadType:', result.payloadType)
        print(result.payload)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    verify_p = subparsers.add_parser('verify')
    verify_p.set_defaults(func=verify)
    verify_p.add_argument('--pubkey', '-k', required=True,
                          help='ECC public key file in DER, PEM, or OpenSSH format')
    verify_p.add_argument('--raw', action='store_true', default=False,
                          help='print raw payload without payloadType line')
    verify_p.add_argument('envelope',
                          help='envelope file to verify')

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
