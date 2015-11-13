# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os

from oscrypto import asymmetric
from certbuilder import CertificateBuilder


fixtures_dir = os.path.join(os.path.dirname(__file__), '..', 'tests', 'fixtures')


root_ca_private_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'test.key'))
root_ca_certificate = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))

root_ocsp_public_key, root_ocsp_private_key = asymmetric.generate_pair('rsa', bit_size=2048)

with open(os.path.join(fixtures_dir, 'test-ocsp.key'), 'wb') as f:
    f.write(asymmetric.dump_private_key(root_ocsp_private_key, 'password', target_ms=20))

builder = CertificateBuilder(
    {
        'country_name': 'US',
        'state_or_province_name': 'Massachusetts',
        'locality_name': 'Newbury',
        'organization_name': 'Codex Non Sufficit LC',
        'organization_unit_name': 'Testing',
        'common_name': 'CodexNS OCSP Responder',
    },
    root_ocsp_public_key
)
builder.extended_key_usage = set(['ocsp_signing'])
builder.issuer = root_ca_certificate
root_ocsp_certificate = builder.build(root_ca_private_key)

with open(os.path.join(fixtures_dir, 'test-ocsp.crt'), 'wb') as f:
    f.write(asymmetric.dump_certificate(root_ocsp_certificate))
