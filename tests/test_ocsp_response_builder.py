# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime
import unittest
import os

import asn1crypto.x509
from oscrypto import asymmetric
from asn1crypto.util import timezone
from ocspbuilder import OCSPResponseBuilder

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPResponseBuilderTests(unittest.TestCase):

    def test_build_good_response(self):
        issuer_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'test.key'))
        issuer_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))
        subject_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-inter.crt'))

        builder = OCSPResponseBuilder('successful', subject_cert, 'good')
        ocsp_response = builder.build(issuer_key, issuer_cert)
        der_bytes = ocsp_response.dump()

        new_response = asn1crypto.ocsp.OCSPResponse.load(der_bytes)
        basic_response = new_response['response_bytes']['response'].parsed
        response_data = basic_response['tbs_response_data']

        self.assertEqual('sha256', basic_response['signature_algorithm'].hash_algo)
        self.assertEqual('rsassa_pkcs1v15', basic_response['signature_algorithm'].signature_algo)
        self.assertEqual('v1', response_data['version'].native)
        self.assertEqual('by_key', response_data['responder_id'].name)
        self.assertEqual(
            issuer_cert.asn1.public_key.sha1,
            response_data['responder_id'].chosen.native
        )
        self.assertGreaterEqual(datetime.now(timezone.utc), response_data['produced_at'].native)
        self.assertEqual(1, len(response_data['responses']))
        self.assertEqual(0, len(response_data['response_extensions']))

        cert_response = response_data['responses'][0]

        self.assertEqual('sha1', cert_response['cert_id']['hash_algorithm']['algorithm'].native)
        self.assertEqual(issuer_cert.asn1.subject.sha1, cert_response['cert_id']['issuer_name_hash'].native)
        self.assertEqual(issuer_cert.asn1.public_key.sha1, cert_response['cert_id']['issuer_key_hash'].native)
        self.assertEqual(subject_cert.asn1.serial_number, cert_response['cert_id']['serial_number'].native)

        self.assertEqual('good', cert_response['cert_status'].name)
        self.assertGreaterEqual(datetime.now(timezone.utc), cert_response['this_update'].native)
        self.assertGreaterEqual(set(), cert_response.critical_extensions)

    def test_build_revoked_response(self):
        issuer_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'test.key'))
        issuer_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))
        subject_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-inter.crt'))

        revoked_time = datetime(2015, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        builder = OCSPResponseBuilder('successful', subject_cert, 'key_compromise', revoked_time)
        ocsp_response = builder.build(issuer_key, issuer_cert)
        der_bytes = ocsp_response.dump()

        new_response = asn1crypto.ocsp.OCSPResponse.load(der_bytes)
        basic_response = new_response['response_bytes']['response'].parsed
        response_data = basic_response['tbs_response_data']

        self.assertEqual('sha256', basic_response['signature_algorithm'].hash_algo)
        self.assertEqual('rsassa_pkcs1v15', basic_response['signature_algorithm'].signature_algo)
        self.assertEqual('v1', response_data['version'].native)
        self.assertEqual('by_key', response_data['responder_id'].name)
        self.assertEqual(
            issuer_cert.asn1.public_key.sha1,
            response_data['responder_id'].chosen.native
        )
        self.assertGreaterEqual(datetime.now(timezone.utc), response_data['produced_at'].native)
        self.assertEqual(1, len(response_data['responses']))
        self.assertEqual(0, len(response_data['response_extensions']))

        cert_response = response_data['responses'][0]

        self.assertEqual('sha1', cert_response['cert_id']['hash_algorithm']['algorithm'].native)
        self.assertEqual(issuer_cert.asn1.subject.sha1, cert_response['cert_id']['issuer_name_hash'].native)
        self.assertEqual(issuer_cert.asn1.public_key.sha1, cert_response['cert_id']['issuer_key_hash'].native)
        self.assertEqual(subject_cert.asn1.serial_number, cert_response['cert_id']['serial_number'].native)

        self.assertEqual('revoked', cert_response['cert_status'].name)
        self.assertEqual(revoked_time, cert_response['cert_status'].chosen['revocation_time'].native)
        self.assertEqual('key_compromise', cert_response['cert_status'].chosen['revocation_reason'].native)
        self.assertGreaterEqual(datetime.now(timezone.utc), cert_response['this_update'].native)
        self.assertGreaterEqual(set(), cert_response.critical_extensions)

    def test_build_revoked_no_reason(self):
        issuer_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'test.key'))
        issuer_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))
        subject_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-inter.crt'))

        revoked_time = datetime(2015, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
        builder = OCSPResponseBuilder('successful', subject_cert, 'revoked', revoked_time)
        ocsp_response = builder.build(issuer_key, issuer_cert)
        der_bytes = ocsp_response.dump()

        new_response = asn1crypto.ocsp.OCSPResponse.load(der_bytes)
        basic_response = new_response['response_bytes']['response'].parsed
        response_data = basic_response['tbs_response_data']
        cert_response = response_data['responses'][0]

        self.assertEqual('revoked', cert_response['cert_status'].name)
        self.assertEqual(revoked_time, cert_response['cert_status'].chosen['revocation_time'].native)
        self.assertEqual('unspecified', cert_response['cert_status'].chosen['revocation_reason'].native)

    def test_build_delegated_good_response(self):
        responder_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'test-ocsp.key'), 'password')
        responder_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-ocsp.crt'))
        issuer_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))
        subject_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-inter.crt'))

        builder = OCSPResponseBuilder('successful', subject_cert, 'good')
        builder.certificate_issuer = issuer_cert
        ocsp_response = builder.build(responder_key, responder_cert)
        der_bytes = ocsp_response.dump()

        new_response = asn1crypto.ocsp.OCSPResponse.load(der_bytes)
        basic_response = new_response['response_bytes']['response'].parsed
        response_data = basic_response['tbs_response_data']

        self.assertEqual('sha256', basic_response['signature_algorithm'].hash_algo)
        self.assertEqual('rsassa_pkcs1v15', basic_response['signature_algorithm'].signature_algo)
        self.assertEqual('v1', response_data['version'].native)
        self.assertEqual('by_key', response_data['responder_id'].name)
        self.assertEqual(
            responder_cert.asn1.public_key.sha1,
            response_data['responder_id'].chosen.native
        )
        self.assertGreaterEqual(datetime.now(timezone.utc), response_data['produced_at'].native)
        self.assertEqual(1, len(response_data['responses']))
        self.assertEqual(0, len(response_data['response_extensions']))

        cert_response = response_data['responses'][0]

        self.assertEqual('sha1', cert_response['cert_id']['hash_algorithm']['algorithm'].native)
        self.assertEqual(issuer_cert.asn1.subject.sha1, cert_response['cert_id']['issuer_name_hash'].native)
        self.assertEqual(issuer_cert.asn1.public_key.sha1, cert_response['cert_id']['issuer_key_hash'].native)
        self.assertEqual(subject_cert.asn1.serial_number, cert_response['cert_id']['serial_number'].native)

        self.assertEqual('good', cert_response['cert_status'].name)
        self.assertGreaterEqual(datetime.now(timezone.utc), cert_response['this_update'].native)
        self.assertGreaterEqual(set(), cert_response.critical_extensions)
