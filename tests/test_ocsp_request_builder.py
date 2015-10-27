# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import unittest
import os

import asn1crypto.x509
from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder

from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


class OCSPRequestBuilderTests(unittest.TestCase):

    def test_build_basic_request(self):
        issuer_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))
        subject_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-inter.crt'))

        builder = OCSPRequestBuilder(subject_cert, issuer_cert)
        ocsp_request = builder.build()
        der_bytes = ocsp_request.dump()

        new_request = asn1crypto.ocsp.OCSPRequest.load(der_bytes)
        tbs_request = new_request['tbs_request']

        self.assertEqual(None, new_request['optional_signature'].native)
        self.assertEqual('v1', tbs_request['version'].native)
        self.assertEqual(None, tbs_request['requestor_name'].native)
        self.assertEqual(1, len(tbs_request['request_list']))

        request = tbs_request['request_list'][0]
        self.assertEqual('sha1', request['req_cert']['hash_algorithm']['algorithm'].native)
        self.assertEqual(issuer_cert.asn1.subject.sha1, request['req_cert']['issuer_name_hash'].native)
        self.assertEqual(issuer_cert.asn1.public_key.sha1, request['req_cert']['issuer_key_hash'].native)
        self.assertEqual(subject_cert.asn1.serial_number, request['req_cert']['serial_number'].native)
        self.assertEqual(0, len(request['single_request_extensions']))

        self.assertEqual(1, len(tbs_request['request_extensions']))
        extn = tbs_request['request_extensions'][0]

        self.assertEqual('nonce', extn['extn_id'].native)
        self.assertEqual(16, len(extn['extn_value'].parsed.native))

    def test_build_signed_request(self):
        issuer_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test.crt'))
        subject_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-inter.crt'))

        requestor_cert = asymmetric.load_certificate(os.path.join(fixtures_dir, 'test-third.crt'))
        requestor_key = asymmetric.load_private_key(os.path.join(fixtures_dir, 'test-third.key'))

        builder = OCSPRequestBuilder(subject_cert, issuer_cert)
        ocsp_request = builder.build(requestor_key, requestor_cert, [subject_cert, issuer_cert])
        der_bytes = ocsp_request.dump()

        new_request = asn1crypto.ocsp.OCSPRequest.load(der_bytes)
        tbs_request = new_request['tbs_request']
        signature = new_request['optional_signature']

        self.assertEqual('sha256', signature['signature_algorithm'].hash_algo)
        self.assertEqual('rsassa_pkcs1v15', signature['signature_algorithm'].signature_algo)
        self.assertEqual(3, len(signature['certs']))
        self.assertEqual('v1', tbs_request['version'].native)
        self.assertEqual(requestor_cert.asn1.subject, tbs_request['requestor_name'].chosen)
        self.assertEqual(1, len(tbs_request['request_list']))

        request = tbs_request['request_list'][0]
        self.assertEqual('sha1', request['req_cert']['hash_algorithm']['algorithm'].native)
        self.assertEqual(issuer_cert.asn1.subject.sha1, request['req_cert']['issuer_name_hash'].native)
        self.assertEqual(issuer_cert.asn1.public_key.sha1, request['req_cert']['issuer_key_hash'].native)
        self.assertEqual(subject_cert.asn1.serial_number, request['req_cert']['serial_number'].native)
        self.assertEqual(0, len(request['single_request_extensions']))

        self.assertEqual(1, len(tbs_request['request_extensions']))
        extn = tbs_request['request_extensions'][0]

        self.assertEqual('nonce', extn['extn_id'].native)
        self.assertEqual(16, len(extn['extn_value'].parsed.native))
