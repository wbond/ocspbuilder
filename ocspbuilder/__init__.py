# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

from datetime import datetime, timedelta
import inspect
import re
import sys
import textwrap

from asn1crypto import x509, keys, core, ocsp
from asn1crypto.util import timezone
from oscrypto import asymmetric, util

if sys.version_info < (3,):
    int_types = (int, long)  # noqa
    str_cls = unicode  # noqa
    byte_cls = str
else:
    int_types = (int,)
    str_cls = str
    byte_cls = bytes


__version__ = '0.9.1'
__version_info__ = (0, 9, 1)


def _writer(func):
    """
    Decorator for a custom writer, but a default reader
    """

    name = func.__name__
    return property(fget=lambda self: getattr(self, '_%s' % name), fset=func)


class OCSPRequestBuilder(object):

    _certificate = None
    _issuer = None
    _hash_algo = None
    _key_hash_algo = None
    _nonce = True
    _request_extensions = None
    _tbs_request_extensions = None

    def __init__(self, certificate, issuer):
        """
        :param certificate:
            An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
            object to create the request for

        :param issuer:
            An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
            object for the issuer of the certificate
        """

        self.certificate = certificate
        self.issuer = issuer

        self._key_hash_algo = 'sha1'
        self._hash_algo = 'sha256'
        self._request_extensions = {}
        self._tbs_request_extensions = {}

    @_writer
    def certificate(self, value):
        """
        An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
        of the certificate to create the request for.
        """

        is_oscrypto = isinstance(value, asymmetric.Certificate)
        if not is_oscrypto and not isinstance(value, x509.Certificate):
            raise TypeError(_pretty_message(
                '''
                certificate must be an instance of asn1crypto.x509.Certificate
                or oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        self._certificate = value

    @_writer
    def issuer(self, value):
        """
        An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
        of the issuer.
        """

        is_oscrypto = isinstance(value, asymmetric.Certificate)
        if not is_oscrypto and not isinstance(value, x509.Certificate):
            raise TypeError(_pretty_message(
                '''
                issuer must be an instance of asn1crypto.x509.Certificate or
                oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        self._issuer = value

    @_writer
    def hash_algo(self, value):
        """
        A unicode string of the hash algorithm to use when signing the
        request - "sha1", "sha256" (default) or "sha512".
        """

        if value not in set(['sha1', 'sha256', 'sha512']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))

        self._hash_algo = value

    @_writer
    def key_hash_algo(self, value):
        """
        A unicode string of the hash algorithm to use when creating the
        certificate identifier - "sha1" (default), or "sha256".
        """

        if value not in set(['sha1', 'sha256']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", not %s
                ''',
                repr(value)
            ))

        self._key_hash_algo = value

    @_writer
    def nonce(self, value):
        """
        A bool - if the nonce extension should be used to prevent replay
        attacks.
        """

        if not isinstance(value, bool):
            raise TypeError(_pretty_message(
                '''
                nonce must be a boolean, not %s
                ''',
                _type_name(value)
            ))

        self._nonce = value

    def set_extension(self, name, value):
        """
        Sets the value for an extension using a fully constructed
        asn1crypto.core.Asn1Value object. Normally this should not be needed,
        and the convenience attributes should be sufficient.

        See the definition of asn1crypto.ocsp.TBSRequestExtension and
        asn1crypto.ocsp.RequestExtension to determine the appropriate object
        type for a given extension. Extensions are marked as critical when RFC
        6960 indicates so.

        :param name:
            A unicode string of an extension id name from
            asn1crypto.ocsp.TBSRequestExtensionId or
            asn1crypto.ocsp.RequestExtensionId. If the extension is not one
            defined in those classes, this must be an instance of one of the
            classes instead of a unicode string.

        :param value:
            A value object per the specs defined by
            asn1crypto.ocsp.TBSRequestExtension or
            asn1crypto.ocsp.RequestExtension
        """

        if isinstance(name, str_cls):
            request_extension_oids = set([
                'service_locator',
                '1.3.6.1.5.5.7.48.1.7'
            ])
            tbs_request_extension_oids = set([
                'nonce',
                'acceptable_responses',
                'preferred_signature_algorithms',
                '1.3.6.1.5.5.7.48.1.2',
                '1.3.6.1.5.5.7.48.1.4',
                '1.3.6.1.5.5.7.48.1.8'
            ])

            if name in request_extension_oids:
                name = ocsp.RequestExtensionId(name)

            elif name in tbs_request_extension_oids:
                name = ocsp.TBSRequestExtensionId(name)

            else:
                raise ValueError(_pretty_message(
                    '''
                    name must be a unicode string from
                    asn1crypto.ocsp.TBSRequestExtensionId or
                    asn1crypto.ocsp.RequestExtensionId, not %s
                    ''',
                    repr(name)
                ))

        if isinstance(name, ocsp.RequestExtensionId):
            extension = ocsp.RequestExtension({'extn_id': name})

        elif isinstance(name, ocsp.TBSRequestExtensionId):
            extension = ocsp.TBSRequestExtension({'extn_id': name})

        else:
            raise TypeError(_pretty_message(
                '''
                name must be a unicode string or an instance of
                asn1crypto.ocsp.TBSRequestExtensionId or
                asn1crypto.ocsp.RequestExtensionId, not %s
                ''',
                _type_name(name)
            ))

        # We use native here to convert OIDs to meaningful names
        name = extension['extn_id'].native
        spec = extension.spec('extn_value')

        if not isinstance(value, spec) and value is not None:
            raise TypeError(_pretty_message(
                '''
                value must be an instance of %s, not %s
                ''',
                _type_name(spec),
                _type_name(value)
            ))

        if isinstance(extension, ocsp.TBSRequestExtension):
            extn_dict = self._tbs_request_extensions
        else:
            extn_dict = self._request_extensions

        if value is None:
            if name in extn_dict:
                del extn_dict[name]
        else:
            extn_dict[name] = value

    def build(self, requestor_private_key=None, requestor_certificate=None, other_certificates=None):
        """
        Validates the request information, constructs the ASN.1 structure and
        then optionally signs it.

        The requestor_private_key, requestor_certificate and other_certificates
        params are all optional and only necessary if the request needs to be
        signed. Signing a request is uncommon for OCSP requests related to web
        TLS connections.

        :param requestor_private_key:
            An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
            object for the private key to sign the request with

        :param requestor_certificate:
            An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
            object of the certificate associated with the private key

        :param other_certificates:
            A list of asn1crypto.x509.Certificate or
            oscrypto.asymmetric.Certificate objects that may be useful for the
            OCSP server to verify the request signature. Intermediate
            certificates would be specified here.

        :return:
            An asn1crypto.ocsp.OCSPRequest object of the request
        """

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': False,
                'extn_value': value
            }

        tbs_request_extensions = []
        request_extensions = []
        has_nonce = False

        for name, value in self._tbs_request_extensions.items():
            if name == 'nonce':
                has_nonce = True
            tbs_request_extensions.append(_make_extension(name, value))
        if self._nonce and not has_nonce:
            tbs_request_extensions.append(
                _make_extension('nonce', util.rand_bytes(16))
            )

        if not tbs_request_extensions:
            tbs_request_extensions = None

        for name, value in self._request_extensions.items():
            request_extensions.append(_make_extension(name, value))

        if not request_extensions:
            request_extensions = None

        tbs_request = ocsp.TBSRequest({
            'request_list': [
                {
                    'req_cert': {
                        'hash_algorithm': {
                            'algorithm': self._key_hash_algo
                        },
                        'issuer_name_hash': getattr(self._certificate.issuer, self._key_hash_algo),
                        'issuer_key_hash': getattr(self._issuer.public_key, self._key_hash_algo),
                        'serial_number': self._certificate.serial_number,
                    },
                    'single_request_extensions': request_extensions
                }
            ],
            'request_extensions': tbs_request_extensions
        })
        signature = None

        if requestor_private_key or requestor_certificate or other_certificates:
            is_oscrypto = isinstance(requestor_private_key, asymmetric.PrivateKey)
            if not isinstance(requestor_private_key, keys.PrivateKeyInfo) and not is_oscrypto:
                raise TypeError(_pretty_message(
                    '''
                    requestor_private_key must be an instance of
                    asn1crypto.keys.PrivateKeyInfo or
                    oscrypto.asymmetric.PrivateKey, not %s
                    ''',
                    _type_name(requestor_private_key)
                ))

            cert_is_oscrypto = isinstance(requestor_certificate, asymmetric.Certificate)
            if not isinstance(requestor_certificate, x509.Certificate) and not cert_is_oscrypto:
                raise TypeError(_pretty_message(
                    '''
                    requestor_certificate must be an instance of
                    asn1crypto.x509.Certificate or
                    oscrypto.asymmetric.Certificate, not %s
                    ''',
                    _type_name(requestor_certificate)
                ))

            if other_certificates is not None and not isinstance(other_certificates, list):
                raise TypeError(_pretty_message(
                    '''
                    other_certificates must be a list of
                    asn1crypto.x509.Certificate or
                    oscrypto.asymmetric.Certificate objects, not %s
                    ''',
                    _type_name(other_certificates)
                ))

            if cert_is_oscrypto:
                requestor_certificate = requestor_certificate.asn1

            tbs_request['requestor_name'] = x509.GeneralName(
                name='directory_name',
                value=requestor_certificate.subject
            )

            certificates = [requestor_certificate]

            for other_certificate in other_certificates:
                other_cert_is_oscrypto = isinstance(other_certificate, asymmetric.Certificate)
                if not isinstance(other_certificate, x509.Certificate) and not other_cert_is_oscrypto:
                    raise TypeError(_pretty_message(
                        '''
                        other_certificate must be an instance of
                        asn1crypto.x509.Certificate or
                        oscrypto.asymmetric.Certificate, not %s
                        ''',
                        _type_name(other_certificate)
                    ))
                if other_cert_is_oscrypto:
                    other_certificate = other_certificate.asn1
                certificates.append(other_certificate)

            signature_algo = requestor_private_key.algorithm
            if signature_algo == 'ec':
                signature_algo = 'ecdsa'

            signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

            if requestor_private_key.algorithm == 'rsa':
                sign_func = asymmetric.rsa_pkcs1v15_sign
            elif requestor_private_key.algorithm == 'dsa':
                sign_func = asymmetric.dsa_sign
            elif requestor_private_key.algorithm == 'ec':
                sign_func = asymmetric.ecdsa_sign

            if not is_oscrypto:
                requestor_private_key = asymmetric.load_private_key(requestor_private_key)
            signature_bytes = sign_func(requestor_private_key, tbs_request.dump(), self._hash_algo)

            signature = ocsp.Signature({
                'signature_algorithm': {'algorithm': signature_algorithm_id},
                'signature': signature_bytes,
                'certs': certificates
            })

        return ocsp.OCSPRequest({
            'tbs_request': tbs_request,
            'optional_signature': signature
        })


class OCSPResponseBuilder(object):

    _response_status = None
    _certificate = None
    _certificate_status = None
    _revocation_date = None
    _certificate_issuer = None
    _hash_algo = None
    _key_hash_algo = None
    _nonce = None
    _this_update = None
    _next_update = None
    _response_data_extensions = None
    _single_response_extensions = None

    def __init__(self, response_status, certificate=None, certificate_status=None, revocation_date=None):
        """
        Unless changed, responses will use SHA-256 for the signature,
        and will be valid from the moment created for one week.

        :param response_status:
            A unicode string of OCSP response type:

            - "successful" - when the response includes information about the certificate
            - "malformed_request" - when the request could not be understood
            - "internal_error" - when an internal error occured with the OCSP responder
            - "try_later" - when the OCSP responder is temporarily unavailable
            - "sign_required" - when the OCSP request must be signed
            - "unauthorized" - when the responder is not the correct responder for the certificate

        :param certificate:
            An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
            object of the certificate the response is about. Only required if
            the response_status is "successful".

        :param certificate_status:
            A unicode string of the status of the certificate. Only required if
            the response_status is "successful".

             - "good" - when the certificate is in good standing
             - "key_compromise" - when a private key is compromised
             - "ca_compromise" - when the CA issuing the certificate is compromised
             - "affiliation_changed" - when the certificate subject name changed
             - "superseded" - when the certificate was replaced with a new one
             - "cessation_of_operation" - when the certificate is no longer needed
             - "certificate_hold" - when the certificate is temporarily invalid
             - "remove_from_crl" - only delta CRLs - when temporary hold is removed
             - "privilege_withdrawn" - one of the usages for a certificate was removed

        :param revocation_date:
            A datetime.datetime object of when the certificate was revoked, if
            the response_status is "successful" and the certificate status is
            not "good".
        """

        self.response_status = response_status
        self.certificate = certificate
        self.certificate_status = certificate_status
        self.revocation_date = revocation_date

        self._key_hash_algo = 'sha1'
        self._hash_algo = 'sha256'
        self._response_data_extensions = {}
        self._single_response_extensions = {}

    @_writer
    def response_status(self, value):
        """
        The overall status of the response. Only a "successful" response will
        include information about the certificate. Other response types are for
        signaling info about the OCSP responder. Valid values include:

         - "successful" - when the response includes information about the certificate
         - "malformed_request" - when the request could not be understood
         - "internal_error" - when an internal error occured with the OCSP responder
         - "try_later" - when the OCSP responder is temporarily unavailable
         - "sign_required" - when the OCSP request must be signed
         - "unauthorized" - when the responder is not the correct responder for the certificate
        """

        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                response_status must be a unicode string, not %s
                ''',
                _type_name(value)
            ))

        valid_response_statuses = set([
            'successful',
            'malformed_request',
            'internal_error',
            'try_later',
            'sign_required',
            'unauthorized'
        ])
        if value not in valid_response_statuses:
            raise ValueError(_pretty_message(
                '''
                response_status must be one of "successful",
                "malformed_request", "internal_error", "try_later",
                "sign_required", "unauthorized", not %s
                ''',
                repr(value)
            ))

        self._response_status = value

    @_writer
    def certificate(self, value):
        """
        An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
        of the certificate the response is about.
        """

        is_oscrypto = isinstance(value, asymmetric.Certificate)
        if not is_oscrypto and not isinstance(value, x509.Certificate):
            raise TypeError(_pretty_message(
                '''
                certificate must be an instance of asn1crypto.x509.Certificate
                or oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(value)
            ))

        if is_oscrypto:
            value = value.asn1

        self._certificate = value

    @_writer
    def certificate_status(self, value):
        """
        A unicode string of the status of the certificate. Valid values include:

         - "good" - when the certificate is in good standing
         - "key_compromise" - when a private key is compromised
         - "ca_compromise" - when the CA issuing the certificate is compromised
         - "affiliation_changed" - when the certificate subject name changed
         - "superseded" - when the certificate was replaced with a new one
         - "cessation_of_operation" - when the certificate is no longer needed
         - "certificate_hold" - when the certificate is temporarily invalid
         - "remove_from_crl" - only delta CRLs - when temporary hold is removed
         - "privilege_withdrawn" - one of the usages for a certificate was removed
        """

        if not isinstance(value, str_cls):
            raise TypeError(_pretty_message(
                '''
                certificate_status must be a unicode string, not %s
                ''',
                _type_name(value)
            ))

        valid_certificate_statuses = set([
            'good',
            'key_compromise',
            'ca_compromise',
            'affiliation_changed',
            'superseded',
            'cessation_of_operation',
            'certificate_hold',
            'remove_from_crl',
            'privilege_withdrawn'
        ])
        if value not in valid_certificate_statuses:
            raise ValueError(_pretty_message(
                '''
                certificate_status must be one of "good", "key_compromise",
                "ca_compromise", "affiliation_changed", "superseded",
                "cessation_of_operation", "certificate_hold", "remove_from_crl",
                "privilege_withdrawn", not %s
                ''',
                repr(value)
            ))

        self._certificate_status = value

    @_writer
    def revocation_date(self, value):
        """
        A datetime.datetime object of when the certificate was revoked, if the
        status is not "good".
        """

        if value is not None and not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                revocation_date must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._revocation_date = value

    @_writer
    def certificate_issuer(self, value):
        """
        An asn1crypto.x509.Certificate object of the issuer of the certificate.
        This should only be set if the OCSP responder is not the issuer of
        the certificate, but instead a special certificate only for OCSP
        responses.
        """

        if value is not None:
            is_oscrypto = isinstance(value, asymmetric.Certificate)
            if not is_oscrypto and not isinstance(value, x509.Certificate):
                raise TypeError(_pretty_message(
                    '''
                    certificate_issuer must be an instance of
                    asn1crypto.x509.Certificate or
                    oscrypto.asymmetric.Certificate, not %s
                    ''',
                    _type_name(value)
                ))

            if is_oscrypto:
                value = value.asn1

        self._certificate_issuer = value

    @_writer
    def hash_algo(self, value):
        """
        A unicode string of the hash algorithm to use when signing the
        request - "sha1", "sha256" (default) or "sha512".
        """

        if value not in set(['sha1', 'sha256', 'sha512']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", "sha512", not %s
                ''',
                repr(value)
            ))

        self._hash_algo = value

    @_writer
    def key_hash_algo(self, value):
        """
        A unicode string of the hash algorithm to use when creating the
        certificate identifier - "sha1" (default), or "sha256".
        """

        if value not in set(['sha1', 'sha256']):
            raise ValueError(_pretty_message(
                '''
                hash_algo must be one of "sha1", "sha256", not %s
                ''',
                repr(value)
            ))

        self._key_hash_algo = value

    @_writer
    def nonce(self, value):
        """
        The nonce that was provided during the request.
        """

        if not isinstance(value, byte_cls):
            raise TypeError(_pretty_message(
                '''
                nonce must be a byte string, not %s
                ''',
                _type_name(value)
            ))

        self._nonce = value

    @_writer
    def this_update(self, value):
        """
        A datetime.datetime object of when the response was generated.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                this_update must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._this_update = value

    @_writer
    def next_update(self, value):
        """
        A datetime.datetime object of when the response may next change. This
        should only be set if responses are cached. If responses are generated
        fresh on every request, this should not be set.
        """

        if not isinstance(value, datetime):
            raise TypeError(_pretty_message(
                '''
                next_update must be an instance of datetime.datetime, not %s
                ''',
                _type_name(value)
            ))

        self._next_update = value

    def set_extension(self, name, value):
        """
        Sets the value for an extension using a fully constructed
        asn1crypto.core.Asn1Value object. Normally this should not be needed,
        and the convenience attributes should be sufficient.

        See the definition of asn1crypto.ocsp.SingleResponseExtension and
        asn1crypto.ocsp.ResponseDataExtension to determine the appropriate
        object type for a given extension. Extensions are marked as critical
        when RFC 6960 indicates so.

        :param name:
            A unicode string of an extension id name from
            asn1crypto.ocsp.SingleResponseExtensionId or
            asn1crypto.ocsp.ResponseDataExtensionId. If the extension is not one
            defined in those classes, this must be an instance of one of the
            classes instead of a unicode string.

        :param value:
            A value object per the specs defined by
            asn1crypto.ocsp.SingleResponseExtension or
            asn1crypto.ocsp.ResponseDataExtension
        """

        if isinstance(name, str_cls):
            response_data_extension_oids = set([
                'nonce',
                'extended_revoke',
                '1.3.6.1.5.5.7.48.1.2',
                '1.3.6.1.5.5.7.48.1.9'
            ])

            single_response_extension_oids = set([
                'crl',
                'archive_cutoff',
                'crl_reason',
                'invalidity_date',
                'certificate_issuer',
                '1.3.6.1.5.5.7.48.1.3',
                '1.3.6.1.5.5.7.48.1.6',
                '2.5.29.21',
                '2.5.29.24',
                '2.5.29.29'
            ])

            if name in response_data_extension_oids:
                name = ocsp.ResponseDataExtensionId(name)

            elif name in single_response_extension_oids:
                name = ocsp.SingleResponseExtensionId(name)

            else:
                raise ValueError(_pretty_message(
                    '''
                    name must be a unicode string from
                    asn1crypto.ocsp.ResponseDataExtensionId or
                    asn1crypto.ocsp.SingleResponseExtensionId, not %s
                    ''',
                    repr(name)
                ))

        if isinstance(name, ocsp.ResponseDataExtensionId):
            extension = ocsp.ResponseDataExtension({'extn_id': name})

        elif isinstance(name, ocsp.SingleResponseExtensionId):
            extension = ocsp.SingleResponseExtension({'extn_id': name})

        else:
            raise TypeError(_pretty_message(
                '''
                name must be a unicode string or an instance of
                asn1crypto.ocsp.SingleResponseExtensionId or
                asn1crypto.ocsp.ResponseDataExtensionId, not %s
                ''',
                _type_name(name)
            ))

        # We use native here to convert OIDs to meaningful names
        name = extension['extn_id'].native
        spec = extension.spec('extn_value')

        if name == 'nonce':
            raise ValueError(_pretty_message(
                '''
                The nonce value should be set via the .nonce attribute, not the
                .set_extension() method
                '''
            ))

        if name == 'crl_reason':
            raise ValueError(_pretty_message(
                '''
                The crl_reason value should be set via the certificate_status
                parameter of the OCSPResponseBuilder() constructor, not the
                .set_extension() method
                '''
            ))

        if name == 'certificate_issuer':
            raise ValueError(_pretty_message(
                '''
                The certificate_issuer value should be set via the
                .certificate_issuer attribute, not the .set_extension() method
                '''
            ))

        if not isinstance(value, spec) and value is not None:
            raise TypeError(_pretty_message(
                '''
                value must be an instance of %s, not %s
                ''',
                _type_name(spec),
                _type_name(value)
            ))

        if isinstance(extension, ocsp.ResponseDataExtension):
            extn_dict = self._response_data_extensions
        else:
            extn_dict = self._single_response_extensions

        if value is None:
            if name in extn_dict:
                del extn_dict[name]
        else:
            extn_dict[name] = value

    def build(self, responder_private_key=None, responder_certificate=None):
        """
        Validates the request information, constructs the ASN.1 structure and
        signs it.

        The responder_private_key and responder_certificate parameters are only
        required if the response_status is "successful".

        :param responder_private_key:
            An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
            object for the private key to sign the response with

        :param responder_certificate:
            An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
            object of the certificate associated with the private key

        :return:
            An asn1crypto.ocsp.OCSPResponse object of the response
        """

        if self._response_status != 'successful':
            return ocsp.OCSPResponse({
                'response_status': self._response_status
            })

        is_oscrypto = isinstance(responder_private_key, asymmetric.PrivateKey)
        if not isinstance(responder_private_key, keys.PrivateKeyInfo) and not is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                responder_private_key must be an instance of
                asn1crypto.keys.PrivateKeyInfo or
                oscrypto.asymmetric.PrivateKey, not %s
                ''',
                _type_name(responder_private_key)
            ))

        cert_is_oscrypto = isinstance(responder_certificate, asymmetric.Certificate)
        if not isinstance(responder_certificate, x509.Certificate) and not cert_is_oscrypto:
            raise TypeError(_pretty_message(
                '''
                responder_certificate must be an instance of
                asn1crypto.x509.Certificate or
                oscrypto.asymmetric.Certificate, not %s
                ''',
                _type_name(responder_certificate)
            ))

        if cert_is_oscrypto:
            responder_certificate = responder_certificate.asn1

        def _make_extension(name, value):
            return {
                'extn_id': name,
                'critical': False,
                'extn_value': value
            }

        response_data_extensions = []
        single_response_extensions = []

        for name, value in self._response_data_extensions.items():
            response_data_extensions.append(_make_extension(name, value))
        if self._nonce:
            response_data_extensions.append(
                _make_extension('nonce', self._nonce)
            )

        if not response_data_extensions:
            response_data_extensions = None

        for name, value in self._single_response_extensions.items():
            single_response_extensions.append(_make_extension(name, value))

        if self._certificate_issuer:
            single_response_extensions.append(
                _make_extension(
                    'certificate_issuer',
                    [
                        x509.GeneralName(
                            name='directory_name',
                            value=self._certificate_issuer.subject
                        )
                    ]
                )
            )

        if not single_response_extensions:
            single_response_extensions = None

        responder_key_hash = getattr(responder_certificate.public_key, self._key_hash_algo)

        if self._certificate_status == 'good':
            cert_status = ocsp.CertStatus(
                name='good',
                value=core.Null()
            )
        else:
            cert_status = ocsp.CertStatus(
                name='revoked',
                value={
                    'revocation_time': self._revocation_date,
                    'revocation_reason': self._certificate_status
                }
            )

        issuer = self._certificate_issuer if self._certificate_issuer else responder_certificate
        if issuer.subject != self._certificate.issuer:
            raise ValueError(_pretty_message(
                '''
                responder_certificate does not appear to be the issuer for
                the certificate. Perhaps set the .certificate_issuer attribute?
                '''
            ))

        produced_at = datetime.now(timezone.utc)

        if self._this_update is None:
            self._this_update = produced_at

        if self._next_update is None:
            self._next_update = self._this_update + timedelta(days=7)

        response_data = ocsp.ResponseData({
            'responder_id': ocsp.ResponderId(name='by_key', value=responder_key_hash),
            'produced_at': produced_at,
            'responses': [
                {
                    'cert_id': {
                        'hash_algorithm': {
                            'algorithm': self._key_hash_algo
                        },
                        'issuer_name_hash': getattr(self._certificate.issuer, self._key_hash_algo),
                        'issuer_key_hash': getattr(issuer.public_key, self._key_hash_algo),
                        'serial_number': self._certificate.serial_number,
                    },
                    'cert_status': cert_status,
                    'this_update': self._this_update,
                    'next_update': self._next_update,
                    'single_extensions': single_response_extensions
                }
            ],
            'response_extensions': response_data_extensions
        })

        signature_algo = responder_private_key.algorithm
        if signature_algo == 'ec':
            signature_algo = 'ecdsa'

        signature_algorithm_id = '%s_%s' % (self._hash_algo, signature_algo)

        if responder_private_key.algorithm == 'rsa':
            sign_func = asymmetric.rsa_pkcs1v15_sign
        elif responder_private_key.algorithm == 'dsa':
            sign_func = asymmetric.dsa_sign
        elif responder_private_key.algorithm == 'ec':
            sign_func = asymmetric.ecdsa_sign

        if not is_oscrypto:
            responder_private_key = asymmetric.load_private_key(responder_private_key)
        signature_bytes = sign_func(responder_private_key, response_data.dump(), self._hash_algo)

        certs = None
        if self._certificate_issuer:
            certs = [responder_certificate]

        return ocsp.OCSPResponse({
            'response_status': self._response_status,
            'response_bytes': {
                'response_type': 'basic_ocsp_response',
                'response': {
                    'tbs_response_data': response_data,
                    'signature_algorithm': {'algorithm': signature_algorithm_id},
                    'signature': signature_bytes,
                    'certs': certs
                }
            }
        })


def _pretty_message(string, *params):
    """
    Takes a multi-line string and does the following:

     - dedents
     - converts newlines with text before and after into a single line
     - strips leading and trailing whitespace

    :param string:
        The string to format

    :param *params:
        Params to interpolate into the string

    :return:
        The formatted string
    """

    output = textwrap.dedent(string)

    # Unwrap lines, taking into account bulleted lists, ordered lists and
    # underlines consisting of = signs
    if output.find('\n') != -1:
        output = re.sub('(?<=\\S)\n(?=[^ \n\t\\d\\*\\-=])', ' ', output)

    if params:
        output = output % params

    output = output.strip()

    return output


def _type_name(value):
    """
    :param value:
        A value to get the object name of

    :return:
        A unicode string of the object name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)
