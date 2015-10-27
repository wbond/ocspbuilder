# ocspbuilder Documentation

*ocspbuilder* is a Python library for constructing OCSP requests and responses.
It provides a high-level interface with knowledge of RFC 6960 to produce, valid,
correct OCSP messages without terrible APIs or hunting through RFCs.

Since its only dependencies are the
[*asn1crypto*](https://github.com/wbond/asn1crypto#readme) and
[*oscrypto*](https://github.com/wbond/oscrypto#readme) libraries, it is
easy to install and use on Windows, OS X, Linux and the BSDs.

The documentation consists of the following topics:

 - [Generating a Request](#generating-a-request)
 - [Constructing a Response](#constructing-a-response)
 - [API Documentation](api.md)

## Generating a Request

A basic OCSP request requires the certificate to obtain the status of, and the
issuer certificate:

```python
from oscrypto import asymmetric
from ocspbuilder import OCSPRequestBuilder


subject_cert = asymmetric.load_certificate('/path/to/certificate.crt')
issuer_cert = asymmetric.load_certificate('/path/to/issuer.crt')

builder = OCSPRequestBuilder(subject_cert, issuer_cert)
ocsp_request = builder.build()

with open('/path/to/cached_request.der', 'wb') as f:
    f.write(ocsp_request.dump())
```

## Constructing a Response

To construct a OCSP response, a few pieces of information are necessary:

 - subject certificate
 - certificate status
 - revocation date and reason (if revoked)
 - issuer certificate and key, or purpose-created OCSP responder certificate
   and key

The following code shows examples of constructing the response for a certificate
in good standing, a revoked certificate and finally a response from an OCSP
responder certificate, instead of the certificate issuer.

```python
from datetime import datetime
from asn1crypto.util import timezone
from oscrypto import asymmetric
from ocspbuilder import OCSPResponseBuilder


subject_cert = asymmetric.load_certificate('/path/to/certificate.crt')
issuer_cert = asymmetric.load_certificate('/path/to/issuer.crt')
issuer_key = asymmetric.load_private_key('/path/to/issuer.key')


# A response for a certificate in good standing
builder = OCSPResponseBuilder('successful', subject_cert, 'good')
ocsp_response = builder.build(issuer_key, issuer_cert)

with open('/path/to/cached_response.der', 'wb') as f:
    f.write(ocsp_response.dump())


# A response for a certificate that has been revoked
revocation_date = datetime(2015, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
builder = OCSPResponseBuilder('successful', subject_cert, 'key_compromise', revocation_date)
ocsp_response = builder.build(issuer_key, issuer_cert)

with open('/path/to/cached_revoked_response.der', 'wb') as f:
    f.write(ocsp_response.dump())


# A response from a special OCSP response certificate/key
responder_cert = asymmetric.load_certificate('/path/to/responder.crt')
responder_key = asymmetric.load_private_key('/path/to/responder.key')

builder = OCSPResponseBuilder('successful', subject_cert, 'good')
builder.certificate_issuer = issuer_cert
ocsp_response = builder.build(responder_key, responder_cert)

with open('/path/to/cached_responder_response.der', 'wb') as f:
    f.write(ocsp_response.dump())
```
