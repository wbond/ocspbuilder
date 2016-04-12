# ocspbuilder API Documentation

 - [`OCSPRequestBuilder()`](#ocsprequestbuilder-class)
 - [`OCSPResponseBuilder()`](#ocspresponsebuilder-class)

### `OCSPRequestBuilder()` class

> ##### constructor
>
> > ```python
> > def __init__(self, certificate, issuer):
> >     """
> >     :param certificate:
> >         An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
> >         object to create the request for
> >     
> >     :param issuer:
> >         An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
> >         object for the issuer of the certificate
> >     """
> > ```
>
> ##### `.certificate` attribute
>
> > An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
> > of the certificate to create the request for.
>
> ##### `.issuer` attribute
>
> > An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
> > of the issuer.
>
> ##### `.hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when signing the
> > request - "sha1", "sha256" (default) or "sha512".
>
> ##### `.key_hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when creating the
> > certificate identifier - "sha1" (default), or "sha256".
>
> ##### `.nonce` attribute
>
> > A bool - if the nonce extension should be used to prevent replay
> > attacks.
>
> ##### `.set_extension()` method
>
> > ```python
> > def set_extension(self, name, value):
> >     """
> >     :param name:
> >         A unicode string of an extension id name from
> >         asn1crypto.ocsp.TBSRequestExtensionId or
> >         asn1crypto.ocsp.RequestExtensionId. If the extension is not one
> >         defined in those classes, this must be an instance of one of the
> >         classes instead of a unicode string.
> >     
> >     :param value:
> >         A value object per the specs defined by
> >         asn1crypto.ocsp.TBSRequestExtension or
> >         asn1crypto.ocsp.RequestExtension
> >     """
> > ```
> >
> > Sets the value for an extension using a fully constructed
> > asn1crypto.core.Asn1Value object. Normally this should not be needed,
> > and the convenience attributes should be sufficient.
> > 
> > See the definition of asn1crypto.ocsp.TBSRequestExtension and
> > asn1crypto.ocsp.RequestExtension to determine the appropriate object
> > type for a given extension. Extensions are marked as critical when RFC
> > 6960 indicates so.
>
> ##### `.build()` method
>
> > ```python
> > def build(self, requestor_private_key=None, requestor_certificate=None, other_certificates=None):
> >     """
> >     :param requestor_private_key:
> >         An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
> >         object for the private key to sign the request with
> >     
> >     :param requestor_certificate:
> >         An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
> >         object of the certificate associated with the private key
> >     
> >     :param other_certificates:
> >         A list of asn1crypto.x509.Certificate or
> >         oscrypto.asymmetric.Certificate objects that may be useful for the
> >         OCSP server to verify the request signature. Intermediate
> >         certificates would be specified here.
> >     
> >     :return:
> >         An asn1crypto.ocsp.OCSPRequest object of the request
> >     """
> > ```
> >
> > Validates the request information, constructs the ASN.1 structure and
> > then optionally signs it.
> > 
> > The requestor_private_key, requestor_certificate and other_certificates
> > params are all optional and only necessary if the request needs to be
> > signed. Signing a request is uncommon for OCSP requests related to web
> > TLS connections.

### `OCSPResponseBuilder()` class

> ##### constructor
>
> > ```python
> > def __init__(self, response_status, certificate=None, certificate_status=None, revocation_date=None):
> >     """
> >     :param response_status:
> >         A unicode string of OCSP response type:
> >     
> >         - "successful" - when the response includes information about the certificate
> >         - "malformed_request" - when the request could not be understood
> >         - "internal_error" - when an internal error occured with the OCSP responder
> >         - "try_later" - when the OCSP responder is temporarily unavailable
> >         - "sign_required" - when the OCSP request must be signed
> >         - "unauthorized" - when the responder is not the correct responder for the certificate
> >     
> >     :param certificate:
> >         An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
> >         object of the certificate the response is about. Only required if
> >         the response_status is "successful".
> >     
> >     :param certificate_status:
> >         A unicode string of the status of the certificate. Only required if
> >         the response_status is "successful".
> >     
> >          - "good" - when the certificate is in good standing
> >          - "revoked" - when the certificate is revoked without a reason code
> >          - "key_compromise" - when a private key is compromised
> >          - "ca_compromise" - when the CA issuing the certificate is compromised
> >          - "affiliation_changed" - when the certificate subject name changed
> >          - "superseded" - when the certificate was replaced with a new one
> >          - "cessation_of_operation" - when the certificate is no longer needed
> >          - "certificate_hold" - when the certificate is temporarily invalid
> >          - "remove_from_crl" - only delta CRLs - when temporary hold is removed
> >          - "privilege_withdrawn" - one of the usages for a certificate was removed
> >          - "unknown" - the responder doesn't know about the certificate being requested
> >     
> >     :param revocation_date:
> >         A datetime.datetime object of when the certificate was revoked, if
> >         the response_status is "successful" and the certificate status is
> >         not "good" or "unknown".
> >     """
> > ```
> >
> > Unless changed, responses will use SHA-256 for the signature,
> > and will be valid from the moment created for one week.
>
> ##### `.response_status` attribute
>
> > The overall status of the response. Only a "successful" response will
> > include information about the certificate. Other response types are for
> > signaling info about the OCSP responder. Valid values include:
> > 
> >  - "successful" - when the response includes information about the certificate
> >  - "malformed_request" - when the request could not be understood
> >  - "internal_error" - when an internal error occured with the OCSP responder
> >  - "try_later" - when the OCSP responder is temporarily unavailable
> >  - "sign_required" - when the OCSP request must be signed
> >  - "unauthorized" - when the responder is not the correct responder for the certificate
>
> ##### `.certificate` attribute
>
> > An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate object
> > of the certificate the response is about.
>
> ##### `.certificate_status` attribute
>
> > A unicode string of the status of the certificate. Valid values include:
> > 
> >  - "good" - when the certificate is in good standing
> >  - "revoked" - when the certificate is revoked without a reason code
> >  - "key_compromise" - when a private key is compromised
> >  - "ca_compromise" - when the CA issuing the certificate is compromised
> >  - "affiliation_changed" - when the certificate subject name changed
> >  - "superseded" - when the certificate was replaced with a new one
> >  - "cessation_of_operation" - when the certificate is no longer needed
> >  - "certificate_hold" - when the certificate is temporarily invalid
> >  - "remove_from_crl" - only delta CRLs - when temporary hold is removed
> >  - "privilege_withdrawn" - one of the usages for a certificate was removed
> >  - "unknown" - when the responder doesn't know about the certificate being requested
>
> ##### `.revocation_date` attribute
>
> > A datetime.datetime object of when the certificate was revoked, if the
> > status is not "good" or "unknown".
>
> ##### `.certificate_issuer` attribute
>
> > An asn1crypto.x509.Certificate object of the issuer of the certificate.
> > This should only be set if the OCSP responder is not the issuer of
> > the certificate, but instead a special certificate only for OCSP
> > responses.
>
> ##### `.hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when signing the
> > request - "sha1", "sha256" (default) or "sha512".
>
> ##### `.key_hash_algo` attribute
>
> > A unicode string of the hash algorithm to use when creating the
> > certificate identifier - "sha1" (default), or "sha256".
>
> ##### `.nonce` attribute
>
> > The nonce that was provided during the request.
>
> ##### `.this_update` attribute
>
> > A datetime.datetime object of when the response was generated.
>
> ##### `.next_update` attribute
>
> > A datetime.datetime object of when the response may next change. This
> > should only be set if responses are cached. If responses are generated
> > fresh on every request, this should not be set.
>
> ##### `.set_extension()` method
>
> > ```python
> > def set_extension(self, name, value):
> >     """
> >     :param name:
> >         A unicode string of an extension id name from
> >         asn1crypto.ocsp.SingleResponseExtensionId or
> >         asn1crypto.ocsp.ResponseDataExtensionId. If the extension is not one
> >         defined in those classes, this must be an instance of one of the
> >         classes instead of a unicode string.
> >     
> >     :param value:
> >         A value object per the specs defined by
> >         asn1crypto.ocsp.SingleResponseExtension or
> >         asn1crypto.ocsp.ResponseDataExtension
> >     """
> > ```
> >
> > Sets the value for an extension using a fully constructed
> > asn1crypto.core.Asn1Value object. Normally this should not be needed,
> > and the convenience attributes should be sufficient.
> > 
> > See the definition of asn1crypto.ocsp.SingleResponseExtension and
> > asn1crypto.ocsp.ResponseDataExtension to determine the appropriate
> > object type for a given extension. Extensions are marked as critical
> > when RFC 6960 indicates so.
>
> ##### `.build()` method
>
> > ```python
> > def build(self, responder_private_key=None, responder_certificate=None):
> >     """
> >     :param responder_private_key:
> >         An asn1crypto.keys.PrivateKeyInfo or oscrypto.asymmetric.PrivateKey
> >         object for the private key to sign the response with
> >     
> >     :param responder_certificate:
> >         An asn1crypto.x509.Certificate or oscrypto.asymmetric.Certificate
> >         object of the certificate associated with the private key
> >     
> >     :return:
> >         An asn1crypto.ocsp.OCSPResponse object of the response
> >     """
> > ```
> >
> > Validates the request information, constructs the ASN.1 structure and
> > signs it.
> > 
> > The responder_private_key and responder_certificate parameters are only
> > required if the response_status is "successful".
