# changelog

## 0.10.2

 - Updated [asn1crypto](https://github.com/wbond/asn1crypto) dependency to
   `0.18.1`, [oscrypto](https://github.com/wbond/oscrypto) dependency to
   `0.16.1`.

## 0.10.1

 - `OCSPResponseBuilder()` no longer requires the `certificate` and
   `certificate_status` parameters when the `response_status` is not
   `"successful"`

## 0.10.0

 - Added the options `unknown` and `revoked` to the `certificate_status`
   parameter of `OCSPResponseBuilder()`

## 0.9.1

 - Package metadata updates

## 0.9.0

 - Initial release
