# SCEP conformance coverage matrix

What each SCEPwright test suite proves, mapped to the RFC 8894 section it exercises.
Generated from `CoverageMatrixDoc` - a test asserts every check the suites emit appears here.

- **PASSED** - the server behaved as the RFC requires.
- **Finding** - the server is *more lenient* than the spec allows (often a security-relevant laxity).
- **Skipped** - inconclusive (e.g. PENDING, or a capability the CA doesn't offer).

## `full`

| Check | RFC § | What it proves |
|---|---|---|
| baseline enrollment (positive control) | RFC 8894 §3.3.1 | a valid PKCSReq is accepted - anchors the negative checks so a reject-everything CA can't score all-green |
| recipientNonce echo | RFC 8894 §3.2.1.1 | the response echoes our senderNonce as recipientNonce (the anti-replay binding); absent/mismatch fails |
| forbidden algorithm (MD5) | RFC 8894 §3.2.1.4 | an MD5-signed request is rejected with badAlg |
| corrupted CMS signature | RFC 8894 §3.2.1.4 | a tampered signature is rejected with badMessageCheck |
| signingTime skew (+2h) | RFC 8894 §3.2.1.4 | a stale signingTime is rejected with badTime |
| wrong challenge password | RFC 8894 §3.3.1 | a bad challengePassword is rejected (Finding if the CA issues anyway) |
| GetCert unknown serial | RFC 8894 §3.2.1.4 | a GetCert for an unknown serial is rejected with badCertId |
| malformed PKCS#10 | RFC 8894 §3.2.1.4 | an unparseable inner CSR is rejected with badRequest |
| RenewalReq when not advertised | RFC 8894 §3.5.2 | honoring a RenewalReq without advertising the Renewal capability is a leniency Finding |
| weak content-encryption (3DES) | RFC 8894 §3.5.2 | accepting a DES-EDE3-CBC-enveloped request is a leniency Finding - a hardened CA should require AES |
| arbitrary subject (no authorization) | RFC 8894 §3.3.1 | issuing for an arbitrary/unauthorized subject is a leniency Finding (production RAs bind the subject to the principal) |
| replayed PKIMessage | RFC 8894 §3.2.1.1 | re-issuing for a byte-identical replayed request is a leniency Finding (no senderNonce/transactionID anti-replay) |

## `lifecycle`

| Check | RFC § | What it proves |
|---|---|---|
| GetCACaps | RFC 8894 §3.5.1 | the capability advertisement is reachable and parseable |
| GetCACert | RFC 8894 §4.2 | the CA/RA certificate chain can be retrieved and an envelope recipient selected |
| enroll | RFC 8894 §3.3.1 | a real certificate can be enrolled via PKCSReq |
| poll | RFC 8894 §3.3.3 | a PENDING enrollment can be polled to completion (CertPoll / GetCertInitial); emitted only when enrollment returns PENDING - a CA that issues immediately has nothing to poll |
| renew | RFC 8894 §3.3.1 | an issued certificate can be renewed (RenewalReq) |
| GetCRL | RFC 8894 §4.6 | a CRL can be retrieved for the issuing CA |

## `probe`

| Check | RFC § | What it proves |
|---|---|---|
| probe SHA-256 digest | RFC 8894 §3.5.2 | the CA accepts a SHA-256-signed request (not only SHA-1) |
| probe POSTPKIOperation | RFC 8894 §3.5.2 / §4.1 | the CA supports the HTTP POST PKIOperation binding |
| probe GetNextCACert | RFC 8894 §4.7 | CA-rollover support (GetNextCACert) is present or cleanly absent |
| probe ML-DSA enrollment | RFC 8894 §3.3.1 | a post-quantum (ML-DSA) subject key can be enrolled (or is cleanly refused) |

