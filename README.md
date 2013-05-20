pycrx
=====

Python module for CRX processing

new: includes version 3
caveat: version 3 is not finalized

normal crx includes:

- CRX magic and version
- public key length
- PKCS signature length
- public key DER blob
- PKCS signature blob
- ZIP file payload
  - https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip-printable.html

crx version 3 includes:

- CRX magic (Cr24) and version (3)
- lengths: (0 = not present)
 - RSA public key
 - PKCS payload signature
 - x509 certificate
 - central directory (intended for zip payload)
 - PKCS central directory signature
 - SHA1SUM directory
 - PKCS SHA1SUM signature
 - payload
- C boolean showing presence of centrial directory inside payload (offset?)
- blobs for previous

Design requirements / thoughts:
 - CRX files must be streamable after the header is read and cryptographically verified.
  - The zip 'central directory' is re/co-located in the header to accomplish this
  - the offsets in said header will be true to the file, not just true to the payload
  - for backwards-compatible / naive zip implementations, the central directory can be kept in the payload 
    (at end-of-file for a valid zip)
 - Verification should be doable through a regular public key _or_ an x509 certificate, 
    in order to tie into existing webs of trust
 - Payloads other than zip (tar? rar? cpio?) might be nice someday