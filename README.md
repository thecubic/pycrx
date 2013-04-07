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
