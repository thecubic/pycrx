#!/usr/bin/env python

import zipfile
import struct
import uuid
import code
import os
import logging
import sys

if sys.version_info > (3, 0):
    iofactory = __import__('io').BytesIO
try:
    iofactory = __import__('cStringIO').StringIO
except ImportError:
    iofactory = __import__('StringIO').StringIO

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
#from Crypto.Signature import PKCS1_v1_5

import CRXFile

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('pycrxtest')

ui32 = lambda blob: struct.unpack('<I', blob)[0]
p_ui32 = lambda ui32: struct.pack('<I', ui32)

k = RSA.generate(2048, os.urandom)

zpayload = iofactory()
fs = []
with zipfile.ZipFile(zpayload, 'w', zipfile.ZIP_DEFLATED) as zipf:
  for i in xrange(10):
    fn = uuid.uuid4()
    data = os.urandom(512)
    zipf.writestr(str(fn), data)
    fs.append((fn, SHA.new(data).hexdigest()))
zipblob = zpayload.getvalue()

crxpayload = iofactory()
cf = CRXFile.CRXFile(crxpayload, mode='w')
cf.setprivatekey(k)

sha1sum = '\n'.join(["%s %s" % (fn, ss) for fn, ss in fs])
cf.setsha1sum(sha1sum)

_endrec = zipfile._EndRecData(zpayload)
zpayload.seek(_endrec[zipfile._ECD_OFFSET])
zipdir = zpayload.read(zipfile._ECD_SIZE)
cf.setzcd(zipdir)
cf.setpayloadblob(zipblob)
cf.write_crx_header()
cf.write_payload()

# REWIND THE TAPE WHIRR WHIRR WHIRR
crxpayload.seek(0)
rcf = CRXFile.CRXFile(crxpayload)

code.interact(local=locals())

