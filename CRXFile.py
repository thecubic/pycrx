#!/usr/bin/env python

import sys
import struct
import logging

if sys.version_info > (3, 0):
    iofactory = __import__('io').BytesIO
try:
    iofactory = __import__('cStringIO').StringIO
except ImportError:
    iofactory = __import__('StringIO').StringIO

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('CRXFile')


class CRXHeader(object):
  _crx_magic = 'Cr24'
  _crx_version = 3
  _crx_pk_len = 0
  _crx_ps_len = 0
  _crx_pk = ''
  _crx_ps = ''
  _crx_crt_len = 0
  _crx_crt = ''
  _crx_zd_len = 0
  _crx_zd_sig_len = 0
  _crx_s1_len = 0
  _crx_s1_sig_len = 0
  _crx_zd = ''
  _crx_s1 = ''
  _crx_zd_at_eof = 0
  _crx_pl_len = 0


class CRXFile(CRXHeader):
  def __init__(self, source=None, mode='r'):
    # source: a filename, file-like object, or blob that represents a CRX file
    # if no source is given, have a stringio
    self._source = source
    self._mode = mode
    if self._source is None:
      self._source = iofactory()
      self._mode = 'w'
    self._readable = hasattr(self._source, 'read')
    self._seekable = hasattr(self._source, 'seek')
    if self._mode == 'r':
      self._read_crx_header()
      self._validate_crx_header()
      self._read_payload()
      self._validate_payload()

  def _read_crx_header(self):
    # read header
    self._crx_magic = self._rbytes(4)
    self._crx_version = self._rlui32()
    self._crx_pk_len = self._rlui32()
    self._crx_ps_len = self._rlui32()
    if self._crx_version == 2:
      # ma-ma-MANDAMUS
      self._crx_pk = self._rbytes(self._crx_pk_len)
      self._crx_ps = self._rbytes(self._crx_ps_len)
    elif self._crx_version == 3:
      # i'm-not-your-dad-itis
      self._crx_crt_len = self._rlui32()
      self._crx_zd_len = self._rlui32()
      self._crx_zd_sig_len = self._rlui32()
      self._crx_s1_len = self._rlui32()
      self._crx_s1_sig_len = self._rlui32()
      self._crx_pl_len = self._rlui32()
      self._crx_zd_at_eof = self._rlui32()
      if self._crx_pk_len:
        self._crx_pk = self._rbytes(self._crx_pk_len)
      if self._crx_ps_len:
        self._crx_ps = self._rbytes(self._crx_ps_len)
      if self._crx_crt_len:
        self._crx_crt = self._rbytes(self._crx_crt_len)
      if self._crx_zd_len:
        self._crx_zd = self._rbytes(self._crx_zd_len)
      if self._crx_zd_sig_len:
        self._crx_zd_sig = self._rbytes(self._crx_zd_sig_len)
      if self._crx_s1_len:
        self._crx_s1 = self._rbytes(self._crx_s1_len)
      if self._crx_s1_sig_len:
        self._crx_s1_sig = self._rbytes(self._crx_s1_sig_len)

  def _write_crx_header(self):
    self._wbytes(self._crx_magic)
    self._wlui32(self._crx_version)
    self._wlui32(self._crx_pk_len)
    self._wlui32(self._crx_ps_len)
    if self._crx_version == 2:
      self._wbytes(self._crx_pk)
      self._wbytes(self._crx_ps)
    elif self._crx_version == 3:
      self._wlui32(self._crx_crt_len)
      self._wlui32(self._crx_zd_len)
      self._wlui32(self._crx_zd_sig_len)
      self._wlui32(self._crx_s1_len)
      self._wlui32(self._crx_s1_sig_len)
      self._wlui32(self._crx_pl_len)
      self._wlui32(self._crx_zd_at_eof)
      self._wbytes(self._crx_pk)
      self._wbytes(self._crx_ps)
      self._wbytes(self._crx_crt)
      self._wbytes(self._crx_zd)
      self._wbytes(self._crx_zd_sig)
      self._wbytes(self._crx_s1)
      self._wbytes(self._crx_s1_sig)

  def _read_payload(self):
    # read payload ( i guess if you wanna )
    # TODO: turn file-like object into a buffered
    #  generator with a "whelp, you're (not) fucked"
    #  at the end depending on SHA1 wrapper
    self.payload = self._rbytes(self._crx_pl_len or None)

  def _validate_payload(self):
    _v = self.verifier.verify(SHA.new(self.payload), self._crx_ps)
    if _v:
      log.debug("Payload valid")
    else:
      log.debug("Payload invalid")
    return _v

  def _validate_crx_header(self):
    assert self._crx_magic == 'Cr24'

    if self._crx_pk:
      self.publickey = RSA.importKey(self._crx_pk)
      self.verifier = PKCS1_v1_5.new(self.publickey)
      log.debug("RSA key present")
    else:
      log.warn("RSA key absent")

    if self._crx_crt:
      # TODO: certificates
      log.debug("X509 present")
    else:
      log.debug("X509 absent")

    if self._crx_zd:
      self._zd_sha1 = SHA.new(self._crx_zd)
    if self._crx_zd_sig:
      self._zd_verified = self.verifier.verify(self._zd_sha1, self._crx_zd_sig)
      if not self._zd_verified:
        log.error("ZCD invalid")
      else:
        log.debug("ZCD valid")
    else:
      log.warn("ZCD unsigned")

    if self._crx_s1:
      self._s1_sha1 = SHA.new(self._crx_s1)
    if self._crx_s1_sig:
      self._s1_verified = self.verifier.verify(self._s1_sha1, self._crx_s1_sig)
      if not self._s1_verified:
        log.error("SHA1SUM invalid")
      else:
        log.debug("SHA1SUM valid")
    else:
      log.warn("SHA1SUM unsigned")

    # don't verify payload yet

  def _rbytes(self, numbytes):
    return self._source.read(numbytes)

  def _rlui32(self):
    return struct.unpack("<I", self._rbytes(struct.calcsize("<I")))[0]

  def setprivatekey(self, privatekey):
    self.privatekey = privatekey
    self.signer = PKCS1_v1_5.new(self.privatekey)
    self.setpubkey(privatekey.publickey())
    # sign even if empty - for the sake of offsets
    # since len( sign( sha1(A) ) ) = len( sign( sha1(B) ) )
    self._crx_ps = self.signer.sign(SHA.new(''))
    self._crx_ps_len = len(self._crx_ps)

  def setpubkey(self, pubkey):
    self.publickey = pubkey
    self._crx_pk = pubkey.publickey().exportKey(format='DER')
    self._crx_pk_len = len(self._crx_pk)

  def setsha1sum(self, sha1sum):
    self._crx_s1 = sha1sum
    self._crx_s1_len = len(sha1sum)
    if self.signer and self.signer.can_sign():
      self._crx_s1_sig = self.signer.sign(SHA.new(sha1sum))
      self._crx_s1_sig_len = len(self._crx_s1_sig)

  def setzcd(self, zcd):
    self._crx_zd = zcd
    self._crx_zd_len = len(zcd)
    if self.signer and self.signer.can_sign():
      self._crx_zd_sig = self.signer.sign(SHA.new(zcd))
      self._crx_zd_sig_len = len(self._crx_zd_sig)

  def setpayloadblob(self, payload):
    self.payload = payload
    self._crx_pl_len = len(payload)
    if self.signer and self.signer.can_sign():
      self._crx_ps = self.signer.sign(SHA.new(payload))
      self._crx_ps_len = len(self._crx_ps)

  def write_crx_header(self):
    self._validate_crx_header()
    self._write_crx_header()

  def write_payload(self):
    if self.payload:
      self._wbytes(self.payload)
    self._validate_payload()

  def _wbytes(self, wbytes):
    return self._source.write(wbytes)

  def _wlui32(self, wint):
    return self._wbytes(struct.pack("<I", wint))
