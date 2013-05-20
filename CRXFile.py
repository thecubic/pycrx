#!/usr/bin/env python

import sys
import struct
import logging
import os

if sys.version_info > (3, 0):
    iofactory = __import__('io').BytesIO
else:
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
  _crx_zd_sig = ''
  _crx_s1_sig = ''
  _crx_zd_at_eof = 0
  _crx_pl_len = 0


class CRXCryptographicallyInvalid(Exception):
  pass


class CRXUnsupportedOrDamaged(Exception):
  pass

ISTRUCT = "<I"
ISIZE = struct.calcsize(ISTRUCT)
pint = lambda wint: struct.pack(ISTRUCT, wint)
uint = lambda wbytes: struct.unpack(ISTRUCT, wbytes)[0]


class CRXFile(CRXHeader):
  _log = None
  _payload_offset = None
  _source = None
  _mode = None

  def __init__(self, source=None, mode='r', log=None):
    # source: a filename, file-like object, or blob that represents a CRX file
    # if no source is given, have a stringio
    if log:
      if type(log) is logging.Logger:
        self._log = log
      elif type(log) is str:
        self._log = log.getChild(log)
    self._source = source
    self._mode = mode
    if self._source is None:
      raise IOError("File source object not provided")
    if self._mode == 'r':
      self._read_crx_header()
      self._validate_crx_header()
      self._payload_offset = self._source.tell()
      if self._seekable():
        self._payload_offset = self._source.tell()
        self._read_payload()
        self._validate_payload()
        self._source.seek(self._payload_offset, os.SEEK_SET)

  _flushable = lambda self: hasattr(self._source, 'flush')

  def flush(self):
    if self._flushable():
      return self._source.flush()

  _readable = lambda self: hasattr(self._source, 'read')

  def read(self, *args, **kwargs):
    if self._readable():
      return self._source.read(*args, **kwargs)

  _writable = lambda self: hasattr(self._source, 'write')

  def write(self, *args, **kwargs):
    if self._writable():
      return self._source.write(*args, **kwargs)

  _seekable = lambda self: hasattr(self._source, 'seek')

  def seek(self, offset, whence=os.SEEK_SET):
    if self._seekable():
      self._log.debug("seek: %d %d" % (offset, whence))
      if whence == os.SEEK_SET:
        return self._source.seek(offset + self._payload_offset, os.SEEK_SET)
      else:
        return self._source.seek(offset, whence)
    else:
      raise IOError("Can't seek() on backing file")

  _tellable = lambda self: hasattr(self._source, 'tell')

  def tell(self):
    if self._tellable():
      _tell = self._source.tell() - self._payload_offset
      self._log.debug('tell: %d' % _tell)
      return _tell
    else:
      raise IOError("Can't tell() on backing file")

  def setpayloadoffset(self, offset=None):
    self._payload_offset = offset or self._source.tell()

  def _readI(self):
    return uint(self.read(ISIZE))

  def _read_crx_header(self):
    # read header
    self._crx_magic = self.read(4)
    self._log.debug("Magic: %s" % self._crx_magic)
    self._crx_version = self._readI()
    self._log.debug("Version: %d" % self._crx_version)
    self._crx_pk_len = self._readI()
    self._log.debug("PK len: %d" % self._crx_pk_len)
    self._crx_ps_len = self._readI()
    self._log.debug("PS len: %d" % self._crx_ps_len)
    if self._crx_version == 2:
      # ma-ma-MANDAMUS
      self._crx_pk = self.read(self._crx_pk_len)
      self._crx_ps = self.read(self._crx_ps_len)
    elif self._crx_version == 3:
      # i'm-not-your-dad-itis
      self._crx_crt_len = self._readI()
      self._log.debug("x509 len: %d" % self._crx_crt_len)
      self._crx_zd_len = self._readI()
      self._log.debug("ZD len: %d" % self._crx_zd_len)
      self._crx_zd_sig_len = self._readI()
      self._log.debug("SIG(ZD) len: %d" % self._crx_zd_sig_len)
      self._crx_s1_len = self._readI()
      self._log.debug("SHA1SUM len: %d" % self._crx_s1_len)
      self._crx_s1_sig_len = self._readI()
      self._log.debug("SIG(SHA1SUM) len: %d" % self._crx_s1_sig_len)
      self._crx_pl_len = self._readI()
      self._log.debug("PAYLOAD len: %d" % self._crx_pl_len)
      self._crx_zd_at_eof = self._readI()
      self._log.debug("ZD@EOF: %d" % self._crx_zd_at_eof)
      if self._crx_pk_len:
        self._crx_pk = self.read(self._crx_pk_len)
      if self._crx_ps_len:
        self._crx_ps = self.read(self._crx_ps_len)
      if self._crx_crt_len:
        self._crx_crt = self.read(self._crx_crt_len)
      if self._crx_zd_len:
        self._crx_zd = self.read(self._crx_zd_len)
      if self._crx_zd_sig_len:
        self._crx_zd_sig = self.read(self._crx_zd_sig_len)
      if self._crx_s1_len:
        self._crx_s1 = self.read(self._crx_s1_len)
      if self._crx_s1_sig_len:
        self._crx_s1_sig = self.read(self._crx_s1_sig_len)
    else:
      raise CRXUnsupportedOrDamaged("Version %d is unknown/unsupported" % self._crx_version)

  def _writeI(self, wint):
    return self.write(pint(wint))

  def _write_crx_header(self):
    self.write(self._crx_magic)
    self._writeI(self._crx_version)
    self._writeI(self._crx_pk_len)
    self._writeI(self._crx_ps_len)
    if self._crx_version == 2:
      self.write(self._crx_pk)
      self.write(self._crx_ps)
    elif self._crx_version == 3:
      self._writeI(self._crx_crt_len)
      self._writeI(self._crx_zd_len)
      self._writeI(self._crx_zd_sig_len)
      self._writeI(self._crx_s1_len)
      self._writeI(self._crx_s1_sig_len)
      self._writeI(self._crx_pl_len)
      self._writeI(self._crx_zd_at_eof)
      self.write(self._crx_pk)
      self.write(self._crx_ps)
      self.write(self._crx_crt)
      self.write(self._crx_zd)
      self.write(self._crx_zd_sig)
      self.write(self._crx_s1)
      self.write(self._crx_s1_sig)

  def _read_payload(self):
    # read payload ( i guess if you wanna )
    # TODO: turn file-like object into a buffered
    #  generator with a "whelp, you're (not) fucked"
    #  at the end depending on SHA1 wrapper
    self.payload = self.read(self._crx_pl_len or None)

  def _validate_payload(self):
    _v = self.verifier.verify(SHA.new(self.payload), self._crx_ps)
    if _v:
      self._log.debug("Payload valid")
    else:
      self._log.debug("Payload invalid")
      raise CRXCryptographicallyInvalid("Payload invalid")
    return _v

  def _validate_crx_header(self):
    assert self._crx_magic == 'Cr24'

    if self._crx_pk:
      self.publickey = RSA.importKey(self._crx_pk)
      self.verifier = PKCS1_v1_5.new(self.publickey)
      self._log.debug("RSA key present")
    else:
      self._log.warn("RSA key absent")

    if self._crx_crt:
      # TODO: certificates
      self._log.debug("X509 present")
    else:
      self._log.debug("X509 absent")

    if self._crx_zd:
      self._zd_sha1 = SHA.new(self._crx_zd)
    if self._crx_zd_sig:
      self._zd_verified = self.verifier.verify(self._zd_sha1, self._crx_zd_sig)
      if not self._zd_verified:
        self._log.error("ZCD invalid")
      else:
        self._log.debug("ZCD valid")
    else:
      self._log.warn("ZCD unsigned")

    if self._crx_s1:
      self._s1_sha1 = SHA.new(self._crx_s1)
    if self._crx_s1_sig:
      self._s1_verified = self.verifier.verify(self._s1_sha1, self._crx_s1_sig)
      if not self._s1_verified:
        self._log.error("SHA1SUM invalid")
      else:
        self._log.debug("SHA1SUM valid")
    else:
      self._log.warn("SHA1SUM unsigned")
    # don't verify payload yet

  #def _rbytes(self, numbytes):
  #  return self._source.read(numbytes)

#  def _rlui32(self):
#    return struct.unpack("<I", self._rbytes(struct.calcsize("<I")))[0]

  def setprivatekey(self, privatekey):
    self.privatekey = privatekey
    self.signer = PKCS1_v1_5.new(self.privatekey)
    self.setpubkey(privatekey.publickey())
    # sign even if empty - for the sake of offsets
    # since len( sign( sha1(A) ) ) = len( sign( sha1(B) ) )
    self._log.debug("signing zero-payload (for padding)")
    self._crx_ps = self.signer.sign(SHA.new(''))
    self._crx_ps_len = len(self._crx_ps)
    self._log.debug("set SIG(PAYLOAD), %d bytes" % self._crx_ps_len)

  def setpubkey(self, pubkey):
    self.publickey = pubkey
    self._crx_pk = pubkey.publickey().exportKey(format='DER')
    self._crx_pk_len = len(self._crx_pk)
    self._log.debug("set PUBKEY, %d bytes" % self._crx_pk_len)

  def setsha1sum(self, sha1sum):
    self._crx_s1 = sha1sum
    self._crx_s1_len = len(sha1sum)
    self._log.debug("set SHA1SUM, %d bytes" % self._crx_s1_len)
    if self.signer and self.signer.can_sign():
      self._log.debug("signing SHA1SUM")
      self._crx_s1_sig = self.signer.sign(SHA.new(sha1sum))
      self._crx_s1_sig_len = len(self._crx_s1_sig)
      self._log.debug("set SIG(SHA1SUM), %d bytes" % self._crx_s1_sig_len)

  def setzcd(self, zcd):
    self._crx_zd = zcd
    self._crx_zd_len = len(zcd)
    self._log.debug("set ZCD, %d bytes" % self._crx_zd_len)
    if self.signer and self.signer.can_sign():
      self._log.debug("signing ZCD")
      self._crx_zd_sig = self.signer.sign(SHA.new(zcd))
      self._crx_zd_sig_len = len(self._crx_zd_sig)
      self._log.debug("set SIG(ZCD), %d bytes" % self._crx_zd_sig_len)

  def setpayloadblob(self, payload):
    self.payload = payload
    self._crx_pl_len = len(payload)
    self._log.debug("set PAYLOAD, %d bytes" % self._crx_pl_len)
    if self.signer and self.signer.can_sign():
      self._log.debug("signing PAYLOAD")
      self._crx_ps = self.signer.sign(SHA.new(payload))
      self._crx_ps_len = len(self._crx_ps)
      self._log.debug("set SIG(PAYLOAD), %d bytes" % self._crx_ps_len)

  def write_crx_header(self):
    self._validate_crx_header()
    self._write_crx_header()

  def write_payload(self):
    if self.payload:
      self.write(self.payload)
    self._validate_payload()

  #def _wbytes(self, wbytes):
  #  return self._source.write(wbytes)

  #def _wlui32(self, wint):
  #  return self._wbytes(struct.pack("<I", wint))


  # payload file-like-interface

  # close
  # flush
  # no -> fileno
  # isatty
  # next() iterator
  # read([size])
  # readline([size])
  # readlines([sizehint])
  # xreadlines
  # seek(offset, wence)
  # tell()
  # truncate()
  # write()
  # writelines()
  # closed = False
  # encoding
  # errors
  # mode
  # name
  # newlines
  # softspace
  # __enter__()
  # __exit__(exc_type, exc_vale, exc_tb)


