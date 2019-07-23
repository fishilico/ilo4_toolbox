#!/usr/bin/env python3
"""
Unpack an iLO firmware, being a packaged .scexe, an extracted .bin (contained
inside a .scexe) or an extracted big-ELF (from the .bin file)
"""
import argparse
import binascii
import base64
import ctypes
import enum
import hashlib
import io
import logging
import os.path
import re
import struct
import sys
import tarfile

import elftools.elf.elffile  # pyelftools package is required

try:
    import OpenSSL.crypto
except ImportError:
    sys.stderr.write(
        "OpenSSL.crypto not found (from python-cryptography), signatures will not be verified.\n")
    has_crypto = False
else:
    try:
        import Crypto.Hash.SHA256
        import Crypto.Hash.SHA512
        import Crypto.PublicKey.RSA
        import Crypto.Signature.PKCS1_v1_5
        has_crypto = True
    except ImportError:
        sys.stderr.write(
            "Crypto modules not found (from python-crypto), signatures will not be verified.\n")
        has_crypto = False


# Use the neighboring symbols.py file
sys.path.insert(0, os.path.dirname(__file__))
import symbols  # noqa

logger = logging.getLogger(__name__)


# Unsigned 32-bit integer type
UINT32 = ctypes.c_uint


def lzss_decompress(data):
    """Decompress the data according to LZSS algorithm"""
    output = bytearray(len(data) * 4)
    outputpos = 0
    datapos = 0
    flags = 0
    while datapos < len(data):
        while outputpos >= len(output) + 19:
            # Expand output
            output += bytearray(len(data))

        if not flags & 0xff:
            flags = (data[datapos] << 8) | 0xff
            datapos += 1

        if flags & 0x8000:
            # Literal byte
            output[outputpos] = data[datapos]
            datapos += 1
            outputpos += 1
        else:
            # Reference
            byte1 = data[datapos]
            byte2 = data[datapos + 1]
            datapos += 2
            offset = (((byte1 & 0xf) << 8) | byte2) + 1
            length = (byte1 >> 4) + 3
            if outputpos >= offset and offset >= length:
                # Common case optimisation
                output[outputpos:outputpos + length] = \
                    output[outputpos - offset:outputpos + length - offset]
                outputpos += length
            else:
                for _ in range(length):
                    if outputpos >= offset:
                        output[outputpos] = output[outputpos - offset]
                    else:
                        output[outputpos] = 0
                    outputpos += 1

        flags = (flags << 1) & 0xffff

    return bytes(output[:outputpos])


def decode_bigint_be(data):
    """Decode a Big-Endian big integer"""
    return int(binascii.hexlify(data).decode('ascii'), 16)


def encode_bigint_be(value, bytelen=None):
    """Encode a Big-Endian big integer"""
    if bytelen is None:
        bytelen = (value.bit_length() + 7) // 8
    hexval = '{{:0{:d}x}}'.format(bytelen * 2).format(value)
    return binascii.unhexlify(hexval.encode('ascii'))


def raw_rsa_encrypt(pubkey, data):
    """Use a RSA public key to encrypt data as RSA-textbook"""
    data_int = decode_bigint_be(data)
    encrypted_int = pow(data_int, pubkey.e, pubkey.n)
    return encode_bigint_be(encrypted_int, (pubkey.n.bit_length() + 7) // 8)


class HPSignedFingerprintedFile(object):
    """HP Signed file which begins with a HP Signed File Fingerprint"""
    def __init__(self, fwdata, syms):
        """Load the content of a file"""
        initial_len = len(fwdata)
        fpr_fields, fwdata = self._extract_fingerprint_fields(fwdata)
        self.keylabel = None
        self.hashname = None
        self.signature = None
        for key, value in fpr_fields.items():
            if key == 'Fingerprint Length':
                fwlen = int(value)
                if fwlen != initial_len - len(fwdata):
                    logger.warning("Invalid fingerprint length: %d != %d", fwlen, initial_len - len(fwdata))
            elif key == 'Key':
                self.keylabel = value
            elif key == 'Hash':
                self.hashname = value
            elif key == 'Signature':
                self.signature = base64.b64decode(value)
            else:
                logger.warning("Unknown fingerprint field %r", key)

        if self.keylabel is None or self.hashname is None or self.signature is None:
            logger.error("Missing field in fingerprint")
            raise ValueError

        self.certs = []
        while fwdata.startswith(b'-----BEGIN CERTIFICATE-----\n'):
            fwdata = self.load_cert(fwdata)

        # Verify the signature
        if self.certs and has_crypto:
            pkey = self.certs[0].get_pubkey().to_cryptography_key().public_numbers()
            rsakey = Crypto.PublicKey.RSA.construct((pkey.n, pkey.e))
            # paddedsign = rsakey.encrypt(self.signature, b'')[0]
            # assert len(paddedsign) == 255, len(paddedsign)
            # print(binascii.hexlify(paddedsign))
            # print(binascii.hexlify(paddedsign[-32:]))
            if self.hashname == 'sha256':
                expected_hash = Crypto.Hash.SHA256.new()
            else:
                logger.error("Unknown hash algorithm %r", self.hashname)
            expected_hash.update(fwdata)
            verifier = Crypto.Signature.PKCS1_v1_5.new(rsakey)
            if not verifier.verify(expected_hash, self.signature):
                logger.warning("Invalid cryptographic signature of HP Signed File")
            else:
                logger.debug("Valid signature in HP Signed File")

        # Ensure we are on HPIMAGE
        if not fwdata.startswith(b'HPIMAGE\0'):
            logger.error("Not an HPIMAGE file: %r", fwdata[:50])
            raise ValueError

        # Record some HPIMAGE fields
        self.hpimage_fields = {
            'unknown_number_0x101': struct.unpack('<I', fwdata[8:0xc])[0],
            'unknown_16bytes': binascii.hexlify(fwdata[0xc:0x1c]).decode('ascii'),
            'unknown_number_1': struct.unpack('<I', fwdata[0x1c:0x20])[0],
            'unknown_zero_bytes': binascii.hexlify(fwdata[0x20:0x3c]).decode('ascii'),
            'unknown_number': struct.unpack('<I', fwdata[0x3c:0x40])[0],
            'version': fwdata[0x40:0x60].rstrip(b'\0').decode('ascii'),
            'ilo_version': fwdata[0x60:0x4a0].rstrip(b'\0').decode('ascii'),
            'unknown_number_1_bis': struct.unpack('<I', fwdata[0x4a0:0x4a4])[0],
            'unknown_16bytes_bis': binascii.hexlify(fwdata[0x4a4:0x4b4]).decode('ascii'),
            'unknown_number_0': struct.unpack('<I', fwdata[0x4b4:0x4b8])[0],
        }

        # Skip it and record the remaining as the "payload"
        self.payload = fwdata[0x4b8:]

    @staticmethod
    def _extract_fingerprint_fields(fwdata):
        iline = -1
        fpr_fields = {}
        while True:
            iline += 1
            curline, fwdata = fwdata.split(b'\n', 1)
            curline = curline.decode('ascii')
            if iline == 0:
                if curline != '--=</Begin HP Signed File Fingerprint\\>=--':
                    logger.error("Unexpected HP Signed File header")
                    raise ValueError(curline)
            elif curline == '--=</End HP Signed File Fingerprint\\>=--':
                return fpr_fields, fwdata
            else:
                key, value = curline.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key not in fpr_fields:
                    fpr_fields[key] = value
                elif fpr_fields[key] != value:
                    logger.error("Unexpected redefinition of field %r: %r", key, value)
                    raise ValueError(curline)

    def load_cert(self, fwdata):
        assert fwdata.startswith(b'-----BEGIN CERTIFICATE-----\n')
        end_pattern = b'-----END CERTIFICATE-----\n'
        endpos = fwdata.index(end_pattern) + len(end_pattern)
        certdata = fwdata[:endpos].decode('ascii')
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certdata)
        self.certs.append(cert)
        return fwdata[endpos:]


class HPSignedParts(object):
    """File made of several signed parts and a bootloader"""
    def __init__(self, fwdata, syms, signed_fpr_file=None):
        # Grab the signature key at the end
        if fwdata[-4:-1] != b'iLO':
            # iLO3 firmware images end with several signatures
            while fwdata.endswith(b'-----END CERTIFICATE-----\n'):
                trailer_offet = fwdata.rfind(b'--=</Begin HP Signed File Fingerprint\>=--\n')
                if trailer_offet > 0:
                    fwdata = fwdata[:trailer_offet]
                    logger.debug('%r', fwdata[-10:])

        if fwdata[-4:-1] != b'iLO':
            logger.error("Invalid iLO version in bootcode footer: %r", fwdata[-4:])
            raise ValueError

        ilo_version = int(fwdata[-1:].decode('ascii'))
        signkey_offset = struct.unpack('<I', fwdata[-8:-4])[0]
        if signkey_offset > 0x10000 - 64:
            logger.error("bootcode signing key at invalid offset %#x", signkey_offset)
            raise ValueError
        bc_signkey = fwdata[-0x10000 + signkey_offset:-64]
        signkey_numbits = struct.unpack('<I', bc_signkey[:4])[0]
        if signkey_numbits != 4096:
            logger.error("unexpected bootcode signing key length %d", signkey_numbits)
            raise ValueError
        signkey_numbytes = signkey_numbits // 8
        if 4 + signkey_numbytes * 2 != len(bc_signkey):
            logger.error("unexpected bootcode signing key position %#x for %d bits",
                         signkey_offset, signkey_numbits)
            raise ValueError
        signkey_n = decode_bigint_be(bc_signkey[4:4 + signkey_numbytes])
        signkey_e = decode_bigint_be(bc_signkey[4 + signkey_numbytes:])
        logger.debug("Found RSA-%d signing key with exponent %d", signkey_numbits, signkey_e)
        if has_crypto:
            self.signing_key = Crypto.PublicKey.RSA.construct((signkey_n, signkey_e))

        # Read parts
        self.parts = []
        self.parts_info = []
        while fwdata.startswith(b'iLO'):
            if ilo_version != int(fwdata[3:4].decode('ascii')):
                logger.error("Multiple iLO versions in file: %d and %s", ilo_version, fwdata[3:4])
                raise ValueError
            fwdata = self.read_ilo_part(fwdata)

        if len(self.parts) != 4:
            raise ValueError("Unknown parts organization")
        # The INTEGRITY kernel lies in the two last partitions
        if self.parts[2] != self.parts[3]:
            raise ValueError("Corrupted INTEGRITY kernel")
        assert not self.parts[0]
        self.bigelf = self.parts[1]
        self.kernel = self.parts[2]

        # Remaining is the bootcode, with a vector table
        if fwdata[3] != 0xea:
            logger.error("Unknown bootcode branch instruction: %r", fwdata[:4])
            raise ValueError
        self.bootcode = fwdata
        logger.debug("Boot code: %d = %#x bytes", len(self.bootcode), len(self.bootcode))

        bootcode_verstr = self.bootcode[-64:-28].rstrip(b'\0\xff').decode('ascii')
        m = re.match(r'v ([0-9.+]+) ([0-9]+)-([a-zA-Z]+)-([0-9]+)$', bootcode_verstr)
        if m is None:
            logger.error("Unable to parse bootcode version %r", bootcode_verstr)
            raise ValueError
        bootcode_version, bootcode_day, bootcode_month, bootcode_year = m.groups()
        monthes = ['Jan', 'Feb', 'Mar', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        bootcode_m = monthes.index(bootcode_month)

        # Register the file
        fwfile_data = {
            'ilo_version': ilo_version,
            'signkey_bitsize': signkey_numbits,
            'signkey_n': hex(signkey_n),
            'signkey_e': signkey_e,
            'bootcode_version': bootcode_version,
            'bootcode_date': '{:04d}-{:02d}-{:02d}'.format(
                int(bootcode_year), bootcode_m, int(bootcode_day)),
            'bootcode_version_string': bootcode_verstr,
            'bootcode_size': len(self.bootcode),
            'bootcode_sha256': hashlib.sha256(self.bootcode).hexdigest(),
        }
        for k, v in self.parts_info[1].items():
            fwfile_data['bigelf_' + k] = v
        for k, v in self.parts_info[2].items():
            fwfile_data['kernel_' + k] = v
        if signed_fpr_file is not None:
            for k, v in signed_fpr_file.hpimage_fields.items():
                fwfile_data['hpimage_' + k] = v
        syms.add_fwfile(fwfile_data)

    def read_ilo_part(self, fwdata):
        """Decode a part by its header
        00000000: 694c 4f34 2076 2032 2e35 332e 3134 2030  iLO4 v 2.53.14 0
        00000010: 332d 4d61 792d 3230 3137 1a00 ffff ffff  3-May-2017......
        00000020: ffff 0000 1e0c 0000 e262 1000 0000 fe00  .........b......
                  ^^^^ ^^^^ ----------------------------- 0xffff: not compressed
                            ^^^^ ^^^^ ------------------- date and time
                                      ^^^^ ^^^^---------- version
        00000030: 0000 0001 ffff ffff 0000 0000 ffff ffff  ................
                  ^^^^ ^^^^------------------------------ data size?

        [ 0]00000440: 694c 4f34 2076 2032 2e35 332e 3134 2030  iLO4 v 2.53.14 0
        [ 4]00000450: 332d 4d61 792d 3230 3137 1a00 ffff ffff  3-May-2017......
        [ 8]00000460: 0800 0010 1e0c 0000 e262 1000 44a9 6e01  .........b..D.n.
                      ^^^^ ^^^^ ----------------------------- 0x10000008 ; (>>28 = 1 : compression type "1")
                                ^^^^ ^^^^ ------------------- date from 2009 (year 0xc1e//372+2009, month...)
                                                                and time (00:00:00)
                                          ^^^^ ^^^^---------- version in low 20 bits (&0xfffff):
                                                                decimal "25314" => 2.53.14
        [ c]00000470: 5b87 d400 ffff ffff 0000 0000 ffff ffff  [...............
                      ^^^^ ^^^^------------------------------ data size = 0x00d4875b
        Encrypted hash: of 64-byte header + (datasize - 1024) after 1024-byte header
        """
        part_data = fwdata[:0x440]
        if len(part_data) != 0x440:
            raise ValueError("Truncated file")
        partver = part_data[:0x20].rstrip(b'\xff').rstrip(b'\0')
        logger.debug("Part %d version: %r", len(self.parts), partver)
        if not part_data.startswith(b'iLO'):
            raise ValueError("Unknown version")

        decomp_type = part_data[0x23] >> 4
        date = struct.unpack('<H', part_data[0x24:0x26])[0]
        version = struct.unpack('<I', part_data[0x28:0x2c])[0] & 0xfffff
        datasize = struct.unpack('<I', part_data[0x30:0x34])[0]
        entrypoint = struct.unpack('<I', part_data[0x34:0x38])[0]

        if date < 80 * 372:  # FIXME which limit?
            # new format
            datestr = '%d-%02d-%02d' % (
                date // 372 + 2009,
                (date % 372) // 31 + 1,
                (date % 372) % 31 + 1)
        else:
            # old format
            datestr = '%d-%02d-%02d' % (
                date // 372 + 1921,
                (date % 372) // 31,
                (date % 372) % 31)
        infos = {
            'version': '%d.%d.%d' % (
                version // 10000,
                (version // 100) % 100,
                version % 100),
            'version_string': partver.rstrip(b'\x1a').decode('ascii'),
            'date': datestr,
            'size': datasize,
        }

        logger.debug("  compression %d", decomp_type)
        logger.debug("  date %s (%#x)", infos['date'], date)
        logger.debug("  version %s (%#x)", infos['version'], version)
        logger.debug("  data size %#x", datasize)
        logger.debug("  entrypoint %#x", entrypoint)
        signature = part_data[0x40:0x240]
        if not all(x == 0xff for x in part_data[0x240:0x440]):
            logger.error("Invalid signature padding")
            raise ValueError

        if has_crypto:
            paddedsign = raw_rsa_encrypt(self.signing_key, signature)
            logger.debug("Decrypted RSA-%d signature is %s",
                         (self.signing_key.n.bit_length() + 7) // 8 * 8,
                         binascii.hexlify(paddedsign).decode('ascii'))
            expected_hash = Crypto.Hash.SHA512.new()
            expected_hash.update(fwdata[:0x40])
            expected_hash.update(fwdata[0x440:datasize])
            logger.debug("SHA512 is %r", expected_hash.hexdigest())
            if paddedsign != b'\x00\x01' + b'\xff' * 445 + b'\0' + expected_hash.digest() != paddedsign:
                logger.warning("Invalid cryptographic signature in HP signed part")
            else:
                logger.debug("Valid signature in HP signed part")

        if decomp_type == 0:
            # The first part holds everything else
            if not self.parts:
                if datasize != len(fwdata):
                    logger.warning("There is stray data which is not signed! (%d bytes)", len(fwdata) - datasize)
                self.parts.append(b'')
                self.parts_info.append(infos)
                return fwdata[0x440:]
            else:
                logger.error("Empty part found")
                raise ValueError
        elif decomp_type == 1:
            compressed_size = struct.unpack('<I', fwdata[0x440:0x444])[0]
            if datasize != compressed_size + 0x444:
                logger.error("Unexpected data size: %#x != %#x + 0x444", datasize, compressed_size)
                raise ValueError
            decomp_data = lzss_decompress(fwdata[0x444:datasize])
            logger.debug("  decompressed size %#x", len(decomp_data))
            self.parts.append(decomp_data)
            infos['size'] = len(decomp_data)
            infos['sha256'] = hashlib.sha256(decomp_data).hexdigest()
            self.parts_info.append(infos)
            fwdata = fwdata[datasize:]
            if fwdata.startswith(b'\xff'):
                oldsize = len(fwdata)
                fwdata = fwdata.lstrip(b'\xff')
                logger.debug("Align: skipped %#x 'FF' bytes", oldsize - len(fwdata))
            return fwdata
        else:
            logger.error("Unknown decompression algorithm")
            raise ValueError


class SectKind(enum.Enum):
    CODE = 'Code'
    DATA = 'Data'
    BSS = 'Bss'
    HEAP = 'Heap'
    INITSTK = 'InitialStack'
    BOOTTABLE = 'BootTable'
    SECINFO = 'SecInfo'
    NULL = 'Null'
    MEMREGION = 'MemRegion'
    HEALTH = 'Health'
    BIOSRAM = 'BiosRam'

    @classmethod
    def from_nameflags(cls, name, shtype, flags):
        """Find a section kind from its name, type and ELF flags"""
        if shtype == 'SHT_PROGBITS':
            if name.endswith('.text') and flags == 6:
                return cls.CODE
            elif name.endswith('.data'):
                return cls.DATA
            elif name.endswith('.boottable'):
                return cls.BOOTTABLE
            elif name.endswith('.secinfo'):
                return cls.SECINFO
        elif shtype == 'SHT_NOBITS':
            if name.startswith('MemRegion'):
                return cls.MEMREGION
            elif name.endswith('.bss'):
                return cls.BSS
            elif name.endswith('.data'):
                # There are some bss sections which are wrongly named .data
                return cls.BSS
            elif name.endswith('.Initial.stack'):
                return cls.INITSTK
            elif name.endswith('.heap'):
                return cls.HEAP
            elif name in ('health_device_readings', 'platdef_health'):
                return cls.HEALTH
            elif name == 'biosram':
                return cls.BIOSRAM
        elif shtype == 'SHT_NULL':
            if name == '' and flags == 0:
                return cls.NULL

        raise ValueError("Unknown section %r/%r/%#x" % (name, shtype, flags))

    @property
    def secinfoflag(self):
        """Return the flag as seen in a .secinfo entry"""
        if self == self.CODE:
            return 0x1
        elif self == self.SECINFO:
            return 0x2
        elif self == self.DATA:
            return 0x9
        elif self == self.BOOTTABLE:
            return 0xa
        elif self in (self.BSS, self.HEAP, self.INITSTK, self.HEALTH, self.BIOSRAM):
            return 0xc
        # Other kinds never appear in .secinfo
        # and if they do, make sure to fail using a negative value
        return -1

    @property
    def elf_ph_flags(self):
        """Return the ELF Program Header flags"""
        if self == self.CODE:
            return 0x5
        elif self in (self.DATA, self.BSS, self.HEAP, self.INITSTK, self.HEALTH):
            return 0x6
        raise ValueError("Unknown program header flags of %r" % self)

    def has_data(self):
        """Does the section contains initialized data?"""
        if self in (self.CODE, self.DATA, self.BOOTTABLE, self.SECINFO):
            return True
        if self in (self.BSS, self.HEAP, self.INITSTK, self.HEALTH, self.MEMREGION, self.NULL, self.BIOSRAM):
            return False
        raise ValueError("Unknown initialisation state of %r" % self)


class ElfSection(object):
    """A section in an ELF file"""
    def __init__(self, name, addr, size, elfflags, kind):
        self.name = name
        self.addr = addr
        self.size = size
        self.elfflags = elfflags
        self.kind = kind

    def __repr__(self):
        return 'Section(%r, %#x, %#x, %#x, %s)' % (
            self.name, self.addr, self.size, self.elfflags, self.kind.value)


class ProcSection(object):
    """A section of a process"""
    def __init__(self, addr, size, attr, sect_id, desc):
        self.addr = addr
        self.size = size
        self.attr = attr
        self.sect_id = sect_id
        self.desc = desc

    def __repr__(self):
        return 'ProcSection(%#x, %#x, %#x, %r, %r)' % (
            self.addr, self.size, self.attr, self.sect_id, self.desc)

    def __str__(self):
        return '%08x...%08x [%#8x]: %s' % (
            self.addr, self.addr + self.size - 1, self.size, self.desc)


class SecInfoEntry(ctypes.Structure):
    """Entry in .secinfo section"""
    _fields_ = (
        ('next', UINT32),  # Adress of next entry
        ('pname', UINT32),  # Pointer to the section name
        ('address', UINT32),  # Start address of the section
        ('size', UINT32),  # Size of the section
        ('flags', UINT32),
        ('padding', UINT32),
    )
    _default_values = {
        'padding': 0,
    }


assert ctypes.sizeof(SecInfoEntry) == 0x18


class BootTableHeader(ctypes.Structure):
    _fields_ = (
        ('nbProcessEntries', UINT32),
        ('pProcessEntries', UINT32),
        ('nbFileEntries', UINT32),
        ('pFileEntries', UINT32),
        ('header_field_4_0xffffffff', UINT32),
        ('header_field_5_1', UINT32),
        ('header_field_6_0', UINT32),
        ('header_field_7_0', UINT32),
        ('header_field_8_0', UINT32),
        ('header_field_9_pFileEntries', UINT32),
        ('header_field_a_0', UINT32),
        ('header_field_b_6', UINT32),
        ('nbSoFileEntries', UINT32),
        ('pSoFileEntries', UINT32),
    )
    _default_values = {
        'header_field_4_0xffffffff': 0xffffffff,
        'header_field_5_1': 1,
        'header_field_6_0': 0,
        'header_field_7_0': 0,
        'header_field_8_0': 0,
        'header_field_a_0': 0,
        'header_field_b_6': 6,
    }
assert ctypes.sizeof(BootTableHeader) == 0x38

class BTFileEntry(ctypes.Structure):
    _fields_ = (
        ('dwFileIndex', UINT32),
        ('file_field_1', UINT32),
        ('file_field_2_1or2or3or4or5', UINT32),
        ('file_field_3', UINT32),
        ('file_field_4', UINT32),
        ('file_field_5', UINT32),
        ('file_field_6_0or1', UINT32),
        ('file_field_7', UINT32),
        ('pszType', UINT32),
        ('pszPath', UINT32),
        ('file_field_a', UINT32),
        ('file_field_b', UINT32),
        ('file_field_c', UINT32),
        ('file_field_d', UINT32),
        ('file_field_e', UINT32),
        ('file_field_f', UINT32),
    )
    _default_values = {
        'file_field_1': 0x10000,
        'file_field_3': 0xff,
        'file_field_4': 0xff,
        'file_field_5': 0,
        'file_field_7': 1,
        'file_field_a': 0,
        'file_field_b': 0,
        'file_field_d': 0xff,
        'file_field_e': 0xff,
        'file_field_f': 0,
    }
assert ctypes.sizeof(BTFileEntry) == 0x40


class BTSoFileEntry(ctypes.Structure):
    _fields_ = (
        ('pszName', UINT32),
        ('dwSizeOfText', UINT32),  # Size of .text section
        ('dwSection', UINT32),  # Index of .text section
        ('so_field_3', UINT32),
        ('so_field_4', UINT32),
    )
    _default_values = {
        'so_field_3': 0xffffffff,
        'so_field_4': 0xffffffff,
    }
assert ctypes.sizeof(BTSoFileEntry) == 0x14


class BTProcessEntry_before_0_8(ctypes.Structure):
    """Structure used before Integrity 0.8.11 kernel (2012-07-26)
    It has been used with Integrity 0.5.72+ (2012-03-08)
    """
    _fields_ = (
        ('unk_field_0', UINT32),
        ('nbMemEntries', UINT32),
        ('pMemEntries', UINT32),
        ('unk_field_3', UINT32),
        ('nbMemRegionEntries', UINT32),
        ('pMemRegionEntries', UINT32),
        ('padding_6', UINT32),
        ('padding_7', UINT32),
    )
    _default_values = {
        'padding_6': 0,
        'padding_7': 0,
    }
assert ctypes.sizeof(BTProcessEntry_before_0_8) == 0x20


class BTProcessEntry_0_8(ctypes.Structure):
    """Structure used since Integrity 0.8.11 kernel (2012-07-26)"""
    _fields_ = (
        ('unk_field_0', UINT32),
        ('nbMemEntries', UINT32),
        ('pMemEntries', UINT32),
        ('unk_field_3', UINT32),
        ('nbMemRegionEntries', UINT32),
        ('pMemRegionEntries', UINT32),
        ('padding_6', UINT32),
        ('padding_7', UINT32),
        ('unk_field_8', UINT32),
        ('padding_9', UINT32),
        ('padding_a', UINT32),
        ('padding_b', UINT32),
        ('padding_c', UINT32),
        ('padding_d', UINT32),
        ('padding_e', UINT32),
        ('padding_f', UINT32),
    )
    _default_values = {
        'padding_6': 0,
        'padding_7': 0,
        'padding_9': 0,
        'padding_a': 0,
        'padding_b': 0,
        'padding_c': 0,
        'padding_d': 0,
        'padding_e': 0,
        'padding_f': 0,
    }
assert ctypes.sizeof(BTProcessEntry_0_8) == 0x40


class BTProcessMemEntry(ctypes.Structure):
    _fields_ = (
        ('init', UINT32),  # Initialisation king (0 for nothing, 1 if there is content, 3 if zero-initialized)
        ('attr', UINT32),  # Memory region attributes (5 for RX, 7 for RWX, 0x507 for IO-RWX)
        ('virtaddr', UINT32),  # Virtual address
        ('size', UINT32),
        ('section_id', UINT32),  # ID of the section containing the content
        ('padding_0', UINT32),
        ('padding_1', UINT32),
        ('padding_2', UINT32),
    )
    _default_values = {
        'padding_0': 0,
        'padding_1': 0,
        'padding_2': 0,
    }
assert ctypes.sizeof(BTProcessMemEntry) == 0x20


class BTProcessRegionEntry(ctypes.Structure):
    _fields_ = (
        ('unkst2_0', UINT32),
        ('unkst2_1', UINT32),
        ('unkst2_2', UINT32),
        ('padding_0', UINT32),
        ('padding_1', UINT32),
        ('padding_2', UINT32),
        ('padding_3', UINT32),
        ('padding_4', UINT32),
    )
    _default_values = {
        'padding_0': 0,
        'padding_1': 0,
        'padding_2': 0,
        'padding_3': 0,
        'padding_4': 0,
    }
assert ctypes.sizeof(BTProcessRegionEntry) == 0x20


def extract_sz(addr, baseaddr, data):
    """Extract a NUL-terminated string from a data blob"""
    if baseaddr <= addr < baseaddr + len(data):
        return data[addr - baseaddr:].split(b'\0', 1)[0].decode('utf-8', 'replace')
    raise ValueError


def dbgprint_structure(structvalue, baseaddr, data):
    """Dump a structure on the debug output, using auxiliary data"""
    logger.debug("%s content:", type(structvalue).__name__)
    for fieldname, _ in structvalue._fields_:
        fieldval = getattr(structvalue, fieldname)
        defval = structvalue._default_values.get(fieldname)
        # Hide default values
        if defval is not None and defval == fieldval:
            continue
        if isinstance(fieldval, int):
            # Format integers as hexadecimal numbers, but when they are counts
            if fieldname.startswith('nb'):
                pass
            elif fieldname.startswith('psz') and baseaddr <= fieldval < baseaddr + len(data):
                # Strings
                fieldval = repr(extract_sz(fieldval, baseaddr, data))
            else:
                fieldval = hex(fieldval)
        logger.debug("  * %s: %s", fieldname, fieldval)


def check_default_fields(structvalue):
    """Check that the fields with a defined default value use this value"""
    result = True
    for fieldname, defaultval in structvalue._default_values.items():
        val = getattr(structvalue, fieldname)
        if val != defaultval:
            logger.error(
                "Unexpected value of field %s.%s: %r != %r",
                type(structvalue).__name__,
                fieldname,
                val,
                defaultval)
            result = False
    return result


class HPBigElf(object):
    """Unpack an ELF file containing the userspace modules"""
    def __init__(self, elfdata, kernelver=None):
        self.kernelver = kernelver

        elffile = io.BytesIO(elfdata)
        self.elf = elftools.elf.elffile.ELFFile(elffile)
        # Do NOT index sections by name as there may be conflicts
        self.sections = []
        secinfo_idx = None
        boottable_idx = None
        for sect in self.elf.iter_sections():
            if sect.name == '.shstrtab' and sect.header.sh_type == 'SHT_STRTAB':
                continue
            if sect.name == '.secinfo':
                if secinfo_idx is not None:
                    logger.warning("Duplicate .secinfo found in ELF file")
                secinfo_idx = len(self.sections)
            if sect.name == '.boottable':
                if boottable_idx is not None:
                    logger.warning("Duplicate .boottable found in ELF file")
                boottable_idx = len(self.sections)
            self.sections.append(ElfSection(
                sect.name,
                sect.header.sh_addr,
                sect.header.sh_size,
                sect.header.sh_flags,
                SectKind.from_nameflags(sect.name, sect.header.sh_type, sect.header.sh_flags)))

        # Check .secinfo, if it is defined
        if secinfo_idx is None:
            logger.warning("No .secinfo found in ELF file")
        else:
            secinfo_addr = self.sections[secinfo_idx].addr
            secinfo_data = self.elf.get_section(secinfo_idx).data()
            if not self.check_secinfo_content(secinfo_addr, secinfo_data):
                raise ValueError("Inconsistent .secinfo content")

        # Parse .boottable
        self.proc_sections = []
        self.proc_names = []
        if boottable_idx is None:
            logger.error("No .boottable found in ELF file")
            raise ValueError
        boottable_addr = self.sections[boottable_idx].addr
        boottable_data = self.elf.get_section(boottable_idx).data()
        self.parse_boottable(boottable_addr, boottable_data)

    def check_secinfo_content(self, baseaddr, data):
        """Check that data in .secinfo is consistent"""
        # Skip memory regions
        i_sect = 0
        if not self.sections[i_sect].name:
            i_sect += 1
        while self.sections[i_sect].name.startswith('MemRegion'):
            i_sect += 1
        logger.debug("Ignoring %d sections before .secinfo's first entry", i_sect)

        curentry_ptr = baseaddr
        while curentry_ptr:
            # Parse the current .secinfo entry
            entry_offset = curentry_ptr - baseaddr
            entry = SecInfoEntry.from_buffer_copy(
                data[entry_offset:entry_offset + ctypes.sizeof(SecInfoEntry)])
            name = extract_sz(entry.pname, baseaddr, data)

            # Compare it with the expected ELF section
            elfsect = self.sections[i_sect]
            if elfsect.name != name:
                logger.error(
                    "Unpexpected section name: entry %r, ELF %r",
                    name, elfsect.name)
                return False
            if elfsect.addr != entry.address or elfsect.size != entry.size:
                logger.error(
                    "Mismatched address/size for %r: entry %#x/%#x, ELF %#x/%#x",
                    name, entry.address, entry.size, elfsect.addr, elfsect.size)
                return False
            if elfsect.kind.secinfoflag != entry.flags:
                # Accept that .boottable uses a .data flag
                if (elfsect.kind, entry.flags) not in ((SectKind.BOOTTABLE, 9), (SectKind.SECINFO, 0x22)):
                    logger.error(
                        "Unexpected .secinfo flags for %r: entry %#x != %#x from ELF:%s",
                        name, entry.flags, elfsect.kind.secinfoflag, elfsect.kind)
                    return False

            logger.debug(
                "Good .secinfo: %08x/%#x %#x %s",
                entry.address,
                entry.size,
                entry.flags,
                name)
            # Process the next entry
            curentry_ptr = entry.next
            i_sect += 1
        return True

    def parse_boottable(self, baseaddr, data):
        """Parse the content of ELF section .boottable"""
        logger.debug("Parsing .boottable @%#x", baseaddr)

        # Parse header
        header = BootTableHeader.from_buffer_copy(data)
        dbgprint_structure(header, baseaddr, data)

        # Dump file tables
        logger.debug("File table @%#x:", header.pFileEntries)
        for idx_file in range(header.nbFileEntries):
            offset = header.pFileEntries - baseaddr + idx_file * ctypes.sizeof(BTFileEntry)
            entry = BTFileEntry.from_buffer_copy(
                data[offset:offset + ctypes.sizeof(BTFileEntry)])
            # dbgprint_structure(entry, baseaddr, data)
            logger.debug(
                "  File %2d: %r %#x",
                entry.dwFileIndex,
                extract_sz(entry.pszPath, baseaddr, data),
                entry.file_field_c)

            # Sanity checks
            if entry.dwFileIndex != idx_file + 1:
                logger.error("Unexpected dwFileIndex (not %d)", idx_file + 1)
                raise ValueError
            if entry.file_field_2_1or2or3or4or5 not in (1, 2, 3, 4, 5):
                logger.error("Unexpected file_field_2_1or2or3or4or5: %r", entry.file_field_2_1or2or3or4or5)
                raise ValueError
            if entry.file_field_6_0or1 not in (0, 1):
                logger.error("Unexpected file_field_6_0or1: %r", entry.file_field_6_0or1)
                raise ValueError
            entrytype = extract_sz(entry.pszType, baseaddr, data)
            if entrytype != 'Initial':
                # Older iLO use the process name concatenated with ".Initial"
                if not entrytype.endswith('.Initial'):
                    logger.error("Unexpected pszType (not Initial): %r", entrytype)
                    raise ValueError
            if not check_default_fields(entry):
                raise ValueError

        # Offset between the indicated section number and the effective one
        # 0 for INTEGRITY kernels <= 0.4, 1 for >= 0.5
        sections_idx_offset = 1
        if self.kernelver and self.kernelver.startswith(('0.3.', '0.4.')):
            sections_idx_offset = 0

        # Dump SO file tables
        logger.debug("SO File table @%#x:", header.pSoFileEntries)
        for idx_file in range(header.nbSoFileEntries):
            offset = header.pSoFileEntries - baseaddr + idx_file * ctypes.sizeof(BTSoFileEntry)
            entry = BTSoFileEntry.from_buffer_copy(
                data[offset:offset + ctypes.sizeof(BTSoFileEntry)])
            # dbgprint_structure(entry, baseaddr, data)
            soname = extract_sz(entry.pszName, baseaddr, data)
            logger.debug("  SOFile %d: %r", idx_file, soname)

            # Sanity checks
            if entry.dwSection + sections_idx_offset >= len(self.sections):
                logger.error("Invalid section index %#x", entry.dwSection)
                raise ValueError
            sect = self.sections[entry.dwSection + sections_idx_offset]
            if sect.name != '.%s.text' % soname or sect.size != entry.dwSizeOfText:
                logger.error("Mismatched section reference %r/%#x", sect.name, sect.size)
                raise ValueError
            if not check_default_fields(entry):
                raise ValueError

        # Choose the right process table structure according to heuristics
        offset = header.pProcessEntries - baseaddr
        entry = BTProcessEntry_0_8.from_buffer_copy(
                data[offset:offset + ctypes.sizeof(BTProcessEntry_0_8)])
        if entry.padding_a == 0:
            logger.debug("Choosing structure for kernel 0.8")
            if self.kernelver and not self.kernelver.startswith('0.8.'):
                logger.warning(
                    "Trying to parse the process structure of kernel 0.8 while using %s",
                    self.kernelver)
            procentry_struct = BTProcessEntry_0_8
        else:
            # TODO add more known-good kernel revisions here
            if self.kernelver and not self.kernelver.startswith('0.5.'):
                logger.warning(
                    "Trying to parse the process structure of kernel 0.5 while using %s",
                    self.kernelver)
            procentry_struct = BTProcessEntry_before_0_8

        # Dump process tables
        self.proc_names = [None] * header.nbProcessEntries
        self.proc_names[0] = 'IDENTITY'
        self.proc_sections = [None] * header.nbProcessEntries
        logger.debug("Process table @%#x:", header.pProcessEntries)
        for idx_process in range(header.nbProcessEntries):
            offset = header.pProcessEntries - baseaddr + idx_process * ctypes.sizeof(procentry_struct)
            entry = procentry_struct.from_buffer_copy(
                data[offset:offset + ctypes.sizeof(procentry_struct)])
            dbgprint_structure(entry, baseaddr, data)
            if not check_default_fields(entry):
                raise ValueError

            self.proc_sections[idx_process] = [None] * entry.nbMemEntries
            for idx_subt in range(entry.nbMemEntries):
                offset = entry.pMemEntries - baseaddr + idx_subt * ctypes.sizeof(BTProcessMemEntry)
                subentry = BTProcessMemEntry.from_buffer_copy(
                    data[offset:offset + ctypes.sizeof(BTProcessMemEntry)])
                # dbgprint_structure(subentry, baseaddr, data)
                if not check_default_fields(subentry):
                    raise ValueError

                desc = None
                sect_id = None
                if subentry.section_id != 0xffffffff:
                    # There is a section
                    if subentry.init != 1:
                        logger.error("Invalid init kind %#x when using section", subentry.init)
                        raise ValueError
                    if subentry.section_id + sections_idx_offset >= len(self.sections):
                        logger.error("Invalid section index %#x", subentry.section_id)
                        raise ValueError
                    sect = self.sections[subentry.section_id + sections_idx_offset]
                    if (sect.elfflags, subentry.attr) not in ((6, 5), (7, 7), (7, 0x107)):
                        logger.error(
                            "Inconsistent section attributes: ELF %#x, entry %#x",
                            sect.elfflags,
                            subentry.attr)
                        raise ValueError
                    desc = 'ELF:%s' % sect.name
                    sect_id = subentry.section_id + sections_idx_offset

                    # While at it, grab the process name from the section name
                    newprocname = None
                    if sect.kind == SectKind.HEAP:
                        assert sect.name.endswith('.heap') and sect.name[0] == '.'
                        newprocname = sect.name[1:-len('.heap')]
                    elif sect.kind == SectKind.INITSTK:
                        assert sect.name.endswith('.Initial.stack') and sect.name[0] == '.'
                        newprocname = sect.name[1:-len('.Initial.stack')]
                    if newprocname:
                        oldprocname = self.proc_names[idx_process]
                        if oldprocname is None:
                            self.proc_names[idx_process] = newprocname
                        elif newprocname != oldprocname:
                            logger.error(
                                "Bad process name guessing heuristic: %r and %r",
                                oldprocname, newprocname)
                            raise ValueError
                elif subentry.init == 0:
                    if idx_process != 0:
                        desc = 'empty'  # Nothing is being mapped yet
                    else:
                        # Kernel mapping
                        elfsect = self.sections[idx_subt + sections_idx_offset]
                        if elfsect.addr != subentry.virtaddr or elfsect.size != subentry.size:
                            logger.error(
                                "Mismatched mem entry address/size: entry %#x/%#x, ELF %#x/%#x",
                                subentry.virtaddr, subentry.size,
                                elfsect.addr, elfsect.size)
                            raise ValueError
                        desc = 'BigElf:%s' % elfsect.name
                elif subentry.init == 1:
                    if idx_process != 0:
                        logger.error("Unexpected direct ELF mapping in non-kernel process")
                        raise ValueError
                    desc = 'direct ELF mapping'  # Mapping the section at the given address
                elif subentry.init == 3:
                    if idx_process != 0:
                        logger.error("Unexpected zero-init ELF mapping in non-kernel process")
                        raise ValueError
                    desc = 'zero-init ELF mapping'

                if desc is None:
                    logger.error("Unknown init kind %#x", subentry.init)
                    raise ValueError

                if subentry.attr == 0:
                    if idx_process != 0:
                        desc += ' (no attr)'
                elif subentry.attr == 5:
                    desc += ' (RX)'
                elif subentry.attr == 7:
                    desc += ' (RWX)'
                elif subentry.attr == 0x107:
                    desc += ' (volatile RWX)'
                elif subentry.attr == 0x507:
                    # MEMORY_VOLATILE | MEMORY_IOCOHERENT = 0x500
                    desc += ' (IO RWX)'
                else:
                    logger.error("Unknown memory attributes %#x", subentry.attr)
                    raise ValueError

                self.proc_sections[idx_process][idx_subt] = ProcSection(
                    subentry.virtaddr,
                    subentry.size,
                    subentry.attr,
                    sect_id,
                    desc)
                logger.debug("    %s", self.proc_sections[idx_process][idx_subt])

            for idx_subt in range(entry.nbMemRegionEntries):
                offset = entry.pMemRegionEntries - baseaddr + idx_subt * ctypes.sizeof(BTProcessRegionEntry)
                subentry = BTProcessRegionEntry.from_buffer_copy(
                    data[offset:offset + ctypes.sizeof(BTProcessRegionEntry)])
                # dbgprint_structure(subentry, baseaddr, data)
                if not check_default_fields(subentry):
                    raise ValueError

                desc = '%#x %#x %#x' % (
                    subentry.unkst2_0,
                    subentry.unkst2_1,
                    subentry.unkst2_2)
                if subentry.unkst2_0 == 7:
                    desc = "Resource %r %#x" % (
                        extract_sz(subentry.unkst2_1, baseaddr, data),
                        subentry.unkst2_2)
                elif (subentry.unkst2_0, subentry.unkst2_1, subentry.unkst2_2) == (1, 0, 0):
                    desc = "1:0:0"
                    # Skip the number
                    continue
                elif subentry.unkst2_0 == 3:
                    if subentry.unkst2_2 >= len(self.proc_sections[subentry.unkst2_1]):
                        logger.error("Invalid process section reference in mem mapping")
                        raise ValueError
                    psect = self.proc_sections[subentry.unkst2_1][subentry.unkst2_2]
                    if subentry.unkst2_1 == 0:
                        desc = 'IdentityMapping:%s' % psect
                    elif subentry.unkst2_1 == idx_process:
                        desc = str(psect)
                    else:
                        logger.error("Invalid process ID reference in mem mapping")
                        raise ValueError
                elif subentry.unkst2_0 == 4:
                    assert subentry.unkst2_1 in (0, idx_process - 1)
                    assert subentry.unkst2_2 == 0
                    desc = 'ref to proc:%#x+1' % (
                        subentry.unkst2_1)

                logger.debug("  MemRegion %#5x: %s", idx_subt + 1, desc)

            # Try to understand unknown fields
            if idx_process == 0:
                if (entry.unk_field_0, entry.unk_field_3) != (0, 0):
                    logger.error("Unknown unknown process fields for process 0")
                    raise ValueError
                if isinstance(entry, BTProcessEntry_0_8):
                    if entry.unk_field_8 != 0:
                        logger.error("Unknown unknown process fields for process 0")
                        raise ValueError
            else:
                if isinstance(entry, BTProcessEntry_0_8):
                    if entry.unk_field_0 != 0x21:
                        logger.error(
                            "Unknown unk_field_0 for process %#x: %#x",
                            idx_process, entry.unk_field_0)
                else:
                    if entry.unk_field_0 not in (1, 0x21):
                        logger.error(
                            "Unknown unk_field_0 for process %#x: %#x",
                            idx_process, entry.unk_field_0)
                if entry.unk_field_3 != entry.nbMemRegionEntries + 0x14:
                    logger.error(
                        "Unknown unk_field_3 for process %#x: %#x",
                        idx_process, entry.unk_field_3)
                    raise ValueError
            # Sum up the informations about the process
            if isinstance(entry, BTProcessEntry_0_8):
                logger.debug("=> Process %u: %s (unknown field %#x)",
                    idx_process,
                    self.proc_names[idx_process],
                    entry.unk_field_8)
            else:
                logger.debug("=> Process %u: %s",
                    idx_process,
                    self.proc_names[idx_process])

        # Ensure that process names are defined and unique
        all_procnames = set()
        for (i, name) in enumerate(self.proc_names):
            if not name:
                logger.error("Unable to find the name of process %d", i)
                raise ValueError
            if name in all_procnames:
                logger.error("Duplicate process %r", name)
                raise ValueError
            all_procnames.add(name)

    def get_proc_elf(self, idx_process, syms, sym_fwproc, arg_emptysect):
        """Craft an ELF file representing a process"""
        sections = self.proc_sections[idx_process]
        file_data = b''

        # Craft ELF program and section headers
        num_ph_entries = len(sections)
        num_sh_entries = len(sections) + 4  # NULL, sections, .symtab, .strtab and .shstrtab
        offset_data = 0x34 + 0x20 * num_ph_entries # ELF section + program headers
        skipped_sections = 0

        # Align the offset of file data
        offset_data = ((offset_data + 511) // 512) * 512
        base_offset_data = offset_data
        prog_header = []
        sect_header = []
        # SHT_NULL entry
        sect_header.append(b'\0' * 0x28)
        shstrtab = b'\0\0\0\0'

        # Symbol table
        symtab = [b'\0' * 0x10]
        symstrtab = b'\0\0\0\0'

        for procsect in sections:
            sh_name_offset = len(shstrtab)

            # If there are symbols for the section, add them too
            sym_elfsect = syms.get_elfsect_from_proc_and_addr(sym_fwproc, procsect.addr)
            if sym_elfsect is not None:
                for sym in sym_elfsect.get('symbols', {}).values():
                    assert procsect.addr <= sym['addr'] < procsect.addr + procsect.size
                    symtab.append(struct.pack('<IIIBBH',
                        len(symstrtab),  # st_name
                        sym['addr'],  # st_value
                        sym.get('size', 0),  # st_size
                        sym.get_elf_sym_info(),
                        0,  # st_other
                        len(sect_header),  # st_shndx
                    ))
                    symstrtab += sym['name'].encode('ascii') + b'\0'

            if procsect.sect_id is not None:
                sect = self.sections[procsect.sect_id]
                shstrtab += sect.name.encode('ascii') + b'\0'
                shstrtab += b'\0' * (4 - (len(shstrtab) % 4))
                if sect.kind.has_data():
                    logger.debug("   %s: initialized section from %r", procsect, sect)
                    logger.debug(
                        "   ... using file offset %#x..%#x",
                        offset_data, offset_data + procsect.size - 1)

                    # Craft program and section header
                    prog_header.append(struct.pack('<IIIIIIII',
                       1,  # p_type = PT_LOAD
                       offset_data,  # p_offset
                       procsect.addr,  # p_vaddr
                       procsect.addr,  # p_paddr
                       procsect.size,  # p_filesz
                       procsect.size,  # p_memsz
                       procsect.attr & 7,  # p_flags
                       0,  # p_align
                    ))
                    elfflags = sect.elfflags
                    # Filter out "CODE" from elfflags for data sections
                    if not sect.name.endswith('.text'):
                        elfflags &= ~4  # SHF_EXECINSTR
                    sect_header.append(struct.pack('<IIIIIIIIII',
                        sh_name_offset,  # sh_name
                        1,  # sh_type = SHT_PROGBITS
                        elfflags,  # sh_flags
                        procsect.addr,  # sh_addr
                        offset_data,  # sh_offset
                        procsect.size,  # sh_size
                        0,  # sh_link
                        0,  # sh_info
                        0,  # sh_addralign
                        0,  # sh_entsize
                    ))
                    sect_data = self.elf.get_section(procsect.sect_id).data()
                    assert sect.size == len(sect_data)
                    assert procsect.size >= sect.size
                    file_data += sect_data
                    offset_data += procsect.size
                    offset_data = ((offset_data + 511) // 512) * 512
                    file_data += b'\0' * (offset_data - base_offset_data - len(file_data))
                    assert offset_data == base_offset_data + len(file_data)
                    continue
                else:
                    logger.debug("   %s: uninitialized section from %r", procsect, sect)
            else:
                if arg_emptysect:
                    logger.debug("   %s: uninitialized anonymous section", procsect)
                    # Put an automatic name
                    shstrtab += b'Empty_%08x\0' % procsect.addr
                    shstrtab += b'\0' * (4 - (len(shstrtab) % 4))
                else:
                    # Skip the empty section
                    skipped_sections += 1
                    continue

            prog_header.append(struct.pack('<IIIIIIII',
               1,  # p_type = PT_LOAD
               offset_data,  # p_offset
               procsect.addr,  # p_vaddr
               procsect.addr,  # p_paddr
               0,  # p_filesz
               procsect.size,  # p_memsz
               procsect.attr & 7,  # p_flags
               0,  # p_align
            ))
            sect_header.append(struct.pack('<IIIIIIIIII',
                sh_name_offset,  # sh_name
                8,  # sh_type = SHT_NOBITS
                3,  # sh_flags = SHF_WRITE=1 | SHF_ALLOC=2
                procsect.addr,  # sh_addr
                offset_data,  # sh_offset
                procsect.size,  # sh_size
                0,  # sh_link
                0,  # sh_info
                0,  # sh_addralign
                0,  # sh_entsize
            ))

        # Add .symtab section
        assert all(len(sym) == 0x10 for sym in symtab)
        sh_name_offset = len(shstrtab)
        shstrtab += b'.symtab\0'
        shstrtab += b'\0' * (4 - (len(shstrtab) % 4))
        sect_header.append(struct.pack('<IIIIIIIIII',
            sh_name_offset,  # sh_name
            2,  # sh_type = SHT_SYMTAB
            0,  # sh_flags
            0,  # sh_addr
            offset_data,  # sh_offset
            0x10 * len(symtab),  # sh_size
            len(sect_header) + 1,  # sh_link = linked string table
            len(symtab),  # sh_info
            0,  # sh_addralign
            0x10,  # sh_entsize
        ))
        file_data += b''.join(symtab)
        offset_data += 0x10 * len(symtab)
        offset_data = ((offset_data + 511) // 512) * 512
        file_data += b'\0' * (offset_data - base_offset_data - len(file_data))
        assert offset_data == base_offset_data + len(file_data)
        del symtab

        # Add .strtab section
        sh_name_offset = len(shstrtab)
        shstrtab += b'.strtab\0'
        shstrtab += b'\0' * (4 - (len(shstrtab) % 4))
        sect_header.append(struct.pack('<IIIIIIIIII',
            sh_name_offset,  # sh_name
            3,  # sh_type = SHT_STRTAB
            0,  # sh_flags
            0,  # sh_addr
            offset_data,  # sh_offset
            len(symstrtab),  # sh_size
            0,  # sh_link
            0,  # sh_info
            0,  # sh_addralign
            0,  # sh_entsize
        ))
        file_data += symstrtab
        offset_data += len(symstrtab)
        offset_data = ((offset_data + 511) // 512) * 512
        file_data += b'\0' * (offset_data - base_offset_data - len(file_data))
        assert offset_data == base_offset_data + len(file_data)
        del symstrtab

        # Add .shstrtab section
        sh_name_offset = len(shstrtab)
        shstrtab += b'.shstrtab\0'
        shstrtab += b'\0' * (4 - (len(shstrtab) % 4))
        sect_header.append(struct.pack('<IIIIIIIIII',
            sh_name_offset,  # sh_name
            3,  # sh_type = SHT_STRTAB
            0,  # sh_flags
            0,  # sh_addr
            offset_data,  # sh_offset
            len(shstrtab),  # sh_size
            0,  # sh_link
            0,  # sh_info
            0,  # sh_addralign
            0,  # sh_entsize
        ))
        file_data += shstrtab
        offset_data += len(shstrtab)  # Now offset_data is the offset to the section header
        offset_data = ((offset_data + 511) // 512) * 512
        file_data += b'\0' * (offset_data - base_offset_data - len(file_data))
        assert offset_data == base_offset_data + len(file_data)
        del shstrtab

        # Sanity checks
        num_ph_entries -= skipped_sections
        num_sh_entries -= skipped_sections
        assert all(len(ph) == 0x20 for ph in prog_header)
        assert all(len(sh) == 0x28 for sh in sect_header)
        assert len(prog_header) == num_ph_entries
        assert len(sect_header) == num_sh_entries

        # Craft the ELF header
        elf_header = (
            binascii.unhexlify(b'7f454c46010101000000000000000000') +
            struct.pack('<HHIIIIIHHHHHH',
                2,  # e_type
                0x28,  # e_machine = EM_ARM
                1,  # e_version
                0x10000,  # e_entry # FIXME where? hardcoded 0x10000?
                0x34,  # e_phoff
                offset_data,  # e_shoff
                0,  # e_flags, 0x170c00 ?
                0x34,  # e_ehsize
                0x20,  # e_phentsize
                num_ph_entries,  # e_phnum
                0x28,  # e_shentsize
                num_sh_entries,  # e_shnum
                num_sh_entries - 1,  # e_shstrndx
            ))
        assert len(elf_header) == 0x34

        # Add the program header and padding, the content, and the section header
        return b''.join((
            elf_header,
             b''.join(prog_header),
             b'\0' * (base_offset_data - (0x34 + 0x20 * num_ph_entries)),
            file_data,
            b''.join(sect_header),
        ))


def unpack_fw(filepath, fwdata, syms, arg_outdir, arg_emptysect, arg_extract_all):
    """Unpack a HP iLO firmware, whatever its format"""
    if fwdata.startswith(b'#!/bin/sh\n#!scexe\n'):
        # Self-extracting archive with an installer
        try:
            skip_variable_idx = fwdata.index(b'\n_SKIP=') + 7
            skip_variable_endidx = fwdata.index(b'\n', skip_variable_idx)
            nline_skip = int(fwdata[skip_variable_idx:skip_variable_endidx].decode('ascii'))
        except ValueError:
            logger.error("No _SKIP variable in scexe file")
            raise ValueError
        # Skip lines
        logger.debug("Skipping %d lines in %s", nline_skip, filepath)
        skippos = 0
        for _ in range(nline_skip - 1):
            skippos = fwdata.index(b'\n', skippos) + 1
        fwdata = fwdata[skippos:]

        if arg_extract_all:
            filename = '%s.tar.gz' % filepath
            logger.info("Writing %s", filename)
            with open(filename, 'wb') as f:
                f.write(fwdata)

        # Extract the .bin firmware
        archive = tarfile.open(fileobj=io.BytesIO(fwdata), mode='r:gz')
        arc_names = archive.getnames()
        logger.debug("Archive content: %r", arc_names)
        binfiles = [name for name in archive.getnames() if name.endswith('.bin')]
        if len(binfiles) != 1:
            logger.error("Unable to find a firmware file in archive content: %r", arc_names)
            raise ValueError
        binfile_name = binfiles[0]
        fwdata = archive.extractfile(binfile_name).read()
        logger.info("Found %r in %s", binfile_name, filepath)
        if arg_extract_all:
            filename = '%s_%s.out' % (filepath, binfile_name)
            logger.info("Writing %s", filename)
            with open(filename, 'wb') as f:
                f.write(fwdata)

    signed_fpr_file = None
    if fwdata.startswith(b'--=</Begin HP Signed File Fingerprint\\>=--\n'):
        signed_fpr_file = HPSignedFingerprintedFile(fwdata, syms)
        fwdata = signed_fpr_file.payload
        if fwdata.startswith(b'neba9'):
            logger.error("iLO5 firmware images are not yet supported :(")
            raise ValueError
        if not fwdata.startswith(b'iLO') or fwdata[4:7] != b' v ':
            logger.error("Unrecognized payload of HP signed file: %r", fwdata[:7])
            raise ValueError

    if fwdata.startswith(b'iLO') and fwdata[4:7] == b' v ':
        signed_file = HPSignedParts(fwdata, syms, signed_fpr_file)
        logger.info(
            "ELF %.2f kB, kernel %.2f kB, boot code %.2f kB",
            len(signed_file.bigelf) / 1024,
            len(signed_file.kernel) / 1024,
            len(signed_file.bootcode) / 1024)
        if arg_extract_all:
            for partname in ('bigelf', 'kernel', 'bootcode'):
                filename = '%s.part_%s.out' % (filepath, partname)
                partdata = getattr(signed_file, partname)
                logger.info("Writing %s", filename)
                with open(filename, 'wb') as f:
                    size = f.write(partdata)
                    assert size == len(partdata)

        # Only use the ELF file later
        fwdata = signed_file.bigelf

    if fwdata.startswith(b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00'):
        # Try grabbing the kernel version
        kernelver = None
        bigelf_sym = syms.find_bigelf_from_data(fwdata)
        if bigelf_sym is not None:
            kernelver = bigelf_sym['kernel_version']
        bigelf = HPBigElf(fwdata, kernelver)
        logger.info("Successfully loaded a big ELF file")

        # Find the fwfile associated with the big elf
        bigelf_sym = syms.find_bigelf_from_data(fwdata)
        if bigelf_sym is None:
            logger.error("Unable to find a reference to the big ELF in symbols")
            raise ValueError

        bigelf_sym['sections'] = []
        bigelf_sym['processes'] = []
        for i_sect, sect in enumerate(bigelf.sections):
            if sect.kind.has_data():
                assert sect.name and sect.size
                sect_data = bigelf.elf.get_section(i_sect).data()
                bigelf_sym.add_section({
                    'name': sect.name,
                    'size': sect.size,
                    'sha256': hashlib.sha256(sect_data).hexdigest(),
                })
        for idx_process in range(1, len(bigelf.proc_sections)):
            proc_sections = []
            # Temporary mapping of text sections to their hashes
            textsect_sha256 = {}
            for procsect in bigelf.proc_sections[idx_process]:
                sec_sym = {
                    'addr': procsect.addr,
                    'size': procsect.size,
                }
                if procsect.sect_id is not None:
                    sect = bigelf.sections[procsect.sect_id]
                    sec_sym['name'] = sect.name
                    if sect.kind.has_data():
                        sect_data = bigelf.elf.get_section(procsect.sect_id).data()
                        assert len(sect_data) <= procsect.size
                        sect_data += b'\0' * (procsect.size - len(sect_data))
                        sec_sym['sha256'] = hashlib.sha256(sect_data).hexdigest()
                        if sect.name.endswith('.text'):
                            textsect_sha256[sect.name[:-5]] = sec_sym['sha256']
                            sec_sym['sha256.text'] = sec_sym['sha256']

                    # If it is a .data or a .bss, add the hash of the .text section
                    basename = None
                    if sect.name.endswith('.bss'):
                        basename = sect.name[:-4]
                    elif sect.name.endswith('.data'):
                        basename = sect.name[:-5]
                    if basename:
                        try:
                            sec_sym['sha256.text'] = textsect_sha256[basename]
                        except KeyError:
                            pass
                proc_sections.append(sec_sym)
            bigelf_sym.add_process({
                'name': bigelf.proc_names[idx_process],
                'sections': proc_sections,
            })

        # Craft the output directory name
        version = '{}-{}'.format(
            bigelf_sym['ilo_version'], bigelf_sym['bigelf_version'])
        outdir = os.path.join(arg_outdir or '.', 'iLO{}'.format(version))
        if not os.path.exists(outdir):
            os.makedirs(outdir)

        # Dump the processes
        for idx_process in range(1, len(bigelf.proc_sections)):
            procname = bigelf.proc_names[idx_process]
            assert procname
            filename = os.path.join(outdir, 'proc_%s_%s.elf' % (procname, version))
            logger.info("Dumping process %r into %s", procname, filename)
            data = bigelf.get_proc_elf(
                idx_process,
                syms,
                bigelf_sym.get_proc_by_name(procname),
                arg_emptysect)
            with open(filename, 'wb') as f:
                size = f.write(data)
                assert size == len(data)
    else:
        logger.fatal("Unknown firmware format for %s", filepath)
        raise ValueError


def main(argv=None):
    symdir = symbols.DEFAULT_SYMDIR
    parser = argparse.ArgumentParser(description="Unpack iLO firmware")
    parser.add_argument('fwpaths', metavar='FIRMWARE', nargs='+', type=str,
                        help="firmware file")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-e', '--emptysect', action='store_true',
                        help="Put empty sections too")
    parser.add_argument('-E', '--extract-all', action='store_true',
                        help="Extract all intermediate files")
    parser.add_argument('-o', '--outdir', type=str,
                        help="Base output directory for process dumps")
    parser.add_argument('-s', '--symdir', type=str, default=symdir,
                        help="directory with symbols (default: %r)" % symdir)
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    syms = symbols.Symbols(args.symdir)

    for filepath in args.fwpaths:
        with open(filepath, 'rb') as f:
            fwdata = f.read()
        logger.debug("Unpacking %s (%d bytes)", filepath, len(fwdata))
        unpack_fw(filepath, fwdata, syms, args.outdir, args.emptysect, args.extract_all)

    syms.save()


if __name__ == '__main__':
    main()
