#!/usr/bin/env python3
"""Manage iLO firmware symbols"""
import argparse
import collections
import hashlib
import json
import logging
import os
import os.path
import re
import sys


logger = logging.getLogger(__name__)

# Default symbol directory
DEFAULT_SYMDIR = os.path.join(os.path.dirname(__file__), 'fw_symbols')


class SerializableDict(collections.OrderedDict):
    _SIMPLE_KEYS = ()
    _COMPLEX_KEYS = ()
    _DICT_KEYS = ()


def obj_from_dict(cls, data):
    unknown_keys = set(data.keys()) - set(cls._SIMPLE_KEYS)
    for (k, c) in cls._COMPLEX_KEYS:
        if k in unknown_keys:
            unknown_keys.remove(k)
    for (k, c) in cls._DICT_KEYS:
        if k in unknown_keys:
            unknown_keys.remove(k)
    if unknown_keys:
        raise ValueError("Unknown keys: %s" % ', '.join(unknown_keys))
    obj = cls()
    for k in cls._SIMPLE_KEYS:
        if k in data:
            obj[k] = data[k]
    for (k, c) in cls._COMPLEX_KEYS:
        if k in data:
            obj[k] = []
            for d in data[k]:
                obj[k].append(obj_from_dict(c, d))
    for (k, c) in cls._DICT_KEYS:
        if k in data:
            obj[k] = collections.OrderedDict()
            for dk, dv in data[k].items():
                obj[k][dk] = obj_from_dict(c, dv)
    return obj


class FirmwareSection(SerializableDict):
    """An ELF section"""
    _SIMPLE_KEYS = (
        'name',
        'size',
        'sha256',
    )

class FirmwareProcSection(SerializableDict):
    """An ELF section of a process"""
    _SIMPLE_KEYS = (
        'name',
        'addr',
        'size',
        'sha256',
        'sha256.text',  # sha256 of the associated .text section
    )

class FirmwareProcess(SerializableDict):
    """A process"""
    _SIMPLE_KEYS = (
        'name',
    )
    _COMPLEX_KEYS = (
        ('sections', FirmwareProcSection),
    )

    def get_sect_by_addr(self, addr):
        """Get a section which covers the given address"""
        for i, sect in enumerate(self['sections']):
            if sect['addr'] <= addr < sect['addr'] + sect['size']:
                return sect if sect.get('sha256.text') else None


class FirmwareFile(SerializableDict):
    """Information about a firmware file"""
    _SIMPLE_KEYS = (
        'ilo_version',
        'hpimage_unknown_number_0x101',
        'hpimage_unknown_16bytes',
        'hpimage_unknown_number_1',
        'hpimage_unknown_zero_bytes',
        'hpimage_unknown_number',
        'hpimage_version',
        'hpimage_ilo_version',
        'hpimage_unknown_number_1_bis',
        'hpimage_unknown_16bytes_bis',
        'hpimage_unknown_number_0',
        'signkey_bitsize',
        'signkey_n',
        'signkey_e',
        'bigelf_version',
        'bigelf_version_string',
        'bigelf_date',
        'bigelf_size',
        'bigelf_sha256',
        'kernel_version',
        'kernel_version_string',
        'kernel_date',
        'kernel_size',
        'kernel_sha256',
        'bootcode_version',
        'bootcode_version_string',
        'bootcode_date',
        'bootcode_size',
        'bootcode_sha256',
    )
    _COMPLEX_KEYS = (
        ('sections', FirmwareSection),
        ('processes', FirmwareProcess),
    )

    @property
    def key(self):
        assert self['ilo_version']
        assert self['bigelf_version']
        return '%d-%s' % (self['ilo_version'], self['bigelf_version'])

    def add_section(self, data):
        self['sections'].append(obj_from_dict(FirmwareSection, data))

    def add_process(self, data):
        self['processes'].append(obj_from_dict(FirmwareProcess, data))

    def get_proc_by_name(self, procname):
        """Find a process structure by its name"""
        for p in self['processes']:
            if p['name'] == procname:
                return p
        raise KeyError(procname)


class ElfSymbol(SerializableDict):
    """A symbol suitable for an ELF file"""
    _SIMPLE_KEYS = (
        'name',
        'addr',
        'size',
        'type',  # func, int, str...
        'str_content',
    )

    @property
    def key(self):
        return hex(self['addr'])

    def get_elf_sym_info(self):
        """Return the st_info field for ELF symbol table:

        st_info = (bind << 4) | type

        bind:
            STB_LOCAL = 0
            STB_GLOBAL = 1
            STB_WEAK = 2

        type:
            STT_NOTYPE = 0
            STT_OBJECT = 1
            STT_FUNC = 2
        """
        symtype = self.get('type')
        if not symtype:
            return 0
        if symtype == 'str':
            return 1
        if symtype == 'func':
            return 2
        return 0


class ElfSectionSymbols(SerializableDict):
    """Information about symbols of a section"""
    _SIMPLE_KEYS = (
        'name',
        'sha256',
        'sha256.text',
        'baseaddr',
        'size',
    )
    _DICT_KEYS = (
        ('symbols', ElfSymbol),
    )

    def __init__(self):
        super(ElfSectionSymbols, self).__init__()
        self.is_dirty = False

    @classmethod
    def build_key(cls, name, addr, shatext):
        return '%s_%#x_%s' % (name, addr, shatext)

    @property
    def key(self):
        return self.build_key(self['name'], self['baseaddr'], self['sha256.text'])

    def add_sym(self, data):
        if self.get('symbols') is None:
            self['symbols'] = collections.OrderedDict()
        sym = obj_from_dict(ElfSymbol, data)
        self['symbols'][sym.key] = sym
        self.is_dirty = True

    def sort_syms(self):
        self['symbols'] = collections.OrderedDict(sorted(
            ((s.key, s) for s in self['symbols'].values()),
            key=lambda t: (t[1]['addr'], t[1]['name'])))
        self.is_dirty = False


class Symbols(object):
    def __init__(self, symdir):
        """Load files from a symbol directory"""
        self.symdir = symdir
        self.fwfiles = {}
        self.elfsects = {}

        for filename in os.listdir(symdir):
            logger.debug("Loading %s", os.path.join(symdir, filename))
            with open(os.path.join(symdir, filename), 'r') as fd:
                json_data = json.load(fd)
                if 'fwfile' in json_data:
                    new_fwfile = obj_from_dict(FirmwareFile, json_data['fwfile'])
                    assert new_fwfile.key not in self.fwfiles
                    self.fwfiles[new_fwfile.key] = new_fwfile
                if 'elfsect' in json_data:
                    new_elfsect = obj_from_dict(ElfSectionSymbols, json_data['elfsect'])
                    new_elfsect.sort_syms()
                    assert new_elfsect.key not in self.elfsects
                    self.elfsects[new_elfsect.key] = new_elfsect

    def add_fwfile(self, data):
        fwfile = obj_from_dict(FirmwareFile, data)
        self.fwfiles[fwfile.key] = fwfile

    def save(self):
        """Save files into the symbol directory"""
        if not self.check_hash_unicity():
            raise ValueError("Symbol hashes structure is not sane. Not saving anything!")

        for fwfile in self.fwfiles.values():
            filepath = os.path.join(self.symdir, 'fwfile_%s.json' % fwfile.key)
            logger.debug("Writing %s" % filepath)
            with open(filepath, 'w') as fd:
                json.dump({'fwfile': fwfile}, fd, indent=2)
                fd.write('\n')

        for elfsect in self.elfsects.values():
            if elfsect.is_dirty:
                elfsect.sort_syms()
            filepath = os.path.join(self.symdir, 'elfsect%s.json' % (elfsect.key))
            logger.debug("Writing %s" % filepath)
            with open(filepath, 'w') as fd:
                json.dump({'elfsect': elfsect}, fd, indent=2)
                fd.write('\n')

    def check_hash_unicity(self):
        """Check that each hash is unique for its kind"""
        component_hashes = {}
        section_hashes = {}
        procsect_hashes = {}
        elfsect_hashes = {}
        result = True
        for fwfile in self.fwfiles.values():
            for k in ('bigelf_sha256', 'kernel_sha256'):
                h = fwfile[k]
                value = (fwfile[k.replace('_sha256', '_version')], k)
                if h not in component_hashes:
                    component_hashes[h] = value
                elif component_hashes[h] != value:
                    logger.error(
                        "Duplicated component hash %s for %r and %r",
                        h, component_hashes[h], value)
                    result = False

            for sect in fwfile['sections']:
                h = sect['sha256']
                name = sect['name']
                if h not in section_hashes:
                    section_hashes[h] = name
                elif section_hashes[h] != name:
                    logger.error(
                        "Duplicated section hash %s for %r and %r",
                        h, section_hashes[h], name)
                    result = False

            for proc in fwfile['processes']:
                for sect in proc['sections']:
                    if 'sha256' in sect:
                        h = sect['sha256']
                        value = (sect['name'], sect['addr'], sect['size'])
                        if h not in section_hashes:
                            procsect_hashes[h] = value
                        elif procsect_hashes[h] != value:
                            logger.error(
                                "Duplicated process section hash %s for %r and %r",
                                h, procsect_hashes[h], value)
                            result = False

            # Also check the unicity of process names, per fwfile
            proc_names = set()
            for proc in fwfile['processes']:
                stripped_name = proc['name']
                if stripped_name.endswith('.elf'):
                    stripped_name = stripped_name[:-4]
                if stripped_name in proc_names:
                    logger.error("Duplicated process name %r", proc['name'])
                    result = False
                proc_names.add(stripped_name)

        for key, elfsect in self.elfsects.items():
            if key != elfsect.key:
                logger.error("Unexpected key for elfsect object: %r != %r", key, elfsect.key)
                result = False
            if not elfsect['name'].endswith(('.text', '.bss', '.data')):
                logger.error("Unknown section name kind %r", elfsect['name'])
                result = False
                continue
            h = elfsect['sha256.text']
            value = elfsect['name'].rsplit('.', 1)[0]
            if h not in elfsect_hashes:
                elfsect_hashes[h] = value
            elif elfsect_hashes[h] != value:
                logger.error(
                    "Duplicated ELF section .text-hash %s for %r and %r",
                    h, elfsect_hashes[h], value)
                result = False

            # Also check symbol address ranges
            for k, sym in elfsect.get('symbols', {}).items():
                if k != sym.key:
                    logger.error("Unexpected key for symbol: %r != %r", key, sym.key)
                    result = False
                sym_addr = sym['addr']
                sym_size = sym.get('size', 0)
                sym_addr_end = sym_addr + (sym_size if sym_size else 1)
                if not elfsect['baseaddr'] <= sym_addr < sym_addr_end <= elfsect['baseaddr'] + elfsect['size']:
                    logger.error(
                        "Symbol %s/%s not in range %#x <= [%#x..%#x] <= %#x",
                        elfsect['name'],
                        sym['name'],
                        elfsect['baseaddr'],
                        sym_addr,
                        sym_addr_end,
                        elfsect['baseaddr'] + elfsect['size'])
                    result = False

        return result

    def find_bigelf_from_data(self, data):
        """Find a bigelf reference from its data, or return None"""
        size = len(data)
        sha = hashlib.sha256(data).hexdigest()
        for fwfile in self.fwfiles.values():
            if fwfile.get('bigelf_size') == size and fwfile.get('bigelf_sha256') == sha:
                return fwfile
        return

    def get_elfsect_by_fwsect(self, fwsect, create_if_nonexisting=False):
        """Get or build a new ElfSectionSymbols table from a FirmwareProcSection entry"""
        result = self.elfsects.get('%s_%#x_%s' % (fwsect['name'], fwsect['addr'], fwsect['sha256.text']))
        if result is not None:
            # Sanity checks
            assert result['name'] == fwsect['name']
            assert result['baseaddr'] == fwsect['addr']
            assert result['sha256.text'] == fwsect['sha256.text']
            if 'size' not in result:
                result['size'] = fwsect['size']
            else:
                assert result['size'] == fwsect['size']
            return result

        if not create_if_nonexisting:
            raise KeyError

        # Build a new section
        result = obj_from_dict(ElfSectionSymbols, {
            'name': fwsect['name'],
            'sha256.text': fwsect['sha256.text'],
            'baseaddr': fwsect['addr'],
            'size': fwsect['size'],
        })
        self.elfsects[result.key] = result
        return result

    def get_elfsect_from_proc_and_addr(self, sym_fwproc, addr):
        base_sect = sym_fwproc.get_sect_by_addr(addr)
        if base_sect is not None:
            try:
                return self.get_elfsect_by_fwsect(base_sect)
            except KeyError:
                pass


def set_symbol(syms, process, addr, symname):
    # Find the relevant section in the process
    fwsect = process.get_sect_by_addr(addr)
    if fwsect is None:
        return False

    logger.debug("Adding %s/%#x: %s", fwsect['name'], addr, symname)

    # Find the relevant symbol tables and add the symbol
    elfsect = syms.get_elfsect_by_fwsect(fwsect, create_if_nonexisting=True)
    elfsect.add_sym({
        'name': symname,
        'addr': addr,
    })
    return True


def add_map_file(syms, process, mapfilepath):
    """Add a .map file to symbols"""
    with open(mapfilepath, 'r') as fd:
        for line in fd:
            m = re.match(r'^\s*[0-9a-fA-F]{4}:([0-9a-fA-F]+)\s+(\S+)\s*$', line)
            if m is None:
                continue
            straddr, symname = m.groups()
            set_symbol(syms, process, int(straddr, 16), symname)


def main(argv=None):
    symdir = DEFAULT_SYMDIR
    parser = argparse.ArgumentParser(description="Manage iLO firmware symbols")
    parser.add_argument('action', metavar='ACTION',
                        help="action to perform (check, regen, addmap, set)")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-p', '--process', type=str,
                        help="iLO firmware process to operate on")
    parser.add_argument('-s', '--symdir', type=str, default=symdir,
                        help="directory with symbols (default: %r)" % symdir)
    parser.add_argument('-v', '--version', type=str,
                        help="iLO firmware version to operate on")
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    syms = Symbols(args.symdir)

    # Parse version like "4-2.50"
    arg_fwfile = None
    arg_fwprocess = None
    if args.version:
        if '-' not in args.version:
            parser.error("Missing '-' in given fw verion, to specify the iLO number")
        ilover, fwver = args.version.split('-', 1)
        if '.' not in fwver:
            # Try "250" for "2.50"
            if len(fwver) <= 2 or not all('0' <= c <= '9' for c in fwver):
                parser.error("Unable to parse fw verion")
            fwver = '%s.%s' % (fwver[0], fwver[1:])
        searching_key = '%s-%s' % (ilover, fwver)
        for fwkey, fwfile in syms.fwfiles.items():
            if fwkey == searching_key:
                arg_fwfile = fwfile
                break
            elif fwkey.startswith(searching_key) and fwkey[len(searching_key)] == '.':
                arg_fwfile = fwfile
                break
        if arg_fwfile is None:
            parser.error("Unable to find firmware %r" % searching_key)

    if arg_fwfile is not None:
        logger.debug("Selecting firmware %s", arg_fwfile.key)
        if args.process:
            searching_name = args.process.lower()
            if searching_name.endswith('.elf'):
                searching_name = searching_name[:-4]
            for process in arg_fwfile['processes']:
                curname = process['name'].lower()
                if curname.endswith('.elf'):
                    curname = curname[:-4]
                if searching_name == curname:
                    logger.debug("Selecting process %s", process['name'])
                    arg_fwprocess = process
                    break
            if arg_fwprocess is None:
                parser.error("Unable to find process %r" % searching_name)

    if args.action == 'check':
        return 0 if syms.check_hash_unicity() else 1
    elif args.action == 'regen':
        syms.save()
    elif args.action == 'addmap':
        # Add a map file to known symbols
        if len(args.args) != 1:
            parser.error("addmap expects a file argument")
        if arg_fwfile is None:
            parser.error("addmap needs a firmware version (-v) and process (-p)")
        if arg_fwprocess is None:
            parser.error("addmap needs a firmware process (-p) in version %s" % arg_fwfile.key)
        add_map_file(syms, arg_fwprocess, args.args[0])
        syms.save()
    elif args.action == 'set':
        # Add a single symbol by address
        if len(args.args) != 2:
            parser.error("set expects address and name arguments")
        addrtext, symname = args.args
        if arg_fwfile is None:
            parser.error("set needs a firmware version (-v) and process (-p)")
        if arg_fwprocess is None:
            parser.error("set needs a firmware process (-p) in version %s" % arg_fwfile.key)
        if not addrtext.startswith(('0x', '0X')):
            addrtext, symname = symname, addrtext
            if not addrtext.startswith(('0x', '0X')):
                parser.error("invalid hexadecimal address")
        addr = int(addrtext[2:], 16)
        if not set_symbol(syms, arg_fwprocess, addr, symname):
            logger.error("Section not found for address %#x", addr)
        else:
            syms.save()
    else:
        parser.error("Unknown action %r" % args.action)


if __name__ == '__main__':
    sys.exit(main())
