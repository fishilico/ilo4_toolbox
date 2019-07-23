#!/usr/bin/env python
"""Add information about strings in symbol table"""
import argparse
import hashlib
import logging
import os.path
import re
import sys

import elftools.elf.elffile  # pyelftools package

sys.path.insert(0, os.path.dirname(__file__))
import symbols


logger = logging.getLogger(__name__)


STRING_CHARACTERS = frozenset([9, 10, 13, 27] + list(range(32, 127)))


def strings_from_elf(syms, filepath):
    with open(filepath, 'rb') as fd:
        elf = elftools.elf.elffile.ELFFile(fd)
        htext_from_name = {}
        for sect in elf.iter_sections():
            if sect.header.sh_type == 'SHT_PROGBITS':
                pass
            elif sect.header.sh_type in ('SHT_NULL', 'SHT_NOBITS', 'SHT_SYMTAB', 'SHT_STRTAB'):
                continue
            else:
                logger.warning("Unknown ELF section type %s", sect.header.sh_type)
                continue

            sect_data = sect.data()
            h = hashlib.sha256(sect_data).hexdigest()
            addr_start = sect.header.sh_addr
            addr_end = addr_start + len(sect_data)

            if sect.name.endswith('.text'):
                htext = h
                htext_from_name[sect.name[:-5]] = h
            elif sect.name.endswith('.data'):
                htext = htext_from_name.get(sect.name[:-5])
                if not htext:
                    logger.error("Unable to find the .text associated with %s", sect.name)
                    continue
            else:
                logger.error("Unknown section %s!", sect.name)
                continue

            # Find the symbols matching the section
            symsect = syms.elfsects.get(
                symbols.ElfSectionSymbols.build_key(sect.name, addr_start, htext))
            if symsect is None or not symsect.get('symbols'):
                logger.info("Skipping section %r with no symbol", sect.name)
                continue

            # Sanity checks
            assert symsect['sha256.text'] == htext
            assert symsect['name'] == sect.name
            assert symsect['baseaddr'] == sect.header.sh_addr

            logger.info("Processing %s:%s", filepath, sect.name)

            # Collect symbols by address
            all_symbols = []
            for sym in symsect['symbols'].values():
                if addr_start <= sym['addr'] < addr_end:
                    all_symbols.append((sym['addr'], sym))
            all_symbols.sort()
            for i_sym, addr_and_sym in enumerate(all_symbols):
                addr, sym = addr_and_sym
                next_addr = all_symbols[i_sym + 1][0] if i_sym + 1 < len(all_symbols) else addr_end

                # Only consider symbols which name begins with "a"
                if not sym['name'].startswith('a'):
                    continue

                sym_data = sect_data[addr - addr_start:next_addr - addr_start]

                # Find a null-terminated string at the beginning of sym_data
                if not sym_data or b'\0' not in sym_data or sym_data[0] == 0:
                    continue
                sym_data = sym_data[:sym_data.index(b'\0')]
                # ASCII strings with special characters
                if any(c not in STRING_CHARACTERS for c in sym_data):
                    continue

                # Ok, it is a string. Compute the symbol name
                str_data = sym_data.decode('ascii')
                slugified = str_data
                slugified = re.sub(r'\x1b', '_ESC_', slugified)
                slugified = re.sub(r'[+-]', '_', slugified)
                slugified = re.sub(r'[^a-zA-Z0-9_]', ' ', slugified)
                sym['name'] = 'a_' + '_'.join(slugified.split())[:50]
                sym['size'] = len(sym_data) + 1
                sym['type'] = 'str'
                sym['str_content'] = str_data
                symsect.add_sym(sym)


def main(argv=None):
    symdir = symbols.DEFAULT_SYMDIR
    parser = argparse.ArgumentParser(description="Add string information to symbols")
    parser.add_argument('procelf', metavar='PROCELF', nargs='+', type=str,
                        help="process ELF file")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-s', '--symdir', type=str, default=symdir,
                        help="directory with symbols (default: %r)" % symdir)
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    syms = symbols.Symbols(args.symdir)

    for filepath in args.procelf:
        logger.debug("Analyzing %r", filepath)
        strings_from_elf(syms, filepath)

    syms.save()


if __name__ == '__main__':
    main()
