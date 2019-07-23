#!/usr/bin/env python3
"""List firmware versions from their analysis"""
import argparse
import logging
import os.path
import sys

sys.path.insert(0, os.path.dirname(__file__))
import symbols


logger = logging.getLogger(__name__)


def list_fw_versions(syms, oneline, verbose):
    all_fws = {}

    # Mapping (soname, hash) => minimal version seen
    sohash_min_fwver = {}

    for fwfile in syms.fwfiles.values():
        fwintver = tuple([fwfile['ilo_version']] + [int(v) for v in fwfile['bigelf_version'].split('.')])
        assert len(fwintver) == 4
        if fwintver in all_fws:
            logger.error("Duplicate firmware %r found!", fwintver)
            continue

        elfver = '{}-{}'.format(fwfile['ilo_version'], fwfile['bigelf_version'])

        # Find addresses and hashes for shared libraries, to study differencies
        so_texthashaddrsize = {}
        for proc in fwfile['processes']:
            for sect in proc['sections']:
                sectname = sect.get('name')
                if not sectname or not sectname.endswith('.so.text'):
                    continue
                if not sectname.startswith('.'):
                    logger.error(
                        "Unknown section name %s/%s/%s",
                        elfver, proc['name'], sectname)
                    continue
                soname = sectname[1:-5]
                sohash = sect['sha256.text']
                sodata = (sohash, sect['addr'], sect['size'])

                if soname not in so_texthashaddrsize:
                    so_texthashaddrsize[soname] = sodata
                elif so_texthashaddrsize[soname] != sodata:
                    logger.error(
                        "Inconsistent data for section %s/%s/%s",
                        elfver, proc['name'], sectname)
                    continue

                if (soname, sohash) not in sohash_min_fwver or fwintver < sohash_min_fwver[soname, sohash]:
                    sohash_min_fwver[soname, sohash] = fwintver

        all_fws[fwintver] = {
            'elfver': elfver,
            'kernver': '{}-{}'.format(fwfile['ilo_version'], fwfile['kernel_version']),
            'elfdate': fwfile['bigelf_date'],
            'kerndate': fwfile['kernel_date'],
            'so': so_texthashaddrsize,
        }

    for fwintver, fwdata in sorted(all_fws.items()):
        firstline = "{:9} ({:10}) krnl:{:9} ({:10})".format(
            fwdata['elfver'], fwdata['elfdate'],
            fwdata['kernver'], fwdata['kerndate'])
        if oneline:
            print("{}: {}".format(
                firstline,
                ' '.join(
                    '{0} {1[0]}-{1[1]}.{1[2]}.{1[3]}'.format(
                        soname,
                        sohash_min_fwver[soname, sodata[0]])
                    for soname, sodata in sorted(fwdata['so'].items()))))
        elif verbose:
            print("{}:".format(firstline))
            for soname, sodata in sorted(fwdata['so'].items()):
                sohash, soaddr, sosize = sodata
                minver = '{0[0]}-{0[1]}.{0[2]}.{0[3]}'.format(sohash_min_fwver[soname, sohash])
                print("    {} {:#x}/{:#x} since {}".format(
                    soname, soaddr, sosize, minver))
            print("")
        else:
            print(firstline)


def main(argv=None):
    symdir = symbols.DEFAULT_SYMDIR
    parser = argparse.ArgumentParser(description="List firmware versions")
    parser.add_argument('-d', '--debug', action='store_true',
                        help="show debug messages")
    parser.add_argument('-o', '--oneline', action='store_true',
                        help="show one line per firmware")
    parser.add_argument('-s', '--symdir', type=str, default=symdir,
                        help="directory with symbols (default: %r)" % symdir)
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="increase verbosity")
    args = parser.parse_args(argv)

    logging.basicConfig(format='[%(levelname)-5s] %(message)s',
                        level=logging.DEBUG if args.debug else logging.INFO)

    syms = symbols.Symbols(args.symdir)
    list_fw_versions(syms, args.oneline, args.verbose)


if __name__ == '__main__':
    main()
