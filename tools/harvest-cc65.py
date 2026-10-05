#!/usr/bin/env python3
"""Generate extra Atari symbol sets from cc65's asminc/atari.inc.

    tools/harvest-cc65.py [path/to/cc65]      (default: ../../cc65 from here)

Writes symbols/atarixl.dop, atarifp.dop, basic.dop and dos.dop, then run
tools/embed-symbols.py. Only address equates are used; constants (command
codes, status codes, key codes, ATASCII) are skipped. Entries already labeled
by symbols/sys.dop or hardware.dop are left out, except XL/XE relocations,
which atarixl.dop must be able to override.

cc65's atari.inc is by Freddy Offenga, Christian Groessler and Christian
Krueger, under the zlib license.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CC65 = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT.parent / 'cc65'
SRC = CC65 / 'asminc' / 'atari.inc'

# section heading (prefix match) -> symbol set; None = constants, skipped
SECTIONS = [
    ('Page Zero Address Equates', 'os'),
    ('Floating Point Package Page Zero', 'fp'),
    ('Page Two Address Equates', 'os'),
    ('Page Three Address Equates', 'os'),
    ('Page Four/Five Address Equates', 'os'),
    ('SpartaDOS-X Definitions', 'dos'),
    ('PBI Address Equates', 'os'),
    ('Floating Point Package Address Equates', 'fp'),
    ('Device Handler Vector Table', 'os'),
    ('Some misc. stuff', 'basic'),     # SIN/COS/ATAN/SQR in the BASIC cartridge
    ('6502', 'os'),
    ('BASIC', 'basic'),
]
FP_PAGE5 = {'LBPR1', 'LBPR2', 'LBUFF', 'PLYARG', 'FPSCR', 'FPSCR1'}
CODE_SECTIONS = {'Floating Point Package Address Equates', 'Some misc. stuff'}


def dop_labels(path):
    """name -> addr, and labeled addresses, from a .dop file."""
    names, addrs = {}, set()
    for line in path.read_text().splitlines():
        m = re.match(r'^\s*\w+\s+(\w+)=\$?([0-9A-Fa-f]+)(?:\+([0-9A-Fa-f]+))?', line.split(';')[0])
        if not m:
            continue
        a, r = int(m.group(2), 16), int(m.group(3) or '0', 16)
        names.setdefault(m.group(1), a)
        addrs.update(range(a, a + r + 1))
    return names, addrs


def parse():
    """Yield (section, name, addr, comment, tag) for literal address equates."""
    section = None
    pending_heading = False
    skip = 0          # inside the __ATARIXL__ branch of an .ifdef
    lines = SRC.read_text(errors='replace').splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(';---'):
            pending_heading = True
            continue
        if pending_heading or s.startswith(';'):
            # a heading, either boxed in ;--- lines or a bare known heading
            boxed, pending_heading = pending_heading, False
            heading = s.lstrip('; ').strip()
            known = next((sec for pre, sec in SECTIONS if heading.startswith(pre)), 'unknown')
            if s.startswith(';') and (boxed or known != 'unknown'):
                section = None if known == 'unknown' else known
                section_name = heading
                continue
        if s.startswith('.ifdef __ATARIXL__'):
            skip = 1
            continue
        if s.startswith('.else') and skip:
            skip = 0
            continue
        if s.startswith('.endif'):
            skip = 0
            continue
        if skip or section is None:
            continue
        # sub-headings inside "Page Four/Five" etc. don't change the set
        m = re.match(r'^([A-Za-z_]\w*)\s*=\s*\$([0-9A-Fa-f]{1,4})\b\s*(?:;(.*))?$', s)
        if not m or m.group(1).endswith('_org'):
            continue
        comment = (m.group(3) or '').strip()
        tag = re.search(r'##(\w+)##', comment)
        comment = re.sub(r'##\w+##\s*', '', comment)
        if section_name.startswith('Some misc. stuff') and int(m.group(2), 16) < 0xA000:
            continue          # ASCII and other constants next to the BASIC routines
        yield section, section_name, m.group(1), int(m.group(2), 16), comment, tag.group(1) if tag else None


def directive(sec_name, name, addr, comment):
    size = re.match(r'(\d+)-byte', comment)
    n = int(size.group(1)) if size else 1
    if (any(sec_name.startswith(c) for c in CODE_SECTIONS) or 'entry point' in comment.lower() or
            addr >= 0xD800 and 'vector table' not in comment):
        kind = 'code'
    elif 'vector' in comment.lower() and n == 2:
        kind = 'vector'
    elif sec_name.startswith('Device Handler Vector Table'):
        kind = 'vector'
    else:
        kind = 'data'
    spec = f'{name}=${addr:X}' + (f'+{n - 1:X}' if n > 1 and kind != 'code' else '')
    return f'{kind} {spec}'.ljust(36) + (f';{comment.upper()}' if comment else '')


def main():
    sys_names, sys_addrs = dop_labels(ROOT / 'symbols' / 'sys.dop')
    hw_names, hw_addrs = dop_labels(ROOT / 'symbols' / 'hardware.dop')
    known_names = {**hw_names, **sys_names}
    known_addrs = sys_addrs | hw_addrs
    sets = {'xl': [], 'fp': [], 'basic': [], 'dos': []}
    skipped = {'known': 0, 'untagged-os': []}
    for section, sec_name, name, addr, comment, tag in parse():
        if tag == 'old':
            continue
        xl = tag in ('1200xl', 'rev2')
        target = section
        if name in FP_PAGE5:
            target = 'fp'
        if name == 'DOS':
            target = 'dos'
        if target == 'os':
            # XL/XE additions and relocations, plus the few OS equates that
            # sys.dop lacks altogether
            if not xl and (name in known_names or addr in known_addrs):
                skipped['known'] += 1
                continue
            if not xl:
                skipped['untagged-os'].append(f'{name}=${addr:04X}')
            target = 'xl'
        elif known_names.get(name) == addr or (addr in known_addrs and name not in known_names):
            skipped['known'] += 1
            continue
        sets[target].append((addr, directive(sec_name, name, addr, comment)))
    titles = {
        'xl': ('atarixl.dop', 'Atari XL/XE OS: locations added or moved by the 1200XL and XL/XE OS, plus\n'
               '; a few OS equates missing from sys.dop. Takes priority over sys.dop.'),
        'fp': ('atarifp.dop', 'Atari floating point package: page zero registers, buffers and ROM routines'),
        'basic': ('basic.dop', 'Atari BASIC: page zero pointers and math routines in the cartridge'),
        'dos': ('dos.dop', 'DOS and SpartaDOS X'),
    }
    for k, entries in sets.items():
        fname, title = titles[k]
        body = '\n'.join(d for _, d in sorted(entries, key=lambda e: e[0]))
        (ROOT / 'symbols' / fname).write_text(
            f'; {title}\n'
            '; Generated by tools/harvest-cc65.py from cc65 asminc/atari.inc\n'
            '; (Freddy Offenga, Christian Groessler, Christian Krueger; zlib license)\n\n'
            f'{body}\n')
        print(f'wrote symbols/{fname}: {len(entries)} entries')
    print('skipped (already in sys/hardware):', skipped['known'])


if __name__ == '__main__':
    main()
