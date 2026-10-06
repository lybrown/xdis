#!/usr/bin/env python3
"""Generate BBC Micro symbol sets.

    tools/harvest-bbc.py [cache-dir]       (default: .cache/bbc)

Writes symbols/bbcmos.dop (MOS entry points, vectors, zero page and the OS
and VDU variables), symbols/bbcmosbuf.dop (MOS buffers and workspace in pages
3-$D, which programs often reuse as ordinary RAM) and symbols/bbchw.dop
(Model B memory-mapped hardware), then run tools/embed-symbols.py.

Sources, downloaded into the cache directory when missing:
- py8dis by Steven Flintham (MIT license), py8dis/acorn.py: OS vectors,
  their descriptions, OS entry points and the hardware register names.
  Its hardware() function is evaluated for the Model B with stub functions,
  so its machine-specific branches are followed exactly.
- "MOS 1.20" reassembly by Toby Nelson (tobylobster.github.io/mos),
  chapter 2: names of the MOS workspace (zero page $B0-$FF, pages 2-3 and the
  other OS areas). Only direct numeric definitions are used, not aliases.
OS entry points and vectors use the official names from Acorn's Advanced User
Guide (OSWRCH, USERV, ...).
"""
import ast
import html
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / '.cache' / 'bbc'
SOURCES = {
    'acorn.py': 'https://raw.githubusercontent.com/tobylobster/py8dis/HEAD/py8dis/acorn.py',
    's2.html': 'https://tobylobster.github.io/mos/mos/S-s2.html',
}


def fetch(name):
    path = CACHE / name
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        print('downloading', SOURCES[name])
        path.write_bytes(urllib.request.urlopen(SOURCES[name]).read())
    return path.read_text(encoding='utf-8', errors='replace')


# ---------------------------------------------------------------- py8dis

def py8dis():
    src = fetch('acorn.py')
    tree = ast.parse(src)
    names = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in ('vectors', 'vector_descriptions'):
                names[target.id] = ast.literal_eval(node.value)

    # OS entry points: subroutine(0xffee, "oswrch", ...) inside mos_labels()
    entries = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == 'mos_labels':
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and getattr(call.func, 'id', '') in ('subroutine', 'optional_label')
                        and len(call.args) >= 2 and isinstance(call.args[0], ast.Constant)
                        and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str)):
                    entries.append((call.args[0].value, call.args[1].value, call.func.id))

    # hardware(): run it for the Model B, collecting optional_label() calls
    funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('hardware', 'label_tube')]
    module = ast.Module(body=funcs, type_ignores=[])
    labels = []

    class MachineType:
        MACHINE_BBC, MACHINE_BPLUS, MACHINE_MASTER, MACHINE_ELECTRON, MACHINE_6502SP = range(5)

    class machinetype:
        pass
    machinetype.MachineType = MachineType
    class Stub:
        # stands in for the rest of py8dis: any attribute or call is ignored
        def __getattr__(self, name):
            return Stub()

        def __call__(self, *a, **k):
            return Stub()

    ns = {
        'machinetype': machinetype,
        'optional_label': lambda addr, name, *a, **k: labels.append((addr, name)),
    }
    exec(compile(module, 'acorn.py', 'exec'), ns)
    for _ in range(50):
        labels.clear()
        try:
            ns['hardware'](MachineType.MACHINE_BBC)
            break
        except NameError as e:
            missing = re.search(r"name '(\w+)'", str(e)).group(1)
            ns[missing] = Stub()
    return names['vectors'], names['vector_descriptions'], entries, labels


# ---------------------------------------------------------------- MOS workspace

def mos_workspace():
    raw = fetch('s2.html')
    raw = re.sub(r'<button class="popup".*?</button>', '', raw, flags=re.S)   # "Usage of ..." popups
    text = html.unescape(re.sub(r'<[^>]+>', '', raw))
    out = []
    section = None
    started = False
    for line in text.splitlines():
        s = re.sub(r'^§\d+\.\s*', '', line.strip())     # section numbers
        head = re.match(r'^(.+?)\.\s*$', s)
        if head and (re.search(r'\(\$[0-9A-F]{3,4}-\$[0-9A-F]{2,4}\)', s) or
                     s.startswith(('Memory addresses', 'Second Processor', 'ROM Header'))):
            section = head.group(1)
            started = started or s.startswith('Memory addresses')
            continue
        if not started:
            continue
        m = re.match(r'^\.(\w+)\s*=\s*\$([0-9A-Fa-f]{2,4})\b\s*(.*)$', s)
        if not m or m.group(1).startswith('unused'):
            continue
        # comments wrap over several lines in the source; the names say enough
        out.append((section, m.group(1), int(m.group(2), 16), ''))
    return out


# ---------------------------------------------------------------- write

OS_CALLS = {  # entry point -> official name and description (Advanced User Guide)
    'osrdsc': ('OSRDSC', 'read byte from screen or paged ROM'), 'vduchr': ('VDUCHR', 'VDU character output'),
    'oseven': ('OSEVEN', 'generate an event'), 'gsinit': ('GSINIT', 'initialise string read'),
    'gsread': ('GSREAD', 'read a character from a string'), 'nvrdch': ('NVRDCH', 'non-vectored OSRDCH'),
    'nvwrch': ('NVWRCH', 'non-vectored OSWRCH'), 'osfind': ('OSFIND', 'open or close a file'),
    'osgbpb': ('OSGBPB', 'read or write a group of bytes'), 'osbput': ('OSBPUT', 'write a byte to a file'),
    'osbget': ('OSBGET', 'read a byte from a file'), 'osargs': ('OSARGS', 'read or write file attributes'),
    'osfile': ('OSFILE', 'load or save a file'), 'osrdch': ('OSRDCH', 'read a character'),
    'osasci': ('OSASCI', 'write a character, CR as CR LF'), 'osnewl': ('OSNEWL', 'write CR LF'),
    'oswrcr': ('OSWRCR', 'write CR'), 'oswrch': ('OSWRCH', 'write a character'),
    'osword': ('OSWORD', 'OS word call'), 'osbyte': ('OSBYTE', 'OS byte call'),
    'oscli': ('OSCLI', 'command line interpreter'),
}


def dop_line(kind, name, addr, rng, comment):
    spec = f'{name}=${addr:X}' + (f'+{rng:X}' if rng else '')
    return f'{kind} {spec}'.ljust(44) + (f';{comment}' if comment else '')


def main():
    vectors, descriptions, entries, hw = py8dis()
    ws = mos_workspace()

    lines = ['; BBC Micro MOS: entry points, vectors and workspace',
             '; Generated by tools/harvest-bbc.py. OS entry points and vectors use the',
             "; official names from Acorn's Advanced User Guide; descriptions from py8dis",
             '; (Steven Flintham, MIT license); workspace names from the MOS 1.20',
             '; reassembly by Toby Nelson (tobylobster.github.io/mos).', '',
             ';       OS ENTRY POINTS', '']
    seen = set()
    for addr, name, kind in sorted(entries):
        if name not in OS_CALLS:
            continue
        off, desc = OS_CALLS[name]
        lines.append(dop_line('code', off, addr, 0, desc))
        seen.add(addr)
    lines += ['', ';       VECTORS', '']
    for addr in sorted(vectors):
        lines.append(dop_line('vector', vectors[addr].upper(), addr, 1, descriptions.get(addr, '')))
        seen.update((addr, addr + 1))
    buf = ['; BBC Micro MOS buffers and workspace ($0380-$0E00): cassette filing system,',
           '; keyboard buffer, Tube service points, sound, buffers, soft keys and',
           '; characters, NMI area. Programs often reuse this memory, so enable this set',
           '; only for code that really uses the MOS there.',
           '; Generated by tools/harvest-bbc.py; names from the MOS 1.20 reassembly by',
           '; Toby Nelson (tobylobster.github.io/mos).']
    sections = {}
    for sec, name, addr, comment in ws:
        if addr in seen or 0x0200 <= addr <= 0x0235:
            continue
        target = buf if 0x0380 <= addr <= 0x0E00 else lines
        if sections.get(id(target)) != sec:
            sections[id(target)] = sec
            target += ['', f';       {sec.upper()}', '']
        target.append(dop_line('data', name, addr, 0, comment))
        seen.add(addr)
    for fname, body in (('bbcmos.dop', lines), ('bbcmosbuf.dop', buf)):
        (ROOT / 'symbols' / fname).write_text('\n'.join(body) + '\n')
        print(f'wrote symbols/{fname}:', sum(1 for l in body if l and not l.startswith(';')), 'entries')

    lines = ['; BBC Micro Model B memory-mapped hardware (FRED, JIM, SHEILA)',
             '; Generated by tools/harvest-bbc.py from py8dis (Steven Flintham, MIT',
             '; license), py8dis/acorn.py hardware() for the Model B.', '']
    hw_seen = set()
    for addr, name in sorted(hw, key=lambda x: x[0]):
        # FRED peripherals are optional add-ons; keep the page names and SHEILA
        if 0xFC00 < addr < 0xFE00 or addr in hw_seen:
            continue
        hw_seen.add(addr)
        lines.append(dop_line('data', name, addr, 0, ''))
    if 0xFD00 not in hw_seen:
        lines.insert(4, dop_line('data', 'jim', 0xFD00, 0xFF, 'paged RAM (1 MHz bus)'))
    (ROOT / 'symbols' / 'bbchw.dop').write_text('\n'.join(lines) + '\n')
    print('wrote symbols/bbchw.dop:', len(hw_seen), 'entries')


if __name__ == '__main__':
    main()
