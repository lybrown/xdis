xdis — Interactive 6502 Disassembler
====================================

xdis is a browser-based, statically tracing 6502 disassembler built on the
ideas of the [dis](../dis) CLI. It keeps a live disassembly of the loaded
binary on screen: mark something as code or data, name a label, add a comment,
and the listing is re-traced and re-rendered immediately.

The generated source is XASM or MADS compatible. Every test binary
reassembles byte-for-byte identical to the original, including after edits.

Try it at **https://lybrown.github.io/xdis/**.

Running
-------

Open `index.html` in a browser. Nothing needs to be built or installed. To use
URL loading (below), serve the directory over http instead:

    python3 -m http.server 8000      # then http://localhost:8000/

Loading
-------

* **Binaries**: raw memory images (.bin/.rom/.mem, with a load address), Atari
  XEX/COM (segments, RUN and INIT vectors, corrupted/truncated files), Atari SAP
  and Commodore 64 PRG (BASIC `SYS` entry point detection). Use *Open binary…*
  or drag and drop.
* **Projects** (`.xdis.json`): directives, options, symbol sets and, optionally,
  the binary itself.
* **dis option files** (`.dop`): *Import .dop…* merges directives and options.
  Files referenced with `arg` are loaded as symbol sets, either from the files
  you selected along with them or from the built-in ones.
* **URL parameters** (http only):
  `index.html?bin=game.xex&dop=game.dop`, `?bin=cart.bin&type=raw&org=A000`
  or `?project=game.xdis.json`.

Built-in symbol sets (under *Directives*) are the dis option files from
`symbols/`: Atari hardware and OS equates, plus C64 6510, VIC, SID and CIA.

Saving
------

* **Save .asm**: the assembly exactly as shown in the listing.
* **Save project**: an `.xdis.json` file. The binary is embedded unless that
  is turned off under *Project*.
* **Export .dop**: an option file the `dis` CLI can read. xdis-only directives
  (plain labels, text, words, comments, operand overrides) are written as
  `;xdis` comment lines, which the CLI ignores but xdis restores on import.

The current session is also autosaved to the browser's local storage.

Editing
-------

Click a line or select a range (shift+arrows or drag), then:

| Key | Action |
| --- | --- |
| `C` | Code: add an entry point and trace from it |
| `D` `T` `W` | Data bytes, text, or words (stops tracing) |
| `A` `P` | Pointer table, or code pointer table whose targets are traced |
| `V` | Vector: trace through the pointer |
| `U` | Undefine: remove code/data marks in the selection |
| `N` | Name the address (double-click a label also works) |
| `;` `:` | Line comment, or block comment above the line |
| `O` | Operand override, e.g. `#<buffer` |
| `K` | Name an immediate constant (like `dis -C`) |
| `Enter` | Follow the operand (or double-click / Ctrl+click a symbol) |
| `Esc`, `Alt+←/→` | Navigate back / forward |
| `G` | Go to an address (`2000`, `3:2000`) or label |
| `Ctrl+Z` `Ctrl+Y` | Undo / redo |
| `Ctrl+S`, `Ctrl+Shift+S` | Save project / save .asm |

All of these are also available in the right-click menu and in the
*Inspect* panel. The inspector also shows callers, accessors and the
directives that apply at the cursor. The memory map strip above the listing
shows code, data, text and pointers; click it to jump.

The *Directives* panel lists every directive in dis option syntax. You can
delete them there, or type new ones (`code start=$2000`, `data tbl=$3000+FF`,
`codeptr vbiptr=3C64_3C62`).

Differences from dis
--------------------

The tracer follows the CLI's rules: it traces JMP/JSR/Bxx from entry points,
stops at RTS/RTI/BRK and illegal opcodes, handles overlaid XEX segments, and
detects the BIT-skip trick. Traced instruction sets match the CLI on every
test file. Where xdis intentionally differs:

* Data bytes are grouped (8 per line by default), and long runs of a repeated
  byte become `:N dta $XX`.
* Pointer tables and vectors are shown as `dta a(label)`.
* A plain label inside a data range overrides the range's `name+N` instead of
  being dropped as a duplicate.
* Automatic labels only get an `sN` segment prefix when an address is loaded by
  more than one segment.
* Contiguous or truncated XEX segments keep their original headers (xasm
  would otherwise merge them).
* The MADS output uses explicit segment headers and `.a` instead of `a:`.

Code layout
-----------

    index.html        page shell
    css/xdis.css      styles (light and dark)
    js/opcodes.js     6502 opcode table, including undocumented opcodes
    js/core.js        loaders, tracer, labels, listing and .asm/.dop/project I/O
                      (no DOM; also runs under node)
    js/app.js         the interactive UI
    js/symbols.js     generated from symbols/*.dop by tools/embed-symbols.py

Tests
-----

`test/roundtrip.js` disassembles a set of binaries, reassembles them with xasm
and/or MADS, and compares the result byte for byte. Where possible it also
checks that the set of traced instructions matches the Perl `dis` CLI. The
cases include edited projects and every output syntax.

    node test/roundtrip.js

The binaries are read from sibling directories (`../escm`, `../ransack`, …).
Cases whose files are missing are skipped.

`test/ui-test.html` drives the real UI, using `test/out/ransack.xex` (staged by
the round-trip test; pass `?bin=` for another file) (rename, mark data, undo/redo, code,
comments, goto, follow, constants, pointers, context menu, project and
.dop round trips). Serve the repo over http and open it, or run it headless:

    chrome --headless=new --dump-dom --virtual-time-budget=20000 \
        http://localhost:8000/test/ui-test.html

Credits
-------

xdis was written by [Claude](https://claude.com/claude-code) (Claude Opus 5.5,
Anthropic) working in Claude Code with Lyren Brown, as a port and extension of
Lyren Brown's [dis](https://github.com/lybrown/dis) CLI. The opcode table
follows the C= Hacking issue 1 table used by dis.

License
-------

MIT — see [LICENSE.md](LICENSE.md).
