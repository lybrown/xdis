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
`symbols/`:

| Set | Contents |
| --- | --- |
| `hardware.dop`, `sys.dop` | Atari hardware registers and 400/800 OS equates, including the cartridge header (`CARTCS`, `CART`, `CARTFG`, `CARTAD`) |
| `atarixl.dop` | XL/XE OS: locations added or moved by the 1200XL and XL/XE OS |
| `atarifp.dop` | Floating point package registers, buffers and ROM routines |
| `basic.dop` | Atari BASIC page zero and math routines |
| `dos.dop` | DOS and SpartaDOS X |
| `6510.dop`, `vic.dop`, `sid.dop`, `cia.dop` | Commodore 64 |

When two sets name the same thing, the earlier one wins. Your own imported
files come first, then `atarixl.dop` (so XL/XE addresses replace 400/800 ones),
then the rest. Built-in sets always use the current text, even in older
projects. `atarixl.dop`, `atarifp.dop`, `basic.dop` and `dos.dop` are generated
from cc65's `asminc/atari.inc` by `tools/harvest-cc65.py`. Run
`tools/embed-symbols.py` after changing anything in `symbols/`.

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
| `R` | Relocate: the bytes are loaded here but run elsewhere (`org r:`) |
| `>` `<` | The immediate (or picked byte) is the high / low byte of an address |
| `Enter` | Follow the operand (or double-click / Ctrl+click a symbol) |
| click | An address in an `Access:` or `Callers:` comment jumps to that instruction |
| `Esc`, `Alt+←/→` | Navigate back / forward |
| `G` | Go to an address (`2000`, `3:2000`) or label |
| `Ctrl+Z` `Ctrl+Y` | Undo / redo |
| `Ctrl+S`, `Ctrl+Shift+S` | Save project / save .asm |

All of these are also available in the right-click menu and in the
*Inspect* panel. The inspector also shows callers, accessors and the
directives that apply at the cursor. The memory map strip above the listing
shows code, data, text and pointers; click it to jump.

Directives that are not needed to get the current split between code and data
are tagged *no effect*, *name only* (a plain label would do) or *format only*
(it only changes how bytes are shown). All tagged directives can be removed
**together** without changing what gets traced; the check is greedy, so when
two directives make each other redundant only one of them is tagged. Tick
*Only show directives not needed for tracing* to review them.

Relocated code
--------------

Loaders often copy code somewhere else before running it, e.g. to zero page or
to RAM under a ROM. Select the block and press `R` (or use `relocate $5600+1FFF
$A000` in the Directives panel) to disassemble it at its run address. Labels,
branches, callers and the memory map then use the run address. The output
places the bytes where they are loaded, using `org r:$A000` for xasm or
`org $A000,*` for MADS, followed by a plain `org` back to the load address.

When a relocation is added, directives on its load addresses move to the
matching run addresses. Removing it moves them back. Go to (`G`) accepts
either a run address or a load address.

xdis also looks for copy loops (`lda src,x` / `sta dst,x` / `dex` / `bpl`,
and page copies through zero page pointers such as `lda (p),y` / `sta (q),y`)
whose destination is later called or jumped to. It lists each one in Problems
as a suggestion; click it to review and apply the relocation.

Pointers in immediates
----------------------

To show `lda #$BA` / `lda #$45` as `lda #>target` / `lda #<target`, use a split
pointer directive naming the two operand bytes, high byte first:
`codeptr $A393_A397` (also traces the target as code) or `address $A393_A397`.

When only one half is in the code, e.g. a page number for `PMBASE`, use
`hi $4801` (the byte is the high byte of `$XX00`), `hi $4801 $4380` for a
specific address, or `lo $4805 $4380`. Press `>` or `<` on the instruction to
do this from the listing. Labels named in an operand override (`O`) also get
their `equ` emitted, so `#>pmdata` works there too.

xdis suggests these itself (in Problems, with an *Apply all* button) when two
immediates are stored into adjacent bytes `P` and `P+1`, or passed in a register
pair to a subroutine, and there is evidence that they form an address. Either
`P` is a known word location (a pointer used as `(P),y`, `jmp (P)`, a vector,
or a 2-byte range in a symbol set), or the address lands on loaded code or a
label. Stores to the I/O area are ignored. Jump vectors become `codeptr`, and
pointers used for data become `address`. On Atari, an immediate stored into a
page register (`PMBASE`, `CHBASE`, `CHBAS`) is suggested as `hi` when that page
is loaded or has a label. `DLISTL` and `SDLSTL` count as pointers.

The *Problems* panel lists load, trace and label warnings. Click one to
jump to the address it concerns, or to the directive that caused it.

The *Directives* panel lists every directive in dis option syntax. You can
delete them there, or type new ones (`code start=$2000`, `data tbl=$3000+FF`,
`codeptr vbiptr=3C64_3C62`).

Differences from dis
--------------------

The tracer follows the CLI's rules: it traces JMP/JSR/Bxx from entry points,
stops at RTS/RTI/BRK and illegal opcodes, handles overlaid XEX segments, and
detects the BIT-skip trick. Traced instruction sets match the CLI on every
test file. Where xdis intentionally differs:

* Data bytes are grouped (16 per line by default), and long runs of a repeated
  byte become `:N dta $XX`.
* Pointer tables and vectors are shown as `dta a(label)`.
* A plain label inside a data range overrides the range's `name+N` instead of
  being dropped as a duplicate.
* An equate's `Access:` and `Callers:` comment includes references to every
  `name+N` offset into its range, not just to `name` itself.
* Automatic labels only get an `sN` segment prefix when an address is loaded by
  more than one segment.
* Contiguous or truncated XEX segments keep their original headers (xasm
  would otherwise merge them).
* The MADS output uses explicit segment headers and `.a` instead of `a:`.
* Forward references to zero page labels get `z:` in xasm output, because
  xasm would otherwise assemble them as absolute (dis has the same issue).

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
