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
  XEX/COM (segments, RUN and INIT vectors, corrupted/truncated files), Atari SAP,
  Commodore 64 PRG (BASIC `SYS` entry point detection) and Atari cartridges
  (`.car` files, or raw dumps with a chosen cartridge type). Use *Open binary…*
  or drag and drop.

Cartridges
----------

Each bank of a cartridge becomes its own segment at its window address, named
`b0`, `b1`, …. Labels are `b5_lA123` where an address is in more than one bank.
Directives and go-to accept `b5:$A123`. The banks visible at power-on are
analyzed last, so the cartridge header (`CARTCS`, `CARTAD`) and directives
without a bank refer to them. The output is the image itself: `opt h-`, the
`.car` header, then an `org` per bank.

The bank registers are labeled for the cartridge type, shown under
*Directives* as a built-in set. Address-select schemes (Williams, Atarimax)
get `CARTBANK=$D500+N` and `CARTOFF`, so a bank switch reads `sta CARTBANK+12`
(offsets in decimal: that's bank 12). Value-select schemes (XEGS, MegaCart,
SIC!) get `CARTBANK=$D500+FF`, as in `lda #5` / `sta CARTBANK`. Your own
labels at those addresses take priority.

Supported types (atari800 numbering): standard 2/4/8/16 KB, Williams (8, 22,
76), XEGS and switchable XEGS (12–14, 23–25, 33–38, 67), Atarimax (41, 42, 75),
SIC! (54–56) and MegaCart (26–32, 64). Other types are shown as 8 KB banks at
`$A000`.

Bank switching is followed along each code path. An access to a `CARTBANK`
address (Williams, Atarimax), or a store of a known value to `CARTBANK` (XEGS,
MegaCart, SIC!, e.g. after `lda #5`), selects that bank for the rest of the
path, so jumps, calls and data accesses into the window resolve to it. That
includes code that switches its own window. Before any select, the window holds
the bank visible at power-on. When the bank can't be known (an indexed select
such as `sta CARTBANK,x`), the jump is listed in Problems; click it to choose
the bank. That adds a `bank b7:$A456 5` directive meaning the operand of the
instruction at `$A456` is in bank 5. *Target bank…* in the context menu and
inspector sets or changes it for any instruction into a bank window.

Carts that copy themselves to RAM (most loaders) are best handled with
`relocate`, one per copied block, e.g. `relocate b3:$A000+1FFF $2A00`. The
*Add* box in the Directives panel accepts several directives pasted at once.
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
| `bbcmos.dop` | BBC Micro MOS: OS entry points (`OSWRCH`, `OSBYTE`, …), vectors (`USERV`, `BRKV`, …), zero page `$B0`–`$FF`, OS and VDU variables, ROM header |
| `bbchw.dop` | BBC Micro Model B hardware: CRTC, ACIA, video ULA, ROMSEL, system and user VIAs, FDC, Econet, ADC, Tube |
| `bbcmosbuf.dop` | BBC Micro MOS buffers and workspace in `$0380`–`$0E00` (opt-in: programs often reuse this RAM) |

Each set's *view* button lists its labels with their descriptions, marks the
ones used by the current program, and lets you switch individual labels off,
or every label matching a filter with *Disable shown*. A switched-off label
is left out completely (no name, no effect on tracing). That's useful when a
program replaces the OS, so `CIOV` and friends at `$E4xx` would otherwise name
the program's own code. The list is saved in the project and in exported
`.dop` files as a `;xdis off` line.

The BBC Micro sets are generated by `tools/harvest-bbc.py`. OS entry points
and vectors use Acorn's official names. Hardware register names come from
py8dis (MIT license), and MOS workspace names from Toby Nelson's MOS 1.20
reassembly.

When two sets name the same thing, the earlier one wins. Your own imported
files come first, then `atarixl.dop` (so XL/XE addresses replace 400/800 ones),
then the rest. Built-in sets always use the current text, even in older
projects. `atarixl.dop`, `atarifp.dop`, `basic.dop` and `dos.dop` are generated
from cc65's `asminc/atari.inc` by `tools/harvest-cc65.py`. Run
`tools/embed-symbols.py` after changing anything in `symbols/`.

Saving
------

* **Save .asm**: the assembly exactly as shown in the listing.
* **Save binary**: the original binary, under its original name. Useful when a
  project with an embedded binary is all you have.
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
| `Ctrl+F`, `/` | Find in the source; `Enter`/`F3` next, `Shift+Enter`/`Shift+F3` previous |
| `Ctrl+Z` `Ctrl+Y` | Undo / redo |
| `Ctrl+S`, `Ctrl+Shift+S` | Save project / save .asm |

All of these are also available in the right-click menu and in the
*Inspect* panel. The inspector also shows callers, accessors and the
directives that apply at the cursor. The memory map strip above the listing
shows code, data, text and pointers; click it to jump.
Hover over any byte to see its address, its value in hex, decimal (signed
too, from `$80`), binary and as a character, and the instruction it would
be as an opcode.

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

Inline data after calls
-----------------------

Some routines take their arguments from the bytes after the `jsr`. They pull
the return address off the stack, read through it, and continue past the data.
An `inline` directive on the routine tells the tracer how to find the end of
the data at every call:

    inline $865C bit7       ; text up to a byte with bit 7 set, which is the next instruction
    inline $865C bit7last   ; text whose last byte has bit 7 set; continues after it
    inline $865C zero       ; text ending in a zero byte; continues after it
    inline $865C 2          ; a fixed number of bytes (1-255)

The data after each call becomes `dta`, and tracing continues where the routine
returns. Choose *Inline data after calls…* from the right-click menu on a `jsr`
or on the routine itself. Routines that start with `pla` / `sta P` / `pla` /
`sta P+1` and then read `(P),y` are suggested in Problems. The test after the
read (`bmi` or `beq`) and a final `jmp (P)` suggest which form applies.

Jump tables
-----------

Indexed dispatch code is recognized and its table suggested as a code pointer
table, which traces every entry:

    lda hi,x / pha / lda lo,x / pha / rts      ; entries are the address minus 1
    lda lo,x / sta P / lda hi,x / sta P+1 / jmp (P)

When the high bytes follow the low bytes (`hi` = `lo`+1) it is a table of
words (`codeptr $9000+1F`), otherwise two split tables (`codeptr $9020_9000+F`).
The size comes from a bounds check before the dispatch (`cpx #N` / `bcs`) or,
without one, from how many entries in a row point at code. A trailing `rts`
on a pointer directive (`codeptr $A642_A62B+16 rts`) says the table holds each
address minus 1; the output then reads `dta <[label-1]`.

Code nothing traces into
------------------------

Untraced bytes are decoded from every address, and blocks that look like real
routines are suggested as `code`. A block has to decode to valid instructions
ending in `rts`, `rti` or `jmp` (or running into traced code). Its branches
have to land on its own instructions or on traced code, and its calls on
traced code, a label, or another block that passes the same test. It is then
scored by how typical each opcode is of 6502 code compared with random bytes,
using a profile of several programs mixed with the program's own traced code.
Calls into traced code and operands with names add to the score. *Apply all*
traces every suggested block at once.

Machine structures
------------------

Immediates stored into a machine's registers, or passed to its OS, point at
data whose layout is known:

* Atari: display lists set in `SDLSTL`/`DLISTL` become data, with their LMS
  and jump operands as addresses (a JVB to another list is followed too).
  Character sets set in `CHBAS`/`CHBASE` become 1 KB of data.
* C64: character sets set in `$D018` (in the VIC bank set in `$DD00`) and
  sprite data from the sprite pointers after the screen.
* BBC Micro: `OSWORD` (by call number), `OSFILE` and `OSGBPB` parameter blocks,
  and `OSCLI`/`OSFIND` strings, addressed by `X` (low) and `Y` (high).

The machine comes from the file type or the symbol sets in use. Each structure
is one suggestion that adds all of its directives.

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

Known OS routines that take a code address in registers are recognized: on
Atari, `ldx #hi` / `ldy #lo` before `jsr SETVBV` is suggested as a code
pointer to the VBI routine (immediate or deferred, from `A`), which also traces
the routine.

Self-modifying jumps are covered too. The operand of a `jmp`/`jsr abs` counts as
a code pointer, so immediates written into it are suggested as `codeptr` pairs,
or as `lo` when only the low byte is written. In that case the page is taken
from the writer's own page, or from the operand's current high byte, whichever
lands on code. Name the operand with a 2-byte label, e.g.
`label dlivec=3:$55AC+1`, to get `dlivec equ *+1` and `sta dlivec` /
`sta dlivec+1`.

A suggestion you don't want can be dismissed with its ×, or with *Dismiss* in
its dialog. That adds a `dismiss $ADDR` directive; delete it to get the
suggestion back.

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
  byte become `:N dta $XX`. Optionally (*Repeat patterns up to* under
  *Project*), repeated patterns become `:N dta $XX,$YY,...` too.
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
