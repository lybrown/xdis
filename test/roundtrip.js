#!/usr/bin/env node
// Round-trip tests: disassemble, reassemble with xasm/mads, compare bytes.
// Optionally compares traced instruction addresses with the Perl `dis` CLI.
//
//   node test/roundtrip.js            # runs every case whose files exist
//
// Environment: XASM (default xasm.exe or xasm), MADS (default mads), DIS (../dis/dis)
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const X = require('../js/core.js');

const HOME = path.resolve(__dirname, '..', '..');
const OUT = path.join(__dirname, 'out');
fs.mkdirSync(OUT, { recursive: true });

function which(names) {
    for (const n of names) {
        try {
            execFileSync('sh', ['-c', `command -v ${n}`], { stdio: 'pipe' });
            return n;
        } catch (e) { /* next */ }
    }
    return null;
}
const XASM = process.env.XASM || which(['xasm', 'xasm.exe']);
const MADS = process.env.MADS || which(['mads']);
const DIS = process.env.DIS || path.join(HOME, 'dis', 'dis');

// test/ui-test.html loads this binary
const uiBin = path.join(HOME, 'ransack', 'ransack.xex');
if (fs.existsSync(uiBin)) fs.copyFileSync(uiBin, path.join(OUT, 'ransack.xex'));

// test/ui-test.html also uses the example project without its relocations
const example = path.join(__dirname, '..', 'examples', 'Galaxian_PLUS_v2.xdis.json');
if (fs.existsSync(example)) {
    const { project, bytes } = X.deserializeProject(fs.readFileSync(example, 'utf8'));
    const img = X.loadImage(bytes, project.binary.type, project.binary.org, project.binary.cartType);
    for (const d of project.directives.filter((x) => x.type === 'relocate')) {
        const m = X.analyze(img, X.allDirectives(project), project.options);
        project.directives = X.edit.removeRelocation(project.directives, m, d);
    }
    fs.writeFileSync(path.join(OUT, 'galaxian-norel.xdis.json'), X.serializeProject(project, bytes, true));
}

const ATARI_SETS = ['atarixl', 'hardware', 'sys', 'atarifp', 'basic', 'dos'].map((n) => `symbols/${n}.dop`);

// n 8 KB banks at $A000, each with `code` at $A000 (so switching banks
// from that code continues in the new bank); bank 0 has a header pointing
// there
function cartImage(n, code) {
    const b = new Uint8Array(n * 0x2000);
    for (let i = 0; i < n; i++) b.set(code, i * 0x2000);
    b.set([0x00, 0xA0, 0x00, 0x04, 0x00, 0xA0], 0x1FFA);
    return b;
}

const cases = [
    {
        name: 'esmc', file: 'escm/Educational System Master Cartridge (Atari).bin',
        dop: 'escm/esmc.dop', type: 'raw', cli: ['-a', 'esmc.dop'],
    },
    {
        name: 'ransack', file: 'ransack/ransack.xex', dop: 'dis/hardware.dop',
        cli: ['-x', '-l', '-a', 'hardware.dop'],
    },
    {
        name: 'ransack-explicit', file: 'ransack/ransack.xex', dop: 'dis/hardware.dop',
        options: { syntax: 'mads' }, mads: true,
    },
    { name: 'bomber', file: 'bomber/bomber.xex', cli: ['-x', '-l'] },
    { name: 'boink', file: 'a8boink/A8_BOINK.XEX', cli: ['-x', '-l'] },
    { name: 'avfplay', file: 'avf/video/avfplay.xex', options: { illegal: true, dataPerLine: 1, fillMin: 0 } },
    { name: 'esmc-edited', file: 'escm/Educational System Master Cartridge (Atari).bin',
      dop: 'escm/esmc.dop', type: 'raw', edits: true },
    { name: 'ransack-edited', file: 'ransack/ransack.xex', dop: 'dis/hardware.dop', edits: true },
    { name: 'ransack-edited-mads', file: 'ransack/ransack.xex', dop: 'dis/hardware.dop', edits: true,
      options: { syntax: 'mads' }, mads: true },
    { name: 'sap', file: 'asap-code/test/benchmark/Lasermania.sap', cli: ['-t', 'sap', '-l'] },
    { name: 'sap-mads', file: 'asap-code/test/benchmark/Montezumas_Revenge.sap', options: { syntax: 'mads' }, mads: true },
    {
        // C64 BASIC stub "10 SYS2061" followed by code
        name: 'prg', type: 'prg', include: ['symbols/vic.dop'], expect: ['sta VICEC', 'l080D'],
        bytes: Uint8Array.from([0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0,
            0xA9, 0x00, 0x8D, 0x20, 0xD0, 0xA2, 0x05, 0xCA, 0xD0, 0xFD, 0x60]),
    },
    // inline data after jsr: a print routine that pops its return address,
    // prints up to a byte with bit 7 set and jumps to that byte
    ...(() => {
        const stub = [0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0];
        const bytes = Uint8Array.from(stub.concat([
            0x20, 0x15, 0x08, 0x48, 0x49, 0xA9, 0x00, 0x60,             // jsr print / "HI" / lda #0 / rts
            0x68, 0x85, 0xFB, 0x68, 0x85, 0xFC, 0xA0, 0x00,             // print: pla sta $FB pla sta $FC ldy #0
            0xE6, 0xFB, 0xD0, 0x02, 0xE6, 0xFC,                         // loop: inc $FB bne +2 inc $FC
            0xB1, 0xFB, 0x30, 0x06, 0x20, 0xD2, 0xFF, 0x4C, 0x1D, 0x08, // lda ($FB),y bmi out jsr $FFD2 jmp loop
            0x6C, 0xFB, 0x00]));                                         // out: jmp ($FB)
        return [
            { name: 'inline-suggest', type: 'prg', bytes, problems: [/l0815 pulls its return address/] },
            { name: 'inline-bit7', type: 'prg', bytes, pointers: true, expect: ["dta c'HI'", 'lda #$00'] },
        ];
    })(),
    // an Acorn-style error routine: an error number, then text up to a byte
    // with bit 7 set (the next instruction) or a zero (raises the error);
    // a wrapper adds "Disk " and passes its caller's data on
    ...(() => {
        const b = new Uint8Array(0x0885 - 0x0801 + 2);
        const put = (a, bytes) => b.set(bytes, a - 0x0801 + 2);
        b.set([0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0]);
        put(0x080D, [0x20, 0x30, 0x08, 0xC7, 0x4F, 0x4B, 0xA9, 0x00,          // jsr err / $C7 "OK" / lda #0
            0x20, 0x60, 0x08, 0x01, 0x46, 0x75, 0x6C, 0x6C, 0xA2, 0x00,          // jsr disk / $01 "Full" / ldx #0
            0x20, 0x30, 0x08, 0x05, 0x42, 0x41, 0x44, 0x00]);                    // jsr err / $05 "BAD" $00
        put(0x0830, [0x68, 0x85, 0xFB, 0x68, 0x85, 0xFC, 0xA0, 0x00,          // err: pla sta $FB pla sta $FC ldy #0
            0x20, 0x50, 0x08, 0xB1, 0xFB, 0x8D, 0x01, 0x01,                      // jsr inc / lda ($FB),y / sta $0101
            0x20, 0x50, 0x08, 0xB1, 0xFB, 0x8D, 0x02, 0x01,                      // loop: jsr inc / lda ($FB),y / sta $0102
            0x30, 0x03, 0xD0, 0xF4, 0x00, 0x6C, 0xFB, 0x00]);                    // bmi out / bne loop / brk / out: jmp ($FB)
        put(0x0850, [0xE6, 0xFB, 0xD0, 0x02, 0xE6, 0xFC, 0x60]);              // inc: inc $FB / bne / inc $FC / rts
        put(0x0860, [0x20, 0x30, 0x08, 0x00, 0x44, 0x69, 0x73, 0x6B, 0x20, 0x90, 0xC5]);   // disk: jsr err / $00 "Disk " / bcc err
        // code nothing calls, with an error call that a branch skips
        put(0x0870, [0xA9, 0x00, 0xD0, 0x08, 0x20, 0x30, 0x08, 0x07, 0x45, 0x52, 0x52, 0x00,   // lda #0 / bne / jsr err / $07 "ERR" $00
            0xA2, 0x05, 0xCA, 0xD0, 0xFD, 0x8D, 0x20, 0xD0, 0x60]);              // ldx #5 / dex / bne / sta $D020 / rts
        return [
            { name: 'inline-error-suggest', type: 'prg', bytes: b,
                problems: [/l0830 pulls its return address and reads the bytes after the jsr: probably inline text up to a byte with bit 7 set, after 1 byte that is always data \(a zero byte raises an error instead\)/] },
            { name: 'inline-error-gap', type: 'prg', bytes: b, directives: ['inline $0830 bit7 lead 1 brk'],
                problems: [/Possible code at \$0870-\$0884 that nothing traces into/] },
            { name: 'inline-error', type: 'prg', bytes: b, pointers: true,
                expect: ["dta $C7,c'OK'", 'lda #$00', "dta $01,c'Full'", 'ldx #$00', "dta $05,c'BAD',$00", "dta $00,c'Disk '", 'bcc l0830', "dta $07,c'ERR',$00", 'dex'] },
        ];
    })(),
    {
        // inline zero-terminated text, a fixed byte count and bit-7-last text
        name: 'inline-modes', type: 'prg', directives: ['inline $081E zero', 'inline $081F 2', 'inline $0820 bit7last'],
        expect: ["dta c'AB',$00", 'dta $34,$12', "dta c'O',$CB"],
        bytes: Uint8Array.from([0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0,
            0x20, 0x1E, 0x08, 0x41, 0x42, 0x00,                         // jsr zr / "AB",0
            0x20, 0x1F, 0x08, 0x34, 0x12,                               // jsr fx / $1234
            0x20, 0x20, 0x08, 0x4F, 0xCB, 0x60,                         // jsr bl / "OK" with bit 7 / rts
            0x60, 0x60, 0x60]),                                         // zr, fx, bl
    },
    // jump tables: split rts tables with a bound check, and a word table
    // behind jmp (P) sized by how many entries point at code
    ...(() => {
        const stub = [0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0];
        const rts = Uint8Array.from(stub.concat([
            0xA2, 0x00, 0xE0, 0x03, 0xB0, 0x08,             // ldx #0 / cpx #3 / bcs done
            0xBD, 0x1F, 0x08, 0x48, 0xBD, 0x1C, 0x08, 0x48, // lda hi,x / pha / lda lo,x / pha
            0x60,                                           // done: rts
            0x21, 0x23, 0x25, 0x08, 0x08, 0x08,             // lo, hi: addresses - 1
            0xE8, 0x60, 0xC8, 0x60, 0xCA, 0x60]));          // inx rts / iny rts / dex rts
        const jmpi = Uint8Array.from(stub.concat([
            0xA6, 0x02, 0xBD, 0x1C, 0x08, 0x85, 0xFB,       // ldx $02 / lda tbl,x / sta $FB
            0xBD, 0x1D, 0x08, 0x85, 0xFC, 0x6C, 0xFB, 0x00, // lda tbl+1,x / sta $FC / jmp ($FB)
            0x20, 0x08, 0x22, 0x08,                         // tbl: a($0820), a($0822)
            0xE8, 0x60, 0xC8, 0x60]));
        return [
            { name: 'table-rts-suggest', type: 'prg', bytes: rts,
                problems: [/Jump tables at \$081C \(low\) and \$081F \(high\): 3 entries dispatched by rts at \$081B/] },
            { name: 'table-rts', type: 'prg', bytes: rts, pointers: true, expect: ['dta <[l0822-1]', 'dta >[l0826-1]', 'inx', 'dex'] },
            { name: 'table-rts-mads', type: 'prg', bytes: rts, pointers: true, options: { syntax: 'mads' }, mads: true, expect: ['dta <[l0822-1]'] },
            { name: 'table-jmpi', type: 'prg', bytes: jmpi, pointers: true, expect: ['dta <l0820', 'dta a(l0822)', 'iny'] },
        ];
    })(),
    // untraced code: a routine nothing calls is suggested; graphics bytes
    // that happen to decode are not
    ...(() => {
        const bytes = Uint8Array.from([0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0,
            0xA9, 0x00, 0x8D, 0x20, 0xD0, 0x60,                         // lda #0 / sta $D020 / rts
            0xA2, 0x00, 0xBD, 0x00, 0x09, 0x9D, 0x00, 0x04,             // ldx #0 / lda $0900,x / sta $0400,x
            0xE8, 0xD0, 0xF7, 0x20, 0x0D, 0x08, 0x60,                   // inx / bne / jsr $080D / rts
            0x01, 0x04, 0x11, 0x44, 0x11, 0x44, 0x15, 0x55, 0x55, 0x55, 0x55, 0x55, 0x40]);
        return [
            { name: 'gap-code-suggest', type: 'prg', bytes, problems: [/Possible code at \$0813-\$0821 that nothing traces into: 7 instructions/] },
            { name: 'gap-code', type: 'prg', bytes, pointers: true, expect: ['l0813', 'sta l0400,x'], absent: ['ora (', 'rti'] },
        ];
    })(),
    // platform structures
    ...(() => {
        // Atari: a display list in SDLSTL and a character set in CHBAS
        const seg = (start, data) => [start & 0xFF, start >> 8, (start + data.length - 1) & 0xFF, (start + data.length - 1) >> 8, ...data];
        const font = Array.from({ length: 1024 }, (_, i) => (i * 37) & 0xFF);
        const xex = Uint8Array.from([0xFF, 0xFF,
            ...seg(0x2000, [0xA9, 0x00, 0x8D, 0x30, 0x02, 0xA9, 0x21, 0x8D, 0x31, 0x02, 0xA9, 0x30, 0x8D, 0xF4, 0x02, 0x60]),
            ...seg(0x2100, [0x70, 0x70, 0x70, 0x42, 0x00, 0x40, 0x02, 0x02, 0x41, 0x00, 0x21]),
            ...seg(0x3000, font),
            ...seg(0x2E0, [0x00, 0x20])]);
        // C64: $D018 = $1C (character set at $3000), sprite pointers $80/$81
        const c64 = new Uint8Array(0x3800 - 0x0801 + 2);
        c64.set([0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0,
            0xA9, 0x1C, 0x8D, 0x18, 0xD0, 0xA9, 0x80, 0x8D, 0xF8, 0x07, 0xA9, 0x81, 0x8D, 0xF9, 0x07, 0x60]);
        for (let a = 0x2000; a < 0x3800; a++) c64[a - 0x0801 + 2] = (a * 13) & 0xFF;
        // BBC: OSWORD 7 (SOUND) with a block at $1918, OSCLI with a string at $1928
        const bbc = new Uint8Array(0x30);
        bbc.set([0xA2, 0x18, 0xA0, 0x19, 0xA9, 0x07, 0x20, 0xF1, 0xFF, 0xA2, 0x28, 0xA0, 0x19, 0x20, 0xF7, 0xFF, 0x60]);
        bbc.set([0x01, 0x00, 0xF1, 0xFF, 0x64, 0x00, 0x14, 0x00], 0x18);
        bbc.set([0x46, 0x58, 0x20, 0x30, 0x0D], 0x28);
        return [
            { name: 'struct-atari', type: 'xex', bytes: xex, include: ['symbols/sys.dop'],
                problems: [/Display list at \$2100-\$210A: 3 mode lines, screen memory at \$4000/, /Character set at \$3000-\$33FF, set in CHBAS at \$200C/] },
            { name: 'struct-atari-applied', type: 'xex', bytes: xex, include: ['symbols/sys.dop'], pointers: true,
                expect: ['dta a(l4000)', 'dta a(l2100)', 'lda #<l2100'] },
            { name: 'struct-c64', type: 'prg', bytes: c64,
                problems: [/Character set at \$3000-\$37FF, set in \$D018 at \$080F/, /Sprite data: 2 sprites at \$2000, \$2040/] },
            { name: 'struct-bbc', type: 'raw', org: 0x1900, bytes: bbc, include: ['symbols/bbcmos.dop'], directives: ['code $1900'],
                problems: [/Parameter block \(8 bytes\) at \$1918 passed to OSWORD 7 at \$1906/, /String at \$1928 passed to OSCLI at \$190D/] },
            { name: 'struct-bbc-applied', type: 'raw', org: 0x1900, bytes: bbc, include: ['symbols/bbcmos.dop'], directives: ['code $1900'],
                pointers: true, expect: ["dta c'FX 0',$0D", 'ldx #<l1918', 'ldy #>l1928'] },
        ];
    })(),
    // a block that branches to a short untraced tail (pla / tax / rts) is
    // still code; text just before a routine is not part of it
    ...(() => {
        const stub = [0x01, 0x08, 0x0B, 0x08, 0x0A, 0x00, 0x9E, 0x32, 0x30, 0x36, 0x31, 0, 0, 0, 0x60];   // main: rts
        const tail = Uint8Array.from(stub.concat([0x68, 0xAA, 0x60,           // tail: pla / tax / rts
            0xA2, 0x05, 0xCA, 0xD0, 0xFD, 0xAD, 0x20, 0xD0, 0xF0, 0xF3,          // ldx #5 / dex / bne / lda $D020 / beq tail
            0x8D, 0x21, 0xD0, 0x60]));                                           // sta $D021 / rts
        const text = Uint8Array.from(stub.concat([0x48, 0x45, 0x52, 0x45, 0x5C, 0x0D,   // "HERE\" CR
            0xA9, 0xC8, 0xA2, 0x03, 0x20, 0x0D, 0x08, 0xA9, 0x8C, 0xA2, 0x00, 0xA0, 0x00, 0x20, 0x0D, 0x08, 0x60]));
        return [
            { name: 'gap-code-tail', type: 'prg', bytes: tail, problems: [/Possible code at \$0811-\$081E that nothing traces into/] },
            { name: 'gap-code-after-text', type: 'prg', bytes: text, problems: [/Possible code at \$0814-\$0824 that nothing traces into/] },
        ];
    })(),
    { name: 'car-abasic-tables', file: '/mnt/c/Users/lyren/Downloads/old/abasic.car', include: ['symbols/sys.dop', 'symbols/hardware.dop'],
      pointers: true, expect: ['dta <[lA558-1]', 'dta >[lA8B3-1]'] },
    // project files; `relocate` applies the relocations xdis suggests
    { name: 'galaxian', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', relocate: true,
      expect: ['org r:$A000', 'jmp lA000'] },
    { name: 'galaxian-mads', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', relocate: true,
      options: { syntax: 'mads' }, mads: true, expect: ['org $A000,*'] },
    { name: 'galaxian-pointers', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', relocate: true, pointers: true,
      expect: ['lda #>lBA45', 'lda #<lBA45', 'lda #>COLDSV'] },
    { name: 'galaxian-pointers-mads', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', relocate: true, pointers: true,
      options: { syntax: 'mads' }, mads: true, expect: ['lda #>lBA45'] },
    { name: 'bomber-pointers', file: 'bomber/bomber.xex', include: ['symbols/sys.dop', 'symbols/hardware.dop'], pointers: true,
      expect: ['#>l7ED5', '#<l7ED5'] },
    // page registers: with pmdata labeled, PMBASE's #$43 becomes #>pmdata
    { name: 'galaxian-pages', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', relocate: true, pointers: true,
      directives: ['data pmdata=$4300', 'data dlist2=$3D00+50'],
      expect: ['lda #>pmdata', 'pmdata equ $4300', 'lda #>l3A00',
          // an equate's comment includes accesses to offsets into its range
          'dlist2 equ $3D00\t\t; Access: A09C A101 A104'] },
    // labels in operand overrides get their equates
    { name: 'override-refs', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json',
      directives: ['data pmdata=$4300', 'operand 5:$4800 #>pmdata', 'lo 5:$4801 $1243'],
      expect: ['lda #>pmdata', 'pmdata equ $4300'] },
    // self-modifying jmp: writes into its operand become #<handler / #>handler
    { name: 'bomb-jack-selfmod', project: 'xdis/examples/bomb-jack-v1.5.xdis.json', pointers: true,
      directives: ['label dlivec=3:$55AC+1'],
      expect: ['dlivec equ *+1', 'lda #<s3l5595', 'sta dlivec', 'lda #>s3l5140', 'sta dlivec+1'] },
    // repeated patterns (opt-in): :N dta $XX,$YY,...
    { name: 'bomber-patterns', file: 'bomber/bomber.xex', options: { patternMax: 16 }, expectRe: [/^ +:\d+ dta \$[0-9A-F]{2},/m] },
    { name: 'boink-patterns', file: 'a8boink/A8_BOINK.XEX', options: { patternMax: 16 }, expectRe: [/^ +:\d+ dta (\$[0-9A-F]{2},){8}\$/m] },
    { name: 'bomb-jack-patterns', project: 'xdis/examples/bomb-jack-v1.5.xdis.json', options: { patternMax: 16 },
      expectRe: [/^ +:\d+ dta (\$[0-9A-F]{2},){7}\$/m] },
    { name: 'bomb-jack-patterns-mads', project: 'xdis/examples/bomb-jack-v1.5.xdis.json',
      options: { patternMax: 16, syntax: 'mads' }, mads: true, expectRe: [/^ +:\d+ dta \$[0-9A-F]{2},/m] },
    // cartridges (.car), from the Downloads folder when present
    ...[['abasic', 'old/abasic.car'], ['hero', 'old/H.E.R.O..car'], ['williams', 'Red Max.car'],
        ['xegs', 'wee_a8_rc5.car'], ['atarimax', 'scorch.car'], ['sic', 'old/CosmicHero2Prologue.car']]
        .map(([n, f]) => ({ name: 'car-' + n, file: '/mnt/c/Users/lyren/Downloads/' + f, include: ['symbols/sys.dop', 'symbols/hardware.dop'] })),
    { name: 'car-xegs-mads', file: '/mnt/c/Users/lyren/Downloads/wee_a8_rc5.car', options: { syntax: 'mads' }, mads: true,
      include: ['symbols/sys.dop'], expect: ['Bank 7: $A000-$BFFF (visible at power-on)', 'CARTCS'] },
    {
        // a raw XEGS 32 KB dump (type 12): banks 0-2 at $8000, bank 3 fixed at $A000
        name: 'cart-raw-xegs', type: 'cart', cartType: 12, expect: ['Bank 3: $A000-$BFFF (visible at power-on)', 'org $8000'],
        bytes: (() => {
            const b = new Uint8Array(0x8000);
            for (let i = 0; i < 4; i++) b.fill(0x11 * (i + 1), i * 0x2000, i * 0x2000 + 0x100);
            b.set([0xA9, 0x00, 0x8D, 0x00, 0xD5, 0x4C, 0x00, 0x80], 0x6000);        // bank 3 at $A000: lda #0 sta $D500 jmp $8000
            b.set([0x00, 0xA0, 0x00, 0x04, 0x00, 0xA0], 0x7FFA);                    // CARTCS=$A000, flags, CARTAD=$A000
            return b;
        })(),
    },
    // built-in bank register labels for the cartridge type
    { name: 'cart-atarimax-regs', type: 'cart', cartType: 41, expect: ['sta CARTBANK+12', 'sta CARTOFF', 'CARTBANK equ $D500'],
      bytes: cartImage(16, [0x8D, 0x0C, 0xD5, 0x8D, 0x10, 0xD5, 0x60]) },     // sta $D50C / sta $D510 / rts
    { name: 'cart-williams-regs', type: 'cart', cartType: 8, expect: ['lda CARTBANK+3', 'sta CARTOFF'],
      bytes: cartImage(8, [0xAD, 0x03, 0xD5, 0x8D, 0x08, 0xD5, 0x60]) },      // lda $D503 / sta $D508 / rts
    { name: 'cart-regs-override', type: 'cart', cartType: 8, directives: ['data bankreg=$D500+7'],
      expect: ['lda bankreg+3'], bytes: cartImage(8, [0xAD, 0x03, 0xD5, 0x60]) },
    {
        // XEGS: the fixed bank selects bank 2 and calls $8000, so the call
        // goes to bank 2's code; an indexed select makes the next call unknown
        name: 'cart-xegs-switch', type: 'cart', cartType: 12,
        expect: ['jsr b2_l8000', 'b2_l8000', 'inc l0602'],
        bytes: (() => {
            const b = new Uint8Array(0x8000);
            for (let i = 0; i < 3; i++) b.set([0xEE, 0x00 + i, 0x06, 0x60], i * 0x2000);   // bank i: inc $06xx / rts
            b.set([0xA9, 0x02, 0x8D, 0x00, 0xD5, 0x20, 0x00, 0x80,                          // lda #2 sta $D500 jsr $8000
                0x9D, 0x00, 0xD5, 0x20, 0x00, 0x80, 0x60], 0x6000);                         // sta $D500,x jsr $8000 rts
            b.set([0x00, 0xA0, 0x00, 0x04, 0x00, 0xA0], 0x7FFA);
            return b;
        })(),
        problems: [/jsr \$8000 at \$A00B goes into the bank window \$8000-\$9FFF/],
    },
    // ... and a bank directive resolves it
    { name: 'cart-xegs-bank-directive', type: 'cart', cartType: 12, directives: ['bank $A00B 1'],
      expect: ['jsr b1_l8000', 'inc l0601'], bytesFrom: 'cart-xegs-switch' },
    // a dismissed suggestion is not applied
    { name: 'dismiss', project: 'xdis/examples/abbayes-evilchurch.xdis.json', pointers: true,
      directives: ['dismiss $2CA7'], absent: ['#>l2CE7'], expect: ['ldx #$2C'] },
    // every Atari symbol set at once, in priority order
    { name: 'ransack-allsyms', file: 'ransack/ransack.xex', include: ATARI_SETS },
    { name: 'galaxian-allsyms', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', include: ATARI_SETS,
      expect: ['CARTCS', 'CARTAD'] },
    { name: 'esmc-allsyms', file: 'escm/Educational System Master Cartridge (Atari).bin', type: 'raw', org: 0xA000,
      include: ATARI_SETS, expect: ['dta a(lB800)', 'CARTFG'] },
    {
        // SETVBV takes the VBI routine in Y/X: suggested as a code pointer and
        // traced, even though nothing else reaches the routine
        name: 'setvbv', type: 'raw', org: 0x2000, directives: ['code $2000'], pointers: true,
        expect: ['ldx #>l2010', 'ldy #<l2010', 'jmp XITVBV'], include: ['symbols/sys.dop'],
        bytes: Uint8Array.from([
            0xA2, 0x20,             // 2000 ldx #$20
            0xA0, 0x10,             // 2002 ldy #$10
            0xA9, 0x07,             // 2004 lda #7 (deferred)
            0x20, 0x5C, 0xE4,       // 2006 jsr SETVBV
            0x60,                   // 2009 rts
            0, 0, 0, 0, 0, 0,       // 200A
            0xEE, 0x00, 0x06,       // 2010 inc $0600   (the VBI routine)
            0x4C, 0x62, 0xE4,       // 2013 jmp XITVBV
        ]),
    },
    {
        // a label switched off in a symbol set is gone, including its effects
        name: 'symbol-off', type: 'raw', org: 0x2000, directives: ['code $2000'], include: ['symbols/sys.dop'],
        includeOff: { 'sys.dop': ['SETVBV'] }, expect: ['jsr lE45C', 'lE45C equ $E45C'], absent: ['SETVBV'],
        bytesFrom: 'setvbv',
    },
    {
        // BBC Micro: OS calls, a VIA register and MOS workspace by name
        name: 'bbc', type: 'raw', org: 0x1900, directives: ['code $1900'],
        include: ['symbols/bbcmos.dop', 'symbols/bbchw.dop'],
        expect: ['jsr OSWRCH', 'jsr OSBYTE', 'sta system_via_ier', 'lda interruptAccumulator', 'OSWRCH equ $FFEE'],
        bytes: Uint8Array.from([
            0xA9, 0x41, 0x20, 0xEE, 0xFF,   // lda #'A' / jsr OSWRCH
            0xA9, 0x81, 0xA2, 0x00, 0xA0, 0xFF, 0x20, 0xF4, 0xFF,   // OSBYTE &81
            0xA9, 0x7F, 0x8D, 0x4E, 0xFE,   // sta system VIA IER
            0xA5, 0xFC,                     // lda &FC
            0x60,
        ]),
    },
    {
        // zero page code with a forward reference: xasm needs "z:" or it
        // assembles lda l0085 as absolute
        name: 'zp-forward', type: 'raw', org: 0x80, directives: ['code $80'], expect: ['lda z:l0085'],
        bytes: Uint8Array.from([0xA5, 0x85, 0x4C, 0x80, 0x00, 0x07]),
    },
    {
        // a block copied from $2010 to $0600 by an indexed loop, then jumped to
        name: 'reloc-indexed', type: 'raw', org: 0x2000, directives: ['code $2000'], relocate: true,
        expect: ['org r:$0600', 'jmp l0600', 'org $2030'],
        bytes: Uint8Array.from([
            0xA2, 0x1F,             // 2000 ldx #$1F
            0xBD, 0x10, 0x20,       // 2002 lda $2010,x
            0x9D, 0x00, 0x06,       // 2005 sta $0600,x
            0xCA,                   // 2008 dex
            0x10, 0xF7,             // 2009 bpl $2002
            0x4C, 0x00, 0x06,       // 200B jmp $0600
            0, 0,                   // 200E
            0xA9, 0x01,             // 2010 lda #1     (runs at $0600)
            0xD0, 0x02,             // 2012 bne +2
            0x00, 0x00,             // 2014
            0x20, 0x0C, 0x06,       // 2016 jsr $060C
            0x4C, 0x00, 0x06,       // 2019 jmp $0600
            0, 0, 0, 0,             // 201C
            0x60,                   // 2020 rts (=$0610)... padding below
            ...new Array(15).fill(0),
            0xEA, 0x60,             // 2030 after the block
        ]),
    },
    // a 64K BBC Micro memory dump (Ransack, with MOS 1.20 and BASIC), traced
    // from the IRQ1V vector and the call chain left on the stack
    { name: 'ransack-bbc', file: 'ransack/ransack-main.mem', type: 'raw', org: 0,
      directives: ['code $1CD1', 'code $240D', 'code $131A', 'code $112C'],
      include: ['symbols/bbcmos.dop', 'symbols/bbchw.dop'],
      expect: ['lda user_via_ifr', 'jsr OSBYTE', 'Callers: -v 0204'] },
    { name: 'selftest-like', file: 'ransack/RANFIX.MEM', type: 'raw', org: 0x2000,
      directives: ['code start=$2000'] },
];

function loadDop(file, project) {
    const text = fs.readFileSync(file, 'utf8');
    const res = X.parseDop(text, path.basename(file));
    for (const arg of res.args) {
        const p = path.join(path.dirname(file), arg);
        project.includes.push({ name: arg, text: fs.readFileSync(p, 'utf8') });
    }
    project.directives.push(...X.dedupeImported(res.directives));
    Object.assign(project.options, res.options);
    return res;
}

// Apply one of every kind of edit the UI can make, the way the UI does.
function applyEdits(project, img) {
    const E = X.edit;
    const model = () => X.analyze(img, X.allDirectives(project), project.options);
    let m = model();
    const T = m.S.find((t) => t.ilen.some((x) => x) && t.seg.data.length > 256);
    const s = img.multi && T ? T.seg.index : 0;
    const scope = (a) => (img.multi && m.cover[a] > 1 ? s : 0);
    const starts = [];
    T.ilen.forEach((n, o) => { if (n) starts.push(T.seg.start + o); });
    const untraced = [];
    T.ilen.forEach((n, o) => { if (!n && o > 0 && !T.ilen[o - 1]) untraced.push(T.seg.start + o); });
    let d = project.directives;
    // rename an instruction address and an auto label target
    d = E.setName(d, scope(starts[0]), starts[0], 'entry_point', m.labelAt(X.key(s, starts[0])));
    // data over an instruction in the middle of the code
    const mid = starts[Math.floor(starts.length / 2)];
    d = E.markData(d, scope(mid), mid, mid + 5, 'data');
    // code in untraced bytes
    d = E.markCode(d, scope(untraced[3]), untraced[3], untraced[3]);
    // text and words and pointers in untraced bytes
    const u = untraced.slice(-40);
    d = E.markData(d, scope(u[0]), u[0], u[0] + 7, 'text');
    d = E.markData(d, scope(u[10]), u[10], u[10] + 5, 'word');
    d = E.markPointers(d, scope(u[20]), u[20], u[20] + 3, 'address');
    // comments, notes, constants
    d = E.setText(d, 'comment', scope(starts[1]), starts[1], 'a comment; with semicolon');
    d = E.setText(d, 'note', scope(starts[2]), starts[2], 'Block comment\nline two');
    d = E.setConstant(d, 0x00, 'ZERO');
    // undefine part of it again
    d = E.undefine(d, scope(u[10]), u[10], u[10] + 1);
    project.directives = d;
    project.options.rangelabels = true;
    m = model();
}

function instrAddrs(asm) {
    const set = new Set();
    for (const line of asm.split('\n')) {
        const m = /^\s+([a-z]{3})\b.*;\s*([0-9A-F]{4}):/.exec(line);
        if (m && m[1] !== 'dta' && m[1] !== 'org') set.add(m[2]);
    }
    return set;
}

// every project in examples/ (ignored by git) is round-tripped as is
const exampleDir = path.join(__dirname, '..', 'examples');
if (fs.existsSync(exampleDir)) {
    for (const f of fs.readdirSync(exampleDir).filter((n) => n.endsWith('.json')).sort()) {
        cases.push({ name: 'example-' + f.replace(/\.json$/, '').replace(/\W+/g, '-').replace(/-+$/, ''), project: 'xdis/examples/' + f });
    }
}

let failed = 0;
for (const c of cases) {
    if (c.bytesFrom) c.bytes = cases.find((x) => x.name === c.bytesFrom).bytes;
    let file = c.bytes ? path.join(OUT, c.name + '.bin') : path.resolve(HOME, c.file || c.project);
    if (c.bytes) fs.writeFileSync(file, c.bytes);
    if (!fs.existsSync(file)) {
        console.log(`SKIP ${c.name}: ${c.file || c.project} not found`);
        continue;
    }
    let bytes = new Uint8Array(fs.readFileSync(file));
    let project = X.newProject();
    if (c.project) {
        const res = X.deserializeProject(fs.readFileSync(file, 'utf8'));
        project = res.project;
        bytes = res.bytes;
        file = path.join(OUT, c.name + '.bin');
        fs.writeFileSync(file, bytes);
        c.type = project.binary.type;
        c.org = project.binary.org;
    }
    if (c.include && c.project) project.includes = [];
    for (const inc of c.include || []) {
        const name = path.basename(inc);
        project.includes.push({ name, text: fs.readFileSync(path.join(__dirname, '..', inc), 'utf8'),
            off: (c.includeOff || {})[name] });
    }
    let type = c.type || X.detectType(file, bytes);
    let org = c.org || 0;
    if (c.dop) {
        const res = loadDop(path.join(HOME, c.dop), project);
        type = res.binary.type || c.type || type;
        if (res.binary.org !== undefined) org = res.binary.org;
    }
    for (const d of c.directives || []) project.directives.push(X.parseDirectiveLine(d));
    Object.assign(project.options, c.options || {});
    if (c.edits) applyEdits(project, X.loadImage(bytes, type, org, c.cartType));
    if (c.relocate) {
        const img0 = X.loadImage(bytes, type, org, c.cartType);
        const m0 = X.analyze(img0, X.allDirectives(project), project.options);
        for (const w of m0.warnings) {
            if (w.suggest && w.suggest.type === 'relocate') project.directives = X.edit.addRelocation(project.directives, img0, w.suggest);
        }
    }
    if (c.pointers) {
        // apply pointer suggestions until no new ones appear
        const img0 = X.loadImage(bytes, type, org, c.cartType);
        for (let round = 0; round < 5; round++) {
            const m0 = X.analyze(img0, X.allDirectives(project), project.options);
            const add = m0.warnings.filter((w) => w.suggest && w.suggest.type !== 'relocate').flatMap((w) => w.dirs || [w.suggest]);
            if (!add.length) break;
            project.directives = project.directives.concat(add);
        }
    }

    const t0 = Date.now();
    const img = X.loadImage(bytes, type, org, c.cartType);
    const model = X.analyze(img, X.allDirectives(project), project.options);
    const listing = X.render(model);
    const asm = X.asmText(listing, project.options);
    const ms = Date.now() - t0;
    const asmFile = path.join(OUT, c.name + '.asm');
    fs.writeFileSync(asmFile, asm);

    const results = [];
    const assemblers = [];
    if (XASM && !c.mads) assemblers.push(['xasm', XASM, [c.name + '.asm', '/o:' + c.name + '.xasm.obx'], c.name + '.xasm.obx']);
    if (MADS && c.mads) assemblers.push(['mads', MADS, [c.name + '.asm', '-o:' + c.name + '.mads.obx'], c.name + '.mads.obx']);
    let ok = true;
    for (const [nm, exe, args, obx] of assemblers) {
        try { fs.unlinkSync(path.join(OUT, obx)); } catch (e) { /* none */ }
        try {
            execFileSync(exe, args, { cwd: OUT, stdio: 'pipe', timeout: 120000 });
        } catch (e) {
            const msg = (e.stdout || '') + (e.stderr || '');
            results.push(`${nm}: FAILED TO ASSEMBLE\n${msg.toString().split('\n').filter((l) => /ERROR|rror/.test(l)).slice(0, 5).join('\n')}`);
            ok = false;
            continue;
        }
        const out = fs.readFileSync(path.join(OUT, obx));
        const same = Buffer.compare(out, Buffer.from(bytes)) === 0;
        results.push(`${nm}: ${same ? 'identical' : 'DIFFERENT'}`);
        ok = ok && same;
    }

    // Every directive the scan calls unneeded can be removed together.
    if (project.directives.length) {
        const sc = X.redundancyScan(img, project, model);
        const removable = new Set();
        let r;
        while ((r = sc.step())) if (r.removable) removable.add(r.d);
        const pruned = Object.assign({}, project, { directives: project.directives.filter((d) => !removable.has(d)) });
        const same = X.sameCode(model, X.analyze(img, X.allDirectives(pruned), project.options));
        results.push(`unneeded ${removable.size}/${sc.total}: ${same ? 'joint removal ok' : 'JOINT REMOVAL CHANGES CODE'}`);
        ok = ok && same;
    }
    for (const re of c.problems || []) {
        const found = model.warnings.some((w) => re.test(w.msg));
        results.push(`problem ${re}: ${found ? 'found' : 'MISSING'}`);
        ok = ok && found;
    }
    for (const re of c.expectRe || []) {
        const found = re.test(asm);
        results.push(`expect ${re}: ${found ? 'found' : 'MISSING'}`);
        ok = ok && found;
    }
    for (const e of c.absent || []) {
        const found = asm.includes(e);
        results.push(`absent "${e}": ${found ? 'PRESENT' : 'absent'}`);
        ok = ok && !found;
    }
    for (const e of c.expect || []) {
        const found = asm.includes(e);
        results.push(`expect "${e}": ${found ? 'found' : 'MISSING'}`);
        ok = ok && found;
    }
    if (c.cli && fs.existsSync(DIS)) {
        const cliDir = path.dirname(path.join(HOME, c.dop || c.file));
        const cliAsm = execFileSync('perl', [DIS, ...c.cli, file], { cwd: cliDir, stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 1 << 28 }).toString();
        fs.writeFileSync(path.join(OUT, c.name + '.cli.asm'), cliAsm);
        const a = instrAddrs(cliAsm), b = instrAddrs(asm);
        const onlyCli = [...a].filter((x) => !b.has(x));
        const onlyUs = [...b].filter((x) => !a.has(x));
        const same = !onlyCli.length && !onlyUs.length;
        results.push(`trace vs CLI: ${same ? 'same' : `cli-only ${onlyCli.length} [${onlyCli.slice(0, 6)}] xdis-only ${onlyUs.length} [${onlyUs.slice(0, 6)}]`} (${a.size} instructions)`);
        ok = ok && same;
    }
    console.log(`${ok ? 'PASS' : 'FAIL'} ${c.name} (${listing.lines.length} lines, ${ms} ms): ${results.join('; ')}`);
    if (!ok) failed++;
}
process.exit(failed ? 1 : 0);
