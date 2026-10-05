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
    const img = X.loadImage(bytes, project.binary.type, project.binary.org);
    for (const d of project.directives.filter((x) => x.type === 'relocate')) {
        const m = X.analyze(img, X.allDirectives(project), project.options);
        project.directives = X.edit.removeRelocation(project.directives, m, d);
    }
    fs.writeFileSync(path.join(OUT, 'galaxian-norel.xdis.json'), X.serializeProject(project, bytes, true));
}

const ATARI_SETS = ['atarixl', 'hardware', 'sys', 'atarifp', 'basic', 'dos'].map((n) => `symbols/${n}.dop`);

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
    // every Atari symbol set at once, in priority order
    { name: 'ransack-allsyms', file: 'ransack/ransack.xex', include: ATARI_SETS },
    { name: 'galaxian-allsyms', project: 'xdis/examples/Galaxian_PLUS_v2.xdis.json', include: ATARI_SETS,
      expect: ['CARTCS', 'CARTAD'] },
    { name: 'esmc-allsyms', file: 'escm/Educational System Master Cartridge (Atari).bin', type: 'raw', org: 0xA000,
      include: ATARI_SETS, expect: ['dta a(lB800)', 'CARTFG'] },
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
    let file = c.bytes ? path.join(OUT, c.name + '.bin') : path.join(HOME, c.file || c.project);
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
        project.includes.push({ name: path.basename(inc), text: fs.readFileSync(path.join(__dirname, '..', inc), 'utf8') });
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
    if (c.edits) applyEdits(project, X.loadImage(bytes, type, org));
    if (c.relocate) {
        const img0 = X.loadImage(bytes, type, org);
        const m0 = X.analyze(img0, X.allDirectives(project), project.options);
        for (const w of m0.warnings) {
            if (w.suggest && w.suggest.type === 'relocate') project.directives = X.edit.addRelocation(project.directives, img0, w.suggest);
        }
    }
    if (c.pointers) {
        // apply pointer suggestions until no new ones appear
        const img0 = X.loadImage(bytes, type, org);
        for (let round = 0; round < 5; round++) {
            const m0 = X.analyze(img0, X.allDirectives(project), project.options);
            const add = m0.warnings.filter((w) => w.suggest && w.suggest.type !== 'relocate').map((w) => w.suggest);
            if (!add.length) break;
            project.directives = project.directives.concat(add);
        }
    }

    const t0 = Date.now();
    const img = X.loadImage(bytes, type, org);
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
    for (const re of c.expectRe || []) {
        const found = re.test(asm);
        results.push(`expect ${re}: ${found ? 'found' : 'MISSING'}`);
        ok = ok && found;
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
