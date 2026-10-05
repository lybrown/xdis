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

let failed = 0;
for (const c of cases) {
    const file = c.bytes ? path.join(OUT, c.name + '.bin') : path.join(HOME, c.file);
    if (c.bytes) fs.writeFileSync(file, c.bytes);
    if (!fs.existsSync(file)) {
        console.log(`SKIP ${c.name}: ${c.file} not found`);
        continue;
    }
    const bytes = new Uint8Array(fs.readFileSync(file));
    const project = X.newProject();
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
