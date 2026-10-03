/* xdis — statically tracing 6502 disassembler engine.
 *
 * A JavaScript port of the ideas in the `dis` CLI: binaries are loaded as
 * segments, code is traced from entry points through JMP/JSR/Bxx, and
 * everything else is data. Output is XASM/MADS compatible.
 *
 * Works in the browser (window.XDis) and in node (module.exports).
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory(require('./opcodes.js'));
    } else {
        root.XDis = factory(root.XDisOpcodes);
    }
})(this, function (Opcodes) {
    'use strict';

    const { OPS } = Opcodes;
    const MEM = 0x10000;

    // ------------------------------------------------------------------
    // Helpers

    const hx = (v) => v.toString(16).toUpperCase();
    const h2 = (v) => hx(v).padStart(2, '0');
    const h4 = (v) => hx(v).padStart(4, '0');
    const key = (seg, addr) => seg * MEM + addr;
    const keySeg = (k) => Math.floor(k / MEM);
    const keyAddr = (k) => k % MEM;
    const word = (mem, a) => mem[a & 0xFFFF] | (mem[(a + 1) & 0xFFFF] << 8);

    // Text for `dta`: printable runs as c'...', everything else as numbers.
    function encodeText(bytes) {
        const out = [];
        let str = '';
        for (const b of bytes) {
            if (b >= 0x20 && b < 0x7F && b !== 0x27) {
                str += String.fromCharCode(b);
            } else {
                if (str) out.push("c'" + str + "'");
                str = '';
                out.push('$' + h2(b));
            }
        }
        if (str) out.push("c'" + str + "'");
        return out.join(',');
    }

    function sortUniq(list) {
        return Array.from(new Set(list)).sort();
    }

    // ------------------------------------------------------------------
    // Binary loaders

    function detectType(name, bytes) {
        const ext = (name || '').toLowerCase().split('.').pop();
        if (['xex', 'com', 'exe', 'obx'].includes(ext)) return 'xex';
        if (ext === 'prg') return 'prg';
        if (ext === 'sap') return 'sap';
        if (bytes.length > 5 && bytes[0] === 0xFF && bytes[1] === 0xFF) {
            // Only guess XEX when the whole file parses cleanly as one.
            const img = { segments: [], warnings: [], extra: null };
            parseXex(bytes, img);
            if (!img.warnings.length && !img.extra) return 'xex';
        }
        if (String.fromCharCode(...bytes.subarray(0, 5)) === 'SAP\r\n') return 'sap';
        return 'raw';
    }

    function addSegment(img, start, data, extra) {
        if (start + data.length > MEM) {
            img.warnings.push(`Segment at $${h4(start)} runs past $FFFF; truncated`);
            data = data.subarray(0, MEM - start);
        }
        const seg = Object.assign({
            index: img.segments.length + 1,
            start,
            end: start + data.length - 1,
            data,
            ffff: false,
        }, extra);
        img.segments.push(seg);
        return seg;
    }

    function parseXex(bytes, img) {
        const n = bytes.length;
        const word16 = (p) => (p + 1 < n ? bytes[p] | (bytes[p + 1] << 8) : -1);
        for (let i = 0; i < n;) {
            const segstart = i;
            let start = word16(i);
            let ffff = false;
            let end = -1;
            if (start >= 0) {
                i += 2;
                if (start === 0xFFFF) {
                    ffff = true;
                    start = word16(i);
                    i += 2;
                }
                if (start >= 0) {
                    end = word16(i);
                    i += 2;
                }
            }
            if (start < 0 || end < 0) {
                img.warnings.push(`Incomplete segment header at byte ${segstart}`);
                img.extra = bytes.subarray(segstart);
                break;
            }
            const len = end - start + 1;
            if (len < 0) {
                img.warnings.push(`Segment length is negative at byte ${segstart}: ${len}`);
                img.extra = bytes.subarray(segstart);
                break;
            }
            if (i + len > n) img.warnings.push(`Segment past EOF at byte ${segstart}`);
            const data = bytes.subarray(i, i + len);
            i += len;
            const seg = addSegment(img, start, data, { ffff, hdrEnd: end, offset: segstart });
            if (seg.start <= 0x2E0 && seg.end >= 0x2E1) {
                seg.run = word(paddedMem(seg), 0x2E0);
            }
            if (seg.start <= 0x2E2 && seg.end >= 0x2E3) {
                seg.ini = word(paddedMem(seg), 0x2E2);
            }
            if (seg.start === 0x2E0 && seg.end === 0x2E1) seg.kind = 'run';
            if (seg.start === 0x2E2 && seg.end === 0x2E3) seg.kind = 'ini';
        }
    }

    function paddedMem(seg) {
        const mem = new Uint8Array(MEM);
        mem.set(seg.data, seg.start);
        return mem;
    }

    function parseSap(bytes, img) {
        let split = -1;
        for (let i = 0; i + 1 < bytes.length; i++) {
            if (bytes[i] === 0xFF && bytes[i + 1] === 0xFF) { split = i; break; }
        }
        const head = String.fromCharCode(...bytes.subarray(0, Math.max(split, 0)));
        if (split < 0 || !head.startsWith('SAP\r\n')) throw new Error('Not a SAP file');
        const attr = {};
        img.prelude.push({ text: 'opt h-' });
        for (const line of head.split('\r\n').slice(0, -1)) {
            const m = /^(\S+)(?: (.*))?$/.exec(line) || [line, line];
            attr[m[1]] = m[2] === undefined ? true : m[2];
            const enc = encodeText(Array.from(line, (c) => c.charCodeAt(0)));
            img.prelude.push({ text: `dta ${enc},13,10` });
        }
        img.prelude.push({ text: 'opt h+', xasmOnly: true });
        parseXex(bytes.subarray(split), img);
        if (attr.TYPE === 'C') {
            const player = parseInt(attr.PLAYER || '0', 16);
            img.entries.push({ addr: player + 3 }, { addr: player + 6 });
        } else {
            for (const name of ['INIT', 'PLAYER']) {
                if (typeof attr[name] === 'string') {
                    img.entries.push({ name, addr: parseInt(attr[name], 16) });
                }
            }
        }
    }

    function parsePrg(bytes, img) {
        if (bytes.length < 2) throw new Error('PRG file too short');
        const start = bytes[0] | (bytes[1] << 8);
        img.prelude.push({ text: 'opt h-' });
        img.prelude.push({ text: `dta a($${h4(start)})`, comment: 'PRG Header' });
        const head = String.fromCharCode(...bytes.subarray(0, 32));
        const m = /^[\s\S]{6}\x9E *(\d+)/.exec(head);
        if (m) img.entries.push({ addr: parseInt(m[1], 10) & 0xFFFF });
        img.org = start;
        addSegment(img, start, bytes.subarray(2));
    }

    function loadImage(bytes, type, org) {
        const img = {
            type, org: org || 0, size: bytes.length,
            segments: [], entries: [], prelude: [], extra: null, warnings: [],
        };
        if (type === 'xex') {
            parseXex(bytes, img);
        } else if (type === 'sap') {
            parseSap(bytes, img);
        } else if (type === 'prg') {
            parsePrg(bytes, img);
        } else {
            img.type = 'raw';
            img.prelude.push({ text: 'opt h-' });
            addSegment(img, img.org & 0xFFFF, bytes);
        }
        img.multi = img.type === 'xex' || img.type === 'sap';
        return img;
    }

    // ------------------------------------------------------------------
    // Directives
    //
    // A directive is {type, name, seg, addr, range, hi?, text?}. The first six
    // types match the CLI options; the rest are xdis extensions that are
    // carried through .dop files as ";xdis ..." comment lines.

    const CLI_TYPES = ['code', 'data', 'vector', 'constant', 'address', 'codeptr'];
    const EXT_TYPES = ['label', 'text', 'word', 'comment', 'note', 'operand'];
    const DATA_TYPES = ['data', 'text', 'word'];
    const POINTER_TYPES = ['vector', 'address', 'codeptr'];
    const FMT = { data: 1, text: 2, word: 3, pointer: 4 };

    const ALIASES = {
        c: 'code', d: 'data', C: 'constant', v: 'vector', A: 'address',
        P: 'codeptr', o: 'org', l: 'labels', i: 'illegal', t: 'type', x: 'xex',
        p: 'prg', a: 'arg',
    };
    // dop option name -> project option name
    const OPTION_MAP = {
        labels: 'labels', comment: 'comments', call: 'callers', access: 'access',
        extern: 'extern', illegal: 'illegal', rangelabels: 'rangelabels',
    };

    const LABEL_RE = /^[A-Za-z_?@][\w?@]*$/;
    const SPEC_RE = /^(?:([A-Za-z_?@][\w?@]*)=)?(?:(\d+):)?\$?([0-9a-fA-F]+)(?:_([0-9a-fA-F]+))?(?:\+([0-9a-fA-F]+))?$/;

    function parseSpec(type, value) {
        const m = SPEC_RE.exec(value || '');
        if (!m) throw new Error(`Unrecognized ${type} address: ${value}`);
        const d = {
            type,
            name: m[1] || null,
            seg: m[2] ? parseInt(m[2], 10) : 0,
            addr: parseInt(m[4] || m[3], 16),
            range: m[5] ? parseInt(m[5], 16) : 0,
        };
        if (m[4]) d.hi = parseInt(m[3], 16);  // HI_LO
        if (d.addr > 0xFFFF || (d.hi || 0) > 0xFFFF) {
            throw new Error(`Address out of range in ${type} ${value}`);
        }
        return d;
    }

    function specString(d) {
        let s = d.name ? d.name + '=' : '';
        if (d.seg) s += d.seg + ':';
        s += d.hi !== undefined && d.hi !== null ? `$${hx(d.hi)}_${hx(d.addr)}` : '$' + hx(d.addr);
        if (d.range) s += '+' + hx(d.range);
        return s;
    }

    function directiveString(d) {
        if (d.type === 'comment' || d.type === 'note' || d.type === 'operand') {
            const loc = (d.seg ? d.seg + ':' : '') + '$' + hx(d.addr);
            return `${d.type} ${loc} ${d.text.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')}`;
        }
        return `${d.type} ${specString(d)}`;
    }

    function parseDirectiveLine(line) {
        const m = /^\s*(\S+)\s*(.*?)\s*$/.exec(line);
        if (!m) return null;
        const type = ALIASES[m[1]] || m[1];
        if (type === 'comment' || type === 'note' || type === 'operand') {
            const t = /^(?:(\d+):)?\$?([0-9a-fA-F]+)(?:\s(.*))?$/.exec(m[2]);
            if (!t) throw new Error(`Bad ${type}: ${m[2]}`);
            const text = (t[3] || '').replace(/\\(n|\\)/g, (_, c) => (c === 'n' ? '\n' : '\\'));
            return { type, name: null, seg: t[1] ? +t[1] : 0, addr: parseInt(t[2], 16) & 0xFFFF, range: 0, text };
        }
        if (CLI_TYPES.includes(type) || EXT_TYPES.includes(type)) {
            return parseSpec(type, m[2]);
        }
        return null;
    }

    // Parse a .dop option file. Returns directives, options and unresolved args.
    function parseDop(text, fileName) {
        const res = { directives: [], options: {}, args: [], errors: [], binary: {} };
        text.split(/\r?\n/).forEach(function (raw, n) {
            let line = raw;
            const ext = /^\s*;xdis\s+(.*)$/.exec(line);
            if (ext) {
                line = ext[1];
                const opt = /^option\s+(\w+)\s+(\S+)/.exec(line);
                if (opt) {
                    const v = opt[2];
                    res.options[opt[1]] = /^-?\d+$/.test(v) ? +v : v === 'true' ? true : v === 'false' ? false : v;
                    return;
                }
            } else {
                line = line.replace(/;.*/, '');
            }
            if (/^\s*$/.test(line)) return;
            const parts = line.trim().split(/\s+/);
            // ";xdis" lines and "comment ADDR text" are always directives;
            // plain "comment 1" is the CLI option.
            if (ext || (parts[0] === 'comment' && parts.length > 2)) {
                try {
                    const d = parseDirectiveLine(line);
                    if (!d) throw new Error(`Unknown xdis directive ${parts[0]}`);
                    res.directives.push(d);
                } catch (e) {
                    res.errors.push(`${fileName || 'dop'}:${n + 1}: ${e.message}`);
                }
                return;
            }
            const opt = ALIASES[parts[0]] || parts[0];
            const value = parts[1];
            try {
                if (opt === 'arg') {
                    res.args.push(value);
                } else if (opt === 'org') {
                    res.binary.org = parseInt(value.replace('$', ''), 16);
                } else if (opt === 'type') {
                    res.binary.type = value;
                } else if (opt === 'xex' || opt === 'prg') {
                    if (value !== '0') res.binary.type = opt;
                } else if (OPTION_MAP[opt]) {
                    res.options[OPTION_MAP[opt]] = value === undefined ? true : value !== '0';
                } else if (['verbose', 'headers', 'orglabels', 'dump', 'dumpequ', 'help'].includes(opt)) {
                    // CLI-only options with no meaning here
                } else {
                    const d = parseDirectiveLine(line);
                    if (!d) throw new Error(`Unknown option ${parts[0]}`);
                    res.directives.push(d);
                }
            } catch (e) {
                res.errors.push(`${fileName || 'dop'}:${n + 1}: ${e.message}`);
            }
        });
        return res;
    }

    // Write a project as a .dop file the CLI can consume. xdis-only
    // information is stored in ";xdis" comments which the CLI ignores.
    function exportDop(project, model) {
        const out = ['; xdis project: ' + ((project.binary && project.binary.name) || '')];
        const o = project.options;
        for (const inc of project.includes || []) {
            if (inc.enabled !== false) out.push('arg ' + inc.name);
        }
        const b = project.binary;
        if (b) {
            out.push('type ' + b.type);
            if (b.type === 'raw') out.push('org ' + hx(b.org || 0));
        }
        for (const [dop, opt] of Object.entries(OPTION_MAP)) {
            out.push(`${dop} ${o[opt] ? 1 : 0}`);
        }
        for (const k of ['syntax', 'dataPerLine', 'fillMin', 'textPerLine']) {
            out.push(`;xdis option ${k} ${o[k]}`);
        }
        for (const d of project.directives) {
            if (CLI_TYPES.includes(d.type)) {
                out.push(directiveString(d));
            } else if (d.type === 'label' || d.type === 'text' || d.type === 'word') {
                // The CLI has no plain label; `code` keeps tracing intact on
                // code, `data` is used everywhere else.
                const k = key(d.seg || (model ? model.finalOwner[d.addr] : 0), d.addr);
                const isCode = d.type === 'label' && model && model.isCodeStart(k);
                if (d.type !== 'label' || d.name) {
                    out.push(';xdis ' + directiveString(d));
                    out.push(directiveString(Object.assign({}, d, { type: isCode ? 'code' : 'data' })));
                } else {
                    out.push(';xdis ' + directiveString(d));
                }
            } else {
                out.push(';xdis ' + directiveString(d));
            }
        }
        return out.join('\n') + '\n';
    }

    // On import, drop the CLI fallback line that follows each ";xdis" line.
    function dedupeImported(dirs) {
        const out = [];
        for (let i = 0; i < dirs.length; i++) {
            const d = dirs[i];
            out.push(d);
            const next = dirs[i + 1];
            if ((d.type === 'label' || d.type === 'text' || d.type === 'word') && next &&
                (next.type === 'code' || next.type === 'data') &&
                next.addr === d.addr && next.seg === d.seg && next.range === d.range && next.name === d.name) {
                i++;
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Analysis: layer segments, trace code, collect labels and references.

    function defaultOptions() {
        return {
            labels: true,
            comments: true,
            callers: true,
            access: true,
            extern: true,
            illegal: false,
            rangelabels: false,
            syntax: 'xasm',        // 'xasm' (org f:, run, ini, a:) or 'mads' (explicit headers, .a)
            dataPerLine: 8,
            textPerLine: 32,
            fillMin: 32,           // collapse runs of identical bytes into :N dta; 0 = off
        };
    }

    function analyze(img, directives, opts) {
        const segs = img.segments;
        const finalOwner = new Int16Array(MEM);
        const cover = new Uint8Array(MEM);
        for (const s of segs) {
            for (let a = s.start; a <= s.end; a++) {
                finalOwner[a] = s.index;
                if (cover[a] < 255) cover[a]++;
            }
        }
        const S = segs.map((s) => ({
            seg: s,
            ilen: new Uint8Array(s.data.length),  // instruction length at instruction starts
            tseg: new Int16Array(s.data.length),  // segment of operand target at trace time
            fmt: new Uint8Array(s.data.length),   // FMT.* for user data / pointers
            ptr: new Map(),                       // offset -> {t, ts, part, other}
        }));
        const warnings = [];
        const warn = (msg) => warnings.push(msg);
        const resolveSeg = (d, a) => (d.seg && d.seg <= segs.length ? d.seg : d.seg ? -1 : finalOwner[a]);
        const segOf = (k) => S[keySeg(k) - 1];

        // --- labels from directives (first exact definition wins)
        const labels = new Map();
        const names = new Map();
        const consts = new Map();
        const comments = new Map();
        const notes = new Map();
        const operands = new Map();
        function addLabel(k, name, off, base, d) {
            const prev = labels.get(k);
            if (prev && (prev.off === 0 || off > 0)) return;
            let ref = name;
            if (off) ref = opts.rangelabels ? `${name}_${hx(off)}` : `${name}+${off > 9 ? '$' + hx(off) : off}`;
            const def = !off || opts.rangelabels;
            labels.set(k, { name: ref, base: def ? ref : name, baseKey: def ? k : base, off: def ? 0 : off, user: true, dir: d });
        }
        for (const d of directives) {
            if (d.seg && d.seg > segs.length) {
                warn(`${d.type} ${specString(d)}: no segment ${d.seg}`);
                continue;
            }
            if (d.type === 'constant') {
                if (d.name && !consts.has(d.addr & 0xFF)) consts.set(d.addr & 0xFF, d.name);
                continue;
            }
            if (d.type === 'comment' || d.type === 'note' || d.type === 'operand') {
                const k = key(resolveSeg(d, d.addr), d.addr);
                const map = d.type === 'comment' ? comments : d.type === 'note' ? notes : operands;
                map.set(k, map.has(k) && d.type === 'note' ? map.get(k) + '\n' + d.text : d.text);
                continue;
            }
            if (!d.name) continue;
            const base = key(resolveSeg(d, d.addr), d.addr);
            for (let off = 0; off <= d.range; off++) {
                const a = d.addr + off;
                if (a > 0xFFFF) { warn(`Out of range ${d.type}: ${specString(d)}`); break; }
                addLabel(key(resolveSeg(d, a), a), d.name, off, base, d);
            }
        }
        for (const [k, l] of labels) {
            if (l.off) continue;
            const prev = names.get(l.name);
            if (prev !== undefined && prev !== k) {
                warn(`Label ${l.name} is defined at both $${h4(keyAddr(prev))} and $${h4(keyAddr(k))}`);
            } else {
                names.set(l.name, k);
            }
        }

        // --- user data formats (block tracing)
        for (const d of directives) {
            let f = 0;
            if (DATA_TYPES.includes(d.type)) f = FMT[d.type];
            else if (POINTER_TYPES.includes(d.type) && d.hi === undefined) f = FMT.pointer;
            if (!f) continue;
            const end = d.type === 'vector' ? d.range | 1 : d.range;
            for (let off = 0; off <= end; off++) {
                const a = d.addr + off;
                if (a > 0xFFFF) break;
                const s = resolveSeg(d, a);
                if (s <= 0) continue;
                const T = S[s - 1];
                const o = a - T.seg.start;
                if (!T.fmt[o] || T.fmt[o] === FMT.pointer) T.fmt[o] = f;
            }
        }

        // --- tracing
        const mem = new Uint8Array(MEM);
        const owner = new Int16Array(MEM);
        const visited = new Uint8Array(MEM);
        const refs = new Map();
        const need = new Set();
        let traced = false;

        function addRef(k, kind, from) {
            let r = refs.get(k);
            if (!r) refs.set(k, (r = { callers: [], access: [] }));
            r[kind].push(from);
        }

        function trace(entry, from) {
            traced = true;
            entry &= 0xFFFF;
            const ek = key(owner[entry], entry);
            need.add(ek);
            addRef(ek, 'callers', from);
            const work = [entry];
            while (work.length) {
                let i = work.pop();
                for (;;) {
                    const s = owner[i];
                    if (!s) break;
                    const op = OPS[mem[i]];
                    if (op.code === 0 || op.jam || (op.illegal && !opts.illegal)) break;
                    if (visited[i]) break;
                    const T = S[s - 1];
                    const off = i - T.seg.start;
                    if (T.fmt[off]) break;
                    visited[i] = 1;
                    if (i + op.len > MEM || (op.len > 1 && !owner[i + 1]) || (op.len > 2 && !owner[i + 2])) {
                        warn(`Instruction goes past end of memory at $${h4(i)}`);
                        break;
                    }
                    T.ilen[off] = op.len;
                    const lo = mem[i + 1], hi = mem[i + 2];
                    const fromKey = key(s, i);
                    let t = -1;
                    switch (op.mode) {
                        case 'rel': t = (i + 2 + (lo < 128 ? lo : lo - 256)) & 0xFFFF; break;
                        case 'zp': case 'zpx': case 'zpy': case 'izx': case 'izy': t = lo; break;
                        case 'abs': case 'abx': case 'aby': case 'ind': t = lo | (hi << 8); break;
                    }
                    if (t >= 0) {
                        T.tseg[off] = owner[t];
                        need.add(key(owner[t], t));
                    }
                    const tk = key(owner[t], t);
                    if (op.mn === 'rts' || op.mn === 'rti') break;
                    if (op.mn === 'jmp') {
                        if (op.mode === 'ind') {
                            addRef(tk, 'access', fromKey);
                            const t2 = (t & 0xFF00) | ((t + 1) & 0xFF);  // NMOS page wrap
                            if (owner[t] && owner[t2]) {
                                const dest = mem[t] | (mem[t2] << 8);
                                need.add(key(owner[dest], dest));
                                addRef(key(owner[dest], dest), 'callers', fromKey);
                                work.push(dest);
                            } else {
                                warn(`Indirect JMP references undefined memory at $${h4(i)}`);
                            }
                        } else {
                            addRef(tk, 'callers', fromKey);
                            work.push(t);
                        }
                        break;
                    }
                    if (op.mn === 'jsr' || op.branch) {
                        addRef(tk, 'callers', fromKey);
                        work.push(t);
                    } else if (t >= 0) {
                        addRef(tk, 'access', fromKey);
                    }
                    i += op.len;
                    if (i > 0xFFFF) break;
                }
            }
        }

        function pointer(lo, hi, d) {
            if (!owner[lo] || !owner[hi]) {
                // Vectors in symbol sets commonly point into ROM that is not loaded.
                if (d.type === 'vector' && !owner[lo] && !owner[hi]) return -1;
                warn(`${d.type} ${specString(d)}: pointer at $${h4(lo)} is in undefined memory`);
                return -1;
            }
            const t = mem[lo] | (mem[hi] << 8);
            const ts = owner[t];
            need.add(key(ts, t));
            const Tl = S[owner[lo] - 1], Th = S[owner[hi] - 1];
            Tl.ptr.set(lo - Tl.seg.start, { t, ts, part: '<', other: hi });
            Th.ptr.set(hi - Th.seg.start, { t, ts, part: '>', other: lo });
            return t;
        }

        function enter(dirs) {
            for (const d of dirs) {
                if (d.type !== 'address' && d.type !== 'codeptr') continue;
                const split = d.hi !== undefined;
                for (let off = 0; off <= d.range; off += split ? 1 : 2) {
                    const lo = d.addr + off;
                    const hi = split ? d.hi + off : lo + 1;
                    if (hi > 0xFFFF) break;
                    const t = pointer(lo, hi, d);
                    if (t >= 0 && d.type === 'codeptr') trace(t, `-P ${h4(hi)}_${h4(lo)}`);
                }
            }
            for (const d of dirs) {
                if (d.type === 'code') trace(d.addr, `-c ${h4(d.addr)}`);
            }
            for (const d of dirs) {
                if (d.type !== 'vector') continue;
                for (let off = 0; off < Math.max(d.range, 1); off += 2) {
                    const lo = d.addr + off;
                    if (lo + 1 > 0xFFFF) break;
                    const t = pointer(lo, lo + 1, d);
                    if (t >= 0) trace(t, `-v ${h4(lo)}`);
                }
            }
        }

        const bySeg = new Map();
        for (const d of directives) {
            if (d.seg && d.seg > segs.length) continue;
            const s = d.seg || 0;
            if (!bySeg.has(s)) bySeg.set(s, []);
            bySeg.get(s).push(d);
        }
        const auto = img.entries.map((e) => ({ type: 'code', name: e.name || null, seg: 0, addr: e.addr, range: 0 }));

        let run = null;
        for (const s of segs) {
            visited.fill(0);
            mem.set(s.data, s.start);
            owner.fill(s.index, s.start, s.end + 1);
            enter(bySeg.get(s.index) || []);
            if (s.run !== undefined) run = s;
            if (s.ini !== undefined) {
                pointer(0x2E2, 0x2E3, { type: 'ini', addr: 0x2E2, range: 0 });
                trace(s.ini, `ini_segment${s.index}`);
            }
        }
        visited.fill(0);
        if (run) {
            pointer(0x2E0, 0x2E1, { type: 'run', addr: 0x2E0, range: 0 });
            trace(run.run, `run_segment${run.index}`);
        }
        if (!traced && img.multi && segs.length) trace(segs[0].start, 'COM');
        enter(auto.concat(bySeg.get(0) || []));
        for (const d of auto) {
            if (d.name) addLabel(key(finalOwner[d.addr], d.addr), d.name, 0, 0, d);
        }

        // --- label lookup
        function autoName(k) {
            const s = keySeg(k), a = keyAddr(k);
            return (s && cover[a] > 1 ? 's' + s : '') + 'l' + h4(a);
        }
        function labelAt(k) {
            const l = labels.get(k);
            if (l) return l;
            if (need.has(k)) {
                const name = autoName(k);
                return { name, base: name, baseKey: k, off: 0, user: false };
            }
            return null;
        }
        function isCodeStart(k) {
            const T = segOf(k);
            return !!(T && T.ilen[keyAddr(k) - T.seg.start]);
        }

        return {
            img, opts, S, mem, finalOwner, cover, refs, need, labels, names, consts,
            comments, notes, operands, warnings, labelAt, isCodeStart, segOf,
        };
    }

    // ------------------------------------------------------------------
    // Listing generation. Each line is
    //   {k: kind, s: seg, a: addr, n: byte count, p: parts, c: auto comment,
    //    x: xref text, u: user comment, def: label key}
    // where parts are [class, text, targetKey?]. The exported .asm is just the
    // concatenation of the lines, so what you see is what you save.

    const IND = '    ';

    function render(model) {
        const { img, opts, S, refs, comments, notes, operands, consts } = model;
        const lines = [];
        const used = new Map();       // base label name -> key, for externs
        const usedConsts = new Map();
        const defined = new Set();
        const problems = model.warnings.slice();
        const xasm = opts.syntax !== 'mads';
        const segPrefix = img.multi;

        function refName(k) {
            if (typeof k === 'string') return k;
            const l = opts.labels && model.labelAt(k);
            if (l && !l.off) return l.name;
            return (segPrefix ? keySeg(k) + ':' : '') + h4(keyAddr(k));
        }
        function xrefs(k, which) {
            const r = refs.get(k);
            if (!r) return '';
            const out = [];
            if (which !== 'callers' && opts.access && r.access.length) {
                out.push('Access: ' + sortUniq(r.access.map(refName)).join(' '));
            }
            if (which !== 'access' && opts.callers && r.callers.length) {
                out.push('Callers: ' + sortUniq(r.callers.map(refName)).join(' '));
            }
            return out.join(' ');
        }
        // Symbol for an operand target, or null to print a number.
        function sym(ts, t) {
            if (!opts.labels) return null;
            const l = model.labelAt(key(ts, t));
            if (!l) return null;
            if (!used.has(l.base)) used.set(l.base, l.baseKey);
            return l;
        }
        function dir(text, comment) {
            lines.push({ k: 'dir', s: 0, a: -1, n: 0, p: [['dir', IND + text]], c: comment || '' });
        }

        // label definition lines for address a in segment T
        function labelLines(T, a, mid) {
            const k = key(T.seg.index, a);
            const note = notes.get(k);
            if (note && !mid) {
                for (const t of note.split('\n')) {
                    lines.push({ k: 'note', s: T.seg.index, a, n: 0, p: [['note', '; ' + t]], c: '' });
                }
            }
            if (!opts.labels) return;
            const l = model.labelAt(k);
            if (!l || l.off) return;
            if (defined.has(l.name)) {
                problems.push(`Label ${l.name} defined more than once`);
            }
            defined.add(l.name);
            if (mid) {
                lines.push({
                    k: 'mid', s: T.seg.index, a, n: 0, def: k,
                    p: [['lbl', l.name, k], ['dir', ' equ '], ['num', '*+' + mid]],
                    c: '', x: xrefs(k, 'access'),
                });
            } else {
                lines.push({ k: 'label', s: T.seg.index, a, n: 0, def: k, p: [['lbl', l.name, k]], c: '', x: xrefs(k, 'callers') });
            }
        }
        function hasLabelDef(T, a) {
            const k = key(T.seg.index, a);
            if (notes.has(k) || comments.has(k)) return true;
            if (!opts.labels) return false;
            const l = model.labelAt(k);
            return !!(l && !l.off);
        }

        function operand(T, i, op) {
            const off = i - T.seg.start;
            const mem = T.seg.data;
            const lo = mem[off + 1], hi = mem[off + 2];
            const ts = T.tseg[off];
            const ok = operands.get(key(T.seg.index, i));
            if (ok !== undefined) return [['op', ok]];
            let tgt, l, val;
            switch (op.mode) {
                case 'imp': return [];
                case 'acc': return [['op', '@']];
                case 'imm': {
                    const p = T.ptr.get(off + 1);
                    if (p) {
                        const pl = sym(p.ts, p.t);
                        if (pl) return [['pun', '#' + p.part], ['sym', pl.name, key(p.ts, p.t)]];
                    }
                    const c = consts.get(lo);
                    if (c) {
                        usedConsts.set(c, lo);
                        return [['pun', '#'], ['sym', c]];
                    }
                    return [['pun', '#'], ['num', '$' + h2(lo)]];
                }
                case 'rel': tgt = (i + 2 + (lo < 128 ? lo : lo - 256)) & 0xFFFF; val = '$' + h4(tgt); break;
                case 'zp': case 'zpx': case 'zpy': case 'izx': case 'izy': tgt = lo; val = '$' + h2(lo); break;
                default: tgt = lo | (hi << 8); val = '$' + h4(tgt);
            }
            l = sym(ts, tgt);
            const tk = key(ts, tgt);
            const v = l ? ['sym', l.name, tk] : ['num', val, tk];
            const ab = xasm && forceAbs(op, hi) ? [['pun', 'a:']] : [];
            switch (op.mode) {
                case 'zpx': case 'abx': return ab.concat([v, ['pun', ',x']]);
                case 'zpy': case 'aby': return ab.concat([v, ['pun', ',y']]);
                case 'izx': return [['pun', '('], v, ['pun', ',x)']];
                case 'izy': return [['pun', '('], v, ['pun', '),y']];
                case 'ind': return [['pun', '('], v, ['pun', ')']];
                default: return ab.concat([v]);
            }
        }

        // Absolute addressing of a zero page address must be forced, or the
        // assembler would pick the shorter zero page encoding.
        function forceAbs(op, hi) {
            return (op.mode === 'abs' || op.mode === 'abx' || op.mode === 'aby') && hi === 0;
        }

        function bytesComment(T, a, n) {
            const off = a - T.seg.start;
            const b = Array.from(T.seg.data.subarray(off, off + n), h2);
            return `${h4(a)}: ${n > 8 ? b.slice(0, 8).join(' ') + ' ...' : b.join(' ')}`;
        }

        function dataLine(T, a, n, parts, extra) {
            const k = key(T.seg.index, a);
            lines.push({
                k: 'data', s: T.seg.index, a, n, p: [['pun', IND]].concat(parts),
                c: bytesComment(T, a, n) + (extra ? ' ' + extra : ''),
                x: xrefs(k, 'access'), u: comments.get(k),
            });
        }

        function segmentBody(T) {
            const seg = T.seg;
            const { start, end, data } = seg;
            const perLine = Math.max(1, opts.dataPerLine | 0);
            for (let a = start; a <= end;) {
                const off = a - start;
                const len = T.ilen[off];
                const bitjmp = data[off] === 0x2C && a + 1 <= end && T.ilen[off + 1] &&
                    (refs.get(key(seg.index, a + 1)) || { callers: [] }).callers.length > 0;
                if (len && !bitjmp && a + len - 1 <= end) {
                    labelLines(T, a);
                    for (let m = 1; m < len; m++) labelLines(T, a + m, m);
                    const op = OPS[data[off]];
                    const parts = operand(T, a, op);
                    const k = key(seg.index, a);
                    const mn = !xasm && forceAbs(op, data[off + 2]) && !operands.has(k) ? op.mn + '.a' : op.mn;
                    lines.push({
                        k: 'ins', s: seg.index, a, n: len,
                        p: [['pun', IND], ['mn', mn]].concat(parts.length ? [['pun', ' ']].concat(parts) : []),
                        c: bytesComment(T, a, len), x: xrefs(k, 'access'), u: comments.get(k),
                        ill: op.illegal || undefined,
                    });
                    a += len;
                    continue;
                }
                labelLines(T, a);
                const f = T.fmt[off];
                const p = T.ptr.get(off);
                const lineEnd = (max) => {
                    // last address that may share a line with a
                    let b = a;
                    while (b < end && b - a + 1 < max) {
                        const o = b + 1 - start;
                        if (T.ilen[o] || T.ptr.has(o) || T.fmt[o] !== f || hasLabelDef(T, b + 1)) break;
                        b++;
                    }
                    return b;
                };
                if (bitjmp) {
                    dataLine(T, a, 1, [['dir', 'dta '], ['num', '$2C']], '<--- Bit Jump');
                    a++;
                } else if (p) {
                    const l = sym(p.ts, p.t);
                    const tv = l ? ['sym', l.name, key(p.ts, p.t)] : ['num', '$' + h4(p.t), key(p.ts, p.t)];
                    if (p.part === '<' && p.other === a + 1 && a + 1 <= end && !T.ilen[off + 1] && !hasLabelDef(T, a + 1)) {
                        dataLine(T, a, 2, [['dir', 'dta '], ['pun', 'a('], tv, ['pun', ')']]);
                        a += 2;
                    } else {
                        dataLine(T, a, 1, [['dir', 'dta '], ['pun', p.part], tv]);
                        a++;
                    }
                } else if (f === FMT.text) {
                    const b = lineEnd(Math.max(1, opts.textPerLine | 0));
                    const enc = encodeText(data.subarray(off, b - start + 1));
                    dataLine(T, a, b - a + 1, [['dir', 'dta ']].concat(
                        enc.split(/,(?=(?:[^']*'[^']*')*[^']*$)/).flatMap((t, i) =>
                            (i ? [['pun', ',']] : []).concat([[t[0] === 'c' ? 'str' : 'num', t]]))));
                    a = b + 1;
                } else if (f === FMT.word && a < end && !T.ilen[off + 1] && !hasLabelDef(T, a + 1)) {
                    let b = lineEnd(perLine * 2);
                    if ((b - a) % 2 === 0) b--;
                    const parts = [['dir', 'dta ']];
                    for (let w = a; w < b; w += 2) {
                        if (w > a) parts.push(['pun', ',']);
                        parts.push(['pun', 'a('], ['num', '$' + h4(data[w - start] | (data[w - start + 1] << 8))], ['pun', ')']);
                    }
                    dataLine(T, a, b - a + 1, parts);
                    a = b + 1;
                } else {
                    // fill runs
                    let run = 1;
                    if (opts.fillMin > 1) {
                        while (a + run <= end && data[off + run] === data[off] && !T.ilen[off + run] &&
                            !T.ptr.has(off + run) && T.fmt[off + run] === f && !hasLabelDef(T, a + run)) run++;
                    }
                    if (opts.fillMin > 1 && run >= opts.fillMin) {
                        dataLine(T, a, run, [['dir', ':' + run + ' dta '], ['num', '$' + h2(data[off])]]);
                        a += run;
                        continue;
                    }
                    let b = lineEnd(perLine);
                    // keep a following fill run whole
                    if (opts.fillMin > 1) {
                        for (let c = a + 1; c <= b; c++) {
                            let r = 1;
                            while (c + r <= end && r < opts.fillMin && data[c + r - start] === data[c - start]) r++;
                            if (r >= opts.fillMin) { b = c - 1; break; }
                        }
                    }
                    const parts = [['dir', 'dta ']];
                    for (let c = a; c <= b; c++) {
                        if (c > a) parts.push(['pun', ',']);
                        parts.push(['num', '$' + h2(data[c - start])]);
                    }
                    dataLine(T, a, b - a + 1, parts);
                    a = b + 1;
                }
            }
        }

        function runIni(T, which) {
            const p = T.ptr.get(which === 'run' ? 0 : 0);
            const l = p && sym(p.ts, p.t);
            const t = word(T.seg.data, 0);
            return l ? ['sym', l.name, key(p.ts, p.t)] : ['num', '$' + h4(t)];
        }

        // --- prelude
        if (!xasm && img.multi) dir('opt h-');
        for (const pl of img.prelude) {
            if (pl.xasmOnly && !xasm) continue;
            dir(pl.text, pl.comment);
        }

        let prevEnd = -2;   // xasm merges a segment into a directly preceding one
        let hOff = false;
        for (const T of S) {
            const seg = T.seg;
            const contiguous = seg.start === prevEnd + 1;
            prevEnd = seg.end;
            if (img.multi) {
                lines.push({
                    k: 'seg', s: seg.index, a: seg.start, n: 0,
                    p: [['note', `${IND};------------------------- Segment ${seg.index}: $${h4(seg.start)}-$${h4(seg.end)}`]],
                    c: '',
                });
                if (!xasm) {
                    if (seg.ffff) dir('dta a($FFFF)', 'Segment header');
                    dir(`dta a($${h4(seg.start)}),a($${h4(seg.hdrEnd)})`);
                    dir(`org $${h4(seg.start)}`);
                    segmentBody(T);
                    continue;
                }
                if ((contiguous || seg.hdrEnd !== seg.end) && !seg.kind) {
                    // Write the header by hand so it stays a separate segment
                    // (or keeps the end address of a truncated one).
                    if (!hOff) dir('opt h-');
                    hOff = true;
                    if (seg.ffff) dir('dta a($FFFF)', 'Segment header');
                    dir(`dta a($${h4(seg.start)}),a($${h4(seg.hdrEnd)})`);
                    dir(`org $${h4(seg.start)}`);
                    segmentBody(T);
                    continue;
                }
                if (hOff) dir('opt h+');
                hOff = false;
                if (seg.kind === 'run' || seg.kind === 'ini') {
                    if (seg.ffff && seg.index > 1) {
                        dir('opt h-');
                        dir('dta a($FFFF)', 'Segment header');
                        dir('opt h+');
                    }
                    const v = runIni(T, seg.kind);
                    lines.push({ k: 'dir', s: seg.index, a: seg.start, n: 2, p: [['dir', IND + seg.kind + ' '], v], c: '' });
                    continue;
                }
                dir(`org ${seg.ffff ? 'f:' : ''}$${h4(seg.start)}`, `start ${h4(seg.start)} end ${h4(seg.end)}`);
            } else {
                dir(`org $${h4(seg.start)}`);
            }
            segmentBody(T);
        }

        if (img.extra && img.extra.length) {
            dir('; Corrupted segment');
            if (xasm) dir('opt h-');
            for (let i = 0; i < img.extra.length; i += 8) {
                dir('dta ' + Array.from(img.extra.subarray(i, i + 8), (b) => '$' + h2(b)).join(','));
            }
        }

        // --- externs and constants go at the top
        const head = [];
        if (opts.labels && opts.extern) {
            const ext = [];
            for (const [name, k] of used) {
                if (defined.has(name)) continue;
                ext.push([keyAddr(k), name, k]);
            }
            ext.sort((x, y) => x[0] - y[0] || (x[1] < y[1] ? -1 : 1));
            for (const [a, name, k] of ext) {
                head.push({
                    k: 'equ', s: keySeg(k), a, n: 0, def: k,
                    p: [['lbl', name, k], ['dir', ' equ '], ['num', '$' + hx(a)]],
                    c: '', x: xrefs(k), u: comments.get(k),
                });
            }
        }
        for (const [name, v] of usedConsts) {
            if (defined.has(name) || used.has(name)) continue;
            head.push({ k: 'equ', s: 0, a: -1, n: 0, p: [['sym', name], ['dir', ' equ '], ['num', '$' + h2(v)]], c: 'constant' });
        }
        const all = head.concat(lines);

        // --- index: (seg, addr) -> line
        const lineOf = S.map((T) => new Int32Array(T.seg.data.length).fill(-1));
        const firstLine = new Map();
        all.forEach((ln, i) => {
            if (ln.k === 'equ' || ln.k === 'seg') {
                if (!firstLine.has(key(ln.s, ln.a))) firstLine.set(key(ln.s, ln.a), i);
                return;
            }
            if (!ln.s || ln.a < 0) return;
            const T = S[ln.s - 1];
            const fk = key(ln.s, ln.a);
            if (!firstLine.has(fk)) firstLine.set(fk, i);
            for (let m = 0; m < ln.n; m++) lineOf[ln.s - 1][ln.a - T.seg.start + m] = i;
        });

        return { lines: all, lineOf, firstLine, problems, defined, used };
    }

    // One line of assembly source, according to the comment options.
    function lineText(ln, opts) {
        let src = ln.p.map((p) => p[1]).join('');
        const cm = [];
        if (ln.k === 'label' || ln.k === 'equ' || ln.k === 'mid') {
            if (ln.x) cm.push(ln.x);
        } else if (ln.k === 'ins' || ln.k === 'data') {
            if (opts.comments) {
                cm.push(ln.c);
                if (ln.x) cm.push(ln.x);
            }
        } else if (ln.c) {
            cm.push(ln.c);
        }
        if (ln.u) cm.push(ln.u.replace(/\n/g, ' '));
        if (!cm.length) return src;
        if (ln.k === 'label') {
            src += '\t'.repeat((3 - (src.length >> 3)) || 1);
            return src + '; ' + cm.join(' ');
        }
        return src + '\t\t; ' + cm.join(' ');
    }

    function asmText(listing, opts) {
        return listing.lines.map((ln) => lineText(ln, opts)).join('\n') + '\n';
    }

    // ------------------------------------------------------------------
    // Directive editing. All functions return a new directive array.

    function covers(d, a) {
        return a >= d.addr && a <= d.addr + d.range;
    }

    // Remove [lo, hi] from the ranges of matching directives.
    function subtract(dirs, types, seg, lo, hi, keepNames) {
        const out = [];
        for (const d of dirs) {
            if (!types.includes(d.type) || (d.seg || 0) !== seg || d.hi !== undefined) {
                out.push(d);
                continue;
            }
            const a = d.addr, b = d.addr + d.range;
            if (b < lo || a > hi) {
                out.push(d);
                continue;
            }
            if (a < lo) out.push(Object.assign({}, d, { range: lo - 1 - a }));
            if (b > hi) out.push(Object.assign({}, d, { addr: hi + 1, range: b - hi - 1, name: null }));
            if (a >= lo && d.name && keepNames) {
                out.push({ type: 'label', name: d.name, seg: d.seg || 0, addr: a, range: 0 });
            }
        }
        return out;
    }

    function setName(dirs, seg, addr, name, labelInfo) {
        let out = dirs.slice();
        // Rename the directive that defines the existing exact label, if it is ours.
        if (labelInfo && labelInfo.user && labelInfo.dir && out.includes(labelInfo.dir) && !labelInfo.off &&
            labelInfo.dir.addr === addr) {
            const i = out.indexOf(labelInfo.dir);
            if (!name && out[i].type === 'label') out.splice(i, 1);
            else out[i] = Object.assign({}, out[i], { name: name || null });
            return out;
        }
        out = out.filter((d) => !(d.type === 'label' && d.addr === addr && (d.seg || 0) === seg));
        if (name) out.push({ type: 'label', name, seg, addr, range: 0 });
        return out;
    }

    function markCode(dirs, seg, lo, hi) {
        // Trim user data from the entry point onward (to the end of the data
        // block when only a single address is selected).
        let end = hi;
        if (lo === hi) {
            for (const d of dirs) {
                if (DATA_TYPES.includes(d.type) && (d.seg || 0) === seg && covers(d, lo)) {
                    end = Math.max(end, d.addr + d.range);
                }
            }
        }
        let out = subtract(dirs, DATA_TYPES.concat(['address', 'codeptr', 'vector']), seg, lo, end, true);
        // A code directive takes over the name of a label at the same address.
        const li = out.findIndex((d) => d.type === 'label' && d.addr === lo && (d.seg || 0) === seg && !d.range);
        if (!out.some((d) => d.type === 'code' && d.addr === lo && (d.seg || 0) === seg)) {
            const name = li >= 0 ? out[li].name : null;
            if (li >= 0) out.splice(li, 1);
            out.push({ type: 'code', name, seg, addr: lo, range: 0 });
        }
        return out;
    }

    function markData(dirs, seg, lo, hi, type) {
        let out = subtract(dirs, DATA_TYPES.concat(['address', 'codeptr', 'vector']), seg, lo, hi, true);
        out = codeToLabels(out, seg, lo, hi);
        out.push({ type: type || 'data', name: null, seg, addr: lo, range: hi - lo });
        return out;
    }

    function markPointers(dirs, seg, lo, hi, type) {
        const count = Math.max(1, Math.floor((hi - lo + 1) / 2));
        const end = lo + count * 2 - 1;
        let out = subtract(dirs, DATA_TYPES.concat(['address', 'codeptr', 'vector']), seg, lo, end, true);
        out = codeToLabels(out, seg, lo, end);
        out.push({ type, name: null, seg, addr: lo, range: count * 2 - 1 });
        return out;
    }

    function codeToLabels(dirs, seg, lo, hi) {
        const out = [];
        for (const d of dirs) {
            if (d.type === 'code' && (d.seg || 0) === seg && d.addr >= lo && d.addr <= hi) {
                if (d.name) out.push({ type: 'label', name: d.name, seg, addr: d.addr, range: d.range });
            } else {
                out.push(d);
            }
        }
        return out;
    }

    function undefine(dirs, seg, lo, hi) {
        let out = subtract(dirs, DATA_TYPES.concat(['address', 'codeptr', 'vector']), seg, lo, hi, true);
        out = codeToLabels(out, seg, lo, hi);
        return out.filter((d) => !(d.type === 'operand' && (d.seg || 0) === seg && d.addr >= lo && d.addr <= hi) &&
            !(d.hi !== undefined && (d.seg || 0) === seg && d.addr >= lo && d.addr <= hi));
    }

    function setText(dirs, type, seg, addr, text) {
        const out = dirs.filter((d) => !(d.type === type && d.addr === addr && (d.seg || 0) === seg));
        if (text) out.push({ type, name: null, seg, addr, range: 0, text });
        return out;
    }

    function setConstant(dirs, value, name) {
        const out = dirs.filter((d) => !(d.type === 'constant' && (d.addr & 0xFF) === value));
        if (name) out.push({ type: 'constant', name, seg: 0, addr: value, range: 0 });
        return out;
    }

    // ------------------------------------------------------------------
    // Projects

    function toBase64(bytes) {
        if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
        let s = '';
        for (let i = 0; i < bytes.length; i += 0x8000) {
            s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
        }
        return btoa(s);
    }

    function fromBase64(str) {
        if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(str, 'base64'));
        const s = atob(str);
        const out = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
        return out;
    }

    function newProject() {
        return { xdis: 1, binary: null, options: defaultOptions(), includes: [], directives: [] };
    }

    // Directives from enabled includes followed by the project's own. Earlier
    // definitions win, so the project's labels override symbol sets.
    function allDirectives(project) {
        const out = project.directives.slice();
        for (const inc of project.includes || []) {
            if (inc.enabled === false) continue;
            if (!inc.parsed) inc.parsed = parseDop(inc.text, inc.name).directives;
            out.push(...inc.parsed);
        }
        return out;
    }

    function serializeProject(project, bytes, embed) {
        const p = {
            xdis: 1,
            binary: project.binary && Object.assign({}, project.binary, { data: undefined }),
            options: project.options,
            includes: (project.includes || []).map((i) => ({ name: i.name, enabled: i.enabled !== false, text: i.text })),
            directives: project.directives.map(directiveString),
        };
        if (embed && bytes && p.binary) p.binary.data = toBase64(bytes);
        return JSON.stringify(p, null, 1);
    }

    function deserializeProject(json) {
        const p = typeof json === 'string' ? JSON.parse(json) : json;
        if (!p || p.xdis !== 1) throw new Error('Not an xdis project file');
        const project = newProject();
        Object.assign(project.options, p.options || {});
        project.binary = p.binary ? Object.assign({}, p.binary) : null;
        let bytes = null;
        if (project.binary && project.binary.data) {
            bytes = fromBase64(project.binary.data);
            delete project.binary.data;
        }
        project.includes = (p.includes || []).map((i) => ({ name: i.name, enabled: i.enabled !== false, text: i.text }));
        project.directives = (p.directives || []).map((s) => {
            const d = parseDirectiveLine(s);
            if (!d) throw new Error('Bad directive: ' + s);
            return d;
        });
        return { project, bytes };
    }

    return {
        OPS, h2, h4, hx, key, keySeg, keyAddr, encodeText, LABEL_RE,
        detectType, loadImage, analyze, render, asmText, lineText,
        parseDop, exportDop, dedupeImported, parseDirectiveLine, directiveString, specString,
        defaultOptions, newProject, allDirectives, serializeProject, deserializeProject,
        toBase64, fromBase64,
        edit: { setName, markCode, markData, markPointers, undefine, setText, setConstant, subtract },
        CLI_TYPES, EXT_TYPES, DATA_TYPES, POINTER_TYPES,
    };
});
