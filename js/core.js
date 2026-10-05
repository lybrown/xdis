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

    // Parts for a text `dta`: c'...' runs and numbers, each tagged with the
    // address of its first byte so single characters can be picked out.
    function textParts(data, from, to, addr) {
        const parts = [];
        let str = '', strAt = 0;
        const flush = () => {
            if (!str) return;
            if (parts.length) parts.push(['pun', ',']);
            parts.push(['str', "c'" + str + "'", undefined, strAt]);
            str = '';
        };
        for (let o = from; o <= to; o++) {
            const b = data[o];
            if (b >= 0x20 && b < 0x7F && b !== 0x27) {
                if (!str) strAt = addr + o - from;
                str += String.fromCharCode(b);
            } else {
                flush();
                if (parts.length) parts.push(['pun', ',']);
                parts.push(['num', '$' + h2(b), undefined, addr + o - from]);
            }
        }
        flush();
        return parts;
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
            img.warnings.push({ msg: `Segment at $${h4(start)} runs past $FFFF; truncated`, k: key(img.segments.length + 1, start) });
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
                img.warnings.push({ msg: `Incomplete segment header at byte ${segstart}`, extra: true });
                img.extra = bytes.subarray(segstart);
                break;
            }
            const len = end - start + 1;
            if (len < 0) {
                img.warnings.push({ msg: `Segment length is negative at byte ${segstart}: ${len}`, extra: true });
                img.extra = bytes.subarray(segstart);
                break;
            }
            const data = bytes.subarray(i, i + len);
            i += len;
            const seg = addSegment(img, start, data, { ffff, hdrEnd: end, offset: segstart });
            if (data.length < len) {
                img.warnings.push({ msg: `Segment ${seg.index} past EOF at byte ${segstart}`, k: key(seg.index, start) });
            }
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
    const EXT_TYPES = ['label', 'text', 'word', 'comment', 'note', 'operand', 'relocate', 'hi', 'lo'];
    const DATA_TYPES = ['data', 'text', 'word'];
    const POINTER_TYPES = ['vector', 'address', 'codeptr'];
    const FMT = { data: 1, text: 2, word: 3, pointer: 4 };
    const DIR_KINDS = { code: 1, data: 1, vector: 1, constant: 1, address: 1, codeptr: 1, label: 1, text: 1, word: 1, relocate: 1, hi: 1, lo: 1 };

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
        if (d.type === 'relocate') return `relocate ${specString(d)} $${hx(d.run)}`;
        if (d.type === 'hi' || d.type === 'lo') return `${d.type} ${specString(d)}${d.target !== undefined ? ' $' + hx(d.target) : ''}`;
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
        if (type === 'relocate') {
            // relocate [name=][seg:]$LOAD+LEN-1 $RUN
            const r = /^(\S+)\s+\$?([0-9a-fA-F]{1,4})$/.exec(m[2]);
            if (!r) throw new Error(`Bad relocate: ${m[2]} (expected e.g. relocate $5600+1FFF $A000)`);
            const d = parseSpec(type, r[1]);
            if (d.hi !== undefined) throw new Error('relocate takes a single address range');
            d.run = parseInt(r[2], 16);
            if (d.run + d.range > 0xFFFF) throw new Error(`relocate: $${hx(d.run)}+${hx(d.range)} runs past $FFFF`);
            return d;
        }
        if (type === 'hi' || type === 'lo') {
            // hi [seg:]$ADDR[+N] [$TARGET]: byte(s) at ADDR are the high (low)
            // byte of TARGET, which defaults to $XX00 for hi
            const r = /^(\S+)(?:\s+\$?([0-9a-fA-F]{1,4}))?$/.exec(m[2]);
            if (!r) throw new Error(`Bad ${type}: ${m[2]} (expected e.g. ${type} $4801${type === 'lo' ? ' $4380' : ''})`);
            const d = parseSpec(type, r[1]);
            if (d.hi !== undefined) throw new Error(`${type} takes a single address`);
            if (r[2] !== undefined) d.target = parseInt(r[2], 16);
            if (type === 'lo' && d.target === undefined) throw new Error('lo needs the full target address, e.g. lo $4805 $4380');
            if (d.target !== undefined && d.range) throw new Error(`${type} with a target applies to a single byte`);
            return d;
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
            dataPerLine: 16,
            textPerLine: 32,
            fillMin: 32,           // collapse runs of identical bytes into :N dta; 0 = off
        };
    }

    // Split relocated blocks ("org r:") out of the segments that load them.
    // Each block becomes a piece: a segment in its own right whose start is
    // the run address, appended after the real segments. Its load range is a
    // hole in the parent segment.
    function relocations(img, directives, warn) {
        const real = img.segments;
        const loadOwner = new Int16Array(MEM);
        for (const s of real) loadOwner.fill(s.index, s.start, s.end + 1);
        const pieces = [];
        for (const d of directives) {
            if (d.type !== 'relocate') continue;
            const parent = d.seg ? real[d.seg - 1] : real[loadOwner[d.addr] - 1];
            if (!parent || d.addr < parent.start || d.addr + d.range > parent.end) {
                warn(`relocate ${specString(d)}: the block must lie within one loaded segment`, undefined, d);
                continue;
            }
            const len = d.range + 1;
            const clash = pieces.find((p) => p.parent === parent.index && d.addr <= p.load + p.data.length - 1 && p.load <= d.addr + d.range);
            if (clash) {
                warn(`relocate ${specString(d)} overlaps relocate ${specString(clash.dir)}`, undefined, d);
                continue;
            }
            const off = d.addr - parent.start;
            pieces.push({
                index: real.length + pieces.length + 1,
                start: d.run, end: d.run + d.range,
                data: parent.data.subarray(off, off + len),
                ffff: false, reloc: true, load: d.addr, parent: parent.index, dir: d,
            });
        }
        const holesOf = new Map();
        for (const p of pieces) {
            if (!holesOf.has(p.parent)) holesOf.set(p.parent, []);
            holesOf.get(p.parent).push(p);
        }
        for (const list of holesOf.values()) list.sort((x, y) => x.load - y.load);
        // Directives on load addresses inside a block apply to the block at
        // its run address. A global directive only does when no other segment
        // loads that address (with the block moved out, that one is there).
        const otherLoads = (a, parent) => real.some((s) => s.index !== parent && a >= s.start && a <= s.end);
        const toRun = (d) => {
            if (d.type === 'relocate') return d;
            for (const p of pieces) {
                const n = p.data.length;
                if (d.addr < p.load || d.addr >= p.load + n) continue;
                if (d.seg ? d.seg !== p.parent : otherLoads(d.addr, p.parent)) continue;
                const t = Object.assign({}, d, { addr: p.start + d.addr - p.load, seg: d.seg ? p.index : 0, orig: d });
                if (d.hi !== undefined && d.hi >= p.load && d.hi < p.load + n) t.hi = p.start + d.hi - p.load;
                return t;
            }
            return d;
        };
        return { pieces, holesOf, loadOwner, toRun };
    }

    function analyze(img, directives, opts) {
        // Each warning is {msg, k?: address key, dir?: directive text} so the
        // UI can jump to where it applies.
        const warnings = [];
        const warn = (msg, k, d) => warnings.push({ msg, k, dir: d && d.type in DIR_KINDS ? directiveString(d) : undefined });
        const real = img.segments;
        const R = relocations(img, directives, warn);
        directives = directives.map(R.toRun);
        const segs = real.concat(R.pieces);
        // load order: each segment followed by the blocks relocated out of it
        const order = [];
        for (const s of real) order.push(s, ...(R.holesOf.get(s.index) || []));
        const finalOwner = new Int16Array(MEM);
        const cover = new Uint8Array(MEM);
        for (const s of order) {
            const holes = R.holesOf.get(s.index) || [];
            for (let a = s.start; a <= s.end; a++) {
                if (holes.length && holes.some((p) => a >= p.load && a < p.load + p.data.length)) continue;
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
        const resolveSeg = (d, a) => (d.seg && d.seg <= segs.length ? d.seg : d.seg ? -1 : finalOwner[a]);
        const segOf = (k) => S[keySeg(k) - 1];

        // --- labels from directives (first exact definition wins)
        const labels = new Map();
        const names = new Map();
        const consts = new Map();
        const comments = new Map();
        const notes = new Map();
        const operands = new Map();
        const nameOwner = new Map();     // label name -> key of its first definition
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
                warn(`${d.type} ${specString(d)}: no segment ${d.seg}`, undefined, d);
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
            // A symbol set can't reuse a name defined earlier (by the project
            // or a higher priority set): its directive still counts for
            // tracing, it just doesn't name anything.
            const owner = nameOwner.get(d.name);
            if (owner === undefined) nameOwner.set(d.name, base);
            else if (owner !== base && d.from) continue;
            for (let off = 0; off <= d.range; off++) {
                const a = d.addr + off;
                if (a > 0xFFFF) { warn(`Out of range ${d.type}: ${specString(d)}`, undefined, d); break; }
                addLabel(key(resolveSeg(d, a), a), d.name, off, base, d);
            }
        }
        for (const [k, l] of labels) {
            if (l.off) continue;
            const prev = names.get(l.name);
            if (prev !== undefined && prev !== k) {
                warn(`Label ${l.name} is defined at both $${h4(keyAddr(prev))} and $${h4(keyAddr(k))}`, k, l.dir);
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
                        warn(`Instruction goes past end of memory at $${h4(i)}`, key(s, i));
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
                                warn(`Indirect JMP references undefined memory at $${h4(i)}`, key(s, i));
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
                warn(`${d.type} ${specString(d)}: pointer at $${h4(lo)} is in undefined memory`,
                    key(owner[lo] || owner[hi], owner[lo] ? lo : hi), d);
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

        // Where each directive-made caller ("-P 3C64_3C62", "-v FFFA", ...)
        // comes from: address keys to go to, or the code directive's address.
        const pseudoRefs = new Map();
        const pseudo = (str, v) => { if (!pseudoRefs.has(str)) pseudoRefs.set(str, v); return str; };

        function enter(dirs) {
            for (const d of dirs) {
                if (d.type !== 'address' && d.type !== 'codeptr') continue;
                const split = d.hi !== undefined;
                for (let off = 0; off <= d.range; off += split ? 1 : 2) {
                    const lo = d.addr + off;
                    const hi = split ? d.hi + off : lo + 1;
                    if (hi > 0xFFFF) break;
                    const t = pointer(lo, hi, d);
                    if (t >= 0 && d.type === 'codeptr') {
                        trace(t, pseudo(`-P ${h4(hi)}_${h4(lo)}`, { keys: [key(owner[lo], lo), key(owner[hi], hi)] }));
                    }
                }
            }
            for (const d of dirs) {
                if (d.type === 'code') trace(d.addr, pseudo(`-c ${h4(d.addr)}`, { addr: d.addr }));
            }
            for (const d of dirs) {
                if (d.type !== 'vector') continue;
                for (let off = 0; off < Math.max(d.range, 1); off += 2) {
                    const lo = d.addr + off;
                    if (lo + 1 > 0xFFFF) break;
                    const t = pointer(lo, lo + 1, d);
                    if (t >= 0) trace(t, pseudo(`-v ${h4(lo)}`, { keys: [key(owner[lo], lo)] }));
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
        for (const s of real) {
            visited.fill(0);
            mem.set(s.data, s.start);
            owner.fill(s.index, s.start, s.end + 1);
            const pieces = R.holesOf.get(s.index) || [];
            for (const p of pieces) owner.fill(0, p.load, p.load + p.data.length);
            for (const p of pieces) {
                mem.set(p.data, p.start);
                owner.fill(p.index, p.start, p.end + 1);
            }
            enter(bySeg.get(s.index) || []);
            for (const p of pieces) enter(bySeg.get(p.index) || []);
            if (s.run !== undefined) run = s;
            if (s.ini !== undefined) {
                pointer(0x2E2, 0x2E3, { type: 'ini', addr: 0x2E2, range: 0 });
                trace(s.ini, pseudo(`ini_segment${s.index}`, { keys: [key(owner[0x2E2], 0x2E2)] }));
            }
        }
        visited.fill(0);
        if (run) {
            pointer(0x2E0, 0x2E1, { type: 'run', addr: 0x2E0, range: 0 });
            trace(run.run, pseudo(`run_segment${run.index}`, { keys: [key(owner[0x2E0], 0x2E0)] }));
        }
        if (!traced && img.multi && real.length) trace(real[0].start, pseudo('COM', { keys: [key(real[0].index, real[0].start)] }));
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

        // The segment an address refers to from code in segment T: T itself if
        // it loads that address (overlays!), otherwise whatever is there last.
        function segFor(T, a) {
            const sg = T.seg;
            if (a >= sg.start && a <= sg.end &&
                !(R.holesOf.get(sg.index) || []).some((p) => a >= p.load && a < p.load + p.data.length)) return sg.index;
            return finalOwner[a];
        }

        // hi/lo: single bytes that are one half of an address
        for (const d of directives) {
            if (d.type !== 'hi' && d.type !== 'lo') continue;
            for (let off = 0; off <= d.range; off++) {
                const a = d.addr + off;
                const s = resolveSeg(d, a);
                if (s <= 0) {
                    warn(`${directiveString(d)}: $${h4(a)} is not loaded`, undefined, d);
                    break;
                }
                const T = S[s - 1];
                const o = a - T.seg.start;
                const b = T.seg.data[o];
                const t = d.target !== undefined ? d.target : b << 8;
                if ((d.type === 'hi' ? t >> 8 : t & 0xFF) !== b) {
                    warn(`${directiveString(d)}: the byte at $${h4(a)} is $${h2(b)}, not the ${d.type === 'hi' ? 'high' : 'low'} byte of $${h4(t)}`, key(s, a), d);
                    continue;
                }
                const ts = segFor(T, t);
                need.add(key(ts, t));
                T.ptr.set(o, { t, ts, part: d.type === 'hi' ? '>' : '<', other: -1 });
            }
        }

        for (const sg of findRelocations()) {
            warnings.push({
                msg: `Code at $${h4(sg.dir.addr)}-$${h4(sg.dir.addr + sg.dir.range)} is copied to $${h4(sg.dir.run)} ` +
                    `by the loop at $${h4(keyAddr(sg.at))} and run there — click to relocate it`,
                k: sg.at, suggest: sg.dir,
            });
        }

        // Find copy loops that move code somewhere it is then called or
        // jumped to, and suggest a relocation for each:
        //   lda SRC,x / sta DST,x / dex / bpl|bne       (indexed, e.g. mva:rpl)
        //   lda (p),y / sta (q),y / iny / bne ... inc p+1 / inc q+1 / lda q+1 / cmp #END / bne
        // Decoded traced instructions of a segment, in address order.
        function instructionsOf(T) {
            const ins = [];
            const data = T.seg.data;
            for (let o = 0; o < T.ilen.length; o++) {
                if (!T.ilen[o]) continue;
                const op = OPS[data[o]];
                ins.push({ a: T.seg.start + o, op, lo: data[o + 1], hi: data[o + 2], w: data[o + 1] | (data[o + 2] << 8) });
            }
            return ins;
        }

        function findRelocations() {
            const out = [];
            for (const T of S) {
                const ins = instructionsOf(T);
                for (let j = 0; j + 3 < ins.length; j++) {
                    const s1 = ins[j], s2 = ins[j + 1];
                    if (s1.op.mn !== 'lda' || s2.op.mn !== 'sta' || s1.op.mode !== s2.op.mode) continue;
                    let found = null;
                    if (s1.op.mode === 'abx' || s1.op.mode === 'aby') found = indexedCopy(ins, j);
                    else if (s1.op.mode === 'izy') found = pointerCopy(ins, j);
                    if (!found) continue;
                    const { load, len, run } = found;
                    if (len < 16 || load === run || load + len > MEM || run + len > MEM) continue;
                    const par = R.loadOwner[load];
                    if (!par || R.loadOwner[load + len - 1] !== par) continue;
                    if (R.pieces.some((p) => p.parent === par && load < p.load + p.data.length && p.load < load + len)) continue;
                    // the copy must be entered: something calls or jumps into it
                    let entered = false;
                    for (const [k, r] of refs) {
                        const a = keyAddr(k);
                        if (a >= run && a < run + len && r.callers.some((c) => typeof c === 'number')) { entered = true; break; }
                    }
                    if (!entered) continue;
                    const cover1 = real.filter((x) => load >= x.start && load <= x.end).length;
                    out.push({
                        at: key(T.seg.index, s1.a),
                        dir: { type: 'relocate', name: null, seg: cover1 > 1 ? par : 0, addr: load, range: len - 1, run },
                    });
                }
            }
            return out;
        }

        function indexedCopy(ins, j) {
            const s1 = ins[j], s2 = ins[j + 1];
            const reg = s1.op.mode === 'abx' ? 'x' : 'y';
            const step = ins[j + 2], br = ins[j + 3];
            if (!step || !br || !br.op.branch) return null;
            const back = (br.a + 2 + (br.lo < 128 ? br.lo : br.lo - 256)) & 0xFFFF;
            if (back > s1.a || back < s1.a - 4) return null;
            let n = null;
            for (let b = j - 1; b >= Math.max(0, j - 6); b--) {
                if (ins[b].op.mn === 'ld' + reg && ins[b].op.mode === 'imm') { n = ins[b].lo; break; }
            }
            if (n === null) return null;
            if (step.op.mn === 'de' + reg && br.op.mn === 'bpl') return { load: s1.w, run: s2.w, len: n + 1 };
            if (step.op.mn === 'de' + reg && br.op.mn === 'bne') return { load: s1.w + 1, run: s2.w + 1, len: n };
            return null;
        }

        function pointerCopy(ins, j) {
            const s1 = ins[j], s2 = ins[j + 1];
            const p = s1.lo, q = s2.lo;
            const iny = ins[j + 2], br = ins[j + 3];
            if (!iny || iny.op.mn !== 'iny' || !br || br.op.mn !== 'bne') return null;
            // track immediates stored into zero page before the loop
            const zp = new Map();
            let acc = null;
            for (let b = Math.max(0, j - 30); b < j; b++) {
                const x = ins[b];
                if (x.op.mn === 'lda') acc = x.op.mode === 'imm' ? x.lo : null;
                else if (x.op.mn === 'sta' && x.op.mode === 'zp') zp.set(x.lo, acc);
                else if (x.op.mn === 'sta' && x.op.mode === 'abs' && x.hi === 0) zp.set(x.lo, acc);
                else if (x.op.branch || x.op.mn === 'jsr' || x.op.mn === 'jmp') acc = null;
            }
            const val = (z) => (zp.get(z) != null && zp.get(z + 1) != null ? zp.get(z) | (zp.get(z + 1) << 8) : null);
            const src = val(p), dst = val(q);
            if (src === null || dst === null) return null;
            // end condition: lda p+1|q+1 / cmp #END shortly after
            for (let b = j + 4; b < Math.min(ins.length - 1, j + 12); b++) {
                const x = ins[b], c = ins[b + 1];
                if (x.op.mn !== 'lda' || (x.op.mode !== 'zp' && x.op.mode !== 'abs') || c.op.mn !== 'cmp' || c.op.mode !== 'imm') continue;
                if (x.lo === q + 1) return { load: src, run: dst, len: ((c.lo << 8) - dst) & 0xFFFF };
                if (x.lo === p + 1) return { load: src, run: dst, len: ((c.lo << 8) - src) & 0xFFFF };
            }
            return null;
        }

        for (const sg of findPointerPairs()) {
            warnings.push({ msg: sg.msg, k: sg.at, suggest: sg.dir });
        }

        // Find pairs of immediates that are the two halves of one address:
        //   lda #hi / sta P+1 ... lda #lo / sta P        (any order, also ldx/ldy, stx/sty)
        //   ldx #hi / ldy #lo / jsr ROUTINE              (e.g. SETVBV)
        // and suggest showing them as #>label / #<label. A pair is only
        // suggested with evidence that it is an address: P is used as a
        // pointer, or the address lands on code or a label.
        function findPointerPairs() {
            // Atari only: page registers take the high byte of an address, and
            // the display list pointers are words (C64 has other chips there)
            const atari = img.type !== 'prg';
            const PAGE_REGS = atari ? new Map([[0xD407, 'PMBASE'], [0xD409, 'CHBASE'], [0x2F4, 'CHBAS']]) : new Map();
            const ptrUse = new Set(atari ? [0xD402, 0x230] : []);   // zero page / absolute pointers in use
            const jumpVec = new Set();       // ... used by jmp (P) or declared as vectors
            const dataPtr = new Set();       // ... used by (P),y / (P,x)
            for (const d of directives) {
                // word-sized locations: pointers, vectors and 2+ byte ranges
                if ((POINTER_TYPES.includes(d.type) || d.range >= 1) && d.hi === undefined && d.type !== 'relocate') ptrUse.add(d.addr);
                if (d.type === 'vector') jumpVec.add(d.addr);
            }
            const jumpAt = new Map();        // operand address of jmp/jsr abs -> instruction
            const lists = S.map((T) => instructionsOf(T));
            lists.forEach((ins) => {
                for (const x of ins) {
                    if (x.op.mode === 'izy' || x.op.mode === 'izx') { ptrUse.add(x.lo); dataPtr.add(x.lo); }
                    if (x.op.mode === 'ind') { ptrUse.add(x.w); jumpVec.add(x.w); }
                    // writing a jmp/jsr operand is self-modifying code: a code pointer
                    if ((x.op.mn === 'jmp' || x.op.mn === 'jsr') && x.op.mode === 'abs') {
                        ptrUse.add(x.a + 1);
                        jumpVec.add(x.a + 1);
                        if (!jumpAt.has(x.a + 1)) jumpAt.set(x.a + 1, x);
                    }
                }
            });
            // only loaded memory counts as evidence; labels from symbol sets
            // on unloaded addresses say nothing about these bytes
            const isTarget = (t, T) => {
                const ts = segFor(T, t);
                if (!ts) return null;
                const k = key(ts, t);
                return isCodeStart(k) ? 'code' : labelAt(k) ? 'label' : null;
            };
            const nameAt = (T, a) => {
                const l = labelAt(key(segFor(T, a), a));
                return l && !l.off ? l.name : null;
            };
            const isIO = (a) => a >= 0xD000 && a <= 0xDFFF;
            const out = [];
            const seen = new Set();
            const WRITES = {
                a: /^(lda|adc|sbc|and|ora|eor|pla|txa|tya|asl|lsr|rol|ror|lax|alr|anc|arr|ane|lxa|las)$/,
                x: /^(ldx|inx|dex|tax|tsx|lax|sbx|lxa|las)$/,
                y: /^(ldy|iny|dey|tay)$/,
            };
            S.forEach((T, ti) => {
                const ins = lists[ti];
                const segIdx = T.seg.index;
                let regs = {};
                let stores = new Map();         // P -> {v, at, i}
                const reset = () => {
                    // a low byte written into a jump operand on its own
                    for (const [P, st] of stores) if (jumpAt.has(P) && !stores.has(P + 1)) lowOnly(T, st, P);
                    regs = {};
                    stores = new Map();
                };
                ins.forEach((x, i) => {
                    // a branch target starts a new block
                    const r = refs.get(key(segIdx, x.a));
                    if (r && r.callers.length) reset();
                    const mn = x.op.mn;
                    const reg = mn[2];
                    if ((mn === 'lda' || mn === 'ldx' || mn === 'ldy') && x.op.mode === 'imm') {
                        regs[reg] = { v: x.lo, at: x.a + 1, i };
                    } else if ((mn === 'sta' || mn === 'stx' || mn === 'sty') && (x.op.mode === 'zp' || x.op.mode === 'abs')) {
                        const P = x.op.mode === 'zp' ? x.lo : x.w;
                        if (regs[reg] && PAGE_REGS.has(P)) page(T, regs[reg], P);
                        if (regs[reg]) {
                            stores.set(P, Object.assign({ i }, regs[reg]));
                            pair(T, stores.get(P - 1), stores.get(P), P - 1, 'store');
                            pair(T, stores.get(P), stores.get(P + 1), P, 'store');
                        } else {
                            stores.delete(P);
                        }
                    } else if (mn === 'jsr') {
                        // register pair passed to a routine: try Y/X and A/X, A/Y orders
                        for (const [lo, hi] of [['y', 'x'], ['a', 'x'], ['a', 'y']]) {
                            if (regs[lo] && regs[hi]) pair(T, regs[lo], regs[hi], -1, x.w);
                        }
                        reset();
                        return;
                    } else if (x.op.branch || mn === 'jmp' || mn === 'rts' || mn === 'rti' || mn === 'brk') {
                        reset();
                        return;
                    }
                    for (const g of ['a', 'x', 'y']) {
                        if (WRITES[g].test(mn) && !((mn === 'ld' + g) && x.op.mode === 'imm')) delete regs[g];
                    }
                });
                reset();
            });
            return out;

            // An immediate written only into the low byte of a jmp/jsr operand
            // keeps the page: try the writer's page and the operand's current
            // high byte, and take the one that lands on code.
            function lowOnly(T, st, P) {
                if (seen.has(st.at) || overridden(T, st.at)) return;
                const Tb = segOf(key(T.seg.index, st.at));
                if (!Tb || Tb.ptr.has(st.at - Tb.seg.start)) return;
                const TP = S[segFor(T, P + 1) - 1];
                const pages = [(st.at - 1) >> 8];
                if (TP) pages.push(TP.seg.data[P + 1 - TP.seg.start]);
                const hp = pages.find((h) => isTarget(st.v | (h << 8), T) === 'code');
                if (hp === undefined) return;
                const t = st.v | (hp << 8);
                seen.add(st.at);
                const jx = jumpAt.get(P);
                const pname = nameAt(T, P) || '$' + h4(P);
                const tname = nameAt(T, t) || 'l' + h4(t);
                out.push({
                    at: key(T.seg.index, st.at - 1),
                    dir: { type: 'lo', name: null, seg: cover[st.at] > 1 ? T.seg.index : 0, addr: st.at, range: 0, target: t },
                    msg: `#$${h2(st.v)} at $${h4(st.at - 1)} is the low byte of $${h4(t)}, the new target of ${jx.op.mn} at ` +
                        `$${h4(jx.a)} (stored into ${pname}) — click to show it as #<${tname}`,
                });
            }

            // an immediate stored into a page register: the page of a label or
            // of loaded memory
            // an instruction whose operand is overridden is already handled
            function overridden(T, at) {
                return operands.has(key(T.seg.index, at - 1));
            }

            function page(T, r, P) {
                if (!r.v || seen.has(r.at) || overridden(T, r.at)) return;
                const t = r.v << 8;
                const l = labelAt(key(segFor(T, t), t));
                if (!segFor(T, t) && !(l && l.user)) return;
                const Tb = segOf(key(T.seg.index, r.at));
                if (!Tb || Tb.ptr.has(r.at - Tb.seg.start)) return;
                seen.add(r.at);
                const name = l && !l.off ? l.name : 'l' + h4(t);
                out.push({
                    at: key(T.seg.index, r.at - 1),
                    dir: { type: 'hi', name: null, seg: cover[r.at] > 1 ? T.seg.index : 0, addr: r.at, range: 0 },
                    msg: `#$${h2(r.v)} at $${h4(r.at - 1)} stored into ${PAGE_REGS.get(P)} is the page of $${h4(t)} ` +
                        `— click to show it as #>${name}`,
                });
            }

            function pair(T, lo, hi, P, via) {
                if (!lo || !hi || lo.at === hi.at || Math.abs(lo.i - hi.i) > 12) return;
                if (overridden(T, lo.at) || overridden(T, hi.at)) return;
                const t = lo.v | (hi.v << 8);
                if (t < 0x100) return;
                const target = isTarget(t, T);
                const viaJsr = typeof via === 'number';
                if (viaJsr) {
                    if (!target) return;                 // registers: need loaded code or a label
                } else if (!ptrUse.has(P)) {
                    if (!target || isIO(P)) return;      // adjacent hardware registers are not pointers
                }
                if (seen.has(lo.at) || seen.has(hi.at)) return;
                // already shown as a pointer?
                const Tl = segOf(key(T.seg.index, lo.at)), Th = segOf(key(T.seg.index, hi.at));
                if (!Tl || !Th || Tl.ptr.has(lo.at - Tl.seg.start) || Th.ptr.has(hi.at - Th.seg.start)) return;
                seen.add(lo.at);
                seen.add(hi.at);
                const scoped = (a) => (cover[a] > 1 ? T.seg.index : 0);
                // code pointer for jump vectors, or code targets not reached as data
                const code = viaJsr ? target === 'code'
                    : jumpVec.has(P) || (target === 'code' && !dataPtr.has(P));
                const dir = { type: code ? 'codeptr' : 'address', name: null, seg: scoped(lo.at), addr: lo.at, range: 0, hi: hi.at };
                const tname = nameAt(T, t) || 'l' + h4(t);
                let where;
                if (viaJsr) {
                    where = `passed to ${nameAt(T, via) || '$' + h4(via)}`;
                } else {
                    const jx = jumpAt.get(P);
                    where = `stored into ${nameAt(T, P) || '$' + h4(P)}${jx ? `, the operand of ${jx.op.mn} at $${h4(jx.a)}` : ''}`;
                }
                out.push({
                    at: key(T.seg.index, Math.min(lo.at, hi.at) - 1),
                    dir,
                    msg: `#$${h2(hi.v)} at $${h4(hi.at - 1)} and #$${h2(lo.v)} at $${h4(lo.at - 1)} form $${h4(t)} (${where}) ` +
                        `— click to show them as #>${tname} / #<${tname}`,
                });
            }
        }

        // Run address key for a load address inside a relocated block.
        function loadToRun(a) {
            for (const p of R.pieces) {
                if (a >= p.load && a < p.load + p.data.length) return key(p.index, p.start + a - p.load);
            }
            return null;
        }

        return {
            img, opts, S, mem, finalOwner, cover, refs, need, labels, names, consts,
            comments, notes, operands, warnings, labelAt, isCodeStart, segOf,
            pieces: R.pieces, holesOf: R.holesOf, loadOwner: R.loadOwner, mapDirective: R.toRun, loadToRun, pseudoRefs,
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
        const forwardZ = [];          // [part, label] needing z: if defined later
        const problems = model.warnings.slice();
        const xasm = opts.syntax !== 'mads';
        const segPrefix = img.multi;

        function refName(k) {
            if (typeof k === 'string') return k;
            const l = opts.labels && model.labelAt(k);
            if (l && !l.off) return l.name;
            const T = S[keySeg(k) - 1];
            // relocated code needs no segment unless its run address is ambiguous
            const pre = segPrefix && !(T && T.seg.reloc && model.cover[keyAddr(k)] <= 1);
            return (pre ? keySeg(k) + ':' : '') + h4(keyAddr(k));
        }
        // label name -> keys of the name+N offsets into its range
        const offsetKeys = new Map();
        for (const [k, l] of model.labels) {
            if (!l.off) continue;
            if (!offsetKeys.has(l.base)) offsetKeys.set(l.base, []);
            offsetKeys.get(l.base).push(k);
        }
        // References to a label, including those to offsets into its range.
        function refsFor(k) {
            const r = refs.get(k);
            const l = model.labelAt(k);
            const extra = l && !l.off ? offsetKeys.get(l.name) : null;
            if (!extra) return r;
            const m = { callers: r ? r.callers.slice() : [], access: r ? r.access.slice() : [] };
            for (const ok of extra) {
                const o = refs.get(ok);
                if (o) {
                    m.callers.push(...o.callers);
                    m.access.push(...o.access);
                }
            }
            return m.callers.length || m.access.length ? m : null;
        }
        function xrefs(k, which, range) {
            const r = range ? refsFor(k) : refs.get(k);
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
                problems.push({ msg: `Label ${l.name} defined more than once`, k, dir: l.dir ? directiveString(l.dir) : undefined });
            }
            defined.add(l.name);
            if (mid) {
                lines.push({
                    k: 'mid', s: T.seg.index, a, n: 0, def: k,
                    p: [['lbl', l.name, k], ['dir', ' equ '], ['num', '*+' + mid]],
                    c: '', x: xrefs(k, 'access', true),
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
            if (ok !== undefined) {
                overrideRefs(ok);
                return [['op', ok]];
            }
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
            let ab = xasm && forceAbs(op, hi) ? [['pun', 'a:']] : [];
            if (xasm && l && (op.mode === 'zp' || op.mode === 'zpx' || op.mode === 'zpy') && !defined.has(l.base)) {
                // xasm treats a label it hasn't seen yet as absolute; if the
                // label turns out to be defined later, force zero page.
                const z = ['pun', ''];
                forwardZ.push([z, l.base]);
                ab = [z];
            }
            switch (op.mode) {
                case 'zpx': case 'abx': return ab.concat([v, ['pun', ',x']]);
                case 'zpy': case 'aby': return ab.concat([v, ['pun', ',y']]);
                case 'izx': return [['pun', '('], v, ['pun', ',x)']];
                case 'izy': return [['pun', '('], v, ['pun', '),y']];
                case 'ind': return [['pun', '('], v, ['pun', ')']];
                default: return ab.concat([v]);
            }
        }

        // Labels named in an operand override count as references, so their
        // equates are emitted. Auto label names like l4300 work too.
        function overrideRefs(text) {
            for (const name of text.match(/[A-Za-z_?@][\w?@]*/g) || []) {
                if (used.has(name)) continue;
                const k = model.names.get(name);
                if (k !== undefined) { used.set(name, k); continue; }
                const m = /^(?:s(\d+))?l([0-9A-F]{4})$/.exec(name);
                if (m) {
                    const a = parseInt(m[2], 16);
                    used.set(name, key(m[1] ? +m[1] : model.finalOwner[a], a));
                    continue;
                }
                for (const [v, c] of consts) if (c === name) usedConsts.set(c, v);
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

        // A segment's body, with any relocated blocks emitted inline where
        // they are loaded: "org r:RUN" (xasm) or "org RUN,*" (MADS), then a
        // plain org back to the load address after the block.
        function segmentBody(T) {
            const seg = T.seg;
            let a = seg.start;
            for (const p of model.holesOf.get(seg.index) || []) {
                if (p.load > a) bodyRange(T, a, p.load - 1);
                const n = p.data.length;
                lines.push({
                    k: 'dir', s: p.index, a: p.start, n: 0,
                    p: [['dir', `${IND}org ${xasm ? 'r:' : ''}$${h4(p.start)}${xasm ? '' : ',*'}`]],
                    c: `relocated: loaded at ${h4(p.load)}-${h4(p.load + n - 1)}, runs at ${h4(p.start)}-${h4(p.end)}`,
                });
                bodyRange(S[p.index - 1], p.start, p.end);
                a = p.load + n;
                if (a <= seg.end) dir(`org $${h4(a)}`, 'end of relocated block');
            }
            if (a <= seg.end) bodyRange(T, a, seg.end);
        }

        function bodyRange(T, from, end) {
            const seg = T.seg;
            const { start, data } = seg;
            const perLine = Math.max(1, opts.dataPerLine | 0);
            for (let a = from; a <= end;) {
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
                    dataLine(T, a, 1, [['dir', 'dta '], ['num', '$2C', undefined, a]], '<--- Bit Jump');
                    a++;
                } else if (p) {
                    const l = sym(p.ts, p.t);
                    const tv = l ? ['sym', l.name, key(p.ts, p.t), a] : ['num', '$' + h4(p.t), key(p.ts, p.t), a];
                    if (p.part === '<' && p.other === a + 1 && a + 1 <= end && !T.ilen[off + 1] && !hasLabelDef(T, a + 1)) {
                        dataLine(T, a, 2, [['dir', 'dta '], ['pun', 'a('], tv, ['pun', ')']]);
                        a += 2;
                    } else {
                        dataLine(T, a, 1, [['dir', 'dta '], ['pun', p.part], tv]);
                        a++;
                    }
                } else if (f === FMT.text) {
                    const b = lineEnd(Math.max(1, opts.textPerLine | 0));
                    dataLine(T, a, b - a + 1, [['dir', 'dta ']].concat(textParts(data, off, b - start, a)));
                    a = b + 1;
                } else if (f === FMT.word && a < end && !T.ilen[off + 1] && !hasLabelDef(T, a + 1)) {
                    let b = lineEnd(perLine * 2);
                    if ((b - a) % 2 === 0) b--;
                    const parts = [['dir', 'dta ']];
                    for (let w = a; w < b; w += 2) {
                        if (w > a) parts.push(['pun', ',']);
                        parts.push(['pun', 'a('], ['num', '$' + h4(data[w - start] | (data[w - start + 1] << 8)), undefined, w], ['pun', ')']);
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
                        dataLine(T, a, run, [['dir', ':' + run + ' dta '], ['num', '$' + h2(data[off]), undefined, a]]);
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
                        parts.push(['num', '$' + h2(data[c - start]), undefined, c]);
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
            if (seg.reloc) continue;   // emitted inside its parent
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

        for (const [z, base] of forwardZ) if (defined.has(base)) z[1] = 'z:';

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
                    c: '', x: xrefs(k, undefined, true), u: comments.get(k),
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

        return { lines: all, lineOf, firstLine, problems, defined, used, refName, refsFor };
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
        const own = labelInfo && labelInfo.dir && (labelInfo.dir.orig || labelInfo.dir);
        if (labelInfo && labelInfo.user && own && out.includes(own) && !labelInfo.off && labelInfo.dir.addr === addr) {
            const i = out.indexOf(own);
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

    // Add relocation d and move the directives on its load addresses to the
    // matching run addresses, so edits made on the relocated code line up.
    function addRelocation(dirs, img, d) {
        const real = img.segments;
        const loadOwner = new Int16Array(MEM);
        for (const s of real) loadOwner.fill(s.index, s.start, s.end + 1);
        const parent = d.seg || loadOwner[d.addr];
        const n = d.range + 1;
        const pieceIndex = real.length + dirs.filter((x) => x.type === 'relocate').length + 1;
        const loaded = (a) => real.some((s) => a >= s.start && a <= s.end);
        const otherLoads = (a) => real.some((s) => s.index !== parent && a >= s.start && a <= s.end);
        const inside = (x) => x.type !== 'relocate' && x.addr >= d.addr && x.addr < d.addr + n &&
            (x.seg ? x.seg === parent : !otherLoads(x.addr));
        const out = dirs.map((x) => {
            if (!inside(x)) return x;
            const ra = d.run + x.addr - d.addr;
            const nx = Object.assign({}, x, { addr: ra, seg: loaded(ra) ? pieceIndex : 0 });
            if (x.hi !== undefined && x.hi >= d.addr && x.hi < d.addr + n) nx.hi = d.run + x.hi - d.addr;
            return nx;
        });
        out.push(d);
        return out;
    }

    // Remove relocation d, moving directives on its run addresses back to
    // the load addresses.
    function removeRelocation(dirs, model, d) {
        const p = model.pieces.find((x) => x.dir === d);
        const out = dirs.filter((x) => x !== d);
        if (!p) return out;
        const real = model.img.segments;
        const loadedBy = (a) => real.filter((s) => a >= s.start && a <= s.end).length;
        return out.map((x) => {
            if (x.type === 'relocate' || x.addr < p.start || x.addr > p.end) return x;
            if ((x.seg || model.finalOwner[x.addr]) !== p.index) return x;
            const la = p.load + x.addr - p.start;
            const nx = Object.assign({}, x, { addr: la, seg: loadedBy(la) > 1 ? p.parent : 0 });
            if (x.hi !== undefined && x.hi >= p.start && x.hi <= p.end) nx.hi = p.load + x.hi - p.start;
            return nx;
        });
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
            if (!inc.parsed) {
                inc.parsed = parseDop(inc.text, inc.name).directives.map((d) => Object.assign(d, { from: inc.name }));
            }
            out.push(...inc.parsed);
        }
        return out;
    }

    // Directive types that can change which bytes are traced as code.
    const TRACE_TYPES = ['code', 'data', 'text', 'word', 'vector', 'address', 'codeptr', 'relocate'];

    // True when two analyses have the same instructions in every segment.
    function sameCode(a, b) {
        if (a.S.length !== b.S.length) return false;
        for (let i = 0; i < a.S.length; i++) {
            const x = a.S[i].ilen, y = b.S[i].ilen;
            if (x.length !== y.length) return false;
            for (let o = 0; o < x.length; o++) if (x[o] !== y[o]) return false;
        }
        return true;
    }

    // Find project directives that are not needed to get the current code/
    // data split. Removing *all* of the ones reported removable together
    // leaves the traced code unchanged. Candidates are tried greedily:
    // unnamed directives first, pointers and vectors last, and each test also
    // drops the ones already found removable. Work is done one directive per
    // step() so callers can spread it out; step() returns {d, removable} or
    // null when finished.
    function redundancyScan(img, project, model) {
        const all = allDirectives(project);
        const rank = (d) => (d.name ? 1 : 0) + (POINTER_TYPES.includes(d.type) ? 2 : 0);
        const order = project.directives
            .map((d, i) => [d, i])
            .filter(([d]) => TRACE_TYPES.includes(d.type))
            .sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1])
            .map(([d]) => d);
        const removed = new Set();
        let i = 0;
        return {
            total: order.length,
            done: () => i,
            step() {
                if (i >= order.length) return null;
                const d = order[i++];
                const removable = (d.type !== 'relocate' && !touchesLoaded(model, model.mapDirective(d))) ||
                    sameCode(model, analyze(img, all.filter((x) => x !== d && !removed.has(x)), project.options));
                if (removable) removed.add(d);
                return { d, removable };
            },
        };
    }

    // Directives that only touch unloaded memory cannot affect tracing.
    function touchesLoaded(model, d) {
        const span = d.type === 'code' ? 0 : d.type === 'vector' ? d.range | 1 : d.range;
        for (let o = 0; o <= span; o++) {
            if (d.addr + o <= 0xFFFF && model.cover[d.addr + o]) return true;
            if (d.hi !== undefined && d.hi + o <= 0xFFFF && model.cover[d.hi + o]) return true;
        }
        return false;
    }

    function serializeProject(project, bytes, embed) {
        const p = {
            xdis: 1,
            binary: project.binary && Object.assign({}, project.binary, { data: undefined }),
            options: project.options,
            includes: (project.includes || []).map((i) => ({
                name: i.name, enabled: i.enabled !== false, text: i.text,
                ...(i.custom ? { custom: true } : {}),
            })),
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
        project.includes = (p.includes || []).map((i) => ({
            name: i.name, enabled: i.enabled !== false, text: i.text, ...(i.custom ? { custom: true } : {}),
        }));
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
        redundancyScan, sameCode, TRACE_TYPES,
        toBase64, fromBase64,
        edit: { setName, markCode, markData, markPointers, undefine, setText, setConstant, subtract, addRelocation, removeRelocation },
        CLI_TYPES, EXT_TYPES, DATA_TYPES, POINTER_TYPES,
    };
});
