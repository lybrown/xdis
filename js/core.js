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
        if (bytes.length >= 16 && String.fromCharCode(...bytes.subarray(0, 4)) === 'CART') return 'car';
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

    // ------------------------------------------------------------------
    // Atari cartridges (atari800's DOC/cart.txt). Each block of the image
    // becomes a segment at its window address; `boot` lists the blocks
    // visible at power-on, which are analyzed last so that global
    // directives (and the header vectors) refer to them.

    // regs(n) lists the bank registers as [name, address, last offset] for n
    // banks: CARTBANK selects (by the address accessed, or the value written),
    // CARTOFF disables the cartridge.
    // switch(n) describes bank switching for n blocks: {windows: [[start,
    // end], ...], byAddress(a) / byValue(v) -> [[window, segment], ...]}
    // where segment is a block's segment number (block + 1) or -1 for "off".
    const blocks = (size, at, boot, regs, sw) => ({ size, at, boot, regs: regs || (() => []), sw: sw || null });
    const swAddress = (win, offBase, offLen) => (n) => ({
        windows: [win],
        byAddress: (a) => (a >= 0xD500 && a < 0xD500 + n ? [[0, a - 0xD500 + 1]]
            : a >= offBase && a <= offBase + offLen ? [[0, -1]] : null),
    });
    // value written to $D5xx: low bits pick the block for one window
    const swValue = (win, off) => (n) => ({
        windows: [win],
        byValue: (v) => [[0, off && v & 0x80 ? -1 : (v & (n - 1)) % n + 1]],
    });
    const byValue = () => [['CARTBANK', 0xD500, 0xFF]];
    const byAddress = (off, offLen) => (n) => [['CARTBANK', 0xD500, n - 1], ['CARTOFF', off, offLen]];
    const xegs = blocks(0x2000, (i, n) => (i === n - 1 ? 0xA000 : 0x8000), (n) => [0, n - 1], byValue,
        swValue([0x8000, 0x9FFF], true));
    const williams = blocks(0x2000, () => 0xA000, () => [0], byAddress(0xD508, 7), swAddress([0xA000, 0xBFFF], 0xD508, 7));
    const atarimax128 = blocks(0x2000, () => 0xA000, () => [0], byAddress(0xD510, 0xF), swAddress([0xA000, 0xBFFF], 0xD510, 0xF));
    const atarimax1m = (boot) => blocks(0x2000, () => 0xA000, boot, byAddress(0xD580, 0x7F), swAddress([0xA000, 0xBFFF], 0xD580, 0x7F));
    const megacart = blocks(0x4000, () => 0x8000, () => [0], byValue, swValue([0x8000, 0xBFFF], true));
    // SIC!: bits 0-2 pick a 16 KB bank (blocks 2b at $8000, 2b+1 at $A000),
    // bit 5 enables the $8000 half, bit 6 disables the $A000 half
    const sic = blocks(0x2000, (i) => (i & 1 ? 0xA000 : 0x8000), () => [1], byValue, (n) => ({
        windows: [[0x8000, 0x9FFF], [0xA000, 0xBFFF]],
        byValue: (v) => {
            const b = (v & 7) % Math.max(1, n >> 1);
            return [[0, v & 0x20 ? 2 * b + 1 : -1], [1, v & 0x40 ? -1 : 2 * b + 2]];
        },
    }));
    const CART_TYPES = {
        1: ['Standard 8 KB', blocks(0x2000, () => 0xA000, () => [0])],
        2: ['Standard 16 KB', blocks(0x4000, () => 0x8000, () => [0])],
        57: ['Standard 2 KB', blocks(0x800, () => 0xB800, () => [0])],
        58: ['Standard 4 KB', blocks(0x1000, () => 0xB000, () => [0])],
        8: ['Williams 64 KB', williams], 22: ['Williams 32 KB', williams], 76: ['Williams 16 KB', williams],
        12: ['XEGS 32 KB', xegs], 13: ['XEGS 64 KB (banks 0-7)', xegs], 67: ['XEGS 64 KB (banks 8-15)', xegs],
        14: ['XEGS 128 KB', xegs], 23: ['XEGS 256 KB', xegs], 24: ['XEGS 512 KB', xegs], 25: ['XEGS 1 MB', xegs],
        33: ['Switchable XEGS 32 KB', xegs], 34: ['Switchable XEGS 64 KB', xegs], 35: ['Switchable XEGS 128 KB', xegs],
        36: ['Switchable XEGS 256 KB', xegs], 37: ['Switchable XEGS 512 KB', xegs], 38: ['Switchable XEGS 1 MB', xegs],
        41: ['Atarimax 128 KB', atarimax128],
        42: ['Atarimax 1 MB (old, boots bank $7F)', atarimax1m((n) => [n - 1])],
        75: ['Atarimax 1 MB (new)', atarimax1m(() => [0])],
        54: ['SIC! 128 KB', sic], 55: ['SIC! 256 KB', sic], 56: ['SIC! 512 KB', sic],
        26: ['MegaCart 16 KB', megacart], 27: ['MegaCart 32 KB', megacart], 28: ['MegaCart 64 KB', megacart],
        29: ['MegaCart 128 KB', megacart], 30: ['MegaCart 256 KB', megacart], 31: ['MegaCart 512 KB', megacart],
        32: ['MegaCart 1 MB', megacart], 64: ['MegaCart 2 MB', megacart],
    };
    const CART_SIZES = {
        1: 8, 2: 16, 57: 2, 58: 4, 8: 64, 22: 32, 76: 16, 12: 32, 13: 64, 67: 64, 14: 128, 23: 256, 24: 512, 25: 1024,
        33: 32, 34: 64, 35: 128, 36: 256, 37: 512, 38: 1024, 41: 128, 42: 1024, 75: 1024, 54: 128, 55: 256, 56: 512,
        26: 16, 27: 32, 28: 64, 29: 128, 30: 256, 31: 512, 32: 1024, 64: 2048,
    };

    // Supported cartridge types whose size matches `bytes` (raw dumps).
    function cartTypesFor(size) {
        return Object.keys(CART_TYPES).map(Number).filter((t) => CART_SIZES[t] * 1024 === size)
            .map((t) => ({ type: t, name: CART_TYPES[t][0] }));
    }

    function parseCart(bytes, img, cartType) {
        let data = bytes;
        if (img.type === 'car') {
            if (String.fromCharCode(...bytes.subarray(0, 4)) !== 'CART') throw new Error('Not a CAR file');
            cartType = ((bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7]) >>> 0;
            data = bytes.subarray(16);
            img.prelude.push({ text: 'opt h-' });
            img.prelude.push({ text: `dta c'CART',${Array.from(bytes.subarray(4, 16), (b) => '$' + h2(b)).join(',')}`, comment: 'CAR header' });
        } else {
            img.prelude.push({ text: 'opt h-' });
        }
        img.cartType = cartType;
        let desc = CART_TYPES[cartType];
        if (!desc) {
            img.warnings.push(`Cartridge type ${cartType} is not supported yet; showing 8 KB banks at $A000`);
            desc = ['Unknown', blocks(0x2000, () => 0xA000, () => [0])];
        }
        img.cartName = desc[0];
        const { size, at, boot, regs, sw } = desc[1];
        const n = Math.ceil(data.length / size);
        for (let i = 0; i < n; i++) {
            const seg = addSegment(img, at(i, n), data.subarray(i * size, (i + 1) * size));
            seg.bank = i;
            seg.tag = 'b' + i;
            seg.prefix = 'b' + i + '_';
        }
        img.boot = new Set(boot(n).filter((i) => i < n).map((i) => i + 1));
        // built-in labels for the bank registers; offsets in decimal so
        // CARTBANK+12 reads as bank 12
        if (sw) img.bankSwitch = sw(n);
        img.cartDirectives = regs(n).map(([name, addr, range]) =>
            ({ type: 'data', name, seg: 0, addr, range, dec: true, from: 'cartridge' }));
        // the header of the cartridge visible at power-on
        img.entries.push(
            { type: 'vector', name: null, seg: 0, addr: 0xBFFA, range: 1 },
            { type: 'vector', name: null, seg: 0, addr: 0xBFFE, range: 1 });
    }

    function loadImage(bytes, type, org, cartType) {
        const img = {
            type, org: org || 0, size: bytes.length,
            segments: [], entries: [], prelude: [], extra: null, warnings: [],
        };
        if (type === 'car' || type === 'cart') {
            parseCart(bytes, img, cartType);
            img.multi = img.banked = true;
            segTags = new Map(img.segments.map((sg) => [sg.index, sg.tag]));
            return img;
        }
        segTags = null;
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
    const EXT_TYPES = ['label', 'text', 'word', 'comment', 'note', 'operand', 'relocate', 'hi', 'lo', 'bank', 'dismiss', 'inline', 'enum', 'enumop', 'read', 'write'];
    const DATA_TYPES = ['data', 'text', 'word'];
    const POINTER_TYPES = ['vector', 'address', 'codeptr'];
    const FMT = { data: 1, text: 2, word: 3, pointer: 4 };
    const DIR_KINDS = { code: 1, data: 1, vector: 1, constant: 1, address: 1, codeptr: 1, label: 1, text: 1, word: 1, relocate: 1, hi: 1, lo: 1, bank: 1, inline: 1, enum: 1, enumop: 1, read: 1, write: 1 };
    // How an instruction uses its operand's address, for read/write names
    // (read-modify-write counts as a write; jumps and immediates as neither).
    const READ_OPS = new Set(['lda', 'ldx', 'ldy', 'cmp', 'cpx', 'cpy', 'bit', 'adc', 'sbc', 'and', 'ora', 'eor', 'lax', 'las']);
    const WRITE_OPS = new Set(['sta', 'stx', 'sty', 'sax', 'sha', 'shx', 'shy', 'tas',
        'inc', 'dec', 'asl', 'lsr', 'rol', 'ror', 'slo', 'rla', 'sre', 'rra', 'dcp', 'isc']);
    const accessOf = (op) => (op.mode === 'imm' || op.mode === 'rel' ? null : READ_OPS.has(op.mn) ? 'read' : WRITE_OPS.has(op.mn) ? 'write' : null);
    // Inline data after a jsr: how the called routine finds its end and
    // where execution continues.
    const INLINE_MODES = {
        bit7: 'text up to a byte with bit 7 set; that byte is the next instruction',
        bit7last: 'text whose last byte has bit 7 set; continues after it',
        zero: 'text ending in a zero byte; continues after it',
    };
    // The inline data after a jsr at `at` for inline directive d, reading
    // bytes with read(a) (-1 if not loaded): {end} just past the data and
    // {resume} where execution continues (-1: it doesn't), or {error}.
    function scanInline(at, d, read) {
        const a0 = at + 3;
        const n = /^\d+$/.test(d.mode) ? +d.mode : 0;
        let a = a0;
        for (;; a++) {
            if (n && a - a0 === n) break;
            const b = a <= 0xFFFF ? read(a) : -1;
            if (b < 0) return { error: 'runs into memory that is not loaded' };
            if (a - a0 > 255) return { error: 'has no end within 256 bytes' };
            if (n || a - a0 < (d.lead || 0)) continue;
            if (d.brk && b === 0) return { end: a + 1, resume: -1 };      // the routine raises an error
            if (d.mode === 'zero' ? b === 0 : b >= 0x80) {
                if (d.mode !== 'bit7') a++;
                break;
            }
        }
        return { end: a, resume: a };
    }
    const inlineModeOk = (m) => m in INLINE_MODES || (/^\d+$/.test(m) && +m >= 1 && +m <= 255);

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
    const SPEC_RE = /^(?:([A-Za-z_?@][\w?@]*)=)?(?:(b?\d+):)?\$?([0-9a-fA-F]+)(?:_([0-9a-fA-F]+))?(?:\+([0-9a-fA-F]+))?$/;

    // Segment numbers in directives: cartridge banks are written bN (bank N
    // is segment N+1). Set for the image being worked on.
    let segTags = null;
    const segNum = (t) => (t[0] === 'b' ? parseInt(t.slice(1), 10) + 1 : parseInt(t, 10));
    const segText = (n) => (segTags && segTags.get(n)) || String(n);

    function parseSpec(type, value) {
        const m = SPEC_RE.exec(value || '');
        if (!m) throw new Error(`Unrecognized ${type} address: ${value}`);
        const d = {
            type,
            name: m[1] || null,
            seg: m[2] ? segNum(m[2]) : 0,
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
        if (d.seg) s += segText(d.seg) + ':';
        s += d.hi !== undefined && d.hi !== null ? `$${hx(d.hi)}_${hx(d.addr)}` : '$' + hx(d.addr);
        if (d.range) s += '+' + hx(d.range);
        return s;
    }

    function directiveString(d) {
        if (d.type === 'relocate') return `relocate ${specString(d)} $${hx(d.run)}`;
        if (d.type === 'bank') return `bank ${specString(d)} ${d.bank}`;
        if (d.type === 'enum') return `enum ${d.enum}${d.members.map(([n, v]) => ` ${n}=$${h2(v)}`).join('')}`;
        if (d.type === 'enumop') return `enumop ${d.seg ? segText(d.seg) + ':' : ''}$${hx(d.addr)} ${d.enum}`;
        if (d.type === 'inline') return `inline ${specString(d)} ${d.mode}${d.lead ? ' lead ' + d.lead : ''}${d.brk ? ' brk' : ''}`;
        if (d.type === 'hi' || d.type === 'lo') return `${d.type} ${specString(d)}${d.target !== undefined ? ' $' + hx(d.target) : ''}`;
        if (d.type === 'comment' || d.type === 'note' || d.type === 'operand') {
            const loc = (d.seg ? segText(d.seg) + ':' : '') + '$' + hx(d.addr);
            return `${d.type} ${loc} ${d.text.replace(/\\/g, '\\\\').replace(/\n/g, '\\n')}`;
        }
        return `${d.type} ${specString(d)}${d.rts ? ' rts' : ''}`;
    }

    function parseDirectiveLine(line) {
        const m = /^\s*(\S+)\s*(.*?)\s*$/.exec(line);
        if (!m) return null;
        const type = ALIASES[m[1]] || m[1];
        if (type === 'comment' || type === 'note' || type === 'operand') {
            const t = /^(?:(b?\d+):)?\$?([0-9a-fA-F]+)(?:\s(.*))?$/.exec(m[2]);
            if (!t) throw new Error(`Bad ${type}: ${m[2]}`);
            const text = (t[3] || '').replace(/\\(n|\\)/g, (_, c) => (c === 'n' ? '\n' : '\\'));
            return { type, name: null, seg: t[1] ? segNum(t[1]) : 0, addr: parseInt(t[2], 16) & 0xFFFF, range: 0, text };
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
        if (type === 'bank') {
            // bank [seg:]$ADDR N: the operand of the instruction at ADDR
            // refers to cartridge bank N
            const r = /^(\S+)\s+(\d+)$/.exec(m[2]);
            if (!r) throw new Error(`Bad bank: ${m[2]} (expected e.g. bank b7:$A456 5)`);
            const d = parseSpec(type, r[1]);
            d.bank = parseInt(r[2], 10);
            return d;
        }
        if (type === 'enum') {
            // enum NAME [MEMBER=$VALUE ...]: a named set of byte values
            // (hex, as everywhere in .dop files)
            const r = /^(\S+)((?:\s+\S+)*)$/.exec(m[2]);
            if (!r || !LABEL_RE.test(r[1])) throw new Error(`Bad enum: ${m[2]} (expected e.g. enum color BLACK=$00 WHITE=$01)`);
            const members = [];
            for (const t of r[2].trim().split(/\s+/).filter(Boolean)) {
                const mm = /^([A-Za-z_?@][\w?@]*)=\$?([0-9a-fA-F]{1,2})$/.exec(t);
                if (!mm) throw new Error(`Bad enum member: ${t} (expected NAME=$XX)`);
                members.push([mm[1], parseInt(mm[2], 16)]);
            }
            return { type, name: null, seg: 0, addr: 0, range: 0, enum: r[1], members };
        }
        if (type === 'enumop') {
            // enumop [seg:]$ADDR ENUM: the immediate of the instruction at
            // ADDR is a value of ENUM
            const r = /^(?:(b?\d+):)?\$?([0-9a-fA-F]{1,4})\s+(\S+)$/.exec(m[2]);
            if (!r || !LABEL_RE.test(r[3])) throw new Error(`Bad enumop: ${m[2]} (expected e.g. enumop $2034 color)`);
            return { type, name: null, seg: r[1] ? segNum(r[1]) : 0, addr: parseInt(r[2], 16), range: 0, enum: r[3] };
        }
        if (type === 'inline') {
            // inline [name=][seg:]$ROUTINE MODE [lead N] [brk]: each jsr to
            // ROUTINE is followed by inline data; MODE is bit7, bit7last,
            // zero or a byte count. "lead N": the first N bytes are data
            // whatever they are (e.g. an error number); "brk": a zero byte
            // ends the text and the routine does not return (BRK errors).
            const r = /^(\S+)\s+(\w+)(?:\s+lead\s+(\d+))?(\s+brk)?$/.exec(m[2]);
            if (!r || !inlineModeOk(r[2])) throw new Error(`Bad inline: ${m[2]} (expected e.g. inline $865C bit7; modes: ${Object.keys(INLINE_MODES).join(', ')} or a byte count, then optionally lead N and brk)`);
            const d = parseSpec(type, r[1]);
            if (d.hi !== undefined || d.range) throw new Error('inline takes a single routine address');
            d.mode = r[2];
            if (r[3] !== undefined) {
                d.lead = +r[3];
                if (d.lead < 1 || d.lead > 16 || /^\d+$/.test(d.mode)) throw new Error('inline: lead is 1-16 bytes, for text modes');
            }
            if (r[4]) {
                if (!/^bit7/.test(d.mode)) throw new Error('inline: brk goes with bit7 or bit7last');
                d.brk = true;
            }
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
        if ((type === 'codeptr' || type === 'address') && /\s+rts$/.test(m[2])) {
            // "rts": the table holds each address minus one, for rts dispatch
            const d = parseSpec(type, m[2].replace(/\s+rts$/, ''));
            d.rts = true;
            return d;
        }
        if (CLI_TYPES.includes(type) || EXT_TYPES.includes(type)) {
            return parseSpec(type, m[2]);
        }
        return null;
    }

    // Parse a .dop option file. Returns directives, options and unresolved args.
    function parseDop(text, fileName) {
        const res = { directives: [], options: {}, args: [], errors: [], binary: {}, off: {} };
        text.split(/\r?\n/).forEach(function (raw, n) {
            let line = raw;
            const ext = /^\s*;xdis\s+(.*)$/.exec(line);
            if (ext) {
                line = ext[1];
                // off SET [NAMES]: the labels switched off in a symbol set
                // (the whole list: none listed means all on)
                const offm = /^off\s+(\S+)(?:\s+(.*))?$/.exec(line);
                if (offm) {
                    res.off[offm[1]] = (res.off[offm[1]] || []).concat((offm[2] || '').trim().split(/\s+/).filter(Boolean));
                    return;
                }
                // defaultoff NAMES, in a symbol set: labels that start switched off
                const defm = /^defaultoff\s+(.*)$/.exec(line);
                if (defm) {
                    res.defaultOff = (res.defaultOff || []).concat(defm[1].trim().split(/\s+/).filter(Boolean));
                    return;
                }
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
            if (inc.enabled === false) continue;
            out.push('arg ' + inc.name);
            // written out when any are off, or when the set switches some off
            // by default (so turning those on survives a round trip)
            if ((inc.off && inc.off.length) || defaultOffOf(inc.text).length) out.push(`;xdis off ${inc.name} ${(inc.off || []).join(' ')}`.trimEnd());
        }
        const b = project.binary;
        if (b) {
            out.push('type ' + b.type);
            if (b.type === 'raw') out.push('org ' + hx(b.org || 0));
        }
        for (const [dop, opt] of Object.entries(OPTION_MAP)) {
            out.push(`${dop} ${o[opt] ? 1 : 0}`);
        }
        for (const k of ['syntax', 'dataPerLine', 'fillMin', 'patternMax', 'textPerLine', 'commentColumn']) {
            out.push(`;xdis option ${k} ${o[k]}`);
        }
        if (model && model.img.cartDirectives && model.img.cartDirectives.length) {
            out.push(`; ${model.img.cartName} bank registers (built into xdis)`);
            for (const d of model.img.cartDirectives) out.push(directiveString(d));
        }
        for (const d of project.directives) {
            if (CLI_TYPES.includes(d.type) && !d.rts) {
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
    // Labels a symbol set switches off until turned on (";xdis defaultoff").
    function defaultOffOf(text) {
        const out = [];
        for (const m of (text || '').matchAll(/^\s*;xdis\s+defaultoff\s+(.*)$/gm)) out.push(...m[1].trim().split(/\s+/).filter(Boolean));
        return out;
    }

    // A symbol set as a project includes it, with its default-off labels off.
    function newInclude(name, text, extra) {
        const off = defaultOffOf(text);
        return Object.assign({ name, text, enabled: true }, off.length ? { off } : {}, extra);
    }

    // A built-in set's text changed (xdis was updated): labels it newly
    // switches off by default start off (switched-on ones it already had
    // switched off by default stay as the project has them).
    function refreshInclude(inc, text) {
        const had = new Set(defaultOffOf(inc.text));
        const add = defaultOffOf(text).filter((n) => !had.has(n));
        const off = add.length ? [...new Set((inc.off || []).concat(add))] : inc.off;
        return Object.assign({}, inc, { text, parsed: null }, off ? { off } : {});
    }

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
            commentColumn: 30,     // ; comments start in this column (padded with spaces)
            fillMin: 32,           // collapse runs of identical bytes into :N dta; 0 = off
            patternMax: 0,         // also repeated patterns up to this many bytes; 0 = off
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
            if (d.type === 'relocate' || d.type === 'enum' || d.type === 'constant') return d;    // not addresses
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
        if (img.cartDirectives) directives = directives.concat(img.cartDirectives);
        const R = relocations(img, directives, warn);
        directives = directives.map(R.toRun);
        const segs = real.concat(R.pieces);
        // Analysis order: cartridge banks visible at power-on come last, so
        // "the final memory" is the boot configuration.
        const loadOrder = img.boot ? real.filter((s) => !img.boot.has(s.index)).concat(real.filter((s) => img.boot.has(s.index))) : real;
        // load order: each segment followed by the blocks relocated out of it
        const order = [];
        for (const s of loadOrder) order.push(s, ...(R.holesOf.get(s.index) || []));
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
        const enums = new Map();         // name -> {name, byValue: value -> member, members: [[name, value]]}
        const memberOf = new Map();      // member name -> {e, v}
        const enumOps = new Map();       // instruction key -> enumop directive
        const aliases = new Map();       // key -> {read?, write?}: names used by reading / writing instructions
        const aliasNames = new Map();    // read/write name -> key
        const comments = new Map();
        const notes = new Map();
        const operands = new Map();
        const nameOwner = new Map();     // label name -> key of its first definition
        function addLabel(k, name, off, base, d) {
            const prev = labels.get(k);
            if (prev && (prev.off === 0 || off > 0)) return;
            let ref = name;
            if (off) ref = opts.rangelabels ? `${name}_${hx(off)}` : `${name}+${off > 9 && !(d && d.dec) ? '$' + hx(off) : off}`;
            const def = !off || opts.rangelabels;
            labels.set(k, { name: ref, base: def ? ref : name, baseKey: def ? k : base, off: def ? 0 : off, user: true, dir: d });
        }
        for (const d of directives) {
            if (d.seg && d.seg > segs.length) {
                warn(`${d.type} ${specString(d)}: no segment ${d.seg}`, undefined, d);
                continue;
            }
            if (d.type === 'read' || d.type === 'write') {
                // a name for the address only where instructions read (write) it
                if (!d.name) continue;
                const k = key(resolveSeg(d, d.addr), d.addr);
                const al = aliases.get(k) || {};
                if (al[d.type] || (aliasNames.has(d.name) && aliasNames.get(d.name) !== k)) continue;
                al[d.type] = d.name;
                aliases.set(k, al);
                aliasNames.set(d.name, k);
                continue;
            }
            if (d.type === 'enum') {
                const e = enums.get(d.enum) || { name: d.enum, byValue: new Map(), members: [] };
                enums.set(d.enum, e);
                for (const [n, v] of d.members) {
                    if (e.members.some(([n2]) => n2 === n)) continue;
                    e.members.push([n, v]);
                    if (!e.byValue.has(v)) e.byValue.set(v, n);
                    const prev = memberOf.get(n);
                    if (prev && prev.v !== v) warn(`Enum member ${n} is $${h2(prev.v)} in ${prev.e} and $${h2(v)} in ${d.enum}`, undefined, d);
                    else memberOf.set(n, { e: d.enum, v });
                }
                continue;
            }
            if (d.type === 'enumop') {
                enumOps.set(key(resolveSeg(d, d.addr), d.addr), d);
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
        const visited = new Set();       // (segment, address) keys traced in this pass
        const refs = new Map();
        const need = new Set();
        let traced = false;

        function addRef(k, kind, from) {
            let r = refs.get(k);
            if (!r) refs.set(k, (r = { callers: [], access: [] }));
            r[kind].push(from);
        }

        // --- cartridge bank switching: the selected banks travel with each
        // code path. A path's state is {w: per-window selection, a, x, y}
        // with known immediates in the registers. A window selection is a
        // segment, -1 (switched off) or UNKNOWN; undefined means whatever the
        // analysis order put there (the power-on banks in the final pass).
        // The machine, from the file type or the symbol sets in use
        const platform = (() => {
            const sets = directives.map((d) => String(d.from || ''));
            if (img.type === 'prg' || sets.some((f) => /(6510|vic|sid|cia)\.dop$/.test(f))) return 'c64';
            if (sets.some((f) => /bbc/i.test(f))) return 'bbc';
            if (['xex', 'sap', 'car', 'cart'].includes(img.type) ||
                sets.some((f) => /(hardware|sys|atarixl|atarifp|basic|dos)\.dop$/.test(f))) return 'atari';
            return null;
        })();

        // Acorn BRK errors: brk, an error number, a message, then a zero.
        // The end of the block (exclusive), or -1 if the bytes after the brk
        // at `at` aren't one. read(a) returns a byte or -1.
        const acornBrk = platform === 'bbc';
        const errEnds = new Set();       // keys of zeros marked only as the end of an error block
        function errorBlock(at, read) {
            if (read(at + 1) < 0) return -1;
            let a = at + 2, n = 0;
            for (; n < 256; a++, n++) {
                const b = read(a);
                if (b === 0) break;
                if (b < 0x20 || b > 0x7E) return -1;
            }
            return n && read(a) === 0 ? a + 1 : -1;
        }

        const SW = img.bankSwitch || null;
        const UNKNOWN = -2;
        const winOf = (a) => {
            if (SW) for (let w = 0; w < SW.windows.length; w++) if (a >= SW.windows[w][0] && a <= SW.windows[w][1]) return w;
            return -1;
        };
        function segAt(st, a) {
            if (st) {
                const w = winOf(a);
                if (w >= 0 && st.w[w] !== undefined) return st.w[w] === -1 ? 0 : st.w[w];
            }
            return owner[a];
        }
        const byteAt = (sg, a) => (sg === owner[a] ? mem[a] : S[sg - 1].seg.data[a - S[sg - 1].seg.start]);
        const WRITES = {
            a: /^(lda|adc|sbc|and|ora|eor|pla|txa|tya|asl|lsr|rol|ror|lax|alr|anc|arr|ane|lxa|las)$/,
            x: /^(ldx|inx|dex|tax|tsx|lax|sbx|lxa|las)$/,
            y: /^(ldy|iny|dey|tay)$/,
        };
        // bank directives: the operand of an instruction refers to bank N
        const bankOv = new Map();
        for (const d of directives) {
            if (d.type !== 'bank') continue;
            if (!img.banked || d.bank >= real.length) {
                warn(`${directiveString(d)}: no such bank`, undefined, d);
                continue;
            }
            bankOv.set(key(resolveSeg(d, d.addr), d.addr), d.bank + 1);
        }
        // inline directives: routines followed by inline data at each jsr
        const inlineAt = new Map();
        for (const d of directives) {
            if (d.type === 'inline' && inlineModeOk(d.mode)) inlineAt.set(key(resolveSeg(d, d.addr), d.addr), d);
        }
        // Mark the inline data after a jsr at `at` and return where execution
        // continues, or -1.
        function inlineData(cs, at, d) {
            const r = scanInline(at, d, (a) => {
                const sg = a <= 0xFFFF ? segAt(cs, a) : 0;
                return sg > 0 ? byteAt(sg, a) : -1;
            });
            if (r.error) {
                warn(`The inline data after jsr ${d.name || '$' + h4(d.addr)} at $${h4(at)} ${r.error}`, key(owner[at], at), d);
                return -1;
            }
            for (let x = at + 3; x < r.end; x++) {
                const T = S[segAt(cs, x) - 1];
                const o = x - T.seg.start;
                if (!T.fmt[o]) T.fmt[o] = /^\d+$/.test(d.mode) ? FMT.data : FMT.text;
            }
            return r.resume;
        }

        // a bank select by instruction op at address t ($D5xx)
        function select(st, op, t) {
            const set = (list) => { for (const [w, sg] of list) st.w[w] = sg; };
            const all = () => SW.windows.forEach((_, w) => { st.w[w] = UNKNOWN; });
            if (SW.byAddress) {
                if (op.mode === 'abs') set(SW.byAddress(t) || []);
                else all();                                    // indexed: which address?
            } else if (SW.byValue && /^st[axy]$/.test(op.mn)) {
                const v = st[op.mn[2]];
                if (v !== null && v !== undefined) set(SW.byValue(v));
                else all();
            }
        }

        // Is branch op always taken after instruction p ({op, lo})?
        const forcedFall = new Map();    // forced branch key -> the address after it
        function forcedBranch(p, op) {
            const mn = p.op.mn;
            if ((mn === 'lda' || mn === 'ldx' || mn === 'ldy') && p.op.mode === 'imm') {
                const v = p.lo;
                return op.mn === 'bne' ? v !== 0 : op.mn === 'beq' ? v === 0 : op.mn === 'bpl' ? v < 0x80 : op.mn === 'bmi' ? v >= 0x80 : false;
            }
            return (mn === 'clc' && op.mn === 'bcc') || (mn === 'sec' && op.mn === 'bcs') || (mn === 'clv' && op.mn === 'bvc');
        }

        function trace(entry, from) {
            traced = true;
            entry &= 0xFFFF;
            const st0 = SW ? { w: [], a: null, x: null, y: null } : null;
            const es = owner[entry];
            const ek = key(es, entry);
            need.add(ek);
            addRef(ek, 'callers', from);
            const work = [[entry, st0]];
            while (work.length) {
                let [i, cs] = work.pop();
                if (cs) cs = { w: cs.w.slice(), a: cs.a, x: cs.x, y: cs.y };
                let prev = null, jumpedIn = true;              // the instruction before; reached by a jump?
                for (;;) {
                    const s = segAt(cs, i);
                    if (s <= 0) break;                         // unloaded, switched off or unknown bank
                    const op = OPS[byteAt(s, i)];
                    if (op.code === 0 && acornBrk) {
                        // a BRK error: the brk is code, the error block data.
                        // The zero ending one block may be the next one's brk
                        // (the MOS shares them), so it can be claimed again.
                        const T = S[s - 1];
                        const off = i - T.seg.start;
                        const vk = key(s, i);
                        const e = (!T.fmt[off] || errEnds.has(vk)) && errorBlock(i, (x) => (x <= T.seg.end ? T.seg.data[x - T.seg.start] : -1));
                        if (e > 0) {
                            T.ilen[off] = 1;
                            T.fmt[off] = 0;
                            errEnds.delete(vk);
                            const end = e - T.seg.start;
                            for (let x = off + 1; x < end; x++) {
                                if (T.ilen[x] || T.fmt[x]) continue;
                                T.fmt[x] = FMT.text;
                                if (x === end - 1) errEnds.add(key(s, T.seg.start + x));
                            }
                        }
                        break;
                    }
                    if (op.code === 0 || op.jam || (op.illegal && !opts.illegal)) break;
                    const vk = key(s, i);
                    if (visited.has(vk)) {
                        // a branch taken as forced, now reached by a jump: the
                        // flags are unknown here, so what follows it runs too
                        if (jumpedIn && forcedFall.has(vk)) {
                            work.push([forcedFall.get(vk), cs]);
                            forcedFall.delete(vk);
                        }
                        break;
                    }
                    const T = S[s - 1];
                    const off = i - T.seg.start;
                    if (T.fmt[off]) break;
                    visited.add(vk);
                    const s1 = op.len > 1 ? segAt(cs, i + 1) : s, s2 = op.len > 2 ? segAt(cs, i + 2) : s;
                    if (i + op.len > MEM || s1 <= 0 || s2 <= 0) {
                        warn(`Instruction goes past end of memory at $${h4(i)}`, key(s, i));
                        break;
                    }
                    T.ilen[off] = op.len;
                    const lo = op.len > 1 ? byteAt(s1, i + 1) : 0, hi = op.len > 2 ? byteAt(s2, i + 2) : 0;
                    const fromKey = key(s, i);
                    let t = -1;
                    switch (op.mode) {
                        case 'rel': t = (i + 2 + (lo < 128 ? lo : lo - 256)) & 0xFFFF; break;
                        case 'zp': case 'zpx': case 'zpy': case 'izx': case 'izy': t = lo; break;
                        case 'abs': case 'abx': case 'aby': case 'ind': t = lo | (hi << 8); break;
                    }
                    let ts = 0, unknownBank = false;
                    if (t >= 0) {
                        ts = bankOv.has(fromKey) ? bankOv.get(fromKey) : segAt(cs, t);
                        if (ts === UNKNOWN) unknownBank = true;
                        if (ts < 0) ts = owner[t];
                        T.tseg[off] = ts;
                        need.add(key(ts, t));
                    }
                    const tk = key(ts, t);
                    // the state a jump target is traced with: a bank directive
                    // selects that bank in the target's window
                    const into = () => {
                        if (!cs || !bankOv.has(fromKey) || winOf(t) < 0) return cs;
                        const ns = { w: cs.w.slice(), a: cs.a, x: cs.x, y: cs.y };
                        ns.w[winOf(t)] = ts;
                        return ns;
                    };
                    // registers and bank selects on this path
                    if (cs) {
                        if (t >= 0xD500 && t <= 0xD5FF && op.mode !== 'imm' && op.mode !== 'rel') select(cs, op, t);
                        if ((op.mn === 'lda' || op.mn === 'ldx' || op.mn === 'ldy') && op.mode === 'imm') cs[op.mn[2]] = lo;
                        else for (const g of ['a', 'x', 'y']) if (WRITES[g].test(op.mn)) cs[g] = null;
                    }
                    const jump = op.mn === 'jmp' || op.mn === 'jsr' || op.branch;
                    if (jump && unknownBank && op.mode !== 'ind') {
                        const w = SW.windows[winOf(t)];
                        warnings.push({
                            msg: `${op.mn} $${h4(t)} at $${h4(i)} goes into the bank window $${h4(w[0])}-$${h4(w[1])}, ` +
                                'but which bank is selected there is unknown — click to choose it',
                            k: fromKey, bankFix: { seg: s, addr: i, target: t },
                        });
                        if (op.mn === 'jmp') break;
                        i += op.len;
                        continue;
                    }
                    if (op.mn === 'rts' || op.mn === 'rti') break;
                    if (op.mn === 'jmp') {
                        if (op.mode === 'ind') {
                            addRef(tk, 'access', fromKey);
                            const t2 = (t & 0xFF00) | ((t + 1) & 0xFF);  // NMOS page wrap
                            if (owner[t] && owner[t2]) {
                                const dest = mem[t] | (mem[t2] << 8);
                                need.add(key(owner[dest], dest));
                                addRef(key(owner[dest], dest), 'callers', fromKey);
                                work.push([dest, cs]);
                            } else {
                                warn(`Indirect JMP references undefined memory at $${h4(i)}`, key(s, i));
                            }
                        } else {
                            addRef(tk, 'callers', fromKey);
                            work.push([t, into()]);
                        }
                        break;
                    }
                    if (op.mn === 'jsr' || op.branch) {
                        addRef(tk, 'callers', fromKey);
                        work.push([t, into()]);
                        if (cs && op.mn === 'jsr') cs = { w: cs.w.slice(), a: null, x: null, y: null };
                        if (op.mn === 'jsr' && inlineAt.has(tk)) {
                            // the routine returns past its inline data
                            const r = inlineData(cs, i, inlineAt.get(tk));
                            if (r >= 0 && r <= 0xFFFF) {
                                const rk = key(segAt(cs, r) > 0 ? segAt(cs, r) : owner[r], r);
                                need.add(rk);
                                addRef(rk, 'callers', fromKey);
                                work.push([r, cs]);
                            }
                            break;
                        }
                    } else if (t >= 0) {
                        addRef(tk, 'access', fromKey);
                    }
                    // a branch the instruction before always takes
                    // (lda #$20 / bne, clc / bcc): what follows it isn't code
                    // on this path
                    if (op.branch && !jumpedIn && prev && forcedBranch(prev, op)) {
                        forcedFall.set(vk, i + op.len);
                        break;
                    }
                    prev = { op, lo };
                    jumpedIn = false;
                    i += op.len;
                    if (i > 0xFFFF) break;
                }
            }
        }

        function pointer(lo, hi, d) {
            if (!owner[lo] || !owner[hi]) {
                // Vectors commonly point into ROM that is not loaded, and symbol
                // sets describe the machine, not this program: no warning.
                if ((d.type === 'vector' && !owner[lo] && !owner[hi]) || d.from) return -1;
                warn(`${d.type} ${specString(d)}: pointer at $${h4(lo)} is in undefined memory`,
                    key(owner[lo] || owner[hi], owner[lo] ? lo : hi), d);
                return -1;
            }
            const adj = d.rts ? 1 : 0;
            const t = ((mem[lo] | (mem[hi] << 8)) + adj) & 0xFFFF;
            const ts = owner[t];
            need.add(key(ts, t));
            const Tl = S[owner[lo] - 1], Th = S[owner[hi] - 1];
            Tl.ptr.set(lo - Tl.seg.start, { t, ts, part: '<', other: hi, adj });
            Th.ptr.set(hi - Th.seg.start, { t, ts, part: '>', other: lo, adj });
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
        const auto = img.entries.map((e) => (e.type ? e : { type: 'code', name: e.name || null, seg: 0, addr: e.addr, range: 0 }));

        let run = null;
        for (const s of loadOrder) {
            visited.clear();
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
        visited.clear();
        if (run) {
            pointer(0x2E0, 0x2E1, { type: 'run', addr: 0x2E0, range: 0 });
            trace(run.run, pseudo(`run_segment${run.index}`, { keys: [key(owner[0x2E0], 0x2E0)] }));
        }
        if (!traced && img.multi && !img.banked && real.length) trace(real[0].start, pseudo('COM', { keys: [key(real[0].index, real[0].start)] }));
        enter(auto.concat(bySeg.get(0) || []));
        for (const d of auto) {
            if (d.name) addLabel(key(finalOwner[d.addr], d.addr), d.name, 0, 0, d);
        }

        // --- label lookup
        function autoName(k) {
            const s = keySeg(k), a = keyAddr(k);
            const sg = s && segs[s - 1];
            return (s && cover[a] > 1 ? (sg && sg.prefix) || 's' + s : '') + 'l' + h4(a);
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

        // suggestions dismissed with "dismiss $ADDR" (the address they point at)
        const dismissed = new Set(directives.filter((d) => d.type === 'dismiss').map((d) => key(resolveSeg(d, d.addr), d.addr)));
        const keep = (sg) => !dismissed.has(sg.at);
        // suggest: false skips the detectors (when only the traced code matters)
        const suggesting = opts.suggest !== false;
        const insCache = new Map();      // segment -> its traced instructions
        for (const sg of (suggesting ? findRelocations() : []).filter(keep)) {
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
            if (insCache.has(T)) return insCache.get(T);
            const ins = [];
            insCache.set(T, ins);
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

        for (const sg of (suggesting ? findPointerPairs() : []).filter(keep)) {
            warnings.push({ msg: sg.msg, k: sg.at, suggest: sg.dir });
        }
        for (const sg of (suggesting ? findInlineRoutines() : []).filter(keep)) {
            warnings.push({ msg: sg.msg, k: sg.at, suggest: sg.dir });
        }
        // structures and jump tables first: the code finder leaves their bytes alone
        const structs = (suggesting ? findStructures() : []).filter(keep);
        const tables = (suggesting ? findJumpTables() : []).filter(keep);
        const reserved = new Set();
        for (const d of structs.flatMap((sg) => sg.dirs).concat(tables.map((sg) => sg.dir))) {
            const span = POINTER_TYPES.includes(d.type) && d.hi === undefined ? Math.max(d.range, 1) : d.range;
            for (let o = 0; o <= span; o++) {
                reserved.add(d.addr + o);
                if (d.hi !== undefined) reserved.add(d.hi + o);
            }
        }
        for (const sg of structs) {
            warnings.push({ msg: sg.msg, k: sg.at, suggest: sg.dirs[0], dirs: sg.dirs, kind: 'struct', title: sg.title });
        }
        for (const sg of tables) {
            warnings.push({ msg: sg.msg, k: sg.at, suggest: sg.dir, kind: 'table' });
        }
        for (const sg of (suggesting ? findUntracedCode(reserved) : []).filter(keep)) {
            warnings.push({ msg: sg.msg, k: sg.at, suggest: sg.dir, kind: 'code' });
        }

        // Find code nothing traces into: decode untraced bytes from each
        // address and keep blocks that look like real routines. A block is
        // valid instructions up to rts/jmp (or running into traced code),
        // with every branch landing on one of its own instructions or on
        // traced code, and every jsr/jmp going to traced code, a label or its
        // own instructions. Each instruction then scores how much more likely
        // its opcode is in 6502 code (a generic profile mixed with this
        // program's traced code) than in random bytes; calls into traced
        // code and absolute operands with names add to the score.
        function findUntracedCode(reserved) {
            const out = [];
            const MIN = 4, MAX = 400;
            // opcode frequencies: traced code vs. untraced bytes
            const inCode = new Float64Array(256);
            let nCode = 0, nFree = 0;
            const busyOf = new Map();
            for (const T of S) {
                const data = T.seg.data, len = data.length;
                const busy = new Uint8Array(len);         // traced code, data formats and pointers
                for (let o = 0; o < len; o++) {
                    if (T.ilen[o]) {
                        busy.fill(1, o, Math.min(len, o + T.ilen[o]));
                        inCode[data[o]]++;
                        nCode++;
                    }
                    if (T.fmt[o]) busy[o] = 1;
                }
                for (const o of T.ptr.keys()) busy[o] = 1;
                for (const a of reserved) if (a >= T.seg.start && a <= T.seg.end) busy[a - T.seg.start] = 1;
                // bytes relocated elsewhere are traced (or not) where they run
                for (const p of R.holesOf.get(T.seg.index) || []) {
                    busy.fill(1, Math.max(0, p.load - T.seg.start), Math.min(len, p.load + p.data.length - T.seg.start));
                }
                for (let o = 0; o < len; o++) if (!busy[o]) nFree++;
                busyOf.set(T, busy);
            }
            if (!nFree) return out;
            // Opcode frequencies (per mille) in traced code of six programs
            // (Atari and BBC games, Atari BASIC cartridges): a generic
            // profile, mixed with this program's own when it has enough code
            const GENERIC = [
                0,0,0,0,0,2,0,0,1,3,5,0,0,1,0,0,13,0,0,0,0,0,0,0,13,0,0,0,0,1,0,0,
                56,0,0,0,2,1,1,0,1,15,2,0,2,0,0,0,6,0,0,0,0,0,0,0,7,0,0,0,0,0,0,0,
                0,0,0,0,0,1,0,0,10,4,13,0,22,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                23,0,0,0,0,3,1,0,10,8,2,0,1,1,0,0,1,0,0,0,0,0,0,0,1,2,0,0,0,0,0,0,
                0,0,0,0,6,56,12,0,9,0,6,0,9,77,8,0,15,10,0,0,0,3,0,0,5,15,1,0,0,14,0,0,
                40,0,42,0,4,35,6,0,6,98,9,0,3,20,2,0,12,13,0,0,1,4,0,0,0,15,1,0,1,15,1,0,
                5,0,0,0,1,7,5,0,9,20,10,0,0,2,1,0,40,1,0,0,0,0,0,0,0,0,0,0,0,0,1,0,
                4,0,0,0,0,1,10,0,7,4,20,0,0,0,5,0,29,0,0,0,0,1,0,0,0,0,0,0,0,0,1,0,
            ];
            const own = nCode >= 200 ? 0.3 : 0;
            const llr = new Float64Array(256);
            let gSum = 0;
            const gen = GENERIC.map((v, b) => v || (OPS[b].illegal || OPS[b].jam ? 0.02 : 0.3));
            for (const v of gen) gSum += v;
            for (let b = 0; b < 256; b++) {
                const pc = (1 - own) * gen[b] / gSum + own * (inCode[b] + 0.1) / (nCode + 25.6);
                llr[b] = Math.log(pc * 256);               // against uniform bytes
            }
            // opcodes a block can start with
            const startsCode = OPS.map((op) => op.code !== 0 && !op.jam && (!op.illegal || opts.illegal) && op.mn !== 'rti');
            for (const T of S) {
                const data = T.seg.data, start = T.seg.start, len = data.length;
                const busy = busyOf.get(T);
                const named = (t) => {
                    const l = labels.get(key(segFor(T, t), t));
                    return !!(l && l.user);
                };
                // traced code, or somewhere traced code calls or jumps to (an
                // entry point whose code isn't in the image, e.g. the Tube's
                // $0406 on a BBC)
                const codeAt = (t) => {
                    const k = key(segFor(T, t), t);
                    if (isCodeStart(k)) return true;
                    const r = refs.get(k);
                    return !!(r && r.callers.some((x) => typeof x === 'number' && isCodeStart(x)));
                };
                // a call or branch out of a block may go to another untraced
                // block that decodes as code; it needs no evidence of its own
                // (often it is the tail of a routine, e.g. pla / tax / jmp)
                const memo = new Map();
                const blockAt = (t) => {
                    const c = t - start;
                    if (c < 0 || c >= len || busy[c] || segFor(T, t) !== T.seg.index) return null;
                    if (!memo.has(c)) {
                        memo.set(c, { pending: true });          // recursion: assume yes
                        memo.set(c, block(c));
                    }
                    return memo.get(c);
                };
                // decode a block at offset c; null if it doesn't look like code
                const block = (c) => {
                    const starts = new Set();
                    const targets = [];
                    let o = c, score = 0, n = 0, far = c;
                    // Code often uses a conditional branch as a jump (a loop
                    // left by another branch, or lda #8 / bne): when what
                    // follows one doesn't decode, the block ends at it, as
                    // long as no branch goes further.
                    let branchEnd = -1;
                    const endsHere = () => branchEnd === o && o > far;
                    for (;;) {
                        if (o >= len) { if (endsHere()) break; return null; }
                        if (busy[o]) {
                            // ran into traced code: fine if exactly at an instruction
                            if (!T.ilen[o] || o === c) { if (endsHere()) break; return null; }
                            break;
                        }
                        const op = OPS[data[o]];
                        if (op.code === 0 && acornBrk) {
                            // a BRK error ends this path, like rts
                            const e = errorBlock(start + o, (x) => (x - start < len && !busy[x - start] ? data[x - start] : -1));
                            if (e > 0) {
                                starts.add(o);
                                n++;
                                score += 2;
                                o = e - start;
                                if (o > far) break;
                                continue;
                            }
                        }
                        if (op.code === 0 || op.jam || (op.illegal && !opts.illegal) || o + op.len > len ||
                            [1, 2].some((x) => x < op.len && busy[o + x])) {
                            if (endsHere()) break;
                            return null;
                        }
                        starts.add(o);
                        if (++n > MAX) return null;
                        score += llr[data[o]];
                        if (score < -6) return null;               // reads like data
                        const lo = data[o + 1], w = lo | (data[o + 2] << 8);
                        const a = start + o;
                        if (op.branch) {
                            const t = (a + 2 + (lo < 128 ? lo : lo - 256)) & 0xFFFF;
                            targets.push(t);
                            if (t - start > far) far = t - start;
                        } else if ((op.mn === 'jsr' || op.mn === 'jmp') && op.mode === 'abs') {
                            if (codeAt(w) || named(w)) score += 3;
                            else targets.push(w);
                        } else if (op.len === 3 && named(w)) {
                            score += 2;
                        }
                        o += op.len;
                        // a call with inline data continues after the data,
                        // or not at all (a routine that raises an error)
                        const inl = op.mn === 'jsr' && op.mode === 'abs' && inlineAt.get(key(segFor(T, w), w));
                        if (inl) {
                            const r = scanInline(a, inl, (x) => (x - start >= 0 && x - start < len && !busy[x - start] ? data[x - start] : -1));
                            if (r.error) return null;
                            if (r.resume < 0) {
                                // like rts: the block ends, unless a branch goes past
                                o = r.end - start;
                                if (o > far) break;
                                continue;
                            }
                            o = r.resume - start;
                        }
                        if (op.branch) branchEnd = o;
                        if (op.mn === 'rti') score -= 4;               // $40 is common in data
                        if ((op.mn === 'rts' || op.mn === 'rti' || op.mn === 'jmp') && o > far) break;
                    }
                    for (const t of targets) {
                        if (!starts.has(t - start) && !codeAt(t) && !blockAt(t)) return null;
                    }
                    if (score < 0) return null;
                    return { end: o, n, score, starts };
                };
                for (let c = 0; c < len; c++) {
                    if (busy[c] || !startsCode[data[c]]) continue;
                    const strict = (x) => {
                        const m = memo.get(x);
                        const b = memo.has(x) && !(m && m.pending) ? m : block(x);
                        return b && b.n >= MIN && b.score >= 12 && b.score >= b.n / 2 ? b : null;   // a suggestion needs evidence
                    };
                    let b = strict(c);
                    if (!b) continue;
                    // data just before code can decode into it: of the later
                    // starts that end in the same place, keep one that scores
                    // clearly better (real code may start with rare
                    // instructions too, more likely right after a routine ends)
                    const after = (x) => {
                        const op = (y) => (y >= 0 && T.ilen[y] ? OPS[data[y]] : null);
                        const p1 = op(x - 1), p3 = op(x - 3);
                        return !!(p1 && (p1.mn === 'rts' || p1.mn === 'rti')) || !!(p3 && p3.mn === 'jmp');
                    };
                    const margin = after(c) ? 4 : 2;
                    for (let c2 = c + 1; c2 < Math.min(b.end, c + 32); c2++) {
                        if (busy[c2] || !startsCode[data[c2]]) continue;
                        const b2 = strict(c2);
                        if (b2 && b2.end === b.end && b2.score > b.score + margin) {
                            b = b2;
                            c = c2;
                        }
                    }
                    const a = start + c;
                    out.push({
                        at: key(T.seg.index, a),
                        dir: { type: 'code', name: null, seg: cover[a] > 1 ? T.seg.index : 0, addr: a, range: 0 },
                        msg: `Possible code at $${h4(a)}-$${h4(start + b.end - 1)} that nothing traces into: ` +
                            `${b.n} instructions — click to review`,
                    });
                    c = b.end - 1;
                }
            }
            return out;
        }

        // Find data structures the machine defines, from immediates stored
        // into its registers or passed to its OS:
        //   Atari: display lists (SDLSTL/DLISTL), with their LMS and jump
        //          addresses; character sets (CHBAS/CHBASE)
        //   C64:   character sets ($D018, with the VIC bank from $DD00);
        //          sprite data (sprite pointers after the screen)
        //   BBC:   OSWORD/OSFILE/OSGBPB parameter blocks and OSCLI/OSFIND
        //          strings, addressed by X (low) and Y (high)
        function findStructures() {
            const out = [];
            if (!platform) return out;
            const scoped = (a) => (cover[a] > 1 ? finalOwner[a] : 0);
            const byteAt = (a) => {
                const s = finalOwner[a];
                const U = s && S[s - 1];
                return U ? U.seg.data[a - U.seg.start] : -1;
            };
            // a range that is loaded and neither code nor already classified
            const free = (a, n) => {
                for (let x = a; x < a + n; x++) {
                    if (x > 0xFFFF) return false;
                    const s = finalOwner[x];
                    const U = s && S[s - 1];
                    if (!U) return false;
                    const o = x - U.seg.start;
                    if (U.ilen[o] || U.fmt[o] || U.ptr.has(o)) return false;
                }
                // not inside an instruction either
                for (let x = a - 2; x < a; x++) {
                    const s = x >= 0 && finalOwner[x];
                    const U = s && S[s - 1];
                    if (U && U.ilen[x - U.seg.start] > a - x) return false;
                }
                return true;
            };
            const CHANGES = { a: /^(adc|sbc|and|ora|eor|pla|txa|tya|asl|lsr|rol|ror)$/, x: /^(inx|dex|tax|tsx)$/, y: /^(iny|dey|tay)$/ };
            // Walk traced code with known immediates in A, X and Y; call
            // store(P, value, instruction) and call(target, regs, instruction).
            const walk = (store, call) => {
                for (const T of S) {
                    const ins = instructionsOf(T);
                    let regs = {};
                    for (const x of ins) {
                        const r = refs.get(key(T.seg.index, x.a));
                        if (r && r.callers.length) regs = {};
                        const mn = x.op.mn;
                        if ((mn === 'lda' || mn === 'ldx' || mn === 'ldy') && x.op.mode === 'imm') {
                            regs[mn[2]] = { v: x.lo, at: x.a + 1 };
                            continue;
                        }
                        if ((mn === 'sta' || mn === 'stx' || mn === 'sty') && (x.op.mode === 'zp' || x.op.mode === 'abs')) {
                            const g = regs[mn[2]];
                            if (g) store(x.op.mode === 'zp' ? x.lo : x.w, g, x, T);
                            continue;
                        }
                        if (mn === 'jsr' && x.op.mode === 'abs') call(x.w, regs, x, T);
                        if (x.op.branch || mn === 'jsr' || mn === 'jmp' || mn === 'rts' || mn === 'rti' || mn === 'brk') regs = {};
                        else for (const g of ['a', 'x', 'y']) if (CHANGES[g].test(mn)) delete regs[g];
                    }
                }
            };
            const seen = new Set();
            const once = (k) => (seen.has(k) ? false : (seen.add(k), true));

            if (platform === 'atari') {
                // display lists: lo/hi immediates stored into SDLSTL or DLISTL
                const halves = new Map();         // register -> {v, at}
                const dls = [], fonts = [];
                walk((P, g, x) => {
                    if (P === 0x230 || P === 0x231 || P === 0xD402 || P === 0xD403) {
                        halves.set(P, { v: g.v, at: x.a });
                        const lo = halves.get(P & ~1), hi = halves.get(P | 1);
                        if (lo && hi && Math.abs(lo.at - hi.at) < 24) dls.push({ addr: lo.v | (hi.v << 8), at: Math.min(lo.at, hi.at) });
                    }
                    if (P === 0x2F4 || P === 0xD409) fonts.push({ addr: g.v << 8, at: x.a, reg: P === 0x2F4 ? 'CHBAS' : 'CHBASE' });
                }, () => {});
                // a JVB to another address is the next frame's display list
                for (let i = 0; i < dls.length && i < 64; i++) {
                    if (!once(dls[i].addr)) continue;
                    const r = parseDisplayList(dls[i].addr);
                    if (!r) continue;
                    out.push(r);
                    if (r.next !== undefined) dls.push({ addr: r.next });
                }
                // character sets: 1 KB from a page in CHBAS/CHBASE
                for (const f of fonts) {
                    if (f.addr & 0x1FF || !once(f.addr)) continue;
                    if (free(f.addr, 0x400)) {
                        out.push({ at: key(finalOwner[f.addr], f.addr), title: 'Character set',
                            dirs: [{ type: 'data', name: null, seg: scoped(f.addr), addr: f.addr, range: 0x3FF }],
                            msg: `Character set at $${h4(f.addr)}-$${h4(f.addr + 0x3FF)}, set in ${f.reg} at $${h4(f.at)} — click to review` });
                    }
                }
            }
            if (platform === 'c64') {
                const d018 = [], banks = new Set(), sprites = [];
                walk((P, g, x) => {
                    if (P === 0xD018) d018.push({ v: g.v, at: x.a });
                    if (P === 0xDD00) banks.add((3 - (g.v & 3)) * 0x4000);
                    if (P >= 0x0400 && P <= 0xFFFF && (P & 0x3FF) >= 0x3F8) sprites.push({ v: g.v, at: x.a, screen: P & ~0x3FF });
                }, () => {});
                if (!banks.size) banks.add(0);
                // character sets: 2 KB at bank + ((v >> 1) & 7) * $800; banks 0
                // and 2 see the character ROM at $1000-$1FFF instead
                for (const r of d018) {
                    for (const bank of banks) {
                        const off = ((r.v >> 1) & 7) * 0x800;
                        if ((bank === 0 || bank === 0x8000) && (off === 0x1000 || off === 0x1800)) continue;
                        const at = bank + off;
                        if (!once(at) || !free(at, 0x800)) continue;
                        out.push({ at: key(finalOwner[at], at), title: 'Character set',
                            dirs: [{ type: 'data', name: null, seg: scoped(at), addr: at, range: 0x7FF }],
                            msg: `Character set at $${h4(at)}-$${h4(at + 0x7FF)}, set in $D018 at $${h4(r.at)} — click to review` });
                    }
                }
                // sprite data: 64 bytes at bank + pointer * 64, for pointers
                // stored into the last 8 bytes of a screen's 1 KB
                const blocks = [];
                for (const sp of sprites) {
                    const screens = d018.map((r) => (r.v >> 4) * 0x400);
                    const onScreen = sp.screen === 0x400 || screens.some((o) => [...banks].some((b) => b + o === sp.screen));
                    if (!onScreen) continue;
                    const at = (sp.screen & 0xC000) + sp.v * 64;
                    if (!once('s' + at) || !free(at, 63)) continue;
                    blocks.push(at);
                }
                if (blocks.length) {
                    blocks.sort((x, y) => x - y);
                    // adjacent sprites become one range
                    const ranges = [];
                    for (const at of blocks) {
                        const last = ranges[ranges.length - 1];
                        if (last && at === last[1] + 1) last[1] = at + 63;
                        else ranges.push([at, at + 63]);
                    }
                    for (const r of ranges) if (r[1] > 0xFFFF || !free(r[0], r[1] - r[0] + 1)) r[1] -= 1;   // the unused 64th byte
                    out.push({ at: key(finalOwner[blocks[0]], blocks[0]), title: 'Sprite data',
                        dirs: ranges.map(([p0, p1]) => ({ type: 'data', name: null, seg: scoped(p0), addr: p0, range: p1 - p0 })),
                        msg: `Sprite data: ${blocks.length} sprite${blocks.length > 1 ? 's' : ''} at ${blocks.map((x) => '$' + h4(x)).join(', ')} — click to review` });
                }
            }

            if (platform === 'bbc') {
                // OS calls that take a block address in X (low) and Y (high)
                const OSWORD_SIZES = { 0: 5, 1: 5, 2: 5, 3: 5, 4: 5, 5: 5, 6: 5, 7: 8, 8: 14, 9: 5, 10: 9, 11: 5, 12: 5 };
                const CALLS = {
                    0xFFF1: { name: 'OSWORD', size: (r) => (r.a ? OSWORD_SIZES[r.a.v] : undefined) },
                    0xFFDD: { name: 'OSFILE', size: () => 18 },
                    0xFFD1: { name: 'OSGBPB', size: () => 13 },
                    0xFFF7: { name: 'OSCLI', text: true },
                    0xFFCE: { name: 'OSFIND', text: true, when: (r) => r.a && r.a.v !== 0 },
                };
                walk(() => {}, (t, regs, x) => {
                    const c = CALLS[t];
                    if (!c || !regs.x || !regs.y || (c.when && !c.when(regs))) return;
                    const at = regs.x.v | (regs.y.v << 8);
                    if (!once(at)) return;
                    let n = c.text ? 0 : c.size(regs);
                    if (c.text) {
                        // a string ending in CR
                        while (n < 256 && byteAt(at + n) >= 0 && byteAt(at + n) !== 0x0D) n++;
                        if (byteAt(at + n) !== 0x0D) return;
                        n++;
                    }
                    if (!n || !free(at, n)) return;
                    const dirs = [{ type: 'address', name: null, seg: scoped(regs.x.at), addr: regs.x.at, range: 0, hi: regs.y.at },
                        { type: c.text ? 'text' : 'data', name: null, seg: scoped(at), addr: at, range: n - 1 }];
                    out.push({ at: key(finalOwner[at], at), title: c.text ? 'OS string' : 'OS parameter block', dirs,
                        msg: `${c.text ? 'String' : `Parameter block (${n} bytes)`} at $${h4(at)} passed to ${c.name}` +
                            `${t === 0xFFF1 ? ' ' + regs.a.v : ''} at $${h4(x.a)} — click to review` });
                });
            }
            return out;

            // Parse the Atari display list at `start`. Lines are 1 byte, 3
            // with LMS (bit 6) and an address; $x1 jumps (JMP), $41 jumps and
            // waits for vertical blank (JVB), which ends the list.
            function parseDisplayList(start) {
                const dirs = [];
                const ptrs = [];
                let a = start, lines = 0, screen = null, next;
                const parts = [[start, start]];
                for (let n = 0; n < 512; n++) {
                    const b = byteAt(a);
                    if (b < 0) return null;
                    const mode = b & 0x0F;
                    if (mode === 1) {
                        if (!free(a, 3)) return null;
                        const t = byteAt(a + 1) | (byteAt(a + 2) << 8);
                        ptrs.push(a + 1);
                        parts[parts.length - 1][1] = a + 2;
                        if (b & 0x40) {                          // JVB: the end
                            if (t !== start) next = t;
                            break;
                        }
                        if (t === start || parts.some(([p0, p1]) => t >= p0 && t <= p1)) break;
                        a = t;
                        parts.push([a, a]);
                        continue;
                    }
                    if (mode && b & 0x40) {
                        if (!free(a, 3)) return null;
                        ptrs.push(a + 1);
                        if (screen === null) screen = byteAt(a + 1) | (byteAt(a + 2) << 8);
                        parts[parts.length - 1][1] = a + 2;
                        a += 3;
                    } else {
                        if (!free(a, 1)) return null;
                        parts[parts.length - 1][1] = a;
                        a++;
                    }
                    if (mode) lines++;
                    if (n === 511) return null;
                }
                if (!lines) return null;
                for (const p of ptrs) dirs.push({ type: 'address', name: null, seg: scoped(p), addr: p, range: 0 });
                for (const [p0, p1] of parts) dirs.push({ type: 'data', name: null, seg: scoped(p0), addr: p0, range: p1 - p0 });
                const end = parts[0][1];
                return {
                    at: key(finalOwner[start], start), title: 'Display list', dirs, next,
                    msg: `Display list at $${h4(start)}-$${h4(end)}: ${lines} mode line${lines > 1 ? 's' : ''}` +
                        `${screen !== null ? `, screen memory at $${h4(screen)}` : ''} — click to review`,
                };
            }
        }

        // Find jump tables behind indexed dispatch code:
        //   lda HI,x / pha / lda LO,x / pha / rts      (entries are address-1)
        //   lda LO,x / sta P / lda HI,x / sta P+1 / jmp (P)
        // HI = LO+1 is a table of words, otherwise two split tables. The size
        // comes from a bounds check (cpx #N / bcs) or, without one, from how
        // many entries in a row point at plausible code.
        function findJumpTables() {
            const out = [];
            const byteOf = (T, a) => {
                const s = segFor(T, a);
                const U = s && S[s - 1];
                return U && a >= U.seg.start && a <= U.seg.end ? U.seg.data[a - U.seg.start] : -1;
            };
            // looks like the start of code: traced, or a few valid instructions
            const plausible = (T, t) => {
                const s = segFor(T, t);
                if (!s) return !!labels.get(key(0, t));          // e.g. an OS entry point
                if (isCodeStart(key(s, t))) return true;
                let a = t;
                for (let n = 0; n < 4; n++) {
                    const b = byteOf(T, a);
                    if (b < 0) return false;
                    const op = OPS[b];
                    if (op.code === 0 || op.jam || op.illegal) return false;
                    if (op.mn === 'rts' || op.mn === 'rti' || op.mn === 'jmp') return true;
                    a += op.len;
                }
                return true;
            };
            // a table byte that ends the table: code, a known pointer, or the
            // start of something else that code reads
            const stops = (T, a, first) => {
                const s = segFor(T, a);
                const U = s && S[s - 1];
                if (!U || a < U.seg.start || a > U.seg.end) return true;
                const o = a - U.seg.start;
                if (U.ilen[o] || U.ptr.has(o) || (U.fmt[o] && U.fmt[o] !== FMT.data)) return true;
                const r = refs.get(key(s, a));
                return !first && !!(r && (r.access.length || r.callers.length));
            };
            // entries in a bound check before instruction j on index register r
            const bound = (ins, j, r, word) => {
                for (let n = j - 1; n >= Math.max(0, j - 10); n--) {
                    const x = ins[n];
                    if (x.op.mode !== 'imm' || !/^(cmp|cpx|cpy)$/.test(x.op.mn)) continue;
                    const nx = ins[n + 1];
                    if (!nx || (nx.op.mn !== 'bcs' && nx.op.mn !== 'bcc')) return 0;
                    const between = ins.slice(n + 2, j);
                    const doubled = between.some((y) => y.op.mn === 'asl' && y.op.mode === 'acc');
                    if (x.op.mn === 'cmp') return between.some((y) => y.op.mn === 'ta' + r) ? x.lo : 0;
                    if (x.op.mn !== 'cp' + r) return 0;
                    return word && !doubled ? x.lo >> 1 : x.lo;
                }
                return 0;
            };
            const seen = new Set();
            S.forEach((T) => {
                const ins = instructionsOf(T);
                const idx = (x) => (x && x.op.mn === 'lda' && (x.op.mode === 'abx' || x.op.mode === 'aby') ? x.op.mode[2] : null);
                for (let j = 0; j + 4 < ins.length; j++) {
                    const w = ins.slice(j, j + 5);
                    if (w.some((x, n) => n && x.a !== w[n - 1].a + w[n - 1].op.len)) continue;
                    let lo, hi, rts = false, r, how;
                    if (idx(w[0]) && w[1].op.mn === 'pha' && idx(w[2]) === idx(w[0]) && w[3].op.mn === 'pha' && w[4].op.mn === 'rts') {
                        hi = w[0].w; lo = w[2].w; r = idx(w[0]); rts = true; how = 'rts';
                    } else if (idx(w[0]) && idx(w[2]) === idx(w[0]) && /^st[a]$/.test(w[1].op.mn) && w[3].op.mn === 'sta' &&
                        w[4].op.mn === 'jmp' && w[4].op.mode === 'ind') {
                        const P = w[4].w;
                        const dst = (x) => (x.op.mode === 'zp' ? x.lo : x.op.mode === 'abs' ? x.w : -1);
                        if (dst(w[1]) === P && dst(w[3]) === P + 1) { lo = w[0].w; hi = w[2].w; }
                        else if (dst(w[1]) === P + 1 && dst(w[3]) === P) { hi = w[0].w; lo = w[2].w; }
                        else continue;
                        r = idx(w[0]); how = 'jmp ($' + (P < 0x100 ? h2(P) : h4(P)) + ')';
                    } else {
                        continue;
                    }
                    const word = hi === lo + 1;
                    const tkey = key(segFor(T, lo), lo);
                    if (seen.has(tkey)) continue;
                    seen.add(tkey);
                    const max = bound(ins, j, r, word) || 0;
                    const limit = max || 128;
                    let n = 0;
                    for (; n < limit; n++) {
                        const la = word ? lo + 2 * n : lo + n, ha = word ? la + 1 : hi + n;
                        if (ha > 0xFFFF || stops(T, la, n === 0) || stops(T, ha, n === 0)) break;
                        if (!word && (lo < hi ? la >= hi : ha >= lo)) break;          // ran into the other half
                        const v = byteOf(T, la) | (byteOf(T, ha) << 8);
                        if (!plausible(T, (v + (rts ? 1 : 0)) & 0xFFFF)) break;
                    }
                    if (n < (max ? Math.min(max, 1) : 2) || (max && n < max)) continue;
                    const scoped = (a) => (cover[a] > 1 ? T.seg.index : 0);
                    const dir = word ? { type: 'codeptr', name: null, seg: scoped(lo), addr: lo, range: 2 * n - 1 }
                        : { type: 'codeptr', name: null, seg: scoped(lo), addr: lo, range: n - 1, hi };
                    if (rts) dir.rts = true;
                    out.push({
                        at: key(T.seg.index, w[0].a), dir,
                        msg: `Jump table${word ? '' : 's'} at $${h4(lo)}${word ? '' : ` (low) and $${h4(hi)} (high)`}: ` +
                            `${n} entr${n > 1 ? 'ies' : 'y'} dispatched by ${how} at $${h4(w[4].a)}` +
                            `${rts ? ', each the address minus 1' : ''} — click to review`,
                    });
                }
            });
            return out;
        }

        // Find routines called with inline data after the jsr: before
        // touching the stack otherwise they pull their return address into
        // a pointer, then read through it and test what they read,
        //   ... pla / sta P / pla / sta P+1 ... lda (P),y / [sta ...] / bmi|bpl|beq|bne
        // How the data ends comes from the tests and from how they return:
        //   bmi/bpl: text up to a byte with bit 7 set; jmp (P) continues at
        //            that byte (bit7), otherwise after it (bit7last)
        //   beq/bne: text ending in a zero byte (zero); with bmi/bpl too, a
        //            zero byte ends it without returning (brk, as in Acorn
        //            error blocks)
        //   reads before the tested one: bytes that are always data (lead)
        // A wrapper that calls such a routine and then jumps into another
        // one's entry (passing on its own caller's data) gets that one's
        // convention.
        function findInlineRoutines() {
            const out = [];
            // a jsr to address a (not a jsr whose data ends there)
            const isJsrTo = (c, a) => {
                if (typeof c !== 'number' || !segOf(c) || !isCodeStart(c)) return false;
                const U = segOf(c), o = keyAddr(c) - U.seg.start, d = U.seg.data;
                return d[o] === 0x20 && (d[o + 1] | (d[o + 2] << 8)) === a;
            };
            const entries = [];
            for (const [k, r] of refs) {
                if (keySeg(k) && isCodeStart(k) && !inlineAt.has(k) && r.callers.some((c) => isJsrTo(c, keyAddr(k)))) entries.push(k);
            }
            entries.sort((x, y) => x - y);
            const indexOf = new Map();
            const insAt = (T, a) => {
                if (!indexOf.has(T)) indexOf.set(T, new Map(instructionsOf(T).map((x, n) => [x.a, n])));
                return indexOf.get(T).get(a);
            };
            const NOFLAGS = /^(sta|stx|sty|pha|php|txs|clc|sec|cld|sed|cli|sei|clv|nop)$/;
            const found = new Map();
            for (const k of entries) {
                const T = segOf(k);
                const ins = instructionsOf(T);
                const j = insAt(T, keyAddr(k));
                if (j === undefined) continue;
                // straight-line code to the pull, leaving the stack alone
                let pop = -1;
                for (let n = j; n < Math.min(ins.length - 3, j + 40); n++) {
                    const x = ins[n];
                    if (n > j && x.a !== ins[n - 1].a + ins[n - 1].op.len) break;
                    const [s1, p2, s2] = [ins[n + 1], ins[n + 2], ins[n + 3]];
                    if (x.op.mn === 'pla' && s1.op.mn === 'sta' && p2.op.mn === 'pla' && s2.op.mn === 'sta' &&
                        s1.op.mode === 'zp' && s2.op.mode === 'zp' && s2.lo === s1.lo + 1 &&
                        s1.a === x.a + 1 && p2.a === s1.a + 2 && s2.a === p2.a + 1) { pop = n; break; }
                    if (/^(pha|php|pla|plp|rts|rti|tsx|txs|brk|jmp)$/.test(x.op.mn)) break;
                }
                if (pop < 0) continue;
                const P = ins[pop + 1].lo;
                let tested = null, lead = 0, jmpInd = false;
                for (let n = pop + 4; n < Math.min(ins.length, pop + 68); n++) {
                    const x = ins[n];
                    if (x.op.mn === 'jmp' && x.op.mode === 'ind' && x.w === P) jmpInd = true;
                    if (tested || x.op.mn !== 'lda' || (x.op.mode !== 'izy' && x.op.mode !== 'izx') || x.lo !== P) continue;
                    const tests = new Set();
                    for (let m = n + 1; m < Math.min(ins.length, n + 6); m++) {
                        const y = ins[m];
                        if (y.op.branch) tests.add(y.op.mn);
                        else if (!NOFLAGS.test(y.op.mn)) break;
                    }
                    const bits = tests.has('bmi') || tests.has('bpl'), zeros = tests.has('beq') || tests.has('bne');
                    if (bits || zeros) tested = { bits, zeros };
                    else lead++;
                }
                if (!tested) continue;
                const dir = { type: 'inline', name: null, seg: cover[keyAddr(k)] > 1 ? T.seg.index : 0, addr: keyAddr(k), range: 0,
                    mode: tested.bits ? (jmpInd ? 'bit7' : 'bit7last') : 'zero' };
                if (lead && lead <= 16) dir.lead = lead;
                if (tested.bits && tested.zeros) dir.brk = true;
                found.set(k, { dir, how: 'pulls its return address and reads the bytes after the jsr' });
            }
            // wrappers: jsr R (inline), then a jump into an inline entry E
            for (const k of entries) {
                if (found.has(k)) continue;
                const T = segOf(k), a = keyAddr(k), o = a - T.seg.start;
                if (T.seg.data[o] !== 0x20) continue;
                const conv = (t) => {
                    const tk = key(segFor(T, t), t);
                    return inlineAt.get(tk) || (found.get(tk) || {}).dir;
                };
                const dR = conv(T.seg.data[o + 1] | (T.seg.data[o + 2] << 8));
                if (!dR) continue;
                const read = (x) => {
                    const s = segFor(T, x);
                    const U = s && S[s - 1];
                    return U && x >= U.seg.start && x <= U.seg.end ? U.seg.data[x - U.seg.start] : -1;
                };
                const r = scanInline(a, dR, read);
                if (r.error || r.resume < 0) continue;
                const op = OPS[read(r.resume)];
                const lo = read(r.resume + 1);
                const t = op.branch ? (r.resume + 2 + (lo < 128 ? lo : lo - 256)) & 0xFFFF
                    : op.mn === 'jmp' && op.mode === 'abs' ? lo | (read(r.resume + 2) << 8) : -1;
                const dE = t >= 0 && conv(t);
                if (!dE) continue;
                const dir = Object.assign({}, dE, { name: null, seg: cover[a] > 1 ? T.seg.index : 0, addr: a, range: 0 });
                found.set(k, { dir, how: `adds its own text and passes the data after its jsr on to $${h4(t)}` });
            }
            for (const [k, f] of found) {
                const l = labelAt(k);
                const d = f.dir;
                const what = d.mode === 'zero' ? 'text ending in a zero byte' : 'text up to a byte with bit 7 set';
                out.push({
                    at: k, dir: d,
                    msg: `${l ? l.name : '$' + h4(d.addr)} ${f.how}: probably inline ${what}` +
                        `${d.lead ? `, after ${d.lead} byte${d.lead > 1 ? 's' : ''} that ${d.lead > 1 ? 'are' : 'is'} always data` : ''}` +
                        `${d.brk ? ' (a zero byte raises an error instead)' : ''} after each call — click to review`,
                });
            }
            return out;
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
            const atari = platform === 'atari';
            const PAGE_REGS = atari ? new Map([[0xD407, 'PMBASE'], [0xD409, 'CHBASE'], [0x2F4, 'CHBAS']]) : new Map();
            // OS routines that take a code address in registers: SETVBV gets the
            // VBI routine in Y (low) and X (high), with A = 6 immediate / 7 deferred
            const REG_VECTORS = atari ? new Map([[0xE45C, { lo: 'y', hi: 'x' }]]) : new Map();
            const ptrUse = new Set(atari ? [0xD402, 0x230] : []);   // zero page / absolute pointers in use
            const jumpVec = new Set();       // ... used by jmp (P) or declared as vectors
            const dataPtr = new Set();       // ... used by (P),y / (P,x)
            for (const d of directives) {
                // declared pointers count as pointer use; a 2-byte data range
                // alone does not (it may be a counter)
                if (POINTER_TYPES.includes(d.type) && d.hi === undefined) ptrUse.add(d.addr);
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
                        const known = REG_VECTORS.get(x.w);
                        if (known) {
                            // a routine with a known register convention
                            if (regs[known.lo] && regs[known.hi]) {
                                const kind = x.w === 0xE45C && regs.a ? { 6: 'immediate VBI', 7: 'deferred VBI' }[regs.a.v] : null;
                                pair(T, regs[known.lo], regs[known.hi], -1, x.w, kind || 'code');
                            }
                        } else {
                            // register pair passed to a routine: try Y/X and A/X, A/Y orders
                            for (const [lo, hi] of [['y', 'x'], ['a', 'x'], ['a', 'y']]) {
                                if (regs[lo] && regs[hi]) pair(T, regs[lo], regs[hi], -1, x.w);
                            }
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

            // `known` is set for routines whose convention says the pair is a
            // code address (the routine is a VBI installer, ...): no evidence needed.
            function pair(T, lo, hi, P, via, known) {
                if (!lo || !hi || lo.at === hi.at || Math.abs(lo.i - hi.i) > 12) return;
                if (overridden(T, lo.at) || overridden(T, hi.at)) return;
                const t = lo.v | (hi.v << 8);
                if (t < 0x100) return;
                const target = isTarget(t, T);
                const viaJsr = typeof via === 'number';
                if (viaJsr) {
                    if (!target && !known) return;       // registers: need loaded code or a label
                } else if (!ptrUse.has(P)) {
                    // without pointer use, the address has to land on loaded code
                    // or a label (a 2-byte data range alone may be a counter)
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
                const code = viaJsr ? target === 'code' || !!known
                    : jumpVec.has(P) || (target === 'code' && !dataPtr.has(P));
                const dir = { type: code ? 'codeptr' : 'address', name: null, seg: scoped(lo.at), addr: lo.at, range: 0, hi: hi.at };
                const tname = nameAt(T, t) || 'l' + h4(t);
                let where;
                if (viaJsr) {
                    where = `passed to ${nameAt(T, via) || '$' + h4(via)}${known && known !== 'code' ? ' as the ' + known + ' routine' : ''}`;
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
            img, opts, S, mem, finalOwner, cover, refs, need, labels, names, consts, enums, enumOps, aliases, aliasNames, accessOf,
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
        const { img, opts, S, refs, comments, notes, operands, consts, enums, enumOps, aliases } = model;
        const lines = [];
        const used = new Map();       // base label name -> key, for externs
        const usedConsts = new Map();
        const usedEnums = new Set();     // enums with a member used: all their members get equates
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
            return (pre ? ((T && T.seg.tag) || keySeg(k)) + ':' : '') + h4(keyAddr(k));
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
        // How the instruction at reference key r uses the address
        function refUse(r) {
            const T = typeof r === 'number' && S[keySeg(r) - 1];
            if (!T) return 'other';
            return accessOf(OPS[T.seg.data[keyAddr(r) - T.seg.start]]) || 'other';
        }
        // uses (read/write/other) a name stands for, at an address with
        // read/write names; null for all
        function usesOf(name, k) {
            const al = aliases.get(k);
            if (!al) return null;
            if (name === al.read) return ['read'];
            if (name === al.write) return ['write'];
            return ['read', 'write', 'other'].filter((u) => !al[u]);
        }
        function xrefs(k, which, range, uses) {
            const r = range ? refsFor(k) : refs.get(k);
            if (!r) return '';
            const out = [];
            const access = uses ? r.access.filter((x) => uses.includes(refUse(x))) : r.access;
            if (which !== 'callers' && opts.access && access.length) {
                out.push('Access: ' + sortUniq(access.map(refName)).join(' '));
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
                    // a value of the enum this instruction was given; values
                    // the enum doesn't name stay numbers
                    const eo = enumOps.get(key(T.seg.index, i));
                    const en = eo && enums.get(eo.enum);
                    if (en) {
                        const member = en.byValue.get(lo);
                        if (member === undefined) return [['pun', '#'], ['num', '$' + h2(lo)]];
                        usedEnums.add(en.name);
                        return [['pun', '#'], ['sym', member]];
                    }
                    const p = T.ptr.get(off + 1);
                    if (p) {
                        const pl = sym(p.ts, p.t);
                        // < and > bind tighter than -: group the adjusted address
                        if (pl && p.adj) return [['pun', '#' + p.part + '['], ['sym', pl.name, key(p.ts, p.t)], ['pun', '-' + p.adj + ']']];
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
            const tk = key(ts, tgt);
            // the address's name for reading (writing) instructions, if it has one
            const al = opts.labels && aliases.get(tk);
            const use = al && accessOf(op);
            if (use && al[use]) {
                l = { name: al[use], base: al[use], baseKey: tk, off: 0 };
                if (!used.has(l.base)) used.set(l.base, tk);
            } else {
                l = sym(ts, tgt);
            }
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
                for (const en of enums.values()) if (en.members.some(([n]) => n === name)) usedEnums.add(en.name);
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
                // The best repeat starting at c: {p: pattern length, n: count}
                // covering at least fillMin bytes (patterns need 3 copies), or
                // null. Patterns longer than one byte are opt-in (patternMax).
                // With full false, any qualifying repeat is returned early.
                const repeatAt = (c, full) => {
                    if (opts.fillMin <= 1) return null;
                    const maxP = Math.max(1, Math.min(64, opts.patternMax | 0));
                    const o = c - start;
                    const free = (x) => x <= end && !T.ilen[x - start] && !T.ptr.has(x - start) &&
                        T.fmt[x - start] === f && !hasLabelDef(T, x);
                    const enough = (p, n) => n >= (p === 1 ? 2 : 3) && n * p >= opts.fillMin;
                    let best = null;
                    for (let p = 1; p <= maxP; p++) {
                        let k = 1;
                        while (k < p && free(c + k)) k++;
                        if (k < p) break;              // a longer pattern would cross the same break
                        while (free(c + k) && data[o + k] === data[o + k - p]) {
                            k++;
                            if (!full && k % p === 0 && enough(p, k / p)) return { p, n: k / p };
                        }
                        const n = Math.floor(k / p);
                        if (enough(p, n) && (!best || n * p > best.n * best.p)) best = { p, n };
                    }
                    return best;
                };
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
                    const adj = p.adj ? [['pun', '-' + p.adj]] : [];
                    if (p.part === '<' && p.other === a + 1 && a + 1 <= end && !T.ilen[off + 1] && !hasLabelDef(T, a + 1)) {
                        dataLine(T, a, 2, [['dir', 'dta '], ['pun', 'a('], tv].concat(adj, [['pun', ')']]));
                        a += 2;
                    } else {
                        // < and > bind tighter than -: group the adjusted address
                        dataLine(T, a, 1, p.adj ? [['dir', 'dta '], ['pun', p.part + '['], tv, ['pun', '-' + p.adj + ']']]
                            : [['dir', 'dta '], ['pun', p.part], tv]);
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
                    // a repeated byte or pattern: ":N dta $XX[,...]"
                    const rp = repeatAt(a, true);
                    if (rp) {
                        const parts = [['dir', `:${rp.n} dta `]];
                        for (let i = 0; i < rp.p; i++) {
                            if (i) parts.push(['pun', ',']);
                            parts.push(['num', '$' + h2(data[off + i]), undefined, a + i]);
                        }
                        dataLine(T, a, rp.n * rp.p, parts);
                        a += rp.n * rp.p;
                        continue;
                    }
                    let b = lineEnd(perLine);
                    // keep a following repeat whole
                    for (let c = a + 1; c <= b; c++) {
                        if (repeatAt(c, false)) { b = c - 1; break; }
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
        if (!xasm && img.multi && !img.banked) dir('opt h-');
        for (const pl of img.prelude) {
            if (pl.xasmOnly && !xasm) continue;
            dir(pl.text, pl.comment);
        }

        let prevEnd = -2;   // xasm merges a segment into a directly preceding one
        let hOff = false;
        for (const T of S) {
            const seg = T.seg;
            if (seg.reloc) continue;   // emitted inside its parent
            if (img.banked) {
                // cartridge: opt h- is on, so each bank is just an org
                lines.push({
                    k: 'seg', s: seg.index, a: seg.start, n: 0,
                    p: [['note', `${IND};------------------------- Bank ${seg.bank}: $${h4(seg.start)}-$${h4(seg.end)}` +
                        (img.boot.has(seg.index) ? ' (visible at power-on)' : '')]],
                    c: '',
                });
                dir(`org $${h4(seg.start)}`);
                segmentBody(T);
                continue;
            }
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
                    c: '', x: xrefs(k, undefined, true, usesOf(name, k)), u: comments.get(k),
                });
            }
        }
        for (const [name, v] of usedConsts) {
            if (defined.has(name) || used.has(name)) continue;
            head.push({ k: 'equ', s: 0, a: -1, n: 0, p: [['sym', name], ['dir', ' equ '], ['num', '$' + h2(v)]], c: 'constant' });
        }
        // every member of each enum in use, in value order
        const emitted = new Set(usedConsts.keys());
        for (const en of enums.values()) {
            if (!usedEnums.has(en.name)) continue;
            let first = true;
            for (const [name, v] of en.members.slice().sort((x, y) => x[1] - y[1])) {
                if (defined.has(name) || used.has(name) || emitted.has(name)) continue;
                emitted.add(name);
                head.push({ k: 'equ', s: 0, a: -1, n: 0, p: [['sym', name], ['dir', ' equ '], ['num', '$' + h2(v)]],
                    c: '', u: first ? 'enum ' + en.name : undefined });
                first = false;
            }
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
        // spaces up to the comment column (at least one)
        const col = opts.commentColumn >= 0 ? opts.commentColumn | 0 : 30;
        return src + ' '.repeat(Math.max(1, col - src.length)) + '; ' + cm.join(' ');
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

    // The instruction at (seg, addr) takes its immediate from enum `name`
    // (or from none, when name is empty).
    function setEnumOp(dirs, seg, addr, name) {
        const out = dirs.filter((d) => !(d.type === 'enumop' && d.addr === addr && (d.seg || 0) === seg));
        if (name) out.push({ type: 'enumop', name: null, seg, addr, range: 0, enum: name });
        return out;
    }

    // Name `value` in enum `name` as `member`, or remove its name when member
    // is empty. Creates the enum when the project doesn't have it yet.
    function setEnumMember(dirs, name, value, member) {
        let found = false;
        const out = dirs.map((d) => {
            if (d.type !== 'enum' || d.enum !== name) return d;
            const members = d.members.filter(([n, v]) => v !== value && n !== member);
            if (!found && member) members.push([member, value]);
            found = true;
            return Object.assign({}, d, { members: members.sort((x, y) => x[1] - y[1]) });
        });
        if (!found) out.push({ type: 'enum', name: null, seg: 0, addr: 0, range: 0, enum: name, members: member ? [[member, value]] : [] });
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
            // labels switched off in this set are left out entirely
            const off = inc.off && inc.off.length ? new Set(inc.off) : null;
            for (const d of inc.parsed) if (!off || !off.has(d.name)) out.push(d);
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
    // `only` limits the candidates (the rest always stay).
    function redundancyScan(img, project, model, only) {
        const all = allDirectives(project);
        const rank = (d) => (d.name ? 1 : 0) + (POINTER_TYPES.includes(d.type) ? 2 : 0);
        const order = project.directives
            .map((d, i) => [d, i])
            .filter(([d]) => TRACE_TYPES.includes(d.type) && (!only || only(d)))
            .sort((a, b) => rank(a[0]) - rank(b[0]) || a[1] - b[1])
            .map(([d]) => d);
        const removed = new Set();
        const quiet = Object.assign({}, project.options, { suggest: false });
        let i = 0;
        return {
            total: order.length,
            done: () => i,
            step() {
                if (i >= order.length) return null;
                const d = order[i++];
                const removable = (d.type !== 'relocate' && !touchesLoaded(model, model.mapDirective(d))) ||
                    sameCode(model, analyze(img, all.filter((x) => x !== d && !removed.has(x)), quiet));
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
                ...(i.off && i.off.length ? { off: i.off.slice() } : {}),
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
            ...(Array.isArray(i.off) && i.off.length ? { off: i.off.slice() } : {}),
        }));
        project.directives = (p.directives || []).map((s) => {
            const d = parseDirectiveLine(s);
            if (!d) throw new Error('Bad directive: ' + s);
            return d;
        });
        return { project, bytes };
    }

    return {
        OPS, h2, h4, hx, key, keySeg, keyAddr, encodeText, LABEL_RE, cartTypesFor,
        cartTypes: () => Object.keys(CART_TYPES).map(Number).map((t) => ({ type: t, name: CART_TYPES[t][0], kb: CART_SIZES[t] })),
        detectType, loadImage, analyze, render, asmText, lineText,
        parseDop, exportDop, dedupeImported, defaultOffOf, newInclude, refreshInclude, parseDirectiveLine, directiveString, specString,
        defaultOptions, newProject, allDirectives, serializeProject, deserializeProject,
        redundancyScan, sameCode, TRACE_TYPES,
        toBase64, fromBase64,
        edit: { setName, markCode, markData, markPointers, undefine, setText, setConstant, setEnumOp, setEnumMember, subtract, addRelocation, removeRelocation },
        CLI_TYPES, EXT_TYPES, DATA_TYPES, POINTER_TYPES,
    };
});
