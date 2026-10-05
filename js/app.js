/* xdis — interactive UI. Every edit rebuilds the analysis and the listing,
 * so the disassembly always reflects the current directives. */
(function () {
    'use strict';

    const X = window.XDis;
    const SYM = window.XDisSymbols || { groups: {}, files: {} };
    const $ = (id) => document.getElementById(id);
    const LH = 18;
    const MNEMONICS = new Set(X.OPS.map((o) => o.mn).concat(['a', 'x', 'y']));

    const S = {
        project: X.newProject(),
        bytes: null,
        img: null,
        model: null,
        listing: null,
        mapCls: null,
        cur: 0,
        anchor: 0,
        undo: [],
        redo: [],
        back: [],
        fwd: [],
        importProblems: [],
        embed: true,
    };

    const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const hexAddr = (a) => '$' + X.h4(a);

    function setStatus(msg, err) {
        const el = $('status-msg');
        el.textContent = msg || '';
        el.classList.toggle('err', !!err);
    }

    // ------------------------------------------------------------------
    // Rebuild: load image -> analyze -> render

    function rebuild(opt) {
        opt = opt || {};
        const p = S.project;
        if (!S.bytes || !p.binary) {
            S.img = S.model = S.listing = null;
            $('empty').hidden = false;
            $('spacer').style.height = '0px';
            $('rows').innerHTML = '';
            updateAll();
            return;
        }
        const keep = opt.keepView !== false && S.listing ? viewAnchor() : null;
        const t0 = performance.now();
        if (opt.reload || !S.img) {
            try {
                S.img = X.loadImage(S.bytes, p.binary.type, p.binary.org);
            } catch (e) {
                setStatus(`${e.message}; loading as raw`, true);
                p.binary.type = 'raw';
                S.img = X.loadImage(S.bytes, 'raw', p.binary.org || 0);
            }
        }
        S.model = X.analyze(S.img, X.allDirectives(p), p.options);
        S.listing = X.render(S.model);
        S.mapCls = null;
        S.ms = performance.now() - t0;
        // size the source column to the widest instruction or data line
        let w = 24;
        for (const ln of S.listing.lines) {
            if (ln.k !== 'ins' && ln.k !== 'data') continue;
            let n = 0;
            for (const p of ln.p) n += p[1].length;
            if (n > w) w = n;
        }
        document.documentElement.style.setProperty('--srcw', Math.min(w + 2, 72) + 'ch');
        $('empty').hidden = true;
        $('spacer').style.height = S.listing.lines.length * LH + 'px';
        if (keep) {
            restoreView(keep);
        } else {
            S.cur = S.anchor = firstInterestingLine();
            $('listing').scrollTop = Math.max(0, S.cur * LH - 3 * LH);
        }
        updateAll();
        scheduleSave();
        startScan();
        if (opt.keepView === false) {
            const sug = S.model.warnings.filter((w) => w.suggest);
            const nr = sug.filter((w) => w.suggest.type === 'relocate').length, np = sug.length - nr;
            const parts = [];
            if (nr) parts.push(`${nr} relocated code block${nr > 1 ? 's' : ''}`);
            if (np) parts.push(`${np} likely pointer${np > 1 ? 's' : ''}`);
            if (parts.length) setTimeout(() => setStatus(`Found ${parts.join(' and ')} — see Problems`), 0);
        }
    }

    // ------------------------------------------------------------------
    // Which directives are not needed for the code/data split. Runs in the
    // background in small slices and restarts after every change.

    let scanId = 0;
    let scanDrawn = 0;
    function startScan() {
        const id = ++scanId;
        S.dirState = new Map();
        S.scan = null;
        if (!S.model) return;
        const sc = X.redundancyScan(S.img, S.project, S.model);
        S.scan = sc;
        const step = () => {
            if (id !== scanId) return;
            const t0 = performance.now();
            let r;
            while (performance.now() - t0 < 20 && (r = sc.step())) {
                S.dirState.set(r.d, r.removable ? unneededKind(r.d) : 'needed');
            }
            const finished = sc.done() >= sc.total;
            if (finished || performance.now() - scanDrawn > 300) {
                scanDrawn = performance.now();
                if (!$('tab-directives').hidden) updateDirectives();
                else updateDirCount();
                if (finished && !$('tab-inspect').hidden) updateInspector();
            }
            if (!finished) setTimeout(step, 0);
        };
        setTimeout(step, 30);
    }

    // How a directive that doesn't change the code/data split is labelled.
    function unneededKind(d) {
        if (d.type === 'code' || d.type === 'data') return d.name ? 'name' : 'none';
        return 'format';
    }

    const DIR_TAGS = {
        none: ['no effect', 'Not needed: removing this (together with the other "no effect", "name only" and "format only" directives) leaves code and data unchanged'],
        name: ['name only', 'Not needed for tracing: it only supplies the name, which a plain label would also do'],
        format: ['format only', 'Not needed for tracing: it only changes how the bytes are shown (text, words or pointers)'],
    };

    function dirTag(d) {
        const st = S.dirState && S.dirState.get(d);
        if (!st || st === 'needed') return '';
        const [text, title] = DIR_TAGS[st];
        return `<span class="tag tag-${st}" title="${esc(title)}">${text}</span>`;
    }

    function updateDirCount() {
        const p = S.project;
        let unneeded = 0;
        for (const st of (S.dirState || new Map()).values()) if (st !== 'needed') unneeded++;
        const sc = S.scan;
        let t = p.directives.length ? `(${p.directives.length})` : '';
        if (sc && sc.done() < sc.total) t += ` · checking ${sc.done()}/${sc.total}…`;
        else if (unneeded) t += ` · ${unneeded} not needed for tracing`;
        $('dir-count').textContent = t;
    }

    function updateAll() {
        draw();
        drawMap();
        updateFileInfo();
        updateInspector();
        updateLabels();
        updateDirectives();
        updateProject();
        updateProblems();
        updateButtons();
    }

    function firstInterestingLine() {
        const L = S.listing.lines;
        for (let i = 0; i < L.length; i++) if (L[i].k === 'label' || L[i].k === 'ins') return i;
        for (let i = 0; i < L.length; i++) if (L[i].s && L[i].a >= 0 && L[i].k !== 'seg') return i;
        return 0;
    }

    // "N:" segment prefix for display; relocated blocks only get one when
    // their run address is also loaded by another segment.
    function segPre(s, a) {
        if (!S.img || !S.img.multi || !s) return '';
        const T = S.model.S[s - 1];
        if (T && T.seg.reloc && S.model.cover[a] <= 1) return '';
        return s + ':';
    }

    function curLine() {
        return S.listing && S.listing.lines[S.cur];
    }

    function lineKey(ln) {
        return ln && ln.a >= 0 && (ln.s || ln.k === 'equ') ? X.key(ln.s, ln.a) : null;
    }

    // A byte picked inside the cursor line (click a byte, or Left/Right), or
    // null when the whole line is meant.
    function subAddr() {
        const ln = curLine();
        if (S.sub === null || S.sub === undefined || !ln || S.anchor !== S.cur || !ln.s) return null;
        return S.sub >= ln.a && S.sub < ln.a + ln.n ? S.sub : null;
    }

    // Key of the address the cursor refers to.
    function curKey() {
        const ln = curLine();
        const sub = subAddr();
        return sub !== null ? X.key(ln.s, sub) : lineKey(ln);
    }

    function viewAnchor() {
        const ln = curLine();
        return { k: curKey(), kind: ln && ln.k, off: S.cur * LH - $('listing').scrollTop, idx: S.cur };
    }

    function restoreView(v) {
        let i = v.k !== null ? lineForKey(v.k, v.kind) : -1;
        if (i < 0) i = Math.min(v.idx, S.listing.lines.length - 1);
        S.cur = S.anchor = i;
        const ln = S.listing.lines[i];
        const a = v.k !== null ? X.keyAddr(v.k) : -1;
        S.sub = ln && ln.n && a > ln.a && a < ln.a + ln.n ? a : null;
        $('listing').scrollTop = i * LH - v.off;
    }

    // Line index for a (seg, addr) key. `prefer` picks the instruction/data
    // line over the label line for the same address.
    function lineForKey(k, prefer) {
        const L = S.listing, m = S.model;
        let s = X.keySeg(k);
        let a = X.keyAddr(k);
        if (!s && m.finalOwner[a] && !L.firstLine.has(k)) {
            s = m.finalOwner[a];
            k = X.key(s, a);
        }
        if (!s && !m.finalOwner[a] && !L.firstLine.has(k) && m.loadToRun(a) !== null) {
            // a load address inside a relocated block
            k = m.loadToRun(a);
            s = X.keySeg(k);
            a = X.keyAddr(k);
        }
        // an address in a segment's relocated hole means the relocated block
        for (const p of (s && m.holesOf.get(s)) || []) {
            if (a >= p.load && a < p.load + p.data.length) {
                s = p.index;
                a = p.start + a - p.load;
                k = X.key(s, a);
                break;
            }
        }
        const primary = () => {
            const T = m.S[s - 1];
            if (!T) return -1;
            const o = a - T.seg.start;
            return o >= 0 && o < T.seg.data.length ? L.lineOf[s - 1][o] : -1;
        };
        if (prefer === 'ins' || prefer === 'data') {
            const i = primary();
            if (i >= 0) return i;
        }
        const f = L.firstLine.get(k);
        if (f !== undefined) return f;
        return primary();
    }

    // ------------------------------------------------------------------
    // Listing view (virtualized)

    function selLines() {
        return [Math.min(S.anchor, S.cur), Math.max(S.anchor, S.cur)];
    }

    function draw() {
        const el = $('listing');
        const rows = $('rows');
        if (!S.listing) return;
        const L = S.listing.lines;
        const first = Math.max(0, Math.floor(el.scrollTop / LH) - 4);
        const last = Math.min(L.length, Math.ceil((el.scrollTop + el.clientHeight) / LH) + 4);
        const [lo, hi] = selLines();
        let html = '';
        for (let i = first; i < last; i++) html += rowHtml(L[i], i, i === S.cur, i >= lo && i <= hi && lo !== hi);
        rows.style.top = first * LH + 'px';
        rows.innerHTML = html;
        updatePos();
        drawViewport();
    }

    // Raw bytes column; each byte can be clicked to pick it.
    function bytesOf(ln, sub) {
        const T = S.model.S[ln.s - 1];
        if (!T || !ln.n) return '';
        const off = ln.a - T.seg.start;
        const shown = ln.n > 3 ? 2 : ln.n;
        let h = '';
        for (let m = 0; m < shown; m++) {
            const a = ln.a + m;
            h += (m ? ' ' : '') + `<span class="b${a === sub ? ' bsel' : ''}" data-a="${a}">${X.h2(T.seg.data[off + m])}</span>`;
        }
        return ln.n > 3 ? h + ' …' : h;
    }

    function rowHtml(ln, i, cur, sel) {
        let ad = '', by = '';
        const sub = cur ? subAddr() : null;
        if (ln.a >= 0 && ln.k !== 'seg' && ln.k !== 'dir') {
            const multi = S.img.multi && ln.s && S.model.cover[ln.a] > 1;
            ad = (multi ? `<span class="sg">${ln.s}:</span>` : '') + X.h4(sub !== null ? sub : ln.a);
            const T = ln.s && S.model.S[ln.s - 1];
            if (T && T.seg.reloc) ad = `<span title="relocated: loaded at $${X.h4(T.seg.load + (sub !== null ? sub : ln.a) - T.seg.start)}">${ad}</span>`;
            by = ln.s ? bytesOf(ln, sub) : '';
        }
        let src = '';
        for (const [cls, text, k, a] of ln.p) {
            const pick = a !== undefined ? ` data-a="${a}"` : '';
            const bsel = a !== undefined && a === sub ? ' bsel' : '';
            if (cls === 'pun') {
                src += esc(text);
            } else if (cls === 'str' && a !== undefined) {
                // one span per character so each byte of a string can be picked
                src += `<span class="t-str">c'`;
                for (let c = 2; c < text.length - 1; c++) {
                    const ca = a + c - 2;
                    src += `<span data-a="${ca}"${ca === sub ? ' class="bsel"' : ''}>${esc(text[c])}</span>`;
                }
                src += `'</span>`;
            } else if (k !== undefined && (cls === 'sym' || cls === 'lbl' || cls === 'num')) {
                const c = cls === 'num' ? 't-num' : 't-' + cls;
                src += `<span class="${c}${bsel}" data-k="${k}"${pick} title="${hexAddr(X.keyAddr(k))}">${esc(text)}</span>`;
            } else {
                const c = cls === 'mn' && ln.ill ? 't-ill' : 't-' + cls;
                src += `<span class="${c}${bsel}"${pick}>${esc(text)}</span>`;
            }
        }
        let cm = '';
        if (ln.u) cm += `<span class="u">; ${esc(ln.u.replace(/\n/g, ' '))}</span> `;
        if (ln.x) cm += xrefHtml(ln);
        else if (ln.k === 'dir' && ln.c) cm += '; ' + esc(ln.c);
        const cls = 'row k-' + ln.k + (cur ? ' cur' : '') + (sel ? ' sel' : '');
        return `<div class="${cls}" data-i="${i}"><span class="ad">${ad}</span><span class="by">${by}</span><span class="src">${src}</span><span class="cm">${cm}</span></div>`;
    }

    // The Access/Callers comment with each referencing address as a link.
    function xrefHtml(ln) {
        const r = S.model.refs.get(lineKey(ln));
        if (!r) return esc(ln.x);
        const keys = new Map();
        for (const k of r.access.concat(r.callers)) {
            if (typeof k === 'number') keys.set(S.listing.refName(k), k);
        }
        return ln.x.split(' ').map((w) => {
            const k = keys.get(w);
            return k === undefined ? esc(w) : `<span class="xl" data-xk="${k}" title="Go to ${hexAddr(X.keyAddr(k))}">${esc(w)}</span>`;
        }).join(' ');
    }

    function ensureVisible(i, center) {
        const el = $('listing');
        const top = i * LH;
        if (center) {
            if (top < el.scrollTop || top + LH > el.scrollTop + el.clientHeight) {
                el.scrollTop = top - el.clientHeight / 3;
            }
        } else if (top < el.scrollTop) {
            el.scrollTop = top;
        } else if (top + LH > el.scrollTop + el.clientHeight) {
            el.scrollTop = top + LH - el.clientHeight;
        }
    }

    let inspectTimer = 0;
    function moveTo(i, extend, center, sub) {
        if (!S.listing) return;
        i = Math.max(0, Math.min(S.listing.lines.length - 1, i));
        S.cur = i;
        if (!extend) S.anchor = i;
        S.sub = sub === undefined ? null : sub;
        ensureVisible(i, center);
        draw();
        clearTimeout(inspectTimer);
        inspectTimer = setTimeout(updateInspector, 30);
    }

    // Step the picked byte left or right, moving to the neighbouring line at
    // either end.
    function stepByte(dir) {
        const ln = curLine();
        if (!ln) return;
        const cur = subAddr() !== null ? subAddr() : ln.a;
        const next = cur + dir;
        if (ln.n > 1 && next >= ln.a && next < ln.a + ln.n) return moveTo(S.cur, false, false, next);
        let i = S.cur + dir;
        const L = S.listing.lines;
        while (i >= 0 && i < L.length && !L[i].n) i += dir;
        if (i < 0 || i >= L.length) return;
        moveTo(i, false, false, dir < 0 && L[i].n > 1 ? L[i].a + L[i].n - 1 : undefined);
    }

    function updatePos() {
        const ln = curLine();
        const el = $('status-pos');
        if (!ln) { el.textContent = ''; return; }
        const [lo, hi] = selLines();
        const r = selRange();
        const sub = subAddr();
        let s = ln.a >= 0 && ln.k !== 'dir' ? segPre(ln.s, sub !== null ? sub : ln.a) + X.h4(sub !== null ? sub : ln.a) : '';
        if (sub !== null) s += ` (byte ${sub - ln.a + 1} of ${ln.n})`;
        if (lo !== hi && r) s += ` · ${hexAddr(r.lo)}–${hexAddr(r.hi)} (${r.hi - r.lo + 1} bytes)`;
        el.textContent = s + `  line ${S.cur + 1}/${S.listing.lines.length}`;
    }

    // ------------------------------------------------------------------
    // Selection to address range

    function lineBytes(ln) {
        if (ln.n) return ln.n;
        if (!ln.s) return 1;
        const i = lineForKey(X.key(ln.s, ln.a), 'ins');
        const p = i >= 0 && S.listing.lines[i];
        return p && p.a === ln.a && p.n ? p.n : 1;
    }

    function selRange() {
        if (!S.listing) return null;
        const L = S.listing.lines;
        const sub = subAddr();
        if (sub !== null) return { seg: L[S.cur].s, lo: sub, hi: sub };
        const [lo, hi] = selLines();
        let seg = L[S.cur].s;
        if (!seg || L[S.cur].a < 0) {
            for (let i = lo; i <= hi && !seg; i++) if (L[i].s && L[i].a >= 0 && L[i].k !== 'seg') seg = L[i].s;
        }
        if (!seg) return null;
        let a0 = Infinity, a1 = -1;
        for (let i = lo; i <= hi; i++) {
            const ln = L[i];
            if (ln.s !== seg || ln.a < 0 || ln.k === 'seg' || ln.k === 'equ' || ln.k === 'dir') continue;
            a0 = Math.min(a0, ln.a);
            a1 = Math.max(a1, ln.a + lineBytes(ln) - 1);
        }
        return a1 < 0 ? null : { seg, lo: a0, hi: a1 };
    }

    // Directives are global unless the address is loaded by more than one
    // segment (overlays), in which case they are segment specific.
    function scopeSeg(seg, addr) {
        return S.img.multi && seg && S.model.cover[addr] > 1 ? seg : 0;
    }

    // ------------------------------------------------------------------
    // Undo / commit

    function snapshot() {
        const p = S.project;
        return {
            directives: p.directives,
            options: Object.assign({}, p.options),
            includes: p.includes.map((i) => Object.assign({}, i)),
            binary: p.binary && Object.assign({}, p.binary),
        };
    }

    function commit(change, msg) {
        S.undo.push(snapshot());
        if (S.undo.length > 500) S.undo.shift();
        S.redo = [];
        const b = S.project.binary;
        const before = b && b.type + ':' + b.org;
        change(S.project);
        const after = b && S.project.binary && S.project.binary.type + ':' + S.project.binary.org;
        rebuild({ reload: before !== after });
        if (msg) setStatus(msg);
    }

    function restoreSnap(snap) {
        Object.assign(S.project, snap);
        rebuild({ reload: true });
    }

    function undo() {
        if (!S.undo.length) return setStatus('Nothing to undo');
        S.redo.push(snapshot());
        restoreSnap(S.undo.pop());
        setStatus('Undone');
    }

    function redo() {
        if (!S.redo.length) return setStatus('Nothing to redo');
        S.undo.push(snapshot());
        restoreSnap(S.redo.pop());
        setStatus('Redone');
    }

    function updateButtons() {
        $('btn-undo').disabled = !S.undo.length;
        $('btn-redo').disabled = !S.redo.length;
        const has = !!S.model;
        for (const id of ['btn-save-proj', 'btn-export-dop', 'btn-save-asm', 'btn-import-dop']) $(id).disabled = !has && id !== 'btn-import-dop';
    }

    // ------------------------------------------------------------------
    // Edit actions

    const ACTIONS = {
        code: { label: 'Code (trace from here)', key: 'C' },
        data: { label: 'Data bytes', key: 'D' },
        text: { label: 'Text', key: 'T' },
        word: { label: 'Words', key: 'W' },
        address: { label: 'Pointer table', key: 'A' },
        codeptr: { label: 'Code pointer table', key: 'P' },
        vector: { label: 'Vector', key: 'V' },
        undefine: { label: 'Undefine', key: 'U' },
        name: { label: 'Rename…', key: 'N' },
        comment: { label: 'Comment…', key: ';' },
        note: { label: 'Block comment…', key: ':' },
        operand: { label: 'Operand override…', key: 'O' },
        constant: { label: 'Name constant…', key: 'K' },
        relocate: { label: 'Relocate (org r:)…', key: 'R' },
        hibyte: { label: 'High byte of an address (#>)…', key: '>' },
        lobyte: { label: 'Low byte of an address (#<)…', key: '<' },
    };

    function collapse() {
        S.anchor = S.cur;
    }

    function act(name, arg) {
        if (!S.model) return;
        const r = selRange();
        const ln = curLine();
        const E = X.edit;
        const rangeText = (r) => (r.lo === r.hi ? hexAddr(r.lo) : `${hexAddr(r.lo)}–${hexAddr(r.hi)}`);
        switch (name) {
            case 'code': {
                if (!r) return noAddr();
                const sc = scopeSeg(r.seg, r.lo);
                collapse();
                commit((p) => { p.directives = E.markCode(p.directives, sc, r.lo, r.hi); }, `Code at ${hexAddr(r.lo)}`);
                if (!S.model.isCodeStart(X.key(r.seg, r.lo))) {
                    setStatus(`Could not trace code at ${hexAddr(r.lo)}: BRK, illegal opcode, or data from an enabled symbol set`, true);
                }
                return;
            }
            case 'data': case 'text': case 'word': {
                if (!r) return noAddr();
                const sc = scopeSeg(r.seg, r.lo);
                collapse();
                commit((p) => { p.directives = E.markData(p.directives, sc, r.lo, r.hi, name); }, `${name} at ${rangeText(r)}`);
                return;
            }
            case 'address': case 'codeptr': case 'vector': {
                if (!r) return noAddr();
                const sc = scopeSeg(r.seg, r.lo);
                collapse();
                commit((p) => { p.directives = E.markPointers(p.directives, sc, r.lo, r.hi, name); }, `${name} at ${rangeText(r)}`);
                return;
            }
            case 'undefine': {
                if (!r) return noAddr();
                const sc = scopeSeg(r.seg, r.lo);
                collapse();
                commit((p) => { p.directives = E.undefine(p.directives, sc, r.lo, r.hi); }, `Undefined ${rangeText(r)}`);
                return;
            }
            case 'name': return rename(arg !== undefined ? arg : curKey());
            case 'comment': return editText('comment', curKey());
            case 'note': return editText('note', curKey());
            case 'operand': return editOperand(ln);
            case 'constant': return editConstant(ln);
            case 'relocate': return relocateDialog(r);
            case 'hibyte': return editHalf(ln, 'hi');
            case 'lobyte': return editHalf(ln, 'lo');
        }
    }

    // The relocated block (piece) the cursor is in, if any.
    function curPiece() {
        const ln = curLine();
        const T = ln && ln.s && S.model.S[ln.s - 1];
        return T && T.seg.reloc ? T.seg : null;
    }

    function relocKey(d) {
        const p = S.model.pieces.find((x) => x.dir === d);
        return p ? X.key(p.index, p.start) : (d.seg || 0) * 0x10000 + d.addr;
    }

    const parseHex = (v) => {
        const n = parseInt(String(v).trim().replace(/^\$|^0x/i, ''), 16);
        return isNaN(n) || n < 0 || n > 0xFFFF ? null : n;
    };

    // Relocate the selection (or offer to undo the relocation the cursor is in).
    async function relocateDialog(r, preset) {
        const piece = !preset && curPiece();
        if (piece) {
            const n = piece.data.length;
            const b = await ask('Relocated block',
                `<p>Bytes loaded at <b>$${X.h4(piece.load)}–$${X.h4(piece.load + n - 1)}</b> are disassembled as running at
                 <b>$${X.h4(piece.start)}–$${X.h4(piece.end)}</b> (<code>org r:</code>).</p>
                 <p>Removing the relocation moves directives inside it back to the load addresses.</p>`,
                [{ label: 'Cancel', value: 'cancel' }, { label: 'Remove relocation', value: 'remove', primary: true }]);
            if (b === 'remove') removeRelocation(piece.dir);
            return;
        }
        if (!r && !preset) return noAddr();
        const T = !preset && S.model.S[r.seg - 1];
        const lo = preset ? preset.addr : r.lo;
        const hi = preset ? preset.addr + preset.range : (r.lo === r.hi ? T.seg.end : r.hi);
        const run = preset ? preset.run : null;
        let res = null;
        const body = `<p class="dim">Disassemble bytes that are loaded at one address but copied elsewhere before they run.
            The output uses <code>org r:</code> (xasm) or <code>org RUN,*</code> (MADS).</p>
            <div class="field"><label>Loaded from (hex)</label><input type="text" id="rl-lo" value="$${X.h4(lo)}"></div>
            <div class="field"><label>Loaded to (hex, inclusive)</label><input type="text" id="rl-hi" value="$${X.h4(hi)}"></div>
            <div class="field"><label>Runs at (hex)</label><input type="text" id="rl-run" value="${run !== null ? '$' + X.h4(run) : ''}" placeholder="e.g. $A000"></div>
            <div id="dlg-err" class="problem" hidden></div>`;
        const btn = await dialog(preset ? 'Relocate suggested block' : 'Relocate code', body,
            [{ label: 'Cancel', value: 'cancel' }, { label: 'Relocate', value: 'ok', primary: true }], (dlg) => {
                const focus = $(run === null ? 'rl-run' : 'rl-lo');
                focus.focus();
                focus.select();
                const check = () => {
                    const a = parseHex($('rl-lo').value), b = parseHex($('rl-hi').value), c = parseHex($('rl-run').value);
                    let err = '';
                    if (a === null || b === null || c === null) err = 'Enter hex addresses';
                    else if (b < a) err = 'The end is before the start';
                    else if (c + (b - a) > 0xFFFF) err = 'The run address range goes past $FFFF';
                    $('dlg-err').hidden = !err;
                    $('dlg-err').textContent = err;
                    if (!err) res = { lo: a, hi: b, run: c };
                    return !err;
                };
                dlg.querySelector('button[value=ok]').addEventListener('click', (e) => { if (!check()) e.preventDefault(); });
                for (const id of ['rl-lo', 'rl-hi', 'rl-run']) {
                    $(id).addEventListener('keydown', (e) => {
                        if (e.key !== 'Enter') return;
                        e.preventDefault();
                        if (check()) closeDialog('ok');
                    });
                }
            });
        if (btn !== 'ok' || !res) return;
        const seg = preset ? preset.seg : scopeSeg(r.seg, res.lo);
        const d = { type: 'relocate', name: null, seg, addr: res.lo, range: res.hi - res.lo, run: res.run };
        commit((p) => { p.directives = X.edit.addRelocation(p.directives, S.img, d); },
            `Relocated $${X.h4(res.lo)}–$${X.h4(res.hi)} to run at $${X.h4(res.run)}`);
        const bad = S.model.warnings.find((w) => w.dir === X.directiveString(d));
        if (bad) return setStatus(bad.msg, true);
        goKey(X.key(S.model.pieces.find((x) => x.dir.addr === d.addr && x.dir.run === d.run).index, d.run));
    }

    // The byte that `>`/`<` applies to: a picked byte, the operand of an
    // immediate instruction, or a one-byte data line.
    function halfByte(ln) {
        if (!ln || !ln.s || ln.a < 0) return null;
        const sub = subAddr();
        if (sub !== null) return sub;
        if (ln.k === 'label' || ln.k === 'note' || ln.k === 'mid') {
            // on a label line, mean the instruction or data it labels
            const i = lineForKey(X.key(ln.s, ln.a), 'ins');
            ln = i >= 0 ? S.listing.lines[i] : ln;
            if (ln.k !== 'ins' && ln.k !== 'data') return null;
        }
        const T = S.model.S[ln.s - 1];
        if (ln.k === 'ins' && X.OPS[T.seg.data[ln.a - T.seg.start]].mode === 'imm') return ln.a + 1;
        if (ln.k === 'data') return ln.a;
        return null;
    }

    // Mark one byte as the high or low byte of an address: #>label / #<label.
    async function editHalf(ln, type) {
        const a = halfByte(ln);
        if (a === null) return setStatus('Select an immediate instruction or pick a byte first', true);
        const T = S.model.segOf(X.key(ln.s, a));
        const b = T.seg.data[a - T.seg.start];
        const sc = scopeSeg(ln.s, a);
        const existing = S.project.directives.find((d) => (d.type === 'hi' || d.type === 'lo') && d.addr === a && (d.seg || 0) === sc);
        const cur = existing ? (existing.target !== undefined ? existing.target : b << 8) : null;
        const text = await promptText(
            `$${X.h2(b)} at $${X.h4(a)} is the ${type === 'hi' ? 'high' : 'low'} byte of…`,
            cur !== null ? '$' + X.h4(cur) : type === 'hi' ? `$${X.h2(b)}00` : '',
            {
                placeholder: type === 'hi' ? `$${X.h2(b)}00` : `$xx${X.h2(b)}`,
                help: `The operand becomes #${type === 'hi' ? '>' : '<'}label. Leave empty to remove.`,
                validate: (v) => {
                    if (!v.trim()) return null;
                    const t = parseHex(v);
                    if (t === null) return 'Enter a hex address';
                    if ((type === 'hi' ? t >> 8 : t & 0xFF) !== b) return `Its ${type === 'hi' ? 'high' : 'low'} byte must be $${X.h2(b)}`;
                    return null;
                },
            });
        if (text === null) return;
        const t = text.trim() ? parseHex(text) : null;
        commit((p) => {
            p.directives = p.directives.filter((d) => !((d.type === 'hi' || d.type === 'lo') && d.addr === a && (d.seg || 0) === sc));
            if (t !== null) {
                const d = { type, name: null, seg: sc, addr: a, range: 0 };
                if (type === 'lo' || t !== b << 8) d.target = t;
                p.directives.push(d);
            }
        }, t === null ? `Removed ${type} at $${X.h4(a)}` : `$${X.h4(a)} is the ${type === 'hi' ? 'high' : 'low'} byte of $${X.h4(t)}`);
    }

    function removeRelocation(d) {
        commit((p) => { p.directives = X.edit.removeRelocation(p.directives, S.model, d); },
            `Removed ${X.directiveString(d)}`);
    }

    function noAddr() {
        setStatus('Select a line with an address first', true);
    }

    function validateName(name, k) {
        if (!name) return null;
        if (!X.LABEL_RE.test(name)) return 'Labels must start with a letter, _ ? or @ and contain only letters, digits, _ ? @';
        if (MNEMONICS.has(name.toLowerCase())) return `"${name}" is a mnemonic or register name`;
        const other = S.model.names.get(name);
        if (other !== undefined && other !== k) return `"${name}" is already used at ${hexAddr(X.keyAddr(other))}`;
        return null;
    }

    async function rename(k) {
        if (k === null || k === undefined) return noAddr();
        const l = S.model.labelAt(k);
        const a = X.keyAddr(k);
        const cur = l && !l.off ? l.name : '';
        const name = await promptText(`Name for ${hexAddr(a)}`, l && l.user && !l.off ? cur : '', {
            placeholder: cur || 'label',
            help: 'Leave empty to remove a name. Names from symbol sets are overridden, not edited.',
            validate: (v) => validateName(v.trim(), k),
        });
        if (name === null) return;
        applyName(k, name.trim());
    }

    function applyName(k, name) {
        const err = validateName(name, k);
        if (err) return setStatus(err, true);
        const l = S.model.labelAt(k);
        const a = X.keyAddr(k);
        const sc = scopeSeg(X.keySeg(k), a);
        commit((p) => { p.directives = X.edit.setName(p.directives, sc, a, name || null, l); },
            name ? `Named ${hexAddr(a)} ${name}` : `Removed name at ${hexAddr(a)}`);
    }

    async function editText(type, k) {
        if (k === null) return noAddr();
        const a = X.keyAddr(k);
        const map = type === 'comment' ? S.model.comments : S.model.notes;
        const cur = map.get(k) || '';
        const text = await promptText(type === 'comment' ? `Comment at ${hexAddr(a)}` : `Block comment above ${hexAddr(a)}`, cur, {
            multiline: type === 'note',
            help: type === 'note' ? 'Shown as ; lines above the address. Ctrl+Enter to apply.' : '',
        });
        if (text === null) return;
        applyText(type, k, text);
    }

    function applyText(type, k, text) {
        const a = X.keyAddr(k);
        const sc = scopeSeg(X.keySeg(k), a);
        commit((p) => { p.directives = X.edit.setText(p.directives, type, sc, a, text.replace(/\s+$/, '')); },
            text ? `${type} at ${hexAddr(a)}` : `Removed ${type} at ${hexAddr(a)}`);
    }

    async function editOperand(ln) {
        if (!ln || ln.k !== 'ins') return setStatus('Operand override applies to instructions', true);
        const k = lineKey(ln);
        const cur = S.model.operands.get(k);
        const shown = ln.p.slice(3).map((p) => p[1]).join('').trim();
        const text = await promptText(`Operand for ${ln.p[1][1]} at ${hexAddr(ln.a)}`, cur !== undefined ? cur : shown, {
            help: 'Replaces the operand text verbatim, e.g. #<buffer or table+1,x. Leave empty to restore.',
        });
        if (text === null) return;
        applyText('operand', k, text.trim());
    }

    async function editConstant(ln) {
        if (!ln || ln.k !== 'ins') return setStatus('Select an instruction with an immediate operand', true);
        const T = S.model.S[ln.s - 1];
        const off = ln.a - T.seg.start;
        const op = X.OPS[T.seg.data[off]];
        if (op.mode !== 'imm') return setStatus('Select an instruction with an immediate operand', true);
        const v = T.seg.data[off + 1];
        const cur = S.model.consts.get(v) || '';
        const name = await promptText(`Name for constant #$${X.h2(v)}`, cur, {
            help: `Every immediate operand #$${X.h2(v)} will use this name (like dis -C). Leave empty to remove.`,
            validate: (n) => (n && !X.LABEL_RE.test(n.trim()) ? 'Invalid name' : null),
        });
        if (name === null) return;
        commit((p) => { p.directives = X.edit.setConstant(p.directives, v, name.trim()); },
            name ? `Constant ${name} = $${X.h2(v)}` : `Removed constant $${X.h2(v)}`);
    }

    // ------------------------------------------------------------------
    // Navigation

    function goKey(k, push) {
        const i = lineForKey(k, 'label');
        if (i < 0) {
            setStatus(`${hexAddr(X.keyAddr(k))} is not in loaded memory`, true);
            return false;
        }
        if (push !== false) {
            S.back.push(viewAnchor());
            if (S.back.length > 200) S.back.shift();
            S.fwd = [];
        }
        moveTo(i, false, true);
        flash(i);
        return true;
    }

    function flash(i) {
        requestAnimationFrame(() => {
            const el = $('rows').querySelector(`[data-i="${i}"]`);
            if (el) el.classList.add('flash');
        });
    }

    function goBack(fwd) {
        const from = fwd ? S.fwd : S.back;
        const to = fwd ? S.back : S.fwd;
        if (!from.length) return;
        to.push(viewAnchor());
        const v = from.pop();
        restoreView(v);
        draw();
        updateInspector();
    }

    function follow(ln) {
        ln = ln || curLine();
        if (!ln) return;
        const part = ln.p.find((p) => p[2] !== undefined && (p[0] === 'sym' || p[0] === 'num'));
        if (part) goKey(part[2]);
    }

    function parseTarget(text) {
        text = text.trim();
        if (!text) return null;
        const m = /^(?:(\d+):)?\$?([0-9a-fA-F]{1,4})$/.exec(text);
        const named = S.model.names.get(text);
        if (named !== undefined) return named;
        for (const [name, k] of S.model.names) if (name.toLowerCase() === text.toLowerCase()) return k;
        for (const ln of S.listing.lines) {
            if (ln.def !== undefined && ln.p[0][1] === text) return ln.def;
        }
        if (m) {
            const a = parseInt(m[2], 16);
            const s = m[1] ? +m[1] : S.model.finalOwner[a];
            return X.key(s, a);
        }
        for (const ln of S.listing.lines) {
            if (ln.def !== undefined && ln.p[0][1].toLowerCase().startsWith(text.toLowerCase())) return ln.def;
        }
        return null;
    }

    async function gotoPrompt() {
        if (!S.model) return;
        const names = [];
        for (const ln of S.listing.lines) if (ln.def !== undefined && names.length < 5000) names.push(ln.p[0][1]);
        const text = await promptText('Go to address or label', '', {
            placeholder: '$2000, 3:2000, or a label', datalist: names,
        });
        if (text === null) return;
        const k = parseTarget(text);
        if (k === null) return setStatus(`Not found: ${text}`, true);
        goKey(k);
    }

    // ------------------------------------------------------------------
    // Dialogs

    function dialog(title, bodyHtml, buttons, setup) {
        const dlg = $('dlg');
        $('dlg-title').textContent = title;
        $('dlg-body').innerHTML = bodyHtml;
        $('dlg-buttons').innerHTML = buttons.map((b) =>
            `<button value="${esc(b.value)}" class="${b.primary ? 'primary' : ''}">${esc(b.label)}</button>`).join('');
        return new Promise((resolve) => {
            dlg.returnValue = '';
            // Settle directly from the buttons (and closeDialog) rather than
            // waiting for the asynchronous "close" event, which is only used
            // for Escape. A stale close event can't settle a newer dialog.
            let settled = false;
            const finish = (v) => {
                if (settled) return;
                settled = true;
                dlg.removeEventListener('close', onClose);
                if (dlgFinish === finish) dlgFinish = null;
                if (dlg.open) dlg.close(v);
                resolve(v);
            };
            const onClose = () => finish(dlg.returnValue);
            dlgFinish = finish;
            dlg.showModal();
            dlg.addEventListener('close', onClose);
            if (setup) setup(dlg);
            for (const b of dlg.querySelectorAll('#dlg-buttons button')) {
                b.addEventListener('click', (e) => {
                    if (e.defaultPrevented) return;   // a validation handler said no
                    e.preventDefault();
                    finish(b.value);
                });
            }
        });
    }

    let dlgFinish = null;
    function closeDialog(value) {
        if (dlgFinish) dlgFinish(value);
        else $('dlg').close(value);
    }

    async function promptText(title, value, o) {
        o = o || {};
        const input = o.multiline
            ? `<textarea id="dlg-input" rows="5" spellcheck="false">${esc(value || '')}</textarea>`
            : `<input id="dlg-input" type="text" value="${esc(value || '')}" placeholder="${esc(o.placeholder || '')}"
                autocomplete="off" spellcheck="false" ${o.datalist ? 'list="dlg-dl"' : ''}>`;
        const dl = o.datalist ? `<datalist id="dlg-dl">${o.datalist.map((n) => `<option value="${esc(n)}">`).join('')}</datalist>` : '';
        const body = `<div class="field">${input}${dl}</div><div id="dlg-err" class="problem" hidden></div>` +
            (o.help ? `<p class="dim">${esc(o.help)}</p>` : '');
        let result = null;
        const btn = await dialog(title, body, [{ label: 'Cancel', value: 'cancel' }, { label: 'OK', value: 'ok', primary: true }], (dlg) => {
            const inp = $('dlg-input');
            inp.focus();
            inp.select();
            const check = () => {
                const err = o.validate && o.validate(inp.value);
                $('dlg-err').hidden = !err;
                $('dlg-err').textContent = err || '';
                return !err;
            };
            inp.addEventListener('input', check);
            inp.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && (!o.multiline || e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    if (check()) { result = inp.value; closeDialog('ok'); }
                }
            });
            dlg.querySelector('button[value=ok]').addEventListener('click', (e) => {
                if (!check()) { e.preventDefault(); return; }
                result = inp.value;
            });
        });
        return btn === 'ok' ? result : null;
    }

    async function ask(title, html, buttons) {
        return dialog(title, html, buttons);
    }

    function showHelp() {
        const rows = [
            ['C', 'Mark as code and trace from here'],
            ['D / T / W', 'Mark selection as data bytes / text / words'],
            ['A / P', 'Mark selection as a pointer table / code pointer table'],
            ['V', 'Mark as vector (traces through the pointer)'],
            ['U', 'Undefine selection (remove code/data marks)'],
            ['N', 'Name (label) the address — double-click a label too'],
            [';  /  :', 'Line comment / block comment'],
            ['O / K', 'Operand override / name an immediate constant'],
            ['R', 'Relocate: bytes loaded here run at another address (org r:)'],
            ['> / <', 'The immediate (or picked byte) is the high / low byte of an address'],
            ['Enter', 'Follow operand — or double/Ctrl-click a symbol'],
            ['Click', 'An address in an Access: or Callers: comment jumps to that instruction'],
            ['Esc / Alt+←', 'Go back · Alt+→ forward'],
            ['G', 'Go to address or label'],
            ['X', 'Show cross references in the inspector'],
            ['Shift+↑↓ / drag', 'Select a range'],
            ['← / →', 'Pick one byte of a line (or click it); N, ;, D… then apply to that byte. Double-click a byte to name it'],
            ['Ctrl+Z / Ctrl+Y', 'Undo / redo'],
            ['Ctrl+S', 'Save project · Ctrl+Shift+S save .asm'],
            ['Ctrl+O', 'Open binary'],
        ];
        dialog('Keyboard shortcuts', `<div class="help-grid">${rows.map(([k, v]) =>
            `<div>${k.split(' ').map((t) => (/^[\/·-]$|^or$/.test(t) ? esc(t) : `<kbd>${esc(t)}</kbd>`)).join(' ')}</div><div>${esc(v)}</div>`).join('')}</div>
            <p class="dim">Addresses accept hex with an optional segment, e.g. <code>3:2000</code>.
            Directives use the dis option file syntax, so projects can be exported as .dop files for the CLI.
            Edit one with ✎ or by double-clicking it in the Directives panel.</p>
            <p class="dim">xdis — by Claude (Anthropic) with Lyren Brown, based on
            <a href="https://github.com/lybrown/dis" target="_blank" rel="noopener">dis</a>.
            <a href="https://github.com/lybrown/xdis" target="_blank" rel="noopener">Source</a> · MIT license.</p>`,
        [{ label: 'Close', value: 'ok', primary: true }]);
    }

    // ------------------------------------------------------------------
    // Context menu

    function showMenu(x, y, symKey) {
        const ln = curLine();
        if (!ln) return;
        const menu = $('ctx');
        const items = [];
        const k = curKey();
        if (k !== null) {
            const l = S.model.labelAt(k);
            items.push(`<div class="hd">${esc(segPre(ln.s, X.keyAddr(k)) + X.h4(X.keyAddr(k)))}${l && !l.off ? ' ' + esc(l.name) : ''}</div>`);
        }
        if (symKey !== undefined) {
            const tl = S.model.labelAt(symKey);
            const tn = tl ? tl.name : hexAddr(X.keyAddr(symKey));
            items.push(mi('follow-sym', `Go to ${tn}`, 'Enter'));
            items.push(mi('rename-sym', `Rename ${tn}…`, ''));
            items.push('<div class="sep"></div>');
        }
        if (ln.s) {
            for (const a of ['code', 'data', 'text', 'word', 'address', 'codeptr', 'vector', 'undefine']) items.push(mi(a, ACTIONS[a].label, ACTIONS[a].key));
            items.push(mi('relocate', curPiece() ? 'Remove relocation…' : ACTIONS.relocate.label, 'R'));
            items.push('<div class="sep"></div>');
        }
        if (k !== null) {
            for (const a of ['name', 'comment', 'note']) items.push(mi(a, ACTIONS[a].label, ACTIONS[a].key));
        }
        if (ln.k === 'ins') {
            items.push(mi('operand', ACTIONS.operand.label, 'O'));
            items.push(mi('constant', ACTIONS.constant.label, 'K'));
        }
        if (halfByte(ln) !== null) {
            items.push(mi('hibyte', ACTIONS.hibyte.label, '>'));
            items.push(mi('lobyte', ACTIONS.lobyte.label, '<'));
        }
        items.push('<div class="sep"></div>');
        items.push(mi('copy', 'Copy selection as assembly', ''));
        menu.innerHTML = items.join('');
        menu.hidden = false;
        const r = menu.getBoundingClientRect();
        menu.style.left = Math.min(x, innerWidth - r.width - 4) + 'px';
        menu.style.top = Math.min(y, innerHeight - r.height - 4) + 'px';
        menu.onclick = (e) => {
            const it = e.target.closest('.mi');
            if (!it) return;
            menu.hidden = true;
            const a = it.dataset.a;
            if (a === 'follow-sym') goKey(symKey);
            else if (a === 'rename-sym') rename(symKey);
            else if (a === 'copy') copySelection();
            else act(a);
        };
        function mi(a, label, key) {
            return `<div class="mi" data-a="${a}"><span>${esc(label)}</span>${key ? `<kbd>${esc(key)}</kbd>` : ''}</div>`;
        }
    }

    function copySelection() {
        const [lo, hi] = selLines();
        const text = S.listing.lines.slice(lo, hi + 1).map((ln) => X.lineText(ln, S.project.options)).join('\n');
        navigator.clipboard.writeText(text + '\n').then(
            () => setStatus(`Copied ${hi - lo + 1} lines`),
            () => setStatus('Clipboard is not available', true));
    }

    // ------------------------------------------------------------------
    // Inspector

    function kindOf(ln) {
        if (ln.k === 'equ') return ['extern', 'External'];
        const T = S.model.S[ln.s - 1];
        if (!T) return ['', ''];
        const off = ln.a - T.seg.start;
        const p = lineForKey(X.key(ln.s, ln.a), 'ins');
        const pl = p >= 0 && S.listing.lines[p];
        if (pl && pl.k === 'ins') return ['code', 'Code'];
        if (T.ptr.has(off)) return ['ptr', 'Pointer'];
        const f = T.fmt[off];
        if (f === 2) return ['text', 'Text'];
        if (f === 3) return ['udata', 'Words'];
        if (f === 1) return ['udata', 'Data (marked)'];
        if (f === 4) return ['ptr', 'Pointer'];
        return ['data', 'Data'];
    }

    function refLinks(list) {
        const seen = new Set();
        const out = [];
        for (const r of list) {
            const id = typeof r === 'string' ? r : 'k' + r;
            if (seen.has(id)) continue;
            seen.add(id);
            if (typeof r === 'string') {
                out.push([r, `<a class="dim" title="entry point from directives">${esc(r)}</a>`]);
            } else {
                const l = S.model.labelAt(r);
                const nm = l && !l.off ? l.name : (S.img.multi ? X.keySeg(r) + ':' : '') + X.h4(X.keyAddr(r));
                out.push([nm, `<a data-k="${r}" title="${hexAddr(X.keyAddr(r))}">${esc(nm)}</a>`]);
            }
        }
        return out.sort((a, b) => (a[0] < b[0] ? -1 : 1)).map((x) => x[1]).join('');
    }

    function directivesAt(seg, a, n) {
        const last = a + Math.max(1, n || 1) - 1;
        const p = S.project;
        const res = [];
        const match = (d) => {
            const ds = d.seg || 0;
            if (ds && ds !== seg) return false;
            if (!ds && seg && S.model.finalOwner[a] !== seg && S.model.finalOwner[a]) return false;
            if (d.type === 'constant' || d.type === 'relocate') return false;
            const end = d.addr + (d.type === 'vector' ? d.range | 1 : d.range);
            const inLo = d.addr <= last && end >= a;
            const inHi = d.hi !== undefined && d.hi <= last && d.hi + d.range >= a;
            return inLo || inHi;
        };
        const T = S.model.S[seg - 1];
        p.directives.forEach((d, i) => {
            if (match(S.model.mapDirective(d)) || (T && T.seg.reloc && T.seg.dir === d)) res.push({ d, i });
        });
        for (const inc of p.includes) {
            if (inc.enabled === false) continue;
            for (const d of inc.parsed || []) if (match(S.model.mapDirective(d))) res.push({ d, inc: inc.name });
        }
        return res;
    }

    function updateInspector() {
        const el = $('tab-inspect');
        if (el.contains(document.activeElement) && document.activeElement.tagName !== 'BUTTON') return;
        const ln = curLine();
        if (!ln || ln.a < 0 || (!ln.s && ln.k !== 'equ') || ln.k === 'seg') {
            el.innerHTML = S.model
                ? '<p class="dim">Select a line with an address.</p>' + overviewHtml()
                : '<p class="dim">Open a binary to begin.</p>';
            return;
        }
        const sub = subAddr();
        const k = curKey();
        const a = sub !== null ? sub : ln.a;
        const l = S.model.labelAt(k);
        const [kc, kn] = kindOf(ln);
        const T = S.model.S[ln.s - 1];
        const r = S.model.refs.get(k) || { callers: [], access: [] };
        const userName = l && l.user && !l.off ? l.name : '';
        const comment = S.model.comments.get(k) || '';
        const note = S.model.notes.get(k) || '';
        let h = `<div class="ins-head"><span class="big">${segPre(ln.s, a)}${X.h4(a)}</span>
            <span class="pill ${kc}">${kn}</span>${l && l.off ? `<span class="dim mono">${esc(l.name)}</span>` : ''}</div>`;
        if (T) {
            const off = a - T.seg.start;
            const n = sub !== null ? 1 : Math.max(lineBytes(ln), 1);
            h += `<div class="kv"><span>Bytes</span><span class="mono">${Array.from(T.seg.data.subarray(off, off + Math.min(n, 16)), X.h2).join(' ')}${n > 16 ? ' …' : ''}</span>
                <span>Segment</span><span class="mono">${T.seg.reloc
                    ? `relocated block (from ${T.seg.parent})`
                    : `${T.seg.index} ($${X.h4(T.seg.start)}–$${X.h4(T.seg.end)})`}</span>
                ${T.seg.reloc ? `<span>Loaded at</span><span class="mono">$${X.h4(T.seg.load + a - T.seg.start)}
                    <button class="small" data-act="relocate" title="Remove this relocation">Remove relocation</button></span>` : ''}</div>`;
        }
        h += `<div class="field"><label>Label <span class="dim">(Enter to apply)</span></label>
            <input type="text" id="in-label" value="${esc(userName)}" placeholder="${esc(l && !l.off ? l.name : 'none')}" spellcheck="false" autocomplete="off"></div>
            <div class="field"><label>Comment</label>
            <input type="text" id="in-comment" value="${esc(comment)}" spellcheck="false" autocomplete="off"></div>
            <div class="field"><label>Block comment <span class="dim">(Ctrl+Enter)</span></label>
            <textarea id="in-note" rows="2" spellcheck="false">${esc(note)}</textarea></div>`;
        if (ln.k === 'ins' && sub === null) {
            const off = a - T.seg.start;
            const op = X.OPS[T.seg.data[off]];
            const ov = S.model.operands.get(k);
            h += `<div class="field"><label>Operand override</label><input type="text" id="in-operand" value="${esc(ov === undefined ? '' : ov)}"
                placeholder="${esc(ln.p.slice(3).map((p) => p[1]).join('').trim())}" spellcheck="false" autocomplete="off"></div>`;
            if (op.mode === 'imm') {
                const v = T.seg.data[off + 1];
                h += `<div class="field"><label>Immediate #$${X.h2(v)} is part of an address</label><div class="row2">
                    <button data-act="hibyte" title="Show as #>label">High byte (#&gt;) <kbd>&gt;</kbd></button>
                    <button data-act="lobyte" title="Show as #<label">Low byte (#&lt;) <kbd>&lt;</kbd></button></div></div>`;
                h += `<div class="field"><label>Constant name for #$${X.h2(v)} <span class="dim">(all uses)</span></label>
                    <input type="text" id="in-const" data-v="${v}" value="${esc(S.model.consts.get(v) || '')}" spellcheck="false" autocomplete="off"></div>`;
            }
        }
        if (ln.s) {
            h += '<div class="actions">' + ['code', 'data', 'text', 'word', 'address', 'codeptr', 'vector', 'undefine'].map((x) =>
                `<button data-act="${x}" title="${esc(ACTIONS[x].label)}">${esc(x === 'address' ? 'Ptrs' : x === 'codeptr' ? 'Code ptrs' : x[0].toUpperCase() + x.slice(1))}<kbd>${ACTIONS[x].key}</kbd></button>`).join('') + '</div>';
        }
        h += `<h3>Callers (${new Set(r.callers.map(String)).size})</h3><div class="xref">${refLinks(r.callers) || '<span class="dim">none</span>'}</div>`;
        h += `<h3>Accessed by (${new Set(r.access.map(String)).size})</h3><div class="xref">${refLinks(r.access) || '<span class="dim">none</span>'}</div>`;
        const target = ln.p.find((p) => p[2] !== undefined && (p[0] === 'sym' || p[0] === 'num') &&
            (sub === null || p[3] === undefined || p[3] === sub));
        if (target) {
            const tl = S.model.labelAt(target[2]);
            h += `<h3>Operand target</h3><div class="xref"><a data-k="${target[2]}">${esc(tl ? tl.name : hexAddr(X.keyAddr(target[2])))}</a>
                <span class="dim">${hexAddr(X.keyAddr(target[2]))}</span></div>`;
        }
        const dirs = directivesAt(ln.s, a, sub !== null ? 1 : lineBytes(ln));
        if (dirs.length) {
            h += '<h3>Directives here</h3><div class="list mono">' + dirs.map(({ d, i, inc }) =>
                `<div class="item"><span class="nm" title="${esc(X.directiveString(d))}">${esc(X.directiveString(d))}</span>${inc ? `<span class="kd">${esc(inc)}</span>` : `${dirTag(d)}<button class="x" data-edit="${i}" title="Edit">✎</button><button class="x" data-del="${i}" title="Delete">×</button>`}</div>`).join('') + '</div>';
        }
        el.innerHTML = h;
        const bindEnter = (id, fn, multi) => {
            const inp = $(id);
            if (!inp) return;
            inp.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && (!multi || e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    inp.blur();
                    fn(inp.value);
                    $('listing').focus();
                } else if (e.key === 'Escape') {
                    e.preventDefault();
                    inp.blur();
                    updateInspector();
                    $('listing').focus();
                }
                e.stopPropagation();
            });
        };
        bindEnter('in-label', (v) => { if (v.trim() !== userName) applyName(k, v.trim()); });
        bindEnter('in-comment', (v) => { if (v !== comment) applyText('comment', k, v); });
        bindEnter('in-note', (v) => { if (v !== note) applyText('note', k, v); }, true);
        bindEnter('in-operand', (v) => applyText('operand', k, v.trim()));
        bindEnter('in-const', (v) => {
            const val = +$('in-const').dataset.v;
            if (v.trim() && !X.LABEL_RE.test(v.trim())) return setStatus('Invalid constant name', true);
            commit((p) => { p.directives = X.edit.setConstant(p.directives, val, v.trim()); }, 'Constant updated');
        });
    }

    function overviewHtml() {
        const m = S.model;
        let code = 0, total = 0;
        for (const T of m.S) {
            total += T.seg.data.length;
            for (let i = 0; i < T.ilen.length; i++) code += T.ilen[i];
        }
        return `<h3>Overview</h3><div class="kv">
            <span>Segments</span><span>${m.S.length}</span>
            <span>Bytes</span><span>${total}</span>
            <span>Traced code</span><span>${code} bytes (${total ? Math.round(100 * code / total) : 0}%)</span>
            <span>Lines</span><span>${S.listing.lines.length}</span>
            <span>Rebuild</span><span>${S.ms.toFixed(1)} ms</span></div>`;
    }

    // ------------------------------------------------------------------
    // Labels panel

    function updateLabels() {
        const el = $('label-list');
        if (!S.listing) { el.innerHTML = ''; return; }
        const f = $('label-filter').value.trim().toLowerCase();
        const showUser = $('lf-user').checked, showAuto = $('lf-auto').checked, showExt = $('lf-ext').checked;
        const out = [];
        let count = 0;
        for (const ln of S.listing.lines) {
            if (ln.def === undefined) continue;
            const name = ln.p[0][1];
            const l = S.model.labelAt(ln.def);
            const kind = ln.k === 'equ' ? 'ext' : l && l.user ? 'user' : 'auto';
            if ((kind === 'ext' && !showExt) || (kind === 'user' && !showUser) || (kind === 'auto' && !showAuto)) continue;
            if (f && !name.toLowerCase().includes(f) && !X.h4(ln.a).toLowerCase().includes(f)) continue;
            count++;
            if (out.length < 2000) {
                out.push(`<div class="item" data-k="${ln.def}"><span class="nm">${esc(name)}</span><span class="ad">${X.h4(ln.a)}</span><span class="kd">${kind === 'ext' ? 'extern' : kind === 'user' ? (l.user && l.dir && S.project.directives.includes(l.dir) ? 'named' : 'symbols') : 'auto'}</span></div>`);
            }
        }
        if (count > out.length) out.push(`<div class="more">${count - out.length} more — refine the filter</div>`);
        el.innerHTML = out.join('') || '<div class="more">No labels</div>';
    }

    // ------------------------------------------------------------------
    // Directives panel

    function updateDirectives() {
        if ($('tab-directives').querySelector('.dir-edit')) return;
        const p = S.project;
        // symbol sets
        const builtin = new Set(Object.keys(SYM.files));
        let h = '';
        for (const [group, files] of Object.entries(SYM.groups)) {
            h += `<div class="opts"><span class="dim">${esc(group)}</span>` + files.map((f) => {
                const inc = p.includes.find((i) => i.name === f);
                return `<label><input type="checkbox" data-sym="${esc(f)}" ${inc && inc.enabled !== false ? 'checked' : ''}> ${esc(f)}</label>`;
            }).join('') + '</div>';
        }
        const custom = p.includes.filter((i) => !builtin.has(i.name));
        if (custom.length) {
            h += '<div class="opts"><span class="dim">Imported</span>' + custom.map((i) =>
                `<label><input type="checkbox" data-sym="${esc(i.name)}" ${i.enabled !== false ? 'checked' : ''}> ${esc(i.name)}
                 <button class="x small" data-unsym="${esc(i.name)}" title="Remove">×</button></label>`).join('') + '</div>';
        }
        $('symbol-sets').innerHTML = h;

        const el = $('dir-list');
        const f = $('dir-filter').value.trim().toLowerCase();
        const onlyUnneeded = $('dir-unneeded').checked;
        const out = [];
        p.directives.forEach((d, i) => {
            const s = X.directiveString(d);
            if (f && !s.toLowerCase().includes(f)) return;
            const st = S.dirState && S.dirState.get(d);
            if (onlyUnneeded && (!st || st === 'needed')) return;
            if (out.length < 3000) {
                const md = S.model ? S.model.mapDirective(d) : d;
                const gk = d.type === 'relocate' && S.model ? relocKey(d) : (md.seg || 0) * 0x10000 + md.addr;
                out.push(`<div class="item" data-goto="${gk}" data-type="${d.type}"><span class="nm" title="${esc(s)} — double-click to edit">${esc(s)}</span>${dirTag(d)}<button class="x" data-edit="${i}" title="Edit">✎</button><button class="x" data-del="${i}" title="Delete">×</button></div>`);
            }
        });
        el.innerHTML = out.join('') || (onlyUnneeded ? '<div class="more">None found — every tracing directive is needed.</div>'
            : '<div class="more">No directives yet. Use the keys in the listing, or type one above.</div>');
        updateDirCount();
    }

    // Edit directive i in place: its text becomes an input in dis option
    // syntax. Enter applies, Escape or leaving the field cancels.
    function editDirective(item, i) {
        const nm = item && item.querySelector('.nm');
        const d = S.project.directives[i];
        if (!nm || !d) return;
        const inp = document.createElement('input');
        inp.type = 'text';
        inp.className = 'dir-edit';
        inp.spellcheck = false;
        inp.autocomplete = 'off';
        inp.value = X.directiveString(d);
        nm.replaceWith(inp);
        inp.focus();
        inp.select();
        let done = false;
        const cancel = () => {
            if (done) return;
            done = true;
            inp.remove();
            updateDirectives();
            updateInspector();
        };
        inp.addEventListener('keydown', (e) => {
            e.stopPropagation();
            if (e.key === 'Escape') {
                e.preventDefault();
                cancel();
                $('listing').focus();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                let nd;
                try {
                    nd = X.parseDirectiveLine(inp.value);
                    if (!nd) throw new Error('Unrecognized directive');
                } catch (err) {
                    setStatus(err.message, true);
                    return;
                }
                done = true;
                inp.blur();
                inp.remove();
                commit((p) => { p.directives = p.directives.map((x, j) => (j === i ? nd : x)); },
                    `Changed to ${X.directiveString(nd)}`);
            }
        });
        inp.addEventListener('blur', () => setTimeout(cancel, 0));
    }

    function deleteDirective(i) {
        const d = S.project.directives[i];
        if (d.type === 'relocate') return removeRelocation(d);
        commit((p) => { p.directives = p.directives.filter((_, j) => j !== i); }, `Deleted ${X.directiveString(d)}`);
    }

    function toggleInclude(name, on) {
        commit((p) => {
            const inc = p.includes.find((i) => i.name === name);
            if (inc) inc.enabled = on;
            else if (SYM.files[name]) p.includes.push({ name, text: SYM.files[name], enabled: true });
            sortIncludes(p);
        }, `${on ? 'Enabled' : 'Disabled'} ${name}`);
    }

    // Symbol set priority (earlier wins): your own imported files, then the
    // built-in sets in their canonical order (atarixl.dop before sys.dop).
    // Built-in symbol sets always use the current built-in text, so fixes and
    // additions reach existing projects. Files you imported keep their text.
    function refreshBuiltins(p) {
        for (const inc of p.includes) {
            if (!inc.custom && SYM.files[inc.name] && inc.text !== SYM.files[inc.name]) {
                inc.text = SYM.files[inc.name];
                inc.parsed = null;
            }
        }
        sortIncludes(p);
    }

    function sortIncludes(p) {
        const order = SYM.order || [];
        const rank = (i) => (!i.custom && order.includes(i.name) ? order.indexOf(i.name) : -1);
        const custom = p.includes.filter((i) => rank(i) < 0);
        const builtin = p.includes.filter((i) => rank(i) >= 0).sort((x, y) => rank(x) - rank(y));
        p.includes = custom.concat(builtin);
    }

    // ------------------------------------------------------------------
    // Project panel

    function updateProject() {
        const el = $('tab-project');
        if (el.contains(document.activeElement) && document.activeElement.type !== 'checkbox' &&
            document.activeElement.tagName !== 'SELECT') return;
        const p = S.project;
        const o = p.options;
        const b = p.binary;
        let h = '<h3>Binary</h3>';
        if (b) {
            h += `<div class="kv"><span>File</span><span class="mono">${esc(b.name)}</span><span>Size</span><span>${b.size} bytes</span></div>
                <div class="opts">
                <div class="num"><span>Format</span><select id="opt-type">${['raw', 'xex', 'prg', 'sap'].map((t) =>
                    `<option value="${t}" ${b.type === t ? 'selected' : ''}>${{ raw: 'Raw memory', xex: 'Atari XEX', prg: 'C64 PRG', sap: 'Atari SAP' }[t]}</option>`).join('')}</select></div>
                ${b.type === 'raw' ? `<div class="num"><span>Load address</span><input type="text" id="opt-org" value="$${X.h4(b.org || 0)}" spellcheck="false"></div>` : ''}
                </div>`;
            if (!S.bytes) h += '<p class="problem">Binary not loaded — open it to continue.</p>';
        } else {
            h += '<p class="dim">No binary loaded.</p>';
        }
        if (S.img && S.img.segments.length > 1) {
            h += '<h3>Segments</h3><table class="seg-table"><tr><th>#</th><th>Start</th><th>End</th><th>Size</th><th></th></tr>' +
                S.img.segments.map((s) => `<tr class="click" data-goto="${X.key(s.index, s.start)}"><td>${s.index}</td><td>${X.h4(s.start)}</td><td>${X.h4(s.end)}</td><td>${s.data.length}</td><td class="dim">${s.kind || (s.ini !== undefined ? 'ini' : '')}${s.run !== undefined && s.kind !== 'run' ? ' run' : ''}</td></tr>` +
                    (S.model ? S.model.pieces.filter((p) => p.parent === s.index).map((p) =>
                        `<tr class="click reloc" data-goto="${X.key(p.index, p.start)}" title="loaded at $${X.h4(p.load)}–$${X.h4(p.load + p.data.length - 1)}"><td>↳</td><td>${X.h4(p.start)}</td><td>${X.h4(p.end)}</td><td>${p.data.length}</td><td class="dim">org r: from ${X.h4(p.load)}</td></tr>`).join('') : '')).join('') + '</table>';
        }
        if (S.model && S.model.pieces.length && S.img.segments.length === 1) {
            h += '<h3>Relocated blocks</h3><table class="seg-table">' + S.model.pieces.map((p) =>
                `<tr class="click reloc" data-goto="${X.key(p.index, p.start)}"><td>${X.h4(p.start)}–${X.h4(p.end)}</td><td class="dim">loaded at ${X.h4(p.load)}</td></tr>`).join('') + '</table>';
        }
        const cb = (k, label, title) => `<label title="${esc(title || '')}"><input type="checkbox" data-opt="${k}" ${o[k] ? 'checked' : ''}> ${esc(label)}</label>`;
        h += `<h3>Output</h3><div class="opts">
            <div class="num"><span>Assembler</span><select id="opt-syntax">
              <option value="xasm" ${o.syntax !== 'mads' ? 'selected' : ''}>xasm</option>
              <option value="mads" ${o.syntax === 'mads' ? 'selected' : ''}>MADS</option></select></div>
            ${cb('labels', 'Labels', 'Create labels for branch, jump and data targets (-l)')}
            ${cb('comments', 'Address and byte comments', '-comment')}
            ${cb('callers', 'Callers', '-call')}
            ${cb('access', 'Accessors', '-access')}
            ${cb('extern', 'Equates for external labels', '-extern')}
            ${cb('rangelabels', 'Range labels as name_N instead of name+N', '-rangelabels')}
            ${cb('illegal', 'Trace through undocumented opcodes', '-i')}
            <div class="num"><span>Data bytes per line</span><input type="number" min="1" max="32" data-num="dataPerLine" value="${o.dataPerLine}"></div>
            <div class="num"><span>Text chars per line</span><input type="number" min="1" max="120" data-num="textPerLine" value="${o.textPerLine}"></div>
            <div class="num"><span title="Collapse runs of identical bytes into :N dta; 0 disables">Fill run minimum</span><input type="number" min="0" max="65536" data-num="fillMin" value="${o.fillMin}"></div>
            </div>
            <h3>App</h3><div class="opts">
            <label><input type="checkbox" id="opt-embed" ${S.embed ? 'checked' : ''}> Embed binary in saved project</label>
            <div class="num"><span>Theme</span><select id="opt-theme">${['system', 'light', 'dark'].map((t) =>
                `<option ${(localGet('xdis.theme') || 'system') === t ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
            </div>`;
        el.innerHTML = h;
    }

    // ------------------------------------------------------------------
    // Problems

    // Problems are strings or {msg, k?, dir?, extra?}; ones with a location
    // are clickable.
    function updateProblems() {
        const list = [];
        for (const m of S.importProblems) list.push(m);
        if (S.img) list.push(...S.img.warnings);
        if (S.listing) list.push(...S.listing.problems);
        const seen = new Set();
        const uniq = [];
        for (const m of list) {
            const p = typeof m === 'string' ? { msg: m } : m;
            if (seen.has(p.msg)) continue;
            seen.add(p.msg);
            uniq.push(p);
        }
        // real problems first, then suggestions
        uniq.sort((x, y) => !!x.suggest - !!y.suggest);
        S.problems = uniq;
        const ptrs = uniq.filter((p) => p.suggest && p.suggest.type !== 'relocate').length;
        const allBtn = ptrs > 1 ? `<p><button id="btn-apply-ptrs" title="Show every suggested pair of immediates as an address">Apply all ${ptrs} pointer suggestions</button></p>` : '';
        $('problem-list').innerHTML = allBtn + uniq.slice(0, 500).map((p, i) => {
            const where = p.suggest ? (p.suggest.type === 'relocate' ? 'Review and apply this relocation' : 'Review and apply') : p.k !== undefined ? `Go to ${hexAddr(X.keyAddr(p.k))}` : p.dir ? `Show directive ${p.dir}` :
                p.extra ? 'Go to the corrupted data' : '';
            return `<div class="problem${where ? ' link' : ''}${p.suggest ? ' suggest' : ''}" ${where ? `data-prob="${i}" title="${esc(where)}"` : ''}>${esc(p.msg)}</div>`;
        }).join('') || '<div class="more">No problems.</div>';
        const nSug = uniq.filter((p) => p.suggest).length;
        const c = $('problem-count');
        c.hidden = uniq.length === nSug;
        c.textContent = uniq.length - nSug;
        $('suggest-count').hidden = !nSug;
        $('suggest-count').textContent = nSug;
    }

    // Show a pair of immediates as the halves of an address.
    async function pointerSuggestion(p) {
        const d = p.suggest;
        const T = S.model.segOf(X.key(d.seg || S.model.finalOwner[d.addr], d.addr));
        const imm = (at) => {
            const T2 = S.model.segOf(X.key(d.seg || S.model.finalOwner[at], at)) || T;
            return T2 ? T2.seg.data[at - T2.seg.start] : 0;
        };
        const t = imm(d.addr) | (imm(d.hi) << 8);
        const l = S.model.labelAt(X.key(S.model.finalOwner[t], t));
        const name = l && !l.off ? l.name : 'l' + X.h4(t);
        let type = d.type;
        const body = `<p>${esc(p.msg.replace(/ — click.*/, ''))}.</p>
            <pre class="mono">    lda #&gt;${esc(name)}	; $${X.h4(d.hi - 1)}
    lda #&lt;${esc(name)}	; $${X.h4(d.addr - 1)}</pre>
            <div class="opts">
            <label><input type="radio" name="pt" value="codeptr" ${type === 'codeptr' ? 'checked' : ''}> Code pointer — also trace $${X.h4(t)} as code</label>
            <label><input type="radio" name="pt" value="address" ${type === 'address' ? 'checked' : ''}> Data pointer</label></div>
            <p class="dim">Adds <code id="ps-dir">${esc(X.directiveString(d))}</code></p>`;
        const btn = await dialog('Show as an address', body,
            [{ label: 'Cancel', value: 'cancel' }, { label: 'Apply', value: 'ok', primary: true }], (dlg) => {
                for (const r of dlg.querySelectorAll('input[name=pt]')) {
                    r.addEventListener('change', () => {
                        type = r.value;
                        $('ps-dir').textContent = X.directiveString(Object.assign({}, d, { type }));
                    });
                }
                dlg.querySelector('button[value=ok]').focus();
            });
        if (btn !== 'ok') return;
        const nd = Object.assign({}, d, { type });
        commit((pr) => { pr.directives = pr.directives.concat([nd]); }, `Added ${X.directiveString(nd)}`);
    }

    async function halfSuggestion(p) {
        const d = p.suggest;
        const name = (/#>(\S+)$/.exec(p.msg) || [])[1] || '';
        const btn = await ask('Show as the high byte of an address',
            `<p>${esc(p.msg.replace(/ — click.*/, ''))}.</p>
             <pre class="mono">    lda #&gt;${esc(name)}	; $${X.h4(d.addr - 1)}</pre>
             <p class="dim">Adds <code>${esc(X.directiveString(d))}</code></p>`,
            [{ label: 'Cancel', value: 'cancel' }, { label: 'Apply', value: 'ok', primary: true }]);
        if (btn !== 'ok') return;
        commit((pr) => { pr.directives = pr.directives.concat([d]); }, `Added ${X.directiveString(d)}`);
    }

    function applyAllPointerSuggestions() {
        const list = (S.problems || []).filter((p) => p.suggest && p.suggest.type !== 'relocate').map((p) => p.suggest);
        if (!list.length) return;
        commit((pr) => { pr.directives = pr.directives.concat(list); }, `Added ${list.length} pointer directives`);
    }

    function gotoProblem(p) {
        if (!p) return;
        if (p.suggest) {
            goKey(p.k);
            if (p.suggest.type === 'relocate') relocateDialog(null, p.suggest);
            else if (p.suggest.type === 'hi') halfSuggestion(p);
            else pointerSuggestion(p);
            return;
        }
        if (p.k !== undefined && S.model && lineForKey(p.k, 'label') >= 0) {
            goKey(p.k);
            $('listing').focus({ preventScroll: true });
            return;
        }
        if (p.extra && S.listing) {
            const i = S.listing.lines.findIndex((ln) => ln.k === 'dir' && /Corrupted segment/.test(ln.p[0][1]));
            if (i >= 0) {
                S.back.push(viewAnchor());
                moveTo(i, false, true);
                flash(i);
                $('listing').focus({ preventScroll: true });
                return;
            }
        }
        if (p.dir) {
            // show the directive that caused it
            showTab('directives');
            $('dir-filter').value = p.dir;
            updateDirectives();
            setStatus(`Showing ${p.dir}`);
            return;
        }
        if (p.k !== undefined) setStatus(`${hexAddr(X.keyAddr(p.k))} is not in loaded memory`, true);
    }

    function updateFileInfo() {
        const b = S.project.binary;
        $('file-info').textContent = b ? `${b.name} · ${b.type}${b.type === 'raw' ? ' @ $' + X.h4(b.org || 0) : ''} · ${b.size} bytes` : '';
        $('file-info').title = $('file-info').textContent;
        document.title = b ? `${b.name} — xdis` : 'xdis — interactive 6502 disassembler';
    }

    // ------------------------------------------------------------------
    // Memory map

    const MAPCOL = ['--m-data', '--m-code', '--m-udata', '--m-text', '--m-ptr'];

    function mapClasses() {
        if (S.mapCls) return S.mapCls;
        const m = S.model;
        const cls = m.S.map((T) => {
            const c = new Uint8Array(T.seg.data.length);
            for (let o = 0; o < c.length; o++) {
                const f = T.fmt[o];
                c[o] = T.ptr.has(o) || f === 4 ? 4 : f === 2 ? 3 : f ? 2 : 0;
            }
            return c;
        });
        for (const ln of S.listing.lines) {
            if (ln.k !== 'ins') continue;
            const c = cls[ln.s - 1];
            const o = ln.a - m.S[ln.s - 1].seg.start;
            for (let i = 0; i < ln.n; i++) c[o + i] = 1;
        }
        // relocated blocks are shown where they are loaded
        for (const p of m.pieces) {
            cls[p.parent - 1].set(cls[p.index - 1], p.load - m.S[p.parent - 1].seg.start);
        }
        S.mapCls = cls;
        return cls;
    }

    // Where a (segment, address) is drawn on the map: relocated blocks map
    // back to their load address in the parent segment.
    function mapPos(s, a) {
        const T = S.model.S[s - 1];
        if (T && T.seg.reloc) return { s: T.seg.parent, a: T.seg.load + a - T.seg.start };
        return { s, a };
    }

    function mapLayout(w) {
        const segs = S.model.S.filter((T) => !T.seg.reloc);
        const total = segs.reduce((n, T) => n + T.seg.data.length, 0) || 1;
        const gap = segs.length > 1 ? 2 : 0;
        const minW = 2;
        const avail = Math.max(10, w - gap * (segs.length - 1) - minW * segs.length);
        const out = [];
        let x = 0;
        for (const T of segs) {
            const sw = minW + avail * T.seg.data.length / total;
            out.push({ T, x0: x, x1: x + sw });
            x += sw + gap;
        }
        out.byIndex = new Map(out.map((lay) => [lay.T.seg.index, lay]));
        return out;
    }

    function drawMap() {
        const c = $('map');
        const dpr = window.devicePixelRatio || 1;
        const w = c.clientWidth, h = c.clientHeight;
        c.width = Math.round(w * dpr);
        c.height = Math.round(h * dpr);
        const g = c.getContext('2d');
        g.setTransform(dpr, 0, 0, dpr, 0, 0);
        const css = getComputedStyle(document.documentElement);
        g.fillStyle = css.getPropertyValue('--m-gap');
        g.fillRect(0, 0, w, h);
        if (!S.model) return;
        const cls = mapClasses();
        const colors = MAPCOL.map((v) => css.getPropertyValue(v).trim());
        S.mapLayout = mapLayout(w);
        for (const { T, x0, x1 } of S.mapLayout) {
            const c2 = cls[T.seg.index - 1];
            const len = c2.length;
            const px = Math.max(1, Math.ceil(x1 - x0));
            for (let i = 0; i < px; i++) {
                const b0 = Math.floor(i * len / px), b1 = Math.max(b0 + 1, Math.floor((i + 1) * len / px));
                const count = [0, 0, 0, 0, 0];
                const step = Math.max(1, Math.floor((b1 - b0) / 64));
                for (let b = b0; b < b1 && b < len; b += step) count[c2[b]]++;
                let best = 0;
                for (let k = 1; k < 5; k++) if (count[k] > count[best] || (count[k] && k === 1 && count[k] * 3 >= count[best])) best = k;
                g.fillStyle = colors[best];
                g.fillRect(x0 + i, 4, 1, h - 8);
            }
        }
        // mark relocated blocks with a stripe along the top
        g.fillStyle = css.getPropertyValue('--m-reloc').trim();
        for (const p of S.model.pieces) {
            const lay = S.mapLayout.byIndex.get(p.parent);
            const len = lay.T.seg.data.length;
            const xa = lay.x0 + (lay.x1 - lay.x0) * (p.load - lay.T.seg.start) / len;
            const xb = lay.x0 + (lay.x1 - lay.x0) * (p.load + p.data.length - lay.T.seg.start) / len;
            g.fillRect(xa, 0, Math.max(1, xb - xa), 3);
        }
        // Keep the clean map so the viewport box can be redrawn on scroll.
        S.mapBase = g.getImageData(0, 0, c.width, c.height);
        S.mapBaseFor = S.listing;
        drawViewport();
    }

    function drawViewport() {
        const c = $('map');
        if (!S.model || !S.mapLayout) return;
        // Restore the clean map drawn by drawMap, then draw the box on top.
        // A stale map (new listing or size) is repainted from scratch.
        if (!S.mapBase || S.mapBase.width !== c.width || S.mapBase.height !== c.height ||
            S.mapBaseFor !== S.listing || c.width !== Math.round(c.clientWidth * (window.devicePixelRatio || 1))) {
            drawMap();
            return;
        }
        const g = c.getContext('2d');
        g.putImageData(S.mapBase, 0, 0);
        const el = $('listing');
        const L = S.listing.lines;
        const first = Math.floor(el.scrollTop / LH);
        const last = Math.min(L.length - 1, Math.ceil((el.scrollTop + el.clientHeight) / LH));
        let a = null, b = null;
        for (let i = first; i <= last; i++) {
            const ln = L[i];
            if (!ln.s || ln.a < 0 || ln.k === 'dir' || ln.k === 'equ') continue;
            if (!a) a = ln;
            b = ln;
        }
        if (!a) return;
        const xOf = (ln) => {
            const pos = mapPos(ln.s, ln.a);
            const lay = S.mapLayout.byIndex.get(pos.s);
            const len = lay.T.seg.data.length;
            return lay.x0 + (lay.x1 - lay.x0) * (pos.a - lay.T.seg.start) / len;
        };
        const dpr = window.devicePixelRatio || 1;
        const x0 = xOf(a), x1 = Math.max(xOf(b), x0 + 2);
        const css = getComputedStyle(document.documentElement);
        g.setTransform(dpr, 0, 0, dpr, 0, 0);
        g.strokeStyle = css.getPropertyValue('--fg');
        g.lineWidth = 1.5;
        g.strokeRect(x0, 1.5, x1 - x0, c.clientHeight - 3);
    }

    // Address under x on the map. With `clamp`, positions left/right of the
    // strip or in the gaps between segments snap to the nearest byte.
    function mapHit(x, clamp) {
        const L = S.mapLayout;
        if (!L || !L.length) return null;
        if (clamp) x = Math.max(L[0].x0, Math.min(L[L.length - 1].x1, x));
        for (const lay of L) {
            if (x > lay.x1 + 1) continue;
            if (x < lay.x0 - 1 && !clamp) return null;
            const len = lay.T.seg.data.length;
            const off = Math.max(0, Math.min(len - 1, Math.floor((x - lay.x0) / (lay.x1 - lay.x0) * len)));
            const a = lay.T.seg.start + off;
            // inside a relocated block: the run address
            for (const p of S.model.holesOf.get(lay.T.seg.index) || []) {
                if (a >= p.load && a < p.load + p.data.length) return { s: p.index, a: p.start + a - p.load };
            }
            return { s: lay.T.seg.index, a };
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Files

    function download(name, text, type) {
        const blob = new Blob([text], { type: type || 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = name;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    }

    function baseName() {
        const n = (S.project.binary && S.project.binary.name) || 'untitled';
        return n.replace(/\.[^.]*$/, '') || n;
    }

    function saveProject() {
        if (!S.project.binary) return;
        download(baseName() + '.xdis.json', X.serializeProject(S.project, S.bytes, S.embed), 'application/json');
        setStatus(`Saved ${baseName()}.xdis.json${S.embed ? ' (binary embedded)' : ''}`);
    }

    function saveAsm() {
        if (!S.listing) return;
        download(baseName() + '.asm', X.asmText(S.listing, S.project.options));
        setStatus(`Saved ${baseName()}.asm (${S.listing.lines.length} lines)`);
    }

    function exportDop() {
        if (!S.project.binary) return;
        download(baseName() + '.dop', X.exportDop(S.project, S.model));
        const custom = S.project.includes.filter((i) => i.enabled !== false).map((i) => i.name);
        setStatus(`Saved ${baseName()}.dop` + (custom.length ? ` — it references ${custom.join(', ')} via arg; keep those next to it (see symbols/)` : ''));
    }

    function guessOrg(size) {
        if (size === 0x10000) return 0;
        if (size === 0x2000) return 0xA000;
        if (size === 0x4000) return 0x8000;
        return 0;
    }

    async function openBinary(file) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const pending = S.project.binary && !S.bytes;
        const prev = pending ? S.project.binary : null;
        let type = prev ? prev.type : X.detectType(file.name, bytes);
        let org = prev ? prev.org || 0 : guessOrg(bytes.length);
        const hasWork = !pending && S.project.directives.length > 0;
        const suggest = type === 'prg' ? 'Commodore 64' : type === 'xex' || type === 'sap' ? 'Atari 8-bit' : '';
        const body = `<div class="kv"><span>File</span><span class="mono">${esc(file.name)}</span><span>Size</span><span>${bytes.length} bytes</span></div>
            <div class="field"><label>Format</label><select id="ld-type">${['raw', 'xex', 'prg', 'sap'].map((t) =>
                `<option value="${t}" ${t === type ? 'selected' : ''}>${{ raw: 'Raw memory image', xex: 'Atari XEX / COM', prg: 'Commodore 64 PRG', sap: 'Atari SAP' }[t]}</option>`).join('')}</select></div>
            <div class="field" id="ld-org-f"><label>Load address (hex) for raw images</label><input type="text" id="ld-org" value="$${X.h4(org)}"></div>
            ${!pending ? `<div class="field"><label>Symbol sets</label>${Object.keys(SYM.groups).map((g) =>
                `<label><input type="checkbox" data-group="${esc(g)}" ${g === suggest ? 'checked' : ''}> ${esc(g)} (${SYM.groups[g].join(', ')})</label>`).join('<br>')}</div>` : ''}
            ${hasWork ? '<div class="field"><label><input type="checkbox" id="ld-keep"> Keep the current directives (same program, new build)</label></div>' : ''}`;
        let groups = [], keep = false;
        const btn = await dialog(pending ? `Open ${prev.name}` : 'Open binary', body,
            [{ label: 'Cancel', value: 'cancel' }, { label: 'Open', value: 'ok', primary: true }], (dlg) => {
                const sync = () => { $('ld-org-f').hidden = $('ld-type').value !== 'raw'; };
                $('ld-type').addEventListener('change', sync);
                sync();
                dlg.querySelector('button[value=ok]').addEventListener('click', () => {
                    type = $('ld-type').value;
                    org = parseInt($('ld-org').value.replace(/^\$|^0x/i, ''), 16) || 0;
                    groups = Array.from(dlg.querySelectorAll('[data-group]:checked'), (c) => c.dataset.group);
                    keep = !!($('ld-keep') && $('ld-keep').checked);
                });
            });
        if (btn !== 'ok') return;
        if (!pending && !keep) {
            S.project = X.newProject();
            S.undo = [];
            S.redo = [];
            S.importProblems = [];
        }
        for (const g of groups) {
            for (const f of SYM.groups[g]) {
                if (!S.project.includes.some((i) => i.name === f)) S.project.includes.push({ name: f, text: SYM.files[f], enabled: true });
            }
        }
        sortIncludes(S.project);
        S.project.binary = { name: file.name, type, org: org & 0xFFFF, size: bytes.length };
        S.bytes = bytes;
        S.back = [];
        S.fwd = [];
        rebuild({ reload: true, keepView: false });
        setStatus(`Loaded ${file.name}: ${S.img.segments.length} segment(s), ${S.listing.lines.length} lines in ${S.ms.toFixed(0)} ms`);
        $('listing').focus();
    }

    async function openProject(file) {
        let res;
        try {
            res = X.deserializeProject(await file.text());
        } catch (e) {
            return setStatus(`${file.name}: ${e.message}`, true);
        }
        S.project = res.project;
        S.bytes = res.bytes;
        refreshBuiltins(S.project);
        S.undo = [];
        S.redo = [];
        S.importProblems = [];
        S.back = [];
        S.fwd = [];
        rebuild({ reload: true, keepView: false });
        if (!S.bytes && S.project.binary) {
            setStatus(`Project loaded — now open the binary ${S.project.binary.name}`);
            updateProject();
            $('file-bin').click();
        } else {
            setStatus(`Opened project ${file.name}`);
        }
    }

    // Import .dop files. Files referenced with `arg` become symbol sets (from
    // the selection or the built-in ones); the rest are merged.
    async function importDops(files, asInclude) {
        const texts = new Map();
        for (const f of files) texts.set(f.name, await f.text());
        const parsed = new Map();
        for (const [name, text] of texts) parsed.set(name, X.parseDop(text, name));
        const referenced = new Set();
        for (const r of parsed.values()) for (const a of r.args) referenced.add(a.split(/[\\/]/).pop());
        const problems = [];
        commit((p) => {
            for (const [name, r] of parsed) {
                problems.push(...r.errors);
                if (asInclude || referenced.has(name)) {
                    const old = p.includes.findIndex((i) => i.name === name);
                    const inc = { name, text: texts.get(name), enabled: true, custom: true };
                    if (old >= 0) p.includes[old] = inc;
                    else p.includes.push(inc);
                    continue;
                }
                p.directives = p.directives.concat(X.dedupeImported(r.directives));
                Object.assign(p.options, r.options);
                if (p.binary && r.binary.type) p.binary.type = r.binary.type;
                if (p.binary && r.binary.org !== undefined) p.binary.org = r.binary.org;
            }
            for (const a of referenced) {
                if (p.includes.some((i) => i.name === a)) continue;
                if (SYM.files[a]) p.includes.push({ name: a, text: SYM.files[a], enabled: true });
                else problems.push(`arg ${a}: not found — select it together with the .dop, or add it under Directives → Symbol sets`);
            }
            sortIncludes(p);
        }, `Imported ${files.map((f) => f.name).join(', ')}`);
        S.importProblems = problems;
        updateProblems();
        if (problems.length) setStatus(`Imported with ${problems.length} problem(s) — see Problems`, true);
    }

    function handleFiles(files) {
        files = Array.from(files);
        const dops = files.filter((f) => /\.(dop|txt)$/i.test(f.name));
        const proj = files.find((f) => /\.json$/i.test(f.name));
        const bin = files.find((f) => !dops.includes(f) && f !== proj);
        (async () => {
            if (proj) await openProject(proj);
            if (bin) await openBinary(bin);
            if (dops.length) {
                if (!S.project.binary) setStatus('Open a binary first, then import .dop files', true);
                else await importDops(dops);
            }
        })();
    }

    // ------------------------------------------------------------------
    // Persistence

    function localGet(k) {
        try { return localStorage.getItem(k); } catch (e) { return null; }
    }
    function localSet(k, v) {
        try { localStorage.setItem(k, v); return true; } catch (e) { return false; }
    }

    let saveTimer = 0;
    function scheduleSave() {
        clearTimeout(saveTimer);
        saveTimer = setTimeout(() => {
            if (!S.project.binary) return;
            const ok = localSet('xdis.session', X.serializeProject(S.project, S.bytes, true));
            if (!ok) localSet('xdis.session', X.serializeProject(S.project, null, false));
        }, 600);
    }

    function restoreSession() {
        const s = localGet('xdis.session');
        if (!s) return;
        try {
            const res = X.deserializeProject(s);
            S.project = res.project;
            S.bytes = res.bytes;
            refreshBuiltins(S.project);
            rebuild({ reload: true, keepView: false });
            const pos = JSON.parse(localGet('xdis.pos') || 'null');
            if (pos && S.listing) {
                const i = lineForKey(pos.k, pos.kind);
                if (i >= 0) { S.cur = S.anchor = i; $('listing').scrollTop = Math.max(0, i * LH - pos.off); draw(); updateInspector(); }
            }
            setStatus(S.bytes ? `Restored session: ${S.project.binary.name}` : `Restored project — open ${S.project.binary.name} to continue`);
        } catch (e) {
            setStatus('Could not restore previous session: ' + e.message, true);
        }
    }

    function applyTheme() {
        const t = localGet('xdis.theme');
        if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
        else delete document.documentElement.dataset.theme;
    }

    // ------------------------------------------------------------------
    // Events

    function bind() {
        const lst = $('listing');
        lst.addEventListener('scroll', () => requestAnimationFrame(draw), { passive: true });
        new ResizeObserver(() => { draw(); drawMap(); }).observe(lst);

        let dragging = false;
        $('rows').addEventListener('mousedown', (e) => {
            const row = e.target.closest('.row');
            if (!row) return;
            const i = +row.dataset.i;
            const xl = e.target.closest('[data-xk]');
            if (xl && e.button === 0) {
                // jump to the caller/accessor
                e.preventDefault();
                moveTo(i);
                goKey(+xl.dataset.xk);
                return;
            }
            const byte = e.target.closest('[data-a]');
            const pick = byte && !e.shiftKey ? +byte.dataset.a : undefined;
            if (e.button === 2) {
                const [lo, hi] = selLines();
                if (i < lo || i > hi || pick !== undefined) moveTo(i, false, false, pick);
                return;
            }
            const sym = e.target.closest('[data-k]');
            if (sym && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                moveTo(i);
                goKey(+sym.dataset.k);
                return;
            }
            dragging = true;
            moveTo(i, e.shiftKey, false, pick);
            lst.focus({ preventScroll: true });
        });
        $('rows').addEventListener('mousemove', (e) => {
            if (!dragging || !(e.buttons & 1)) { dragging = false; return; }
            const row = e.target.closest('.row');
            if (row && +row.dataset.i !== S.cur) moveTo(+row.dataset.i, true);
        });
        addEventListener('mouseup', () => { dragging = false; });
        $('rows').addEventListener('dblclick', (e) => {
            const sym = e.target.closest('[data-k]');
            const byte = e.target.closest('[data-a]');
            const row = e.target.closest('.row');
            if (sym && !(byte && sym.classList.contains('t-num'))) {
                // symbols: follow; label definitions: rename
                e.preventDefault();
                const k = +sym.dataset.k;
                if (sym.classList.contains('t-lbl')) rename(k);
                else goKey(k);
            } else if (byte && row) {
                // a byte: name it (a label in the middle of a dta line)
                e.preventDefault();
                rename(X.key(S.listing.lines[+row.dataset.i].s, +byte.dataset.a));
            }
        });
        $('rows').addEventListener('contextmenu', (e) => {
            e.preventDefault();
            const sym = e.target.closest('[data-k]');
            showMenu(e.clientX, e.clientY, sym && !sym.classList.contains('t-lbl') ? +sym.dataset.k : undefined);
        });
        addEventListener('mousedown', (e) => { if (!e.target.closest('#ctx')) $('ctx').hidden = true; });
        addEventListener('blur', () => { $('ctx').hidden = true; });

        // map
        const map = $('map');
        let mapDrag = false;
        const mapGo = (hit) => {
            if (!hit) return;
            const i = lineForKey(X.key(hit.s, hit.a), 'ins');
            if (i >= 0) { moveTo(i); lst.scrollTop = i * LH - lst.clientHeight / 2; draw(); }
        };
        const mapTip = (e, hit) => {
            const tip = $('tip');
            if (!hit || !S.model) { tip.hidden = true; return; }
            const r = map.getBoundingClientRect();
            const l = S.model.labelAt(X.key(hit.s, hit.a));
            tip.textContent = segPre(hit.s, hit.a) + X.h4(hit.a) + (l && !l.off ? ' ' + l.name : '');
            tip.hidden = false;
            tip.style.left = Math.max(0, Math.min(e.clientX + 12, innerWidth - 160)) + 'px';
            tip.style.top = r.bottom + 4 + 'px';
        };
        // Pointer capture keeps the drag going when the mouse leaves the strip;
        // positions outside it clamp to the first or last byte.
        map.addEventListener('pointerdown', (e) => {
            if (e.button !== 0 || !S.model) return;
            e.preventDefault();
            try { map.setPointerCapture(e.pointerId); } catch (err) { /* synthetic pointer */ }
            mapDrag = true;
            const hit = mapHit(e.clientX - map.getBoundingClientRect().left, true);
            mapGo(hit);
            mapTip(e, hit);
        });
        map.addEventListener('pointermove', (e) => {
            if (!S.model) return;
            const hit = mapHit(e.clientX - map.getBoundingClientRect().left, mapDrag);
            if (mapDrag) mapGo(hit);
            mapTip(e, hit);
        });
        const mapEnd = (e) => {
            if (!mapDrag) return;
            mapDrag = false;
            if (map.hasPointerCapture(e.pointerId)) map.releasePointerCapture(e.pointerId);
            const r = map.getBoundingClientRect();
            if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) $('tip').hidden = true;
            lst.focus({ preventScroll: true });
        };
        map.addEventListener('pointerup', mapEnd);
        map.addEventListener('pointercancel', mapEnd);
        map.addEventListener('lostpointercapture', () => { mapDrag = false; });
        map.addEventListener('pointerleave', () => { if (!mapDrag) $('tip').hidden = true; });

        // side panel links (labels, xrefs, directives, segments)
        document.querySelector('.side').addEventListener('click', (e) => {
            if (e.target.classList.contains('dir-edit')) return;
            const prob = e.target.closest('[data-prob]');
            if (prob) return gotoProblem(S.problems[+prob.dataset.prob]);
            if (e.target.id === 'btn-apply-ptrs') return applyAllPointerSuggestions();
            const ed = e.target.closest('[data-edit]');
            if (ed) return editDirective(ed.closest('.item'), +ed.dataset.edit);
            const del = e.target.closest('[data-del]');
            if (del) return deleteDirective(+del.dataset.del);
            const unsym = e.target.closest('[data-unsym]');
            if (unsym) {
                e.preventDefault();
                const name = unsym.dataset.unsym;
                return commit((p) => { p.includes = p.includes.filter((i) => i.name !== name); }, `Removed ${name}`);
            }
            const actBtn = e.target.closest('[data-act]');
            if (actBtn) return act(actBtn.dataset.act);
            const k = e.target.closest('[data-k]');
            if (k) return goKey(+k.dataset.k);
            const g = e.target.closest('[data-goto]');
            if (g && S.model) {
                const gk = +g.dataset.goto;
                return goKey(X.keySeg(gk) ? gk : X.key(S.model.finalOwner[X.keyAddr(gk)], X.keyAddr(gk)));
            }
        });
        document.querySelector('.side').addEventListener('dblclick', (e) => {
            const item = e.target.closest('.item');
            const ed = item && item.querySelector('[data-edit]');
            if (ed && e.target.closest('.nm')) editDirective(item, +ed.dataset.edit);
        });
        document.querySelector('.side').addEventListener('change', (e) => {
            const t = e.target;
            if (t.dataset.sym) return toggleInclude(t.dataset.sym, t.checked);
            if (t.dataset.opt) return commit((p) => { p.options = Object.assign({}, p.options, { [t.dataset.opt]: t.checked }); }, `${t.dataset.opt} ${t.checked ? 'on' : 'off'}`);
            if (t.dataset.num) {
                const v = Math.max(+t.min, Math.min(+t.max, parseInt(t.value, 10) || 0));
                return commit((p) => { p.options = Object.assign({}, p.options, { [t.dataset.num]: v }); });
            }
            if (t.id === 'opt-syntax') return commit((p) => { p.options = Object.assign({}, p.options, { syntax: t.value }); }, `Output syntax: ${t.value}`);
            if (t.id === 'opt-type') return commit((p) => { p.binary = Object.assign({}, p.binary, { type: t.value }); }, `Format: ${t.value}`);
            if (t.id === 'opt-org') {
                const v = parseInt(t.value.replace(/^\$|^0x/i, ''), 16);
                if (isNaN(v) || v < 0 || v > 0xFFFF) return setStatus('Bad load address', true);
                t.blur();
                return commit((p) => { p.binary = Object.assign({}, p.binary, { org: v }); }, `Load address $${X.h4(v)}`);
            }
            if (t.id === 'opt-embed') { S.embed = t.checked; localSet('xdis.embed', t.checked ? '1' : '0'); return; }
            if (t.id === 'opt-theme') { localSet('xdis.theme', t.value); applyTheme(); drawMap(); return; }
            if (t.id === 'lf-user' || t.id === 'lf-auto' || t.id === 'lf-ext') return updateLabels();
        });
        document.querySelector('.side').addEventListener('keydown', (e) => {
            if (e.target.id === 'opt-org' && e.key === 'Enter') e.target.dispatchEvent(new Event('change', { bubbles: true }));
        });
        $('label-filter').addEventListener('input', updateLabels);
        $('dir-filter').addEventListener('input', updateDirectives);
        $('dir-unneeded').addEventListener('change', updateDirectives);
        $('dir-add').addEventListener('keydown', (e) => {
            if (e.key !== 'Enter') return;
            const v = e.target.value.trim();
            if (!v) return;
            const r = X.parseDop(v, 'input');
            if (r.errors.length || (!r.directives.length && !Object.keys(r.options).length && !r.args.length)) {
                return setStatus(r.errors[0] || 'Unrecognized directive', true);
            }
            e.target.value = '';
            commit((p) => {
                p.directives = p.directives.concat(r.directives);
                Object.assign(p.options, r.options);
                for (const a of r.args) if (SYM.files[a] && !p.includes.some((i) => i.name === a)) p.includes.push({ name: a, text: SYM.files[a], enabled: true });
            }, `Added ${v}`);
        });

        // tabs
        document.querySelector('.tabs').addEventListener('click', (e) => {
            const b = e.target.closest('button[data-tab]');
            if (b) showTab(b.dataset.tab);
        });

        // toolbar
        $('btn-open-bin').onclick = $('btn-open-bin2').onclick = () => $('file-bin').click();
        $('btn-open-proj').onclick = $('btn-open-proj2').onclick = () => $('file-proj').click();
        $('btn-save-proj').onclick = saveProject;
        $('btn-save-asm').onclick = saveAsm;
        $('btn-export-dop').onclick = exportDop;
        $('btn-import-dop').onclick = () => (S.project.binary ? $('file-dop').click() : setStatus('Open a binary first', true));
        $('btn-add-include').onclick = () => $('file-include').click();
        $('btn-undo').onclick = undo;
        $('btn-redo').onclick = redo;
        $('btn-help').onclick = showHelp;
        $('btn-new').onclick = async () => {
            if (S.project.binary) {
                const r = await ask('Close project?', '<p>The current project is autosaved in this browser until you open another one. Save it to a file first if you want to keep it.</p>',
                    [{ label: 'Cancel', value: 'cancel' }, { label: 'Save project first', value: 'save' }, { label: 'Close', value: 'close', primary: true }]);
                if (r === 'save') saveProject();
                if (r !== 'close' && r !== 'save') return;
            }
            S.project = X.newProject();
            S.bytes = null;
            S.undo = [];
            S.redo = [];
            S.importProblems = [];
            try { localStorage.removeItem('xdis.session'); } catch (e) { /* ignore */ }
            rebuild({ reload: true, keepView: false });
            setStatus('');
        };
        $('file-bin').onchange = (e) => { if (e.target.files[0]) openBinary(e.target.files[0]); e.target.value = ''; };
        $('file-proj').onchange = (e) => { if (e.target.files[0]) openProject(e.target.files[0]); e.target.value = ''; };
        $('file-dop').onchange = (e) => { if (e.target.files.length) importDops(Array.from(e.target.files)); e.target.value = ''; };
        $('file-include').onchange = (e) => { if (e.target.files.length) importDops(Array.from(e.target.files), true); e.target.value = ''; };

        // drag and drop
        let dragDepth = 0;
        addEventListener('dragenter', (e) => { e.preventDefault(); dragDepth++; document.body.classList.add('dragging'); });
        addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove('dragging'); } });
        addEventListener('dragover', (e) => e.preventDefault());
        addEventListener('drop', (e) => {
            e.preventDefault();
            dragDepth = 0;
            document.body.classList.remove('dragging');
            if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
        });

        addEventListener('keydown', onKey);
        addEventListener('beforeunload', () => {
            const ln = curLine();
            if (ln) localSet('xdis.pos', JSON.stringify({ k: lineKey(ln), kind: ln.k, off: S.cur * LH - $('listing').scrollTop }));
        });
        addEventListener('resize', () => { $('ctx').hidden = true; });
    }

    function showTab(name) {
        for (const b of document.querySelectorAll('.tabs button')) b.classList.toggle('on', b.dataset.tab === name);
        for (const p of document.querySelectorAll('.side .panel')) p.hidden = p.id !== 'tab-' + name;
        if (name === 'labels') $('label-filter').focus();
        if (name === 'directives') updateDirectives();
    }

    function onKey(e) {
        if ($('dlg').open) return;
        const t = e.target;
        const typing = t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT';
        const mod = e.ctrlKey || e.metaKey;
        if (mod && !e.altKey) {
            const k = e.key.toLowerCase();
            if (k === 'z' && !typing) { e.preventDefault(); return e.shiftKey ? redo() : undo(); }
            if (k === 'y' && !typing) { e.preventDefault(); return redo(); }
            if (k === 's') { e.preventDefault(); return e.shiftKey ? saveAsm() : saveProject(); }
            if (k === 'o') { e.preventDefault(); return $('file-bin').click(); }
            if (k === 'c' && !typing && S.listing && S.anchor !== S.cur) { e.preventDefault(); return copySelection(); }
            if (!typing && (e.key === 'Home' || e.key === 'End')) { e.preventDefault(); return moveTo(e.key === 'Home' ? 0 : 1e9, e.shiftKey); }
            return;
        }
        if (typing) return;
        if (!$('ctx').hidden && e.key === 'Escape') { $('ctx').hidden = true; return; }
        if (e.key === '?') { e.preventDefault(); return showHelp(); }
        if (!S.listing) return;
        const page = Math.max(1, Math.floor($('listing').clientHeight / LH) - 1);
        if (e.altKey) {
            if (e.key === 'ArrowLeft') { e.preventDefault(); return goBack(false); }
            if (e.key === 'ArrowRight') { e.preventDefault(); return goBack(true); }
            return;
        }
        const nav = { ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page };
        if (nav[e.key]) { e.preventDefault(); return moveTo(S.cur + nav[e.key], e.shiftKey); }
        if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') { e.preventDefault(); return stepByte(e.key === 'ArrowLeft' ? -1 : 1); }
        if (e.key === 'Home' || e.key === 'End') { e.preventDefault(); return moveTo(e.key === 'Home' ? 0 : 1e9, e.shiftKey); }
        if (e.key === 'Enter') { e.preventDefault(); return follow(); }
        if (e.key === 'Escape' || e.key === 'Backspace') { e.preventDefault(); return goBack(false); }
        const keys = {
            c: 'code', d: 'data', t: 'text', w: 'word', a: 'address', p: 'codeptr', v: 'vector',
            u: 'undefine', n: 'name', l: 'name', ';': 'comment', ':': 'note', o: 'operand', k: 'constant', r: 'relocate',
            '>': 'hibyte', '<': 'lobyte',
        };
        const key = e.key.length === 1 ? e.key : '';
        if (key === 'g' || key === 'G') { e.preventDefault(); return gotoPrompt(); }
        if (key === 'x' || key === 'X') { e.preventDefault(); showTab('inspect'); return updateInspector(); }
        const a = keys[key.toLowerCase()] || keys[key];
        if (a) { e.preventDefault(); act(a); }
    }

    // ------------------------------------------------------------------

    // index.html?bin=game.xex&dop=game.dop[,more.dop]&type=raw&org=A000
    // or ?project=game.xdis.json (only when served over http).
    async function loadFromUrl(q) {
        const get = async (url, bin) => {
            const r = await fetch(url);
            if (!r.ok) throw new Error(`${url}: ${r.status}`);
            return bin ? new Uint8Array(await r.arrayBuffer()) : r.text();
        };
        try {
            if (q.get('project')) {
                const res = X.deserializeProject(await get(q.get('project')));
                S.project = res.project;
                S.bytes = res.bytes;
                refreshBuiltins(S.project);
            }
            if (q.get('bin')) {
                const url = q.get('bin');
                const bytes = await get(url, true);
                const name = decodeURIComponent(url.split('/').pop());
                if (!q.get('project')) S.project = X.newProject();
                S.project.binary = Object.assign(S.project.binary || {}, {
                    name, size: bytes.length,
                    type: q.get('type') || (S.project.binary && S.project.binary.type) || X.detectType(name, bytes),
                    org: q.get('org') ? parseInt(q.get('org'), 16) : (S.project.binary && S.project.binary.org) || 0,
                });
                S.bytes = bytes;
            }
            for (const url of (q.get('dop') || '').split(',').filter(Boolean)) {
                const r = X.parseDop(await get(url), url);
                for (const a of r.args) {
                    const text = SYM.files[a] || await get(url.replace(/[^/]*$/, '') + a).catch(() => null);
                    if (text) S.project.includes.push({ name: a, text, enabled: true });
                    else S.importProblems.push(`arg ${a}: not found`);
                }
                S.importProblems.push(...r.errors);
                S.project.directives = S.project.directives.concat(X.dedupeImported(r.directives));
                Object.assign(S.project.options, r.options);
                if (r.binary.type) S.project.binary.type = r.binary.type;
                if (r.binary.org !== undefined) S.project.binary.org = r.binary.org;
            }
            rebuild({ reload: true, keepView: false });
        } catch (e) {
            setStatus('Could not load from URL: ' + e.message, true);
        }
    }

    function init() {
        applyTheme();
        S.embed = localGet('xdis.embed') !== '0';
        bind();
        const q = new URLSearchParams(location.search);
        if (q.get('bin') || q.get('project')) loadFromUrl(q);
        else restoreSession();
        if (!S.project.binary) rebuild();
        updateAll();
        if (S.listing) $('listing').focus();
    }

    init();

    // For debugging from the console.
    window.xdis = S;
})();
