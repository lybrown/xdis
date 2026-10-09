#!/usr/bin/env python3
"""Turn a Claude Code transcript (as saved from the terminal) into a single
self-contained HTML page.

    tools/transcript-html.py transcript.md [-o transcript.html] [--title TITLE]

The page has a timeline of every prompt across the top (one segment per turn,
wider for longer turns, grouped by day), a list of prompts down the side and
the conversation itself, with tool calls and their output collapsed.

Keys: j/k next/previous prompt, J/K next/previous message, e expands or
collapses all tool output, / searches the prompts.

The transcript's markers are:
  ❯  a prompt          ●  a message or tool call   ⎿  tool output
  ✻  end of a turn ("Worked for 1m 2s · done Monday 9:30 AM")
  ※  a recap
Continuation lines are indented by two spaces. Turn footers give only a
weekday and a time, so days are numbered by counting weekday changes.
"""
import argparse
import datetime
import html
import json
import os
import re

TOOL = re.compile(r'^([A-Z]\w*)\((.*)$')
SUMMARY = re.compile(r'^(Ran|Read|Searched|Wrote|Listed|Fetched|Updated|Edited)\b.*\(ctrl\+o to expand\)$')
LIST_ITEM = re.compile(r'^(\s*)([-•·]|\d+\.)\s+(.*)$')
BOX = '┌│├└╭╰┬┼┴─'
DIFF = re.compile(r'^\s+\d+\s+[+-]?\S?')
FOOTER = re.compile(r'^✻ (\S+) for ((?:\d+h ?)?(?:\d+m ?)?(?:\d+s)?)(?: · done (?:(\w+day) )?(\d+):(\d+) ([AP]M))?')
KEY = re.compile(r'^[A-Z][A-Za-z ]{0,18}: \S')
URL = re.compile(r'https?://[^\s<>"\')]+[^\s<>"\').,;:]')
DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']


def esc(s):
    return html.escape(s, quote=False)


def inline(s):
    out, last = [], 0
    for m in URL.finditer(s):
        out.append(esc(s[last:m.start()]))
        out.append('<a href="%s">%s</a>' % (html.escape(m.group(0)), esc(m.group(0))))
        last = m.end()
    out.append(esc(s[last:]))
    return ''.join(out)


def dedent(line):
    return line[2:] if line.startswith('  ') else line.lstrip(' ')


def indent(line):
    return len(line) - len(line.lstrip(' '))


def render_prose(lines):
    """Render terminal-wrapped text: rejoin wrapped paragraphs and list items,
    keep tables, tool output and indented code as preformatted text."""
    out, para, i = [], [], 0

    def flush():
        if para:
            # "Key: value" records keep one key per line
            keys = KEY.match(para[0])
            out.append('<p>%s</p>' % ''.join(
                ('<br>' if keys and KEY.match(l) and j else ' ' if j else '') + inline(l)
                for j, l in enumerate(para)))
            para.clear()

    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if not s:
            flush()
            i += 1
        elif s.startswith('⎿'):
            flush()
            block = [line]
            i += 1
            while i < len(lines) and lines[i].startswith('   ') and not lines[i].strip().startswith('⎿'):
                block.append(lines[i])
                i += 1
            text = '\n'.join(block)
            cls = 'out note' if 'Interrupted' in s else 'out'
            out.append('<pre class="%s">%s</pre>' % (cls, esc(text)))
        elif set(s) == {'─'}:
            flush()
            out.append('<hr>')
            i += 1
        elif SUMMARY.match(s):
            flush()
            out.append('<div class="ran">%s</div>' % esc(s.replace('(ctrl+o to expand)', '').strip()))
            i += 1
        elif line.startswith('|'):
            # a Markdown table; the terminal wraps long rows, putting the end
            # of a row on the next line, which doesn't start with |
            flush()
            rows = []
            while i < len(lines) and lines[i].strip():
                l = lines[i]
                if l.startswith('|'):
                    rows.append(l.strip())
                elif rows and not l.startswith(' ') and l.rstrip().endswith('|'):
                    rows[-1] += ' ' + l.strip()
                else:
                    break
                i += 1
            out.append(render_table(rows))
        elif s[0] in BOX:
            flush()
            block = []
            while i < len(lines) and lines[i].strip() and lines[i].strip()[0] in BOX:
                block.append(lines[i])
                i += 1
            out.append('<pre class="table">%s</pre>' % esc('\n'.join(block)))
        elif s.startswith('! '):
            flush()
            out.append('<pre class="cmd">%s</pre>' % esc(s))
            i += 1
        elif LIST_ITEM.match(line):
            flush()
            m = LIST_ITEM.match(line)
            ind, text = indent(line), [m.group(3)]
            i += 1
            while (i < len(lines) and lines[i].strip() and indent(lines[i]) > ind
                   and not LIST_ITEM.match(lines[i]) and not lines[i].strip().startswith('⎿')):
                text.append(lines[i].strip())
                i += 1
            out.append('<div class="li" style="margin-left:%.1fem"><span class="mk">%s</span><span>%s</span></div>'
                       % (ind * 0.6, esc(m.group(2) if m.group(2)[0].isdigit() else '•'), inline(' '.join(text))))
        elif indent(line) >= 2 and not para:
            block = []
            while i < len(lines) and lines[i].strip() and indent(lines[i]) >= 2:
                block.append(lines[i])
                i += 1
            # indented text right after a list item or table continues it
            if (out and out[-1].startswith(('<div class="li"', '<div class="tablewrap"'))
                    and re.match(r'[A-Za-z]', block[0].strip())):
                out.append('<p class="cont" style="margin-left:%.1fem">%s</p>'
                           % (indent(block[0]) * 0.6, inline(' '.join(l.strip() for l in block))))
            else:
                out.append('<pre class="code">%s</pre>' % esc('\n'.join(block)))
        else:
            para.append(s)
            i += 1
    flush()
    return '\n'.join(out)


def render_table(rows):
    cells = [[c.strip() for c in r.strip('|').split('|')] for r in rows]
    rule = [all(re.fullmatch(r':?-+:?', c) for c in r) for r in cells]
    head = cells[0] if len(cells) > 1 and rule[1] else None
    body = [r for r, sep in zip(cells, rule) if not sep and r is not head]
    out = ['<div class="tablewrap"><table>']
    if head:
        out.append('<thead><tr>%s</tr></thead>' % ''.join('<th>%s</th>' % inline(c) for c in head))
    out.append('<tbody>%s</tbody></table></div>' % ''.join(
        '<tr>%s</tr>' % ''.join('<td>%s</td>' % inline(c) for c in r) for r in body))
    return ''.join(out)


def parse(text):
    """Split the transcript into turns: [{prompt, entries, footer, recap}]."""
    turns, cur, entry = [], None, None
    for raw in text.split('\n'):
        line = raw.rstrip()
        mark = line[:1]
        if mark == '❯':
            cur = {'prompt': [line[1:].strip()], 'entries': [], 'footer': None, 'recap': None}
            turns.append(cur)
            entry = cur['prompt']
        elif cur is None:
            continue  # the banner before the first prompt
        elif mark == '●':
            entry = [line[1:].strip()]
            cur['entries'].append(entry)
        elif mark == '✻':
            cur['footer'] = line
            entry = None
        elif mark == '※':
            cur['recap'] = [re.sub(r'^※\s*(recap:\s*)?', '', line)]
            entry = cur['recap']
        elif entry is not None:
            if entry is cur['prompt'] and (dedent(line).startswith('⎿') or SUMMARY.match(line.strip())):
                entry = []
                cur['entries'].append(entry)
            entry.append(dedent(line))
    return turns


def seconds(d):
    t = 0
    for n, u in re.findall(r'(\d+)([hms])', d or ''):
        t += int(n) * {'h': 3600, 'm': 60, 's': 1}[u]
    return t


def build(turns, title, last_date=None):
    day, prev_wd, prev_min, today = 0, None, None, False
    meta, body = [], []
    for n, t in enumerate(turns, 1):
        prompt = '\n'.join(t['prompt']).strip()
        m = FOOTER.match(t['footer'] or '')
        dur = seconds(m.group(2)) if m else 0
        when = ''
        if m and m.group(4):
            hh = int(m.group(4)) % 12 + (12 if m.group(6) == 'PM' else 0)
            mins = hh * 60 + int(m.group(5))
            if m.group(3):
                wd = DAYS.index(m.group(3))
                if prev_wd is not None:
                    delta = (wd - prev_wd) % 7
                    if delta == 0 and mins < prev_min:
                        delta = 7
                    day += delta
                prev_wd = wd
            elif not today:
                # Claude Code leaves out the weekday on the day the transcript
                # was saved, which comes after every day that has one
                if prev_wd is not None:
                    day += 1
                today, prev_wd = True, None
            prev_min = mins
            when = '%s:%s %s' % (m.group(4), m.group(5), m.group(6))
        dayname = 'Last day' if today else DAYS[prev_wd] if prev_wd is not None else ''
        summary = ' '.join(prompt.split())
        meta.append({'n': n, 'day': day, 'dayname': dayname, 'when': when, 'dur': dur,
                     'text': summary[:140], 'cmd': summary.startswith('/')})

        parts = ['<section class="turn" id="t%d" data-n="%d">' % (n, n)]
        parts.append('<div class="msg user%s"><div class="who">You <span class="num">#%d</span>'
                     '<span class="stamp">%s %s</span></div>%s</div>'
                     % (' cmd' if summary.startswith('/') else '', n, '{{DAY%d}}' % n, esc(when),
                        render_prose([l.rstrip() for l in prompt.split('\n')])))
        for e in t['entries']:
            tm = TOOL.match(e[0])
            if tm:
                rest = '\n'.join(e[1:]).rstrip()
                head = e[0] if len(e[0]) < 110 else e[0][:107] + '…'
                parts.append('<details class="msg tool"><summary><span class="tname">%s</span> %s</summary>'
                             '<pre>%s</pre></details>'
                             % (esc(tm.group(1)), esc(head[len(tm.group(1)):]), esc(e[0] + '\n' + rest)))
            else:
                parts.append('<div class="msg claude">%s</div>' % render_prose(e))
        if t['footer']:
            parts.append('<div class="footer">%s</div>' % esc(t['footer'].lstrip('✻ ')))
        if t['recap']:
            recap = ' '.join(l.strip() for l in t['recap']).replace('(disable recaps in /config)', '').strip()
            parts.append('<div class="recap"><b>Recap</b> %s</div>' % inline(recap))
        parts.append('</section>')
        body.append('\n'.join(parts))

    for i in range(len(meta) - 2, -1, -1):
        if not meta[i]['dayname'] and not meta[i]['when']:
            meta[i]['dayname'] = meta[i + 1]['dayname']
    if last_date:
        last = meta[-1]['day']
        for m in meta:
            m['dayname'] = (last_date - datetime.timedelta(days=last - m['day'])).strftime('%A %-d %b %Y')
    side = []
    last_day = None
    for m in meta:
        if m['day'] != last_day:
            side.append('<div class="dayhead">%s</div>' % esc(m['dayname'] if last_date else
                                                            'Day %d · %s' % (m['day'] + 1, m['dayname'])))
            last_day = m['day']
        side.append('<a class="item%s" href="#t%d" data-n="%d"><span class="when">%s</span>'
                    '<span class="txt">%s</span></a>'
                    % (' cmd' if m['cmd'] else '', m['n'], m['n'], esc(m['when']), esc(m['text'])))

    body = re.sub(r'\{\{DAY(\d+)\}\}', lambda x: esc(meta[int(x.group(1)) - 1]['dayname']), '\n'.join(body))
    return PAGE.replace('{{TITLE}}', esc(title)) \
               .replace('{{SIDE}}', '\n'.join(side)) \
               .replace('{{BODY}}', body) \
               .replace('{{META}}', json.dumps(meta).replace('</', '<\\/')) \
               .replace('{{COUNT}}', str(len(meta)))


PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{TITLE}}</title>
<style>
:root {
  --bg: #fbfaf8; --panel: #f3f1ed; --text: #1f1e1c; --muted: #6b6862; --line: #e2dfd8;
  --accent: #c2410c; --accent-soft: #fdeee6; --user: #ffffff; --code: #f1efea; --link: #1d4ed8;
  --seg: #cfc9bf; --seg-alt: #b9b2a6;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #1a1918; --panel: #232220; --text: #ebe8e2; --muted: #9c978e; --line: #34322f;
    --accent: #f08a5d; --accent-soft: #3a261d; --user: #262523; --code: #201f1d; --link: #8ab4ff;
    --seg: #4a4741; --seg-alt: #5d5951;
  }
}
:root[data-theme="dark"] {
  --bg: #1a1918; --panel: #232220; --text: #ebe8e2; --muted: #9c978e; --line: #34322f;
  --accent: #f08a5d; --accent-soft: #3a261d; --user: #262523; --code: #201f1d; --link: #8ab4ff;
  --seg: #4a4741; --seg-alt: #5d5951;
}
* { box-sizing: border-box; }
html, body { margin: 0; height: 100%; }
body { display: flex; flex-direction: column; overflow: hidden; background: var(--bg); color: var(--text); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--link); }
pre, .mono { font: 12.5px/1.45 ui-monospace, "SF Mono", Menlo, Consolas, monospace; }

header { flex: none; z-index: 5; background: var(--bg); border-bottom: 1px solid var(--line); padding: 10px 16px 8px; }
.bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
h1 { font-size: 16px; margin: 0 auto 0 0; font-weight: 600; }
button { font: inherit; font-size: 13px; color: var(--text); background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 4px 10px; cursor: pointer; }
button:hover { border-color: var(--muted); }
#pos { font-size: 13px; color: var(--muted); min-width: 7em; text-align: center; font-variant-numeric: tabular-nums; }
#menu { display: none; }

#timeline { display: flex; align-items: flex-end; gap: 1px; height: 30px; margin-top: 8px; overflow: hidden; }
#timeline .seg { flex: none; height: 14px; background: var(--seg); border-radius: 2px; cursor: pointer; position: relative; }
#timeline .seg.alt { background: var(--seg-alt); }
#timeline .seg:hover { background: var(--muted); }
#timeline .seg.cur { background: var(--accent); height: 22px; }
#timeline .gap { flex: none; width: 8px; }
#tip { position: fixed; z-index: 10; pointer-events: none; background: var(--text); color: var(--bg); font-size: 12px; padding: 5px 8px; border-radius: 6px; max-width: 360px; display: none; }

.layout { flex: 1; min-height: 0; display: grid; grid-template-columns: 300px minmax(0, 1fr); }
aside { overflow-y: auto; border-right: 1px solid var(--line); background: var(--panel); padding: 10px 8px 40px; }
#q { width: 100%; font: inherit; font-size: 13px; padding: 6px 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--text); margin-bottom: 6px; }
.dayhead { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin: 14px 6px 4px; }
.item { display: flex; gap: 8px; padding: 5px 6px; border-radius: 6px; color: var(--text); text-decoration: none; font-size: 13px; line-height: 1.35; }
.item:hover { background: var(--line); }
.item.cur { background: var(--accent-soft); box-shadow: inset 3px 0 var(--accent); }
.item.cmd .txt { font-family: ui-monospace, monospace; color: var(--muted); }
.item .when { flex: none; width: 4.6em; color: var(--muted); font-variant-numeric: tabular-nums; font-size: 12px; padding-top: 1px; }
.item .txt { display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.item.hide, .dayhead.hide { display: none; }

main { overflow-y: auto; padding: 0 24px 60vh; }
main > * { max-width: 860px; }
.turn { padding: 18px 0 22px; border-bottom: 1px solid var(--line); scroll-margin-top: 4px; }
.msg { margin: 10px 0; scroll-margin-top: 8px; }
.msg p { margin: 0 0 .6em; }
.msg p, .li { overflow-wrap: anywhere; }
.tablewrap { overflow-x: auto; margin: .4em 0 .8em; }
.msg table { border-collapse: collapse; font-size: 13.5px; }
.msg th, .msg td { border: 1px solid var(--line); padding: 4px 10px; text-align: left; vertical-align: top; }
.msg th { background: var(--panel); font-weight: 600; }
.msg hr { border: 0; border-top: 1px solid var(--line); margin: .8em 0; }
.user { background: var(--user); border: 1px solid var(--line); border-left: 3px solid var(--accent); border-radius: 8px; padding: 10px 14px; }
.user.cmd { font-family: ui-monospace, monospace; font-size: 13px; padding: 6px 12px; }
.who { font-size: 12px; font-weight: 600; color: var(--accent); margin-bottom: 4px; display: flex; gap: 8px; }
.who .num { color: var(--muted); font-weight: 400; }
.who .stamp { margin-left: auto; color: var(--muted); font-weight: 400; }
.claude { padding-left: 16px; position: relative; }
.claude::before { content: ""; position: absolute; left: 2px; top: .55em; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.li { display: flex; gap: 8px; margin-bottom: .3em; }
.li + p:not(.cont), .li + pre { margin-top: .7em; }
.li .mk { flex: none; color: var(--muted); min-width: .8em; }
pre { background: var(--code); border: 1px solid var(--line); border-radius: 6px; padding: 8px 10px; overflow-x: auto; margin: .4em 0 .8em; white-space: pre; }
pre.note { color: var(--muted); }
pre.cmd { border-left: 3px solid var(--accent); }
.ran { font-size: 12.5px; color: var(--muted); margin: .3em 0 .7em; }
.ran::before { content: "⚙ "; }
details.tool { margin-left: 16px; border: 1px solid var(--line); border-radius: 6px; background: var(--code); }
details.tool summary { cursor: pointer; padding: 5px 10px; font: 12.5px/1.4 ui-monospace, Menlo, Consolas, monospace; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
details.tool .tname { color: var(--text); font-weight: 600; }
details.tool pre { margin: 0; border: 0; border-top: 1px solid var(--line); border-radius: 0 0 6px 6px; }
.footer { font-size: 12px; color: var(--muted); margin-top: 12px; }
.footer::before { content: "✻ "; color: var(--accent); }
.recap { font-size: 13px; color: var(--muted); background: var(--panel); border-radius: 6px; padding: 8px 12px; margin-top: 10px; }
.recap b { color: var(--text); margin-right: 4px; }
.keys { font-size: 12px; color: var(--muted); margin: 18px 6px 0; line-height: 1.7; }
kbd { font: 11px ui-monospace, monospace; border: 1px solid var(--line); border-bottom-width: 2px; border-radius: 4px; padding: 0 4px; background: var(--bg); }

@media (max-width: 800px) {
  .layout { grid-template-columns: minmax(0, 1fr); }
  aside { display: none; position: fixed; left: 0; right: 0; bottom: 0; top: var(--hh, 90px); z-index: 4; border-right: 0; }
  body.side aside { display: block; }
  #menu { display: inline-block; }
  main { padding: 0 16px 60vh; }
  details.tool, .claude { margin-left: 0; }
}
</style>
</head>
<body>
<header>
  <div class="bar">
    <button id="menu" title="Prompts">☰</button>
    <h1>{{TITLE}}</h1>
    <button id="prev" title="Previous prompt (k)">◀ Prev</button>
    <span id="pos">1 / {{COUNT}}</span>
    <button id="next" title="Next prompt (j)">Next ▶</button>
    <button id="tools" title="Expand or collapse tool output (e)">Expand tools</button>
  </div>
  <div id="timeline"></div>
</header>
<div id="tip"></div>
<div class="layout">
  <aside>
    <input id="q" type="search" placeholder="Search prompts  /">
    {{SIDE}}
    <div class="keys"><kbd>j</kbd>/<kbd>k</kbd> next/prev prompt<br><kbd>J</kbd>/<kbd>K</kbd> next/prev message<br><kbd>e</kbd> expand tool output<br><kbd>/</kbd> search prompts</div>
  </aside>
  <main>
{{BODY}}
  </main>
</div>
<script>
const META = {{META}};
const $ = s => document.querySelector(s);
const turns = [...document.querySelectorAll('.turn')];
const items = new Map([...document.querySelectorAll('.item')].map(a => [+a.dataset.n, a]));
const header = $('header'), main = $('main');
const setHH = () => document.documentElement.style.setProperty('--hh', header.offsetHeight + 'px');

// timeline: one segment per turn, width by the square root of its duration
const tl = $('#timeline'), segs = new Map();
function drawTimeline() {
  tl.innerHTML = '';
  const days = new Set(META.map(m => m.day)).size;
  const avail = tl.clientWidth - (days - 1) * 8 - META.length;
  const w = META.map(m => Math.sqrt(Math.max(m.dur, 20)));
  const scale = avail / w.reduce((a, b) => a + b, 0);
  let prevDay = META.length ? META[0].day : 0, alt = false;
  META.forEach((m, i) => {
    if (m.day !== prevDay) { const g = document.createElement('div'); g.className = 'gap'; tl.append(g); alt = !alt; prevDay = m.day; }
    const s = document.createElement('div');
    s.className = 'seg' + (alt ? ' alt' : '');
    s.style.width = Math.max(2, w[i] * scale) + 'px';
    s.dataset.n = m.n;
    tl.append(s);
    segs.set(m.n, s);
  });
  mark(cur, true);
}
const fmt = s => s >= 3600 ? Math.floor(s / 3600) + 'h ' + Math.floor(s % 3600 / 60) + 'm' : s >= 60 ? Math.floor(s / 60) + 'm ' + s % 60 + 's' : s ? s + 's' : '';
const tip = $('#tip');
tl.addEventListener('mousemove', e => {
  const n = +e.target.dataset.n;
  if (!n) { tip.style.display = 'none'; return; }
  const m = META[n - 1];
  tip.textContent = `#${n} · ${m.dayname} ${m.when}${m.dur ? ' · ' + fmt(m.dur) : ''} — ${m.text}`;
  tip.style.display = 'block';
  tip.style.left = Math.min(e.clientX + 12, innerWidth - tip.offsetWidth - 8) + 'px';
  tip.style.top = e.clientY + 16 + 'px';
});
tl.addEventListener('mouseleave', () => tip.style.display = 'none');
tl.addEventListener('click', e => { const n = +e.target.dataset.n; if (n) go(n); });

let cur = 1;
function mark(n, force) {
  if (n === cur && !force) return;
  segs.get(cur)?.classList.remove('cur'); items.get(cur)?.classList.remove('cur');
  cur = n;
  segs.get(n)?.classList.add('cur');
  const it = items.get(n);
  if (it) { it.classList.add('cur'); it.scrollIntoView({ block: 'nearest' }); }
  $('#pos').textContent = n + ' / ' + META.length;
}
function go(n) {
  n = Math.max(1, Math.min(META.length, n));
  const t = document.getElementById('t' + n);
  if (!t) return;
  t.scrollIntoView();
  mark(n);
  history.replaceState(null, '', '#t' + n);
  document.body.classList.remove('side');
}
// the current turn is the last one whose top is above a third of the window
let ticking = false;
main.addEventListener('scroll', () => {
  if (ticking) return;
  ticking = true;
  requestAnimationFrame(() => {
    ticking = false;
    const y = main.getBoundingClientRect().top + main.clientHeight / 3;
    let lo = 0, hi = turns.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (turns[mid].getBoundingClientRect().top <= y) lo = mid; else hi = mid - 1; }
    if (turns[lo]) mark(+turns[lo].dataset.n);
  });
});
// step through individual messages
function stepMsg(dir) {
  const msgs = [...document.querySelectorAll('.msg')];
  const top = main.getBoundingClientRect().top + 8;
  const idx = msgs.findIndex(m => m.getBoundingClientRect().top > top + 2);
  let i = idx < 0 ? msgs.length : idx;
  i = dir > 0 ? i : i - 2;
  if (msgs[i]) msgs[i].scrollIntoView();
}
let open = false;
function toggleTools() {
  open = !open;
  document.querySelectorAll('details.tool').forEach(d => d.open = open);
  $('#tools').textContent = open ? 'Collapse tools' : 'Expand tools';
}
$('#prev').onclick = () => go(cur - 1);
$('#next').onclick = () => go(cur + 1);
$('#tools').onclick = toggleTools;
$('#menu').onclick = () => document.body.classList.toggle('side');
document.querySelectorAll('.item').forEach(a => a.onclick = e => { e.preventDefault(); go(+a.dataset.n); });
$('#q').addEventListener('input', e => {
  const q = e.target.value.toLowerCase();
  let head = null, any = false;
  for (const el of document.querySelectorAll('aside .dayhead, aside .item')) {
    if (el.classList.contains('dayhead')) { if (head) head.classList.toggle('hide', !any); head = el; any = false; continue; }
    const hit = !q || META[el.dataset.n - 1].text.toLowerCase().includes(q);
    el.classList.toggle('hide', !hit);
    any = any || hit;
  }
  if (head) head.classList.toggle('hide', !any);
});
addEventListener('keydown', e => {
  if (e.target.matches?.('input, textarea') || e.ctrlKey || e.metaKey || e.altKey) {
    if (e.key === 'Escape') e.target.blur();
    return;
  }
  const k = { j: () => go(cur + 1), k: () => go(cur - 1), J: () => stepMsg(1), K: () => stepMsg(-1), e: toggleTools,
              '/': () => { document.body.classList.add('side'); $('#q').focus(); } }[e.key];
  if (k) { e.preventDefault(); k(); }
});
addEventListener('resize', () => { setHH(); drawTimeline(); });
setHH();
drawTimeline();
const h = /^#t(\d+)$/.exec(location.hash);
if (h) go(+h[1]); else mark(1, true);
</script>
</body>
</html>
'''


def main():
    ap = argparse.ArgumentParser(description='Turn a Claude Code transcript into an HTML page.')
    ap.add_argument('file')
    ap.add_argument('-o', '--output', help='output file (default: FILE with .html)')
    ap.add_argument('--date', type=datetime.date.fromisoformat,
                    help='date of the last day (YYYY-MM-DD), to show calendar dates instead of weekdays')
    ap.add_argument('--title', help='page title (default: the project folder, from the banner)')
    args = ap.parse_args()

    with open(args.file, encoding='utf-8') as f:
        text = f.read()
    title = args.title
    if not title:
        m = re.search(r'\s(~?/\S+)\s*$', text.split('\n❯')[0], re.M)
        title = (os.path.basename(m.group(1).rstrip('/')) + ' transcript') if m else 'Transcript'
    out = args.output or os.path.splitext(args.file)[0] + '.html'
    turns = parse(text)
    with open(out, 'w', encoding='utf-8') as f:
        f.write(build(turns, title, args.date))
    print('%s: %d prompts' % (out, len(turns)))


if __name__ == '__main__':
    main()
