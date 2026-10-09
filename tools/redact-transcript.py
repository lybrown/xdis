#!/usr/bin/env python3
"""Redact personal information from a Claude Code transcript.

    tools/redact-transcript.py [options] transcript.md

By default it prints the redacted transcript to stdout; -i rewrites the file
in place (keeping a .bak copy) and -n only lists what would be redacted.

Redacted by default:
- Windows account names in paths (/mnt/c/Users/NAME, C:\\Users\\NAME) become
  USER. Every later occurrence of NAME is redacted too, wherever it appears.
- IPv4 addresses become documentation addresses (192.0.2.N), the same N for
  the same address. Loopback, 0.0.0.0 and 192.0.2.N itself are kept.
- Email addresses, except git@github.com and noreply@ addresses.
- Tokens that look like credentials (GitHub, Slack, OpenAI/Anthropic, AWS).

Options:
  --home       also redact Unix account names in /home/NAME and /Users/NAME
  --term TEXT  also redact TEXT (repeatable), e.g. a real name or a hostname

Claude Code wraps long lines when it prints them, so a name may be split
across two lines, as in "/mnt/c/Us" followed by "+ers/name/". Names are
matched across such breaks too: the replacement goes before the break and the
break itself is kept.
"""
import argparse
import re
import shutil
import sys

# A terminal line break inside a word: newline, indent, and the "+"/"-" that
# begins a wrapped diff line.
BREAK = r'(?:\n[ \t]*[+-]?)'

# An account name must be followed by a path separator, quote or space on the
# same line, so a name cut short by a line wrap is never taken for a whole one.
END = r'(?=[/\\\'"`) \t,:])'
WINDOWS_USER = re.compile(r'(?:/mnt/[a-z]/|[A-Za-z]:\\\\?)Users[/\\]+([^/\\\s\'"`]+)' + END)
UNIX_USER = re.compile(r'(?<![a-z]/)(?:/home/|/Users/)([a-z_][a-z0-9_.-]*)' + END)
SKIP_USERS = {'Public', 'Default', 'All Users', 'USER', 'runner', 'ubuntu'}

EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
KEEP_EMAIL = re.compile(r'^(git@github\.com|noreply@.*|.*@users\.noreply\.github\.com)$')

IPV4 = re.compile(r'(?<![\w.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\w.])')
KEEP_IP = {'127.0.0.1', '0.0.0.0'}

TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}'
                   r'|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})')


def term_pattern(term):
    """Match term literally, allowing a terminal line break between any two
    characters."""
    return re.compile((BREAK + '?').join(re.escape(c) for c in term))


def replace_term(text, term, placeholder, found):
    def sub(m):
        found.append((m.start(), m.group(0), placeholder))
        # keep any line breaks, so wrapped lines stay wrapped
        return placeholder + ''.join(re.findall(BREAK, m.group(0)))
    return term_pattern(term).sub(sub, text)


def redact(text, home=False, terms=()):
    found = []
    names = {}  # account name or term -> placeholder
    for m in WINDOWS_USER.finditer(text):
        if m.group(1) not in SKIP_USERS:
            names[m.group(1)] = 'USER'
    if home:
        for m in UNIX_USER.finditer(text):
            if m.group(1) not in SKIP_USERS:
                names.setdefault(m.group(1), 'user')
    for t in terms:
        names[t] = 'REDACTED'
    # longest first, so a name that contains another is replaced whole
    for name in sorted(names, key=len, reverse=True):
        text = replace_term(text, name, names[name], found)

    def sub_email(m):
        if KEEP_EMAIL.match(m.group(0)):
            return m.group(0)
        found.append((m.start(), m.group(0), 'user@example.com'))
        return 'user@example.com'
    text = EMAIL.sub(sub_email, text)

    ips = {}
    def sub_ip(m):
        ip = m.group(1)
        if ip in KEEP_IP or ip.startswith('192.0.2.'):  # already a placeholder
            return ip
        new = ips.setdefault(ip, '192.0.2.%d' % (len(ips) + 1))
        found.append((m.start(), ip, new))
        return new
    text = IPV4.sub(sub_ip, text)

    def sub_token(m):
        found.append((m.start(), m.group(0), '[REDACTED-TOKEN]'))
        return '[REDACTED-TOKEN]'
    text = TOKEN.sub(sub_token, text)
    return text, found


def main():
    ap = argparse.ArgumentParser(description='Redact personal information from a Claude Code transcript.')
    ap.add_argument('file')
    ap.add_argument('-i', '--in-place', action='store_true', help='rewrite the file, keeping FILE.bak')
    ap.add_argument('-n', '--dry-run', action='store_true', help='list what would be redacted')
    ap.add_argument('--home', action='store_true', help='also redact /home/NAME and /Users/NAME account names')
    ap.add_argument('--term', action='append', default=[], help='also redact this text (repeatable)')
    args = ap.parse_args()

    with open(args.file, encoding='utf-8') as f:
        text = f.read()
    out, found = redact(text, args.home, args.term)

    if args.dry_run or args.in_place:
        # positions are approximate after earlier replacements; good enough to
        # point at the line
        for pos, old, new in sorted(found):
            line = text.count('\n', 0, min(pos, len(text))) + 1
            print('%s:%d: %r -> %r' % (args.file, line, old, new), file=sys.stderr)
        print('%d redaction(s)' % len(found), file=sys.stderr)
    if args.dry_run:
        return
    if args.in_place:
        shutil.copyfile(args.file, args.file + '.bak')
        with open(args.file, 'w', encoding='utf-8') as f:
            f.write(out)
    else:
        sys.stdout.write(out)


if __name__ == '__main__':
    main()
