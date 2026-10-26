#!/usr/bin/env python3
"""mcssrtrace.py : extract MADOCA-PPP L6E decoder events from a MALIB trace

Reads a MALIB trace file of a program built with -DTRACE_MCSSR (trace lines
"N MCSSRDBG,<event>,key=value,...", trace level >= 2), rebuilds the L6
packets, subframes and Compact SSR messages seen by src/mdccssr.c, and writes

  - a Markdown report of the findings, for a GitHub issue comment
  - the tables as CSV files (--csv DIR):
      packets.csv   : L6 packets (PKT/L6/L6DROP/FRM)
      subframes.csv : subframes assembled by decode_qzss_l6emsg()
      messages.csv  : messages found in the subframes (MSG)
      st1.csv       : ST1 masks and their GNSS blocks (MASK/MASKBLK)
      biassat.csv   : ST4/ST5 satellites traced by BIASSAT
      timeline.csv  : events per minute with the positioning trace messages

usage  : mcssrtrace.py file.trace [-o report.md] [--csv DIR] [--max-evidence N]
"""
import argparse
import csv
import datetime
import os
import re
import sys
from collections import Counter, OrderedDict

TAG = 'MCSSRDBG,'
GPS_EPOCH = datetime.datetime(1980, 1, 6)
ST_NAME = {1: 'Mask', 2: 'Orbit', 3: 'Clock', 4: 'Code Bias',
           5: 'Phase Bias', 7: 'URA'}
GNSS_NAME = {0: 'GPS', 1: 'GLONASS', 2: 'Galileo', 3: 'BDS', 4: 'QZSS',
             7: 'BDS3'}
GT_JUMP_LIMIT = 3600.0  # gt - receiver time regarded as broken (s)
PKT_GAP_LIMIT = 1.5     # L6 packet interval regarded as a gap (s)

# positioning trace messages counted in the timeline
IMPACT_RE = re.compile(r'(age of ssr error|no ssr orbit correction|'
                       r'no ssr clock correction): '
                       r'(\d{4}/\d\d/\d\d \d\d:\d\d):\d\d')


# --- helpers -----------------------------------------------------------------

def to_value(s):
    for conv in (int, float):
        try:
            return conv(s)
        except ValueError:
            pass
    return s


HEX_KEYS = ('cellmask', 'svmask', 'sigmask', 'or_byte')  # traced with %X


def parse_kv(s):
    d = OrderedDict()
    for item in s.split(','):
        k, sep, v = item.partition('=')
        if sep:
            d[k] = int(v, 16) if k in HEX_KEYS else to_value(v)
    return d


def gt2sec(s):
    """'week:tow' -> seconds from the GPS epoch"""
    week, _, tow = str(s).partition(':')
    return int(week) * 604800.0 + float(tow)


def sec2str(sec, ms=False):
    if sec is None:
        return '-'
    t = GPS_EPOCH + datetime.timedelta(seconds=sec)
    return t.strftime('%Y/%m/%d %H:%M:%S.%f')[:-3] if ms else \
        t.strftime('%Y/%m/%d %H:%M:%S')


def gnss_name(gid):
    return GNSS_NAME.get(gid, 'GNSS ID %s' % gid)


def st_name(st):
    return 'ST%s %s' % (st, ST_NAME.get(st, '?'))


# --- data model --------------------------------------------------------------

class Packet:
    def __init__(self, pkt):
        self.pkt = pkt      # PKT event (None: input other than SBF)
        self.l6 = None      # L6 event
        self.drop = None    # L6DROP event
        self.frm = None     # FRM event
        self.sf = None      # subframe the packet was stored in

    @property
    def sec(self):
        return self.pkt['wn'] * 604800.0 + self.pkt['tow'] if self.pkt else None

    @property
    def line(self):
        return (self.pkt or self.l6)['line']


class Subframe:
    def __init__(self, no, start, pkt):
        self.no = no
        self.start = start  # SFSTART event
        self.pkts = []
        self.first = pkt
        self.sf = None      # SF event
        self.end = None     # SFEND event
        self.msgs = []
        self.status = None
        self.events = [start]

    @property
    def sec(self):
        for p in [self.first] + self.pkts:
            if p is not None and p.sec is not None:
                return p.sec
        return None


class Message:
    def __init__(self, ev, sf, pre):
        self.ev = ev
        self.sf = sf
        self.pre = pre      # events traced while decoding (MASK, BIASSAT, ...)
        self.mask = next((e for e in pre if e['ev'] == 'MASK'), None)
        self.blocks = [e for e in pre if e['ev'] == 'MASKBLK']
        self.bias = [e for e in pre if e['ev'] == 'BIASSAT']
        self.jumps = [e for e in pre if e['ev'] == 'GTJUMP']

    def __getitem__(self, k):
        return self.ev[k]

    @property
    def ok(self):
        return self.ev['end'] >= 0

    @property
    def offset(self):
        """decoder time gt - receiver time of the subframe (s)"""
        t = self.sf.sec if self.sf else None
        return None if t is None else gt2sec(self.ev['gt']) - t


class Trace:
    def __init__(self, path):
        self.path = path
        self.events = []
        self.opt = None
        self.init = None
        self.impact = []    # (minute, category)
        self.read(path)
        self.build()

    def read(self, path):
        with open(path, errors='replace') as f:
            for ln, text in enumerate(f, 1):
                p = text.find(TAG)
                if p < 0:
                    m = IMPACT_RE.search(text)
                    if m:
                        self.impact.append((m.group(2), m.group(1)))
                    continue
                body = text[p + len(TAG):].rstrip('\r\n')
                name, _, rest = body.partition(',')
                ev = OrderedDict(ev=name, line=ln, raw=text.strip())
                if name == 'OPT':
                    head, _, opt = rest.partition('opt=')
                    ev.update(parse_kv(head))
                    ev['opt'] = opt
                else:
                    ev.update(parse_kv(rest))
                self.events.append(ev)

    def build(self):
        self.pkts, self.sfs, self.msgs = [], [], []
        self.aborts, self.prnsw = [], []
        pkt, sf, pending = None, None, []

        def close(status):
            sf.status = status
            self.sfs.append(sf)

        for e in self.events:
            name = e['ev']
            if name == 'OPT':
                self.opt = e
            elif name == 'INIT':
                self.init = e
            elif name == 'PKT':
                pkt = Packet(e)
                self.pkts.append(pkt)
            elif name == 'L6':
                if pkt is None or pkt.l6 is not None:  # no PKT: not SBF input
                    pkt = Packet(None)
                    self.pkts.append(pkt)
                pkt.l6 = e
            elif name == 'L6DROP':
                if pkt:
                    pkt.drop = e
            elif name == 'PRNSW':
                self.prnsw.append(e)
            elif name == 'SFABORT':
                self.aborts.append(e)
                if sf:
                    sf.events.append(e)
                    close('Aborted: next subframe started (si=1)')
                    sf = None
            elif name == 'SFSTART':
                if sf:
                    close('Aborted: restarted')
                sf = Subframe(len(self.sfs) + 1, e, pkt)
            elif name == 'FRM':
                if pkt:
                    pkt.frm = e
                    pkt.sf = sf
                if sf:
                    sf.pkts.append(pkt)
                    sf.events.append(e)
            elif name == 'SF':
                if sf:
                    sf.sf = e
                    sf.events.append(e)
                pending = []
            elif name in ('MASK', 'MASKBLK', 'BIASSAT', 'GTJUMP'):
                pending.append(e)
                if sf:
                    sf.events.append(e)
            elif name == 'MSG':
                m = Message(e, sf, pending)
                pending = []
                self.msgs.append(m)
                if sf:
                    sf.msgs.append(m)
                    sf.events.append(e)
            elif name == 'SFEND':
                if sf:
                    sf.end = e
                    sf.events.append(e)
                    close('Complete' if e['ret'] >= 0 else 'Complete: decode error')
                    sf = None
        if sf:
            close('Truncated: end of trace')
        self.sfs.sort(key=lambda s: s.no)
        self.index = {e['line']: i for i, e in enumerate(self.events)}

    # time range of the receiver
    def time_range(self):
        t = [p.sec for p in self.pkts if p.sec is not None]
        return (min(t), max(t)) if t else (None, None)


# --- findings ----------------------------------------------------------------

class Finding:
    def __init__(self, key, title, count, first, explain, body, evidence):
        self.key = key
        self.title = title
        self.count = count
        self.first = first          # receiver time of the first occurrence
        self.explain = explain
        self.body = body            # list of markdown lines
        self.evidence = evidence    # list of trace events


def md_table(header, rows):
    out = ['| ' + ' | '.join(header) + ' |',
           '|' + '|'.join('---' for _ in header) + '|']
    for r in rows:
        out.append('| ' + ' | '.join(str(c) for c in r) + ' |')
    return out


def msg_time(m):
    return m.sf.sec if m.sf else None


def find_overread(tr):
    msgs = [m for m in tr.msgs if m.ok and m['exp'] >= 0 and m['diff'] != 0]
    if not msgs:
        return None
    sats = [b for m in msgs for b in m.bias if b['nread'] != b['ncell']]
    rows, seen = [], Counter()
    for m in msgs:
        seen[(m['st'], m['iod'], m['exp'], m['len'], m['diff'])] += 1
    for (st, iod, exp, ln, diff), n in sorted(seen.items()):
        rows.append([st_name(st), iod, exp, ln, '%+d' % diff, n])
    body = ['Messages read longer than the length derived from the ST1 mask:', '']
    body += md_table(['Sub type', 'IOD SSR', 'Derived [bit]', 'Read [bit]',
                      'Diff [bit]', 'Messages'], rows)
    if sats:
        srows, sseen = [], Counter()
        for b in sats:
            sseen[(b['st'], b['gnssid'], b['j'], b['cellmask'], b['nsig'],
                   b['ncell'], b['nread'], b['cont_sat0'], b['cont_invalid'])] += 1
        for (st, gid, j, cm, nsig, nc, nr, c0, ci), n in sorted(sseen.items()):
            srows.append([st_name(st), '%d (%s)' % (gid, gnss_name(gid)), j,
                          format(cm, '0%db' % nsig), nc, nr, c0, ci, n])
        body += ['', 'Satellites with more cells read than set in the cell mask '
                 '(`BIASSAT`):', '']
        body += md_table(['Sub type', 'GNSS ID', 'Sat index j', 'Cell mask',
                          'Cells in mask', 'Cells read', 'continue (sat=0)',
                          'continue (invalid)', 'Messages'], srows)
    explain = ('`decode_mcssr_cb()` / `decode_mcssr_pb()` consumed more bits than '
               'the cells set in the ST1 cell mask. ')
    if any(b['cont_sat0'] or b['cont_invalid'] for b in sats):
        explain += ('For every such satellite the read cells went through '
                    '`continue` (`if(sat == 0)` or the invalid-value check) '
                    'inside the signal loop. The `continue` skips `mask >>= 1`, '
                    'so the same cell-mask bit is tested again and the following '
                    'signals are read even when their cell-mask bits are 0.')
    ev = [msgs[0].ev] + [b for b in msgs[0].bias if b['nread'] != b['ncell']]
    return Finding('overread', 'ST4/ST5 read longer than the ST1 mask defines',
                   len(msgs), msg_time(msgs[0]), explain, body, ev)


def find_oob(tr):
    hits = [(m, b) for m in tr.msgs for b in m.bias
            if b['apply'] == 1 and b['sat'] == 0]
    if not hits:
        return None
    nmsg = len({id(m) for m, _ in hits})
    cnt = Counter((b['st'], b['gnssid']) for _, b in hits)
    rows = [[st_name(st), '%d (%s)' % (g, gnss_name(g)), n]
            for (st, g), n in sorted(cnt.items())]
    body = ['Writes to `ssr[sat-1]` with `sat == 0` (`ssr_index=-1`) in %d '
            'messages:' % nmsg, '']
    body += md_table(['Sub type', 'GNSS ID', 'Satellite writes'], rows)
    explain = ('In `decode_mcssr_cb()` / `decode_mcssr_pb()` the `if(apply)` '
               'block after the signal loop writes `ssr[sat-1]` also when the '
               'satellite is not supported by MALIB (`sat == 0`), i.e. '
               '`ssr[-1]`, out of the bounds of `rtcm->ssr[]`.')
    m0, b0 = hits[0]
    return Finding('oob', 'Out-of-bounds write `ssr[-1]` for unsupported satellites',
                   len(hits), msg_time(m0), explain, body, [b0, m0.ev])


def find_resync(tr):
    msgs = [m for m in tr.msgs if m['skip'] > 0]
    if not msgs:
        return None
    rows = []
    for m in msgs:
        prev = None
        if m.sf:
            k = m.sf.msgs.index(m)
            prev = m.sf.msgs[k - 1] if k > 0 else None
        rows.append([sec2str(msg_time(m)), m['pos'], m['skip'], st_name(m['st']),
                     m['ep'], m['iod'],
                     '%s, diff %+d' % (st_name(prev['st']), prev['diff'])
                     if prev else '-'])
    body = md_table(['Subframe start (GPST)', 'Bit offset', 'Skipped [bit]',
                     'Found as', 'Epoch', 'IOD SSR', 'Previous message'], rows)
    explain = ('After a message, `decode_qzss_l6emsg()` searches the next '
               'Message Number 4073 in 12/16-bit steps; the bits passed over are '
               'traced as `skip`. A non-zero skip right after a message with '
               '`diff > 0` means the search started at a wrong bit position, so '
               'the header found there is not a real message boundary.')
    return Finding('resync', 'Message found only after skipping bits',
                   len(msgs), msg_time(msgs[0]), explain, body, [msgs[0].ev])


def find_bad_st1(tr):
    bad = []
    for m in tr.msgs:
        if m['st'] != 1 or not m.mask:
            continue
        why = []
        if m.mask['ep_valid'] == 0:
            why.append('Epoch %d s >= 604800' % m.mask['ep'])
        gids = [b['gnssid'] for b in m.blocks]
        dup = [g for g, n in Counter(gids).items() if n > 1]
        if dup:
            why.append('GNSS ID repeated: %s' % ', '.join(map(str, dup)))
        unk = [g for g in gids if g not in GNSS_NAME]
        if unk:
            why.append('undefined GNSS ID: %s' % ', '.join(map(str, sorted(set(unk)))))
        if why:
            bad.append((m, why))
    if not bad:
        return None
    rows = [[sec2str(msg_time(m)), m.mask['ep'], m.mask['iod'], m.mask['ngnss'],
             m.mask['ns'], '; '.join(why)] for m, why in bad]
    body = md_table(['Subframe start (GPST)', 'Epoch [s]', 'IOD SSR', 'No. of GNSS',
                     'Sats', 'Out of range'], rows)
    explain = ('`decode_mcssr_mask()` accepted an ST1 with values that cannot be '
               'valid, and replaced the mask, IOD SSR, `tow0`/`ep0`/`valep0` and '
               '`gt` with them.')
    m0 = bad[0][0]
    return Finding('badst1', 'ST1 with out-of-range values accepted',
                   len(bad), msg_time(m0), explain, body,
                   m0.jumps + m0.blocks[:2] + [m0.mask, m0.ev])


def find_gt(tr):
    jumps = [e for e in tr.events if e['ev'] == 'GTJUMP']
    off = [m for m in tr.msgs if m.offset is not None and abs(m.offset) > GT_JUMP_LIMIT]
    if not jumps and not off:
        return None
    body = []
    if jumps:
        body += md_table(['Trace line', 'From (week:tow)', 'To (week:tow)', 'Jump [s]'],
                         [[e['line'], e['from'], e['to'], '%+d' % e['dt']]
                          for e in jumps])
    if off:
        last = tr.msgs[-1]
        body += ['', '%d messages were decoded with `gt` more than %d s away from '
                 'the receiver time, from %s to %s%s.' %
                 (len(off), GT_JUMP_LIMIT, sec2str(msg_time(off[0])),
                  sec2str(msg_time(off[-1])),
                  ' (still at the end of the trace, offset %+d s)' % last.offset
                  if last in off else '')]
    explain = ('`adjweek()` moved the decoder time `gt` by more than 1 hour. '
               '`gt` is passed to `rtcm->time` and to the SSR time tags, so the '
               'corrections decoded afterwards carry a wrong week.')
    first = None
    if off:
        first = msg_time(off[0])
    return Finding('gt', 'Decoder time `gt` jumped', len(jumps) or len(off), first,
                   explain, body, jumps)


def find_rest(tr):
    sfs = [s for s in tr.sfs if s.end and s.end['ret'] >= 0 and s.end['rest_nonzero'] > 0]
    if not sfs:
        return None
    rows, cnt = [], Counter()
    for s in sfs:
        last = s.msgs[-1] if s.msgs else None
        cnt[(st_name(last['st']) if last else '-',
             '%+d' % last['diff'] if last else '-')] += 1
    for (st, diff), n in sorted(cnt.items()):
        rows.append([st, diff, n])
    body = md_table(['Last message decoded', 'Its diff [bit]', 'Subframes'], rows)
    explain = ('The message loop ended with non-zero bits left in the subframe '
               'that were not decoded as any message (`SFEND rest_nonzero`). '
               'When the last message decoded has `diff > 0`, the next message '
               'started inside the bits already consumed and was lost.')
    return Finding('rest', 'Non-zero bits left undecoded at the end of subframes',
                   len(sfs), sfs[0].sec, explain, body, [sfs[0].end])


def find_rejected(tr):
    msgs = [m for m in tr.msgs if not m.ok]
    if not msgs:
        return None
    rows = []
    for m in msgs:
        ctx = ''
        if m['chk'] == 'expired':
            ctx = 'ep %s >= valep0 %s' % (m['ep_adj'], m['valep0'])
        elif m['chk'] == 'iod':
            ctx = 'IOD %s != mask IOD %s' % (m['iod'], m['iod_mask'])
        rows.append([sec2str(msg_time(m)), st_name(m['st']), m['ep'], m['iod'],
                     m['chk'], ctx, 'IOD %s, tow0 %s' % (m['iod_mask'], m['tow0'])])
    body = md_table(['Subframe start (GPST)', 'Sub type', 'Epoch', 'IOD SSR',
                     'Check', 'Detail', 'Mask in use'], rows)
    explain = ('Messages rejected by the mask/epoch/IOD check of '
               '`decode_mcssr_xx()`; MALIB then stops decoding the rest of the '
               'subframe.')
    return Finding('rejected', 'Messages rejected by the decoder', len(msgs),
                   msg_time(msgs[0]), explain, body, [msgs[0].ev])


def find_input(tr):
    gaps = []
    last = {}
    for p in tr.pkts:  # all L6E blocks: other vendors are interleaved
        if p.pkt is None or p.pkt['source'] != 2:
            continue
        sv = p.pkt['svid']
        if sv in last and p.sec - last[sv].sec > PKT_GAP_LIMIT:
            gaps.append((last[sv], p))
        last[sv] = p
    drops = Counter(p.drop['reason'] for p in tr.pkts if p.drop)
    nodec = [p for p in tr.pkts if p.pkt and p.l6 is None]
    if not gaps and not tr.aborts and not [r for r in drops if r != 'vendor']:
        return None
    body = []
    if gaps:
        body += ['MADOCA-PPP L6 packets missing in the input:', '']
        body += md_table(['SVID', 'Last packet (GPST)', 'Next packet (GPST)', 'Gap [s]'],
                         [[a.pkt['svid'], sec2str(a.sec), sec2str(b.sec),
                           '%.0f' % (b.sec - a.sec)] for a, b in gaps])
    if tr.aborts:
        body += ['', 'Subframes aborted: %d (`SFABORT`).' % len(tr.aborts)]
    if drops:
        body += ['', 'L6 packets not stored (`L6DROP`): ' + ', '.join(
            '%s %d' % (r, n) for r, n in sorted(drops.items())) +
            ' (`vendor`: other than MADOCA-PPP, expected).']
    if nodec:
        body += ['', 'QZSRawL6 blocks not passed to the decoder (parity error or '
                 'invalid SVID): %d.' % len(nodec)]
    explain = ('L6 input conditions around the decoder errors. These are not '
               'errors of MALIB by themselves, but explain the messages '
               'rejected as expired.')
    ev = [gaps[0][0].pkt, gaps[0][1].pkt] if gaps else tr.aborts[:1]
    return Finding('input', 'L6 input: packet gaps and aborted subframes',
                   len(gaps) + len(tr.aborts),
                   gaps[0][0].sec if gaps else None, explain, body, ev)


FINDERS = [find_overread, find_oob, find_resync, find_bad_st1, find_gt,
           find_rest, find_rejected, find_input]


# --- incident (causal chain around a resynchronised message) ----------------

def incident_events(tr, m):
    """trace events from the subframe of m until the mask is valid again"""
    sf = m.sf
    out = [e for e in sf.events if e['ev'] not in ('FRM',) and
           not (e['ev'] == 'BIASSAT' and e['nread'] == e['ncell'])]
    out = [e for e in out if e['ev'] != 'MASKBLK' or e['gnssid'] not in GNSS_NAME
           or e is next((b for b in out if b['ev'] == 'MASKBLK'), None)]
    i = tr.index[sf.end['line']] + 1 if sf.end else len(tr.events)
    njump = 0
    while i < len(tr.events):
        e = tr.events[i]
        i += 1
        if e['ev'] == 'GTJUMP':
            out.append(e)
            njump += 1
        elif e['ev'] == 'MSG' and (e['end'] < 0 or e['st'] == 1):
            out.append(e)
            if e['st'] == 1 and e['skip'] == 0:
                # take the next jump of gt (if any) with the valid ST1
                if i < len(tr.events) and njump == 0:
                    continue
                break
        elif e['ev'] == 'SFABORT':
            out.append(e)
    return out


def incident_md(tr, m, n):
    evs = incident_events(tr, m)
    if len(evs) > n * 4:
        evs = evs[:n * 4]
    return ['```text'] + ['%7d: %s' % (e['line'], e['raw']) for e in evs] + ['```']


# --- report ------------------------------------------------------------------

def summary_rows(tr):
    t0, t1 = tr.time_range()
    vid2 = [p for p in tr.pkts if p.l6 and p.l6['vid'] == 2]
    st = Counter(s.status for s in tr.sfs)
    ok = sum(1 for m in tr.msgs if m.ok)
    st1 = sum(1 for m in tr.msgs if m['st'] == 1)
    rows = [
        ['Receiver time (GPST)', '%s - %s' % (sec2str(t0), sec2str(t1))],
        ['QZSRawL6 blocks (`PKT`)', sum(1 for p in tr.pkts if p.pkt)],
        ['L6 messages to the decoder (`L6`)', sum(1 for p in tr.pkts if p.l6)],
        ['MADOCA-PPP L6 messages (vendor ID 2)', len(vid2)],
        ['Subframes', '%d (%s)' % (len(tr.sfs), ', '.join(
            '%s %d' % (k, v) for k, v in sorted(st.items())))],
        ['Compact SSR messages', '%d (decoded %d, rejected %d, ST1 %d)' %
         (len(tr.msgs), ok, len(tr.msgs) - ok, st1)],
    ]
    return rows


def timeline(tr):
    rows = OrderedDict()

    def row(key):
        if key not in rows:
            rows[key] = Counter()
        return rows[key]

    for p in tr.pkts:
        if p.sec is not None and p.l6 is not None and p.l6['vid'] == 2:
            row(sec2str(p.sec)[:16])['l6'] += 1
    for s in tr.sfs:
        if s.sec is None:
            continue
        r = row(sec2str(s.sec)[:16])
        r['sf_ok' if s.status == 'Complete' else 'sf_ng'] += 1
        for m in s.msgs:
            r['msg_ok' if m.ok else 'msg_ng'] += 1
            if m['skip'] > 0:
                r['skip'] += 1
            if m.ok and m['exp'] >= 0 and m['diff'] != 0:
                r['overread'] += 1
            if m.offset is not None and abs(m.offset) > GT_JUMP_LIMIT:
                r['gt_off'] += 1
    for minute, cat in tr.impact:
        row(minute)[cat] += 1
    return OrderedDict(sorted(rows.items()))


TL_COLS = [('l6', 'L6 msgs'), ('sf_ok', 'SF ok'), ('sf_ng', 'SF ng'),
           ('msg_ok', 'Msg ok'), ('msg_ng', 'Msg rejected'),
           ('overread', 'Over-read'), ('skip', 'Skip'),
           ('gt_off', 'gt off > 1 h'),
           ('age of ssr error', '"age of ssr error"'),
           ('no ssr orbit correction', '"no ssr orbit correction"'),
           ('no ssr clock correction', '"no ssr clock correction"')]


def write_report(tr, findings, nev, out):
    w = lambda s='': out.write(s + '\n')
    opt = tr.opt or {}
    w('## MADOCA-PPP L6E decoder trace analysis')
    w()
    w('Extracted by `util/mcssrtrace/mcssrtrace.py` from `%s`, a MALIB trace '
      'built with `-DTRACE_MCSSR` (MALIB %s %s, opt `%s`).' %
      (os.path.basename(tr.path), opt.get('ver', '?'), opt.get('patch', ''),
       opt.get('opt', '') or '-'))
    w()
    for line in md_table(['Item', 'Value'], summary_rows(tr)):
        w(line)
    w()
    w('### Findings')
    w()
    for line in md_table(['#', 'Finding', 'Count', 'First at (GPST)'],
                         [[i + 1, f.title, f.count, sec2str(f.first)]
                          for i, f in enumerate(findings)]):
        w(line)

    res = [m for m in tr.msgs if m['skip'] > 0 and m.sf]
    if res:
        w()
        w('### Sequence around the first resynchronised message')
        w()
        w('`MCSSRDBG` lines from the subframe of %s until the mask is valid again '
          '(`BIASSAT` lines with `nread == ncell` and `FRM` lines omitted):' %
          sec2str(msg_time(res[0])))
        w()
        for line in incident_md(tr, res[0], nev):
            w(line)

    for i, f in enumerate(findings):
        w()
        w('### %d. %s' % (i + 1, f.title))
        w()
        w(f.explain)
        w()
        for line in f.body:
            w(line)
        if f.evidence:
            w()
            w('```text')
            for e in f.evidence[:nev]:
                w('%7d: %s' % (e['line'], e['raw']))
            w('```')

    tl = timeline(tr)
    if tl:
        cols = [c for c in TL_COLS if any(r[c[0]] for r in tl.values())]
        w()
        w('### Timeline per minute')
        w()
        w('<details><summary>Decoder events and positioning trace messages '
          'per minute (receiver GPST)</summary>')
        w()
        for line in md_table(['Minute'] + [c[1] for c in cols],
                             [[k] + [r[c[0]] or '' for c in cols]
                              for k, r in tl.items()]):
            w(line)
        w()
        w('</details>')


# --- csv ---------------------------------------------------------------------

def write_csv(tr, d):
    os.makedirs(d, exist_ok=True)

    def open_csv(name, header):
        f = open(os.path.join(d, name), 'w', newline='')
        wr = csv.writer(f)
        wr.writerow(header)
        return f, wr

    f, wr = open_csv('packets.csv', [
        'Line', 'GPST', 'SVID', 'Parity', 'RSCnt', 'Source', 'dt [s]', 'L6 PRN',
        'Vendor', 'Facility', 'SI', 'Alert', 'Data MsgNum', 'Data SubType',
        'Drop', 'Subframe', 'Frame', 'OR byte'])
    for p in tr.pkts:
        k, l6, fr = p.pkt or {}, p.l6 or {}, p.frm or {}
        wr.writerow([p.line, sec2str(p.sec, True), k.get('svid', ''),
                     k.get('parity', ''), k.get('rscnt', ''), k.get('source', ''),
                     k.get('dt', ''), l6.get('prn', ''), l6.get('vid', ''),
                     l6.get('mgfid', ''), l6.get('si', ''), l6.get('alert', ''),
                     l6.get('data_mn', ''), l6.get('data_st', ''),
                     p.drop['reason'] if p.drop else '', p.sf.no if p.sf else '',
                     fr.get('frame', ''),
                     '%02X' % fr['or_byte'] if fr else ''])
    f.close()

    f, wr = open_csv('subframes.csv', [
        'No', 'Line', 'GPST Start', 'GPST End', 'First SubType', 'Max frames',
        'Packets', 'Bit length', 'Messages', 'Rejected', 'Status', 'Last bit',
        'Rest [bit]', 'Rest non-zero [bit]'])
    for s in tr.sfs:
        ends = [p.sec for p in s.pkts if p and p.sec is not None]
        e = s.end or {}
        wr.writerow([s.no, s.start['line'], sec2str(s.sec, True),
                     sec2str(max(ends), True) if ends else '-', s.start['st'],
                     s.start['maxframe'], len(s.pkts),
                     s.sf['nbit'] if s.sf else '', len(s.msgs),
                     sum(1 for m in s.msgs if not m.ok), s.status,
                     e.get('last', ''), e.get('rest', ''), e.get('rest_nonzero', '')])
    f.close()

    f, wr = open_csv('messages.csv', [
        'Line', 'Subframe', 'SF GPST Start', 'No', 'Bit offset', 'Skip [bit]',
        'SubType', 'Epoch', 'UDI', 'MMI', 'IOD SSR', 'End', 'Length [bit]',
        'Derived [bit]', 'Diff [bit]', 'Check', 'ep adj', 'valep0', 'IOD mask',
        'gt', 'gt GPST', 'gt - receiver [s]'])
    for m in tr.msgs:
        e = m.ev
        off = m.offset
        wr.writerow([e['line'], m.sf.no if m.sf else '', sec2str(msg_time(m), True),
                     e['no'], e['pos'], e['skip'], st_name(e['st']), e['ep'],
                     e['udi'], e['mmi'], e['iod'], e['end'], e['len'], e['exp'],
                     e['diff'], e['chk'], e.get('ep_adj', ''), e.get('valep0', ''),
                     e.get('iod_mask', ''), e['gt'], sec2str(gt2sec(e['gt']), True),
                     '' if off is None else '%.0f' % off])
    f.close()

    f, wr = open_csv('st1.csv', [
        'Line', 'SF GPST Start', 'Epoch', 'Epoch valid', 'IOD SSR', 'No. of GNSS',
        'Sats', 'tow0', 'ep0', 'valep0', 'Derived ST2', 'ST3', 'ST4', 'ST5',
        'ST7', 'Block', 'GNSS ID', 'GNSS', 'Supported', 'Sat mask', 'Signal mask',
        'Cell-mask flag', 'Nsat', 'Nsig', 'Ncell', 'Block bits'])
    for m in tr.msgs:
        if not m.mask:
            continue
        k = m.mask
        head = [m['line'], sec2str(msg_time(m), True), k['ep'], k['ep_valid'],
                k['iod'], k['ngnss'], k['ns'], k['tow0'], k['ep0'], k['valep0'],
                k['st2'], k['st3'], k['st4'], k['st5'], k['st7']]
        for b in m.blocks:
            wr.writerow(head + [b['blk'], b['gnssid'], gnss_name(b['gnssid']),
                                b['sys_supported'], '%010X' % b['svmask'],
                                '%04X' % b['sigmask'],
                                b['cmaflg'], b['nsat'], b['nsig'], b['ncell'],
                                b['blkbits']])
    f.close()

    f, wr = open_csv('biassat.csv', [
        'Line', 'SF GPST Start', 'SubType', 'Sat index j', 'GNSS ID', 'sat',
        'Nsig', 'Cell mask', 'Cells in mask', 'Cells read', 'continue (sat=0)',
        'continue (invalid)', 'apply', 'ssr index'])
    for m in tr.msgs:
        for b in m.bias:
            wr.writerow([b['line'], sec2str(msg_time(m), True), st_name(b['st']),
                         b['j'], b['gnssid'], b['sat'], b['nsig'],
                         format(b['cellmask'], '0%db' % b['nsig']), b['ncell'],
                         b['nread'], b['cont_sat0'], b['cont_invalid'],
                         b['apply'], b['ssr_index']])
    f.close()

    f, wr = open_csv('timeline.csv', ['Minute'] + [c[0] for c in TL_COLS])
    for k, r in timeline(tr).items():
        wr.writerow([k] + [r[c[0]] for c in TL_COLS])
    f.close()


def main():
    ap = argparse.ArgumentParser(
        description='extract MADOCA-PPP L6E decoder events (MCSSRDBG) from a '
                    'MALIB trace file')
    ap.add_argument('trace', help='trace file (built with -DTRACE_MCSSR, level >= 2)')
    ap.add_argument('-o', '--out', help='Markdown report file (default: stdout)')
    ap.add_argument('--csv', metavar='DIR', help='write the tables as CSV to DIR')
    ap.add_argument('--max-evidence', type=int, default=8, metavar='N',
                    help='trace lines quoted per finding (default: 8)')
    args = ap.parse_args()

    try:
        tr = Trace(args.trace)
    except OSError as e:
        sys.stderr.write('error: %s\n' % e)
        return 2
    if not tr.events:
        sys.stderr.write('error: no MCSSRDBG line in %s (build with -DTRACE_MCSSR '
                         'and trace level >= 2)\n' % args.trace)
        return 1
    findings = [f for f in (fn(tr) for fn in FINDERS) if f]

    if args.out:
        with open(args.out, 'w') as out:
            write_report(tr, findings, args.max_evidence, out)
    else:
        write_report(tr, findings, args.max_evidence, sys.stdout)
    if args.csv:
        write_csv(tr, args.csv)

    sys.stderr.write('%s: %d MCSSRDBG lines, %d packets, %d subframes, '
                     '%d messages, %d findings\n' %
                     (args.trace, len(tr.events), len(tr.pkts), len(tr.sfs),
                      len(tr.msgs), len(findings)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
