#!/usr/bin/env python3
"""mcssrtrace.py : extract MADOCA-PPP L6E decoder events from a MALIB trace

Reads a MALIB trace file of a program built with -DTRACE_MCSSR (trace lines
"N MCSSRDBG,<event>,key=value,...", trace level >= 2), rebuilds the L6
packets, subframes and Compact SSR messages seen by src/mdccssr.c, and writes
them as CSV files to the output directory (-d DIR, default: current):

      packets.csv   : L6 packets (PKT/L6/L6DROP/FRM)
      subframes.csv : subframes assembled by decode_qzss_l6emsg()
      messages.csv  : messages found in the subframes (MSG)
      st1.csv       : ST1 masks and their GNSS blocks (MASK/MASKBLK)
      biassat.csv   : ST4/ST5 satellites traced by BIASSAT
      timeline.csv  : events per minute with the positioning trace messages

usage  : mcssrtrace.py file.trace [-d DIR]
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


# --- timeline ----------------------------------------------------------------

def msg_time(m):
    return m.sf.sec if m.sf else None


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
           ('age of ssr error', 'age of ssr error'),
           ('no ssr orbit correction', 'no ssr orbit correction'),
           ('no ssr clock correction', 'no ssr clock correction')]


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

    f, wr = open_csv('timeline.csv', ['Minute'] + [c[1] for c in TL_COLS])
    for k, r in timeline(tr).items():
        wr.writerow([k] + [r[c[0]] for c in TL_COLS])
    f.close()



def main():
    ap = argparse.ArgumentParser(
        description='extract MADOCA-PPP L6E decoder events (MCSSRDBG) from a '
                    'MALIB trace file to CSV files')
    ap.add_argument('trace', help='trace file (built with -DTRACE_MCSSR, level >= 2)')
    ap.add_argument('-d', '--dir', default='.',
                    help='output directory of the CSV files (default: .)')
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
    write_csv(tr, args.dir)

    sys.stderr.write('%s: %d MCSSRDBG lines, %d packets, %d subframes, '
                     '%d messages -> %s\n' %
                     (args.trace, len(tr.events), len(tr.pkts), len(tr.sfs),
                      len(tr.msgs), os.path.join(args.dir, '*.csv')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
