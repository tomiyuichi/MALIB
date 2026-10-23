/*------------------------------------------------------------------------------
* sbfMALIB.c : dump SBF QZSRawL6 packets to CSV with the MALIB SBF reader
*
* Reads an SBF file with the MALIB SBF reader (input_sbff()) and writes the
* QZSRawL6 blocks (ID 4069) to CSV files in the current directory, in the
* column layout of the gsg_log_visualizer tables plus a GPST column:
*
*   sbfMALIB_01.csv : "QZSRawL6 -> overview" packet dump (all packets)
*   sbfMALIB_02.csv : "QZSRawL6 -> L6E" L6 header dump (Source = L6E only)
*   sbfMALIB_03.csv : "QZSRawL6 -> MADOCA-PPP-1" subframe dump, assembled by
*                     the MALIB decoder (decode_qzss_l6emsg())
*   sbfMALIB_04.csv : "QZSRawL6 -> MADOCA-PPP-2" message dump, as cut out and
*                     decoded by the MALIB decoders (decode_mcssr_*())
*
* mdccssr.c is included here to read its assembly state (_mcssr), and
* decode_qzss_l6emsg() is wrapped by the linker (-Wl,--wrap) to observe each
* call from septentrio.c. For sbfMALIB_04.csv, every complete subframe is
* replayed with the message loop of decode_qzss_l6emsg() and the MALIB
* decode_mcssr_*() on a copy of _mcssr (apply=0), and checked against the
* real run. trace() is also wrapped to catch the MALIB error messages.
* The MALIB sources are not modified.
*
* usage  : sbfMALIB file.sbf
* return : 0: ok, 1: no QZSRawL6 block found, 2: usage/file error
*-----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "rtklib.h"
#include "mdccssr.c" /* MALIB L6E decoder, built in this unit to access _mcssr */

#define SBF_QZSRAWL6   4069         /* SBF block ID of QZSRawL6 */
#define L6_NAVBITS_W   63           /* number of NAVBits words (u32) */
#define L6_MSG_BYTES   250          /* L6 message length (2000 bits) */
#define L6_MIN_LEN     (20 + L6_NAVBITS_W * 4) /* min QZSRawL6 block length */
#define L6_HEAD_BITS   49           /* L6 header length (bits) */
#define L6_DATA_BITS   1695         /* L6 data part length (bits) */
#define L6_RSC_BITS    256          /* L6 RS code length (bits) */
#define SRC_L6E        2            /* QZSRawL6 Source: L6E */
#define OUTFILE1       "sbfMALIB_01.csv" /* packet dump */
#define OUTFILE2       "sbfMALIB_02.csv" /* L6E header dump */
#define OUTFILE3       "sbfMALIB_03.csv" /* MADOCA-PPP subframe dump */
#define OUTFILE4       "sbfMALIB_04.csv" /* MADOCA-PPP message dump */

typedef struct {                    /* subframe being assembled by MALIB */
    int active;                     /* 1: assembly in progress */
    int svid, prn, fid;             /* SBF SVID, L6 PRN, Facility ID */
    int week_s, week_e;             /* week of the first/last packet */
    uint32_t tow_s, tow_e;          /* TOW (ms) of the first/last packet */
    int npkt;                       /* number of packets (_mcssr.frame) */
    uint8_t buff[MCSSR_BYTELEN];    /* copy of _mcssr.buff */
} sfrm_t;

static raw_t  raw;  /* large structs: keep them off the stack */
static rtcm_t rtcm;
static sfrm_t sf;
static FILE  *ofp3, *ofp4;
static int    n3;   /* rows in sbfMALIB_03.csv */
static int    n4;   /* rows in sbfMALIB_04.csv */
static int    nmis; /* replays that do not match the real run */
static mcssr_t pre; /* _mcssr before the current decode_qzss_l6emsg() call */
static mcssr_t rep; /* _mcssr used for the replay */
static ssr_t  dummy_ssr[MAXSAT]; /* not written: replay uses apply=0 */
static int    capture;           /* 1: keep MALIB trace(2) messages */
static int    prescan;           /* 1: skip the L6E decoder (time search) */
static char   errmsg[1024];      /* last MALIB trace(2) message */

/* little-endian readers, same as septentrio.c */
static uint16_t U2(const uint8_t *p) {uint16_t a; memcpy(&a,p,2); return a;}
static uint32_t U4(const uint8_t *p) {uint32_t a; memcpy(&a,p,4); return a;}

static void usage(void)
{
    fprintf(stderr, "usage: sbfMALIB file.sbf\n"
                    "  writes %s, %s, %s and %s to the current directory\n",
                    OUTFILE1, OUTFILE2, OUTFILE3, OUTFILE4);
}

/* SBF SVID to PRN string (QZSS only) */
static void svid2str(int svid, char *str)
{
    if (svid >= 181 && svid <= 190) sprintf(str, "J%02d", svid - 180);
    else sprintf(str, "?%d", svid);
}

/* L6 signal source name */
static const char *source_name(int source, char *buf)
{
    switch (source) {
        case 0: return "Unknown";
        case 1: return "L6D";
        case 2: return "L6E";
    }
    sprintf(buf, "Unknown (%d)", source);
    return buf;
}

/* L6 vendor ID name */
static const char *vendor_name(int vid)
{
    switch (vid) {
        case 2: return "MADOCA-PPP";
        case 3: return "QZNMA";
        case 5: return "CLAS";
    }
    return "Unknown";
}

/* integer to binary string of the given width */
static void bin2str(unsigned int v, int width, char *str)
{
    int i;

    for (i = 0; i < width; i++) str[i] = (v >> (width - 1 - i)) & 1 ? '1' : '0';
    str[width] = '\0';
}

/* write n bits from bit pos as hex, 8 digits per group, last digit left-justified */
static void write_hex(FILE *ofp, const uint8_t *msg, int pos, int n)
{
    int i, take;

    for (i = 0; n > 0; i++, pos += take, n -= take) {
        take = n < 4 ? n : 4;
        fprintf(ofp, "%s%X", (i > 0 && i % 8 == 0) ? " " : "",
                getbitu(msg, pos, take) << (4 - take));
    }
}

/* NAVBits words to the 250-byte L6 message, same as decode_qzsrawl6() */
static void navbits2msg(const uint8_t *p, uint8_t *msg)
{
    uint8_t buff[L6_NAVBITS_W * 4];
    uint32_t w;
    int i;

    for (i = 0; i < L6_NAVBITS_W; i++) {
        w = U4(p + i * 4);
        buff[i*4  ] = (uint8_t)(w >> 24);
        buff[i*4+1] = (uint8_t)(w >> 16);
        buff[i*4+2] = (uint8_t)(w >>  8);
        buff[i*4+3] = (uint8_t)(w      );
    }
    memcpy(msg, buff, L6_MSG_BYTES);
}

/* write the columns common to both CSVs: #,SVID,WN,TOW [s],GPST */
static void write_time(FILE *ofp, int no, const uint8_t *b)
{
    uint32_t tow = U4(b + 8);
    int week = U2(b + 12);
    char prn[16], gpst[64];

    svid2str(b[14], prn);
    time2str(gpst2time(week, tow * 0.001), gpst, 3);
    fprintf(ofp, "%d,%s,%d,%.3f,%s,", no, prn, week, tow * 0.001, gpst);
}

/* sbfMALIB_01.csv: one row of the packet dump */
static void write_row1(FILE *ofp, int no, const uint8_t *b, const uint8_t *msg)
{
    int type = (int)getbitu(msg, 40, 8); /* L6 Msg. Type ID */
    char src[32];

    write_time(ofp, no, b);
    fprintf(ofp, "%s,%d,%s,%d,%u,%d,%02X,%u,", source_name(b[17], src), b[19],
            b[15] ? "OK" : "NG", b[16], getbitu(msg, 32, 8), (type >> 5) & 0x7,
            type, getbitu(msg, 48, 1));
    write_hex(ofp, msg, 0, L6_MSG_BYTES * 8);
    fprintf(ofp, "\n");
}

/* sbfMALIB_02.csv: one row of the L6E header dump */
static void write_row2(FILE *ofp, int no, const uint8_t *b, const uint8_t *msg)
{
    unsigned int vid  = getbitu(msg, 40, 3); /* Vendor ID */
    unsigned int fid  = getbitu(msg, 43, 2); /* Facility ID */
    unsigned int csid = getbitu(msg, 45, 1); /* Correction Service ID */
    unsigned int anme = getbitu(msg, 46, 1); /* Applicable Nav. Msg. Ext. */
    unsigned int si   = getbitu(msg, 47, 1); /* Subframe Indicator */
    char vbin[8], fbin[8];

    bin2str(vid, 3, vbin);
    bin2str(fid, 2, fbin);
    write_time(ofp, no, b);
    fprintf(ofp, "%s,%08X,%u,%s %s,%s %s,%u %s,%u %s,%u %s,%u,",
            b[15] ? "OK" : "NG", getbitu(msg, 0, 32), getbitu(msg, 32, 8),
            vbin, vendor_name(vid), fbin, fid < 2 ? "Hitachi-Ota" : "Kobe",
            csid, csid ? "Ionosphere" : "Orbit/Clock", anme, anme ? "CNAV" : "LNAV",
            si, si ? "First" : "Continued", getbitu(msg, 48, 1));
    write_hex(ofp, msg, L6_HEAD_BITS, L6_DATA_BITS);
    fprintf(ofp, ",");
    write_hex(ofp, msg, L6_HEAD_BITS + L6_DATA_BITS, L6_RSC_BITS);
    fprintf(ofp, "\n");
}

/* sbfMALIB_03.csv: one row of the subframe dump, status is "Label[: note]" */
static void write_row3(const char *status)
{
    unsigned int mn, st, ep, nep;
    char prn[16], gs[64], ge[64], fbin[8];
    int nbit = sf.npkt * L6_DATA_BITS;

    svid2str(sf.svid, prn);
    bin2str(sf.fid, 2, fbin);
    time2str(gpst2time(sf.week_s, sf.tow_s * 0.001), gs, 3);
    time2str(gpst2time(sf.week_e, sf.tow_e * 0.001), ge, 3);
    fprintf(ofp3, "%d,%s,%d,%s %s,%d,%.3f,%s,%.3f,%s,%d,%s,%d,%s,", ++n3, prn,
            sf.prn, fbin, sf.fid < 2 ? "Hitachi-Ota" : "Kobe", sf.week_s,
            sf.tow_s * 0.001, gs, sf.tow_e * 0.001, ge, sf.npkt,
            sf.npkt == 5 ? "SF1/5/9" : sf.npkt == 3 ? "SF4/8/12" : "-", nbit,
            status);

    /* first Compact SSR message header */
    mn = getbitu(sf.buff, 0, 12);
    st = getbitu(sf.buff, 12, 4);
    nep = st == MCSSR_ST_MASK ? 20 : 12; /* ST1: GPS epoch, others: hourly */
    ep = getbitu(sf.buff, 16, nep);
    if (mn != RTCM_MN_CSSR) {
        fprintf(ofp3, "MsgNum != 4073,,,,,");
    }
    else if (st == MCSSR_ST_MASK) {
        fprintf(ofp3, "%u,%u,%u s (TOW),", mn, st, ep);
    }
    else {
        fprintf(ofp3, "%u,%u,%u s (hourly %u:%02u),", mn, st, ep, ep / 60, ep % 60);
    }
    if (mn == RTCM_MN_CSSR) {
        fprintf(ofp3, "%u / %u,%u,", getbitu(sf.buff, 16 + nep, 4),
                getbitu(sf.buff, 20 + nep, 1), getbitu(sf.buff, 21 + nep, 4));
    }
    write_hex(ofp3, sf.buff, 0, nbit);
    fprintf(ofp3, "\n");
    sf.active = 0;
}

/* linker wrap of trace(): keep the MALIB error message while replaying */
void __wrap_trace(int level, const char *format, ...)
{
    va_list ap;
    char *p;

    if (!capture || level > 2) return;
    va_start(ap, format);
    vsprintf(errmsg, format, ap);
    va_end(ap);
    for (p = errmsg; *p; p++) {
        if (*p == ',') *p = ';';              /* keep the CSV columns */
        else if (*p == '\n') { *p = '\0'; break; }
    }
}

/* Compact SSR sub type name */
static const char *st_name(int st)
{
    switch (st) {
        case 1: return "Mask";
        case 2: return "Orbit";
        case 3: return "Clock";
        case 4: return "Code Bias";
        case 5: return "Phase Bias";
        case 7: return "URA";
    }
    return "?";
}

/* GNSS ID name of the Compact SSR mask */
static const char *gnss_name(int id, char *buf)
{
    switch (id) {
        case 0: return "GPS";
        case 1: return "GLONASS";
        case 2: return "Galileo";
        case 3: return "BDS";
        case 4: return "QZSS";
        case 7: return "BDS3";
    }
    sprintf(buf, "Undefined (%d)", id);
    return buf;
}

/* GPS time to "TOW s (Day hh:mm:ss)" */
static void tow2str(gtime_t t, char *str)
{
    static const char *wday[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    int week, tow = (int)(time2gpst(t, &week) + 0.5), s = tow % 86400;

    sprintf(str, "%d s (%s %02d:%02d:%02d)", tow, wday[(tow / 86400) % 7],
            s / 3600, s % 3600 / 60, s % 60);
}

/* header epoch time to GPST, taking the epoch nearest to the receiver time */
static gtime_t hdrep2time(int st, unsigned int ep, gtime_t trcv)
{
    gtime_t t;
    double dt;
    int week;

    if (st == MCSSR_ST_MASK) { /* GPS epoch time (s of week) */
        time2gpst(trcv, &week);
        t = gpst2time(week, ep);
        dt = timediff(t, trcv);
        if (dt >  302400.0) t = timeadd(t, -604800.0);
        if (dt < -302400.0) t = timeadd(t,  604800.0);
        return t;
    }
    t = timeadd(trcv, ep - fmod(time2gpst(trcv, &week), 3600.0)); /* hourly */
    dt = timediff(t, trcv);
    if (dt >  1800.0) t = timeadd(t, -3600.0);
    if (dt < -1800.0) t = timeadd(t,  3600.0);
    return t;
}

/* sbfMALIB_04.csv: one row per message found by MALIB in the subframe */
static void write_row4(int no, int pos, int end, int skip, const char *pad)
{
    unsigned int st = getbitu(rep.buff, pos + 12, 4), ep, nep, nhead;
    gtime_t trcv = gpst2time(sf.week_s, sf.tow_s * 0.001), tep;
    char prn[16], gs[64], es[64], rt[64], rg[64], buf[32];
    int j, n = 0;

    nep = st == MCSSR_ST_MASK ? 20 : 12;
    nhead = 16 + nep + 9; /* ST1: up to IOD SSR (No. of GNSS is payload) */
    ep = getbitu(rep.buff, pos + 16, nep);
    tep = hdrep2time(st, ep, trcv);
    svid2str(sf.svid, prn);
    time2str(trcv, gs, 3);
    time2str(tep, es, 3);
    if (end >= 0) { tow2str(rep.gt, rt); time2str(rep.gt, rg, 3); }
    else strcpy(rt, "-"), strcpy(rg, "-");

    fprintf(ofp4, "%d,%s,%d,%.3f,%s,%d,%d,", ++n4, prn, sf.week_s,
            sf.tow_s * 0.001, gs, no, pos);
    if (end >= 0) fprintf(ofp4, "%d,", end - pos);
    else fprintf(ofp4, "-,");
    fprintf(ofp4, "%u,%u %s,", getbitu(rep.buff, pos, 12), st, st_name(st));
    if (st == MCSSR_ST_MASK) fprintf(ofp4, "%u s (TOW),", ep);
    else fprintf(ofp4, "%u s (hourly %u:%02u),", ep, ep / 60, ep % 60);
    fprintf(ofp4, "%s,%u,%u,%u,%s,%s,", es, getbitu(rep.buff, pos + 16 + nep, 4),
            getbitu(rep.buff, pos + 20 + nep, 1),
            getbitu(rep.buff, pos + 21 + nep, 4), rt, rg);
    if (rep.tow0 < 0) fprintf(ofp4, "-,");
    else fprintf(ofp4, "IOD %d @ %d,", rep.iod, rep.tow0 + rep.ep0);

    /* status: MALIB result, rescanned bits before the message, padding */
    if (skip > 0) fprintf(ofp4, "Found after skipping %d bit; ", skip);
    if (end >= 0) fprintf(ofp4, "OK");
    else fprintf(ofp4, "Decode error: %s", errmsg[0] ? errmsg : "-");
    fprintf(ofp4, "%s,", pad);

    /* payload: mask summary of MALIB for ST1, then the bits after the header */
    if (end < 0) { fprintf(ofp4, "-\n"); return; }
    if (st == MCSSR_ST_MASK) {
        for (j = 0; j < MCSSR_MAX_SYS; j++) {
            if (!rep.nsat[j]) continue;
            fprintf(ofp4, "%s%s: %d", n++ ? " / " : "", gnss_name(j, buf), rep.nsat[j]);
        }
        fprintf(ofp4, " (total %d sats) | ", rep.ns);
    }
    write_hex(ofp4, rep.buff, pos + nhead, end - pos - nhead);
    fprintf(ofp4, "\n");
}

/* one replay of the message loop of decode_qzss_l6emsg() from the state
   before the call; writes the rows if pad != NULL, returns no. of messages */
static int replay_pass(const char *pad, int *lastend)
{
    int i = 0, pos, mn, st, no = 0, skip = 0, nbit = sf.npkt * L6_DATA_BITS;

    rep = pre;
    memcpy(rep.buff, _mcssr.buff, MCSSR_BYTELEN);
    capture = 1;
    while (i < nbit) {
        pos = i;
        mn = getbitu(rep.buff, i, 12); i += 12;
        if (mn != RTCM_MN_CSSR) { skip += 12; continue; }
        st = getbitu(rep.buff, i, 4); i += 4;
        if ((st != MCSSR_ST_MASK) && (st != MCSSR_ST_OC) &&
            (st != MCSSR_ST_CC)   && (st != MCSSR_ST_CB) &&
            (st != MCSSR_ST_PB)   && (st != MCSSR_ST_URA)) { skip += 16; continue; }

        errmsg[0] = '\0';
        switch (st) {
            case MCSSR_ST_MASK: i = decode_mcssr_mask(&rep, i); break;
            case MCSSR_ST_OC  : i = decode_mcssr_oc (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_CC  : i = decode_mcssr_cc (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_CB  : i = decode_mcssr_cb (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_PB  : i = decode_mcssr_pb (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_URA : i = decode_mcssr_ura(&rep, dummy_ssr, i, 0); break;
        }
        no++;
        if (pad) write_row4(no, pos, i, skip, no == *lastend ? pad : "");
        else *lastend = i;
        skip = 0;
        if (i < 0) break; /* MALIB stops the subframe on an error */
    }
    capture = 0;
    return no;
}

/* replay a complete subframe: pass 1 finds the last message, pass 2 writes */
static void replay_subframe(void)
{
    int k, nz = 0, end = -1, nmsg, nbit = sf.npkt * L6_DATA_BITS;
    char pad[128] = "";

    nmsg = replay_pass(NULL, &end);
    if (nmsg > 0 && end >= 0 && end <= nbit) {
        for (k = end; k < nbit; k++) if (getbitu(rep.buff, k, 1)) nz++;
        sprintf(pad, "; rest after last message %d bit (%s)", nbit - end,
                nz ? "non-zero: not decoded" : "all 0");
    }
    replay_pass(pad, &nmsg); /* the last message gets the padding note */

    /* the replay must end in the same state as the real run */
    if (rep.gt.time != _mcssr.gt.time || rep.tow0 != _mcssr.tow0 ||
        rep.iod != _mcssr.iod) {
        nmis++;
    }
}

/* linker wrap of decode_qzss_l6emsg(): track the subframe assembly of MALIB */
extern int __real_decode_qzss_l6emsg(rtcm_t *rtcm);

int __wrap_decode_qzss_l6emsg(rtcm_t *rtcm)
{
    int mb = _mcssr.maxframe, fb = _mcssr.frame, ret, start, saved;

    if (prescan) return 0;
    pre = _mcssr;      /* state before this call, for the replay */
    _mcssr.ibuff = -1; /* probe: MALIB sets it to 0 only on a new subframe */
    ret = __real_decode_qzss_l6emsg(rtcm);
    start = _mcssr.ibuff == 0;
    saved = start || (mb > 0 && _mcssr.frame == fb + 1);

    /* assembly in progress dropped by MALIB */
    if (sf.active && start) write_row3("Aborted: next subframe started");
    else if (sf.active && !saved && _mcssr.maxframe == 0) {
        write_row3("Aborted: reset by invalid first message");
    }
    if (!saved) return ret;

    if (start) {
        sf.active = 1;
        sf.svid   = raw.buff[14];
        sf.prn    = (int)getbitu(rtcm->buff, 32, 8); /* L6 PRN */
        sf.fid    = (int)getbitu(rtcm->buff, 43, 2); /* Facility ID */
        sf.week_s = U2(raw.buff + 12);
        sf.tow_s  = U4(raw.buff + 8);
    }
    sf.week_e = U2(raw.buff + 12);
    sf.tow_e  = U4(raw.buff + 8);
    sf.npkt   = _mcssr.frame;
    memcpy(sf.buff, _mcssr.buff, MCSSR_BYTELEN);

    /* maxframe is reset to 0 after the subframe is decoded */
    if (_mcssr.maxframe == 0) {
        replay_subframe();
        write_row3(ret < 0 ? "Complete: decode error" : "Complete");
    }
    return ret;
}

/* time of the first SBF block, as rtksvr passes the stream time to init_mcssr() */
static gtime_t first_time(FILE *fp)
{
    gtime_t t0 = {0};

    prescan = 1;
    init_raw(&raw, STRFMT_SEPT);
    while (input_sbff(&raw, &rtcm, fp) >= -1) {
        if (raw.time.time != 0) { t0 = raw.time; break; }
    }
    free_raw(&raw);
    rewind(fp);
    prescan = 0;
    return t0;
}

int main(int argc, char **argv)
{
    FILE *fp, *ofp1, *ofp2;
    gtime_t t0;
    uint8_t msg[L6_MSG_BYTES];
    char *file = NULL;
    int i, type, n1 = 0, n2 = 0, nng = 0, ncrc = 0, nshort = 0;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') { usage(); return 2; }
        file = argv[i];
    }
    if (!file) { usage(); return 2; }

    if (!(fp = fopen(file, "rb"))) {
        fprintf(stderr, "error: cannot open %s\n", file);
        return 2;
    }
    if (!(ofp1 = fopen(OUTFILE1, "w")) || !(ofp2 = fopen(OUTFILE2, "w")) ||
        !(ofp3 = fopen(OUTFILE3, "w")) || !(ofp4 = fopen(OUTFILE4, "w"))) {
        fprintf(stderr, "error: cannot open output file\n");
        return 2;
    }
    init_rtcm(&rtcm);
    t0 = first_time(fp);
    init_raw(&raw, STRFMT_SEPT);
    init_mcssr(t0); /* input_sbff() also runs the MALIB L6E decoder */

    fprintf(ofp1, "#,SVID,WN,TOW [s],GPST,Source,RxCh,Parity,RSCnt,L6 PRN,"
            "Vendor,MsgType (hex),Alert,NAV Bits (hex)\n");
    fprintf(ofp2, "#,SVID,WN,TOW [s],GPST,Parity,Preamble,PRN,Vendor,Facility,"
            "Corr. Svc,NavMsgExt,Subframe,Alert,"
            "\"Data Part (hex, 1695 bit)\",\"RS Code (hex, 256 bit)\"\n");
    fprintf(ofp3, "#,SVID,L6 PRN,Facility,WN,TOW Start [s],GPST Start,"
            "TOW End [s],GPST End,Packets,Kind,Bit Length,Status,MsgNum,SubType,"
            "Epoch Time,UI / MMI,IOD SSR,Subframe Data (hex)\n");
    fprintf(ofp4, "#,SVID,WN,SF TOW Start [s],SF GPST Start,SF Msg No.,"
            "Bit Offset,Bit Length,MsgNum,SubType,Epoch Time,Epoch GPST,UI,MMI,"
            "IOD SSR,Restored TOW,Restored GPST,Mask (ST1),Status,Payload (hex)\n");

    for (;;) {
        raw.buff[4] = raw.buff[5] = 0; /* mark buff as stale: type 0 */
        if (input_sbff(&raw, &rtcm, fp) < -1) break; /* end of file */

        type = U2(raw.buff + 4) & 0x1FFF;
        if (type != SBF_QZSRAWL6 || raw.len <= 8 || raw.len > MAXRAWLEN) continue;

        /* blocks rejected by decode_sbf()/decode_qzsrawl6() are not dumped */
        if (rtk_crc16(raw.buff + 4, raw.len - 4) != U2(raw.buff + 2)) { ncrc++; continue; }
        if (raw.len < L6_MIN_LEN) { nshort++; continue; }

        navbits2msg(raw.buff + 20, msg);
        write_row1(ofp1, ++n1, raw.buff, msg);
        if (raw.buff[17] == SRC_L6E) write_row2(ofp2, ++n2, raw.buff, msg);
        if (!raw.buff[15]) nng++;
    }
    if (sf.active) write_row3("Truncated: end of data");
    fclose(fp);
    fclose(ofp1);
    fclose(ofp2);
    fclose(ofp3);
    fclose(ofp4);

    fprintf(stderr, "file          : %s\n", file);
    fprintf(stderr, "output        : %s (%d rows), %s (%d rows)\n",
            OUTFILE1, n1, OUTFILE2, n2);
    fprintf(stderr, "                %s (%d rows), %s (%d rows)\n",
            OUTFILE3, n3, OUTFILE4, n4);
    if (nmis > 0) {
        fprintf(stderr, "warning       : %d subframes: replay differs from MALIB run\n", nmis);
    }
    fprintf(stderr, "QZSRawL6      : %d packets (L6E: %d, Parity NG: %d)\n", n1, n2, nng);
    fprintf(stderr, "skipped       : CRC error %d, short block %d\n", ncrc, nshort);

    free_raw(&raw);
    free_rtcm(&rtcm);
    return n1 > 0 ? 0 : 1;
}
