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
*   sbfMALIB_05.log : "QZSRawL6 -> MADOCA-PPP-3" every ST1, as decoded by
*                     decode_mcssr_mask() (text)
*
* mdccssr.c is included here to read its assembly state (_mcssr), and
* decode_qzss_l6emsg() is wrapped by the linker (-Wl,--wrap) to observe each
* call from septentrio.c. For sbfMALIB_04.csv, every complete subframe is
* replayed with the message loop of decode_qzss_l6emsg() and the MALIB
* decode_mcssr_*() on a copy of _mcssr (apply=0), and checked against the
* real run. trace() is also wrapped to catch the MALIB error messages and
* the GNSS blocks of ST1 traced by decode_mcssr_mask().
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
#define OUTFILE5       "sbfMALIB_05.log" /* every ST1 decoded by MALIB */

typedef struct {                    /* subframe being assembled by MALIB */
    int active;                     /* 1: assembly in progress */
    int svid, prn, fid;             /* SBF SVID, L6 PRN, Facility ID */
    int week_s, week_e;             /* week of the first/last packet */
    uint32_t tow_s, tow_e;          /* TOW (ms) of the first/last packet */
    int npkt;                       /* number of packets (_mcssr.frame) */
    uint8_t buff[MCSSR_BYTELEN];    /* copy of _mcssr.buff */
} sfrm_t;

typedef struct {                    /* GNSS block of ST1, as decoded by MALIB */
    int gnssid, nsat, nsig, cmaflg; /* GNSS ID, Nsat, Nsig, Cell-mask flag */
    uint32_t svhi, svlo;            /* satellite mask (upper 8 / lower 32 bits) */
    unsigned int sigmask;           /* signal mask */
    int cellmask[MCSSR_MAX_SATMASK];/* cell mask per satellite */
    int cells;                      /* number of cells (cell mask bits set) */
} st1blk_t;

typedef struct {                    /* ST1 message, as decoded by MALIB */
    int svid, week;                 /* SBF SVID, week of the subframe */
    uint32_t tow_s;                 /* TOW (ms) of the first packet of the subframe */
    unsigned int ep, udi, mmi, iod, nsys; /* header fields, No. of GNSS */
    int nblk;                       /* number of GNSS blocks traced by MALIB */
    st1blk_t blk[MCSSR_MAX_SYS];
    int rlen[8];                    /* bits read by MALIB per sub type (-1: none) */
    char status[192];               /* MALIB result, as in sbfMALIB_04.csv */
} st1_t;

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
static st1_t *st1s;               /* every ST1, in the order of decoding */
static int    nst1, nst1max;
static int    cur_st1 = -1;       /* ST1 of the mask in use (index of st1s) */
static st1_t *cap_st1;            /* ST1 being decoded: collect GNSS blocks */

/* little-endian readers, same as septentrio.c */
static uint16_t U2(const uint8_t *p) {uint16_t a; memcpy(&a,p,2); return a;}
static uint32_t U4(const uint8_t *p) {uint32_t a; memcpy(&a,p,4); return a;}

static void usage(void)
{
    fprintf(stderr, "usage: sbfMALIB file.sbf\n"
                    "  writes %s, %s, %s, %s and %s\n"
                    "  to the current directory\n",
                    OUTFILE1, OUTFILE2, OUTFILE3, OUTFILE4, OUTFILE5);
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
    st1blk_t *b;
    char *p;

    /* GNSS block of ST1: same arguments as the trace(4) in decode_mcssr_mask() */
    if (cap_st1 && !strncmp(format, "decode_mcssr_mask: gnssid=", 26)) {
        if (cap_st1->nblk >= MCSSR_MAX_SYS) return;
        b = cap_st1->blk + cap_st1->nblk++;
        va_start(ap, format);
        b->gnssid  = va_arg(ap, int);
        b->svhi    = (uint32_t)va_arg(ap, int); /* (uint8_t)(svmask>>32) */
        b->svlo    = va_arg(ap, unsigned int);
        b->sigmask = (unsigned int)va_arg(ap, int); /* uint16_t */
        b->cmaflg  = va_arg(ap, int);
        b->nsat    = va_arg(ap, int);
        b->nsig    = va_arg(ap, int);
        va_end(ap);
        return;
    }
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

/* seconds of week to "TOW s (Day hh:mm:ss)", Day is "?" beyond a week */
static void towday2str(unsigned int tow, char *str)
{
    static const char *wday[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    unsigned int s = tow % 86400;

    sprintf(str, "%u s (%s %02u:%02u:%02u)", tow, tow / 86400 < 7 ?
            wday[tow / 86400] : "?", s / 3600, s % 3600 / 60, s % 60);
}

/* GPS time to "TOW s (Day hh:mm:ss)" */
static void tow2str(gtime_t t, char *str)
{
    int week;

    towday2str((unsigned int)(time2gpst(t, &week) + 0.5), str);
}

/* status column: MALIB result, rescanned bits before the message, padding */
static void status2str(int end, int skip, const char *pad, char *str)
{
    char *p = str;

    if (skip > 0) p += sprintf(p, "Found after skipping %d bit; ", skip);
    if (end >= 0) p += sprintf(p, "OK");
    else p += sprintf(p, "Decode error: %.120s", errmsg[0] ? errmsg : "-");
    sprintf(p, "%s", pad);
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
    char prn[16], gs[64], es[64], rt[64], rg[64], buf[32], stat[256];
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

    status2str(end, skip, pad, stat);
    fprintf(ofp4, "%s,", stat);

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

/* new ST1 record for the message at bit pos of the replayed subframe */
static st1_t *new_st1(int pos)
{
    st1_t *s;
    int k;

    if (nst1 >= nst1max) {
        nst1max = nst1max ? nst1max * 2 : 256;
        if (!(st1s = (st1_t *)realloc(st1s, sizeof(st1_t) * nst1max))) {
            fprintf(stderr, "error: out of memory\n");
            exit(2);
        }
    }
    s = st1s + nst1++;
    memset(s, 0, sizeof(st1_t));
    s->svid  = sf.svid;
    s->week  = sf.week_s;
    s->tow_s = sf.tow_s;
    s->ep    = getbitu(rep.buff, pos + 16, 20);
    s->udi   = getbitu(rep.buff, pos + 36, 4);
    s->mmi   = getbitu(rep.buff, pos + 40, 1);
    s->iod   = getbitu(rep.buff, pos + 41, 4);
    s->nsys  = getbitu(rep.buff, pos + 45, 4);
    for (k = 0; k < 8; k++) s->rlen[k] = -1;
    return s;
}

/* complete an ST1 record with the cell masks left in the replayed _mcssr */
static void finish_st1(st1_t *s, int pos, int end, int skip, const char *pad)
{
    int j, k, off = 0;

    if (end >= 0) s->rlen[MCSSR_ST_MASK] = end - pos;
    for (j = 0; j < s->nblk; j++) {
        for (k = 0; k < s->blk[j].nsat && off + k < MAXSAT; k++) {
            if (k < MCSSR_MAX_SATMASK) s->blk[j].cellmask[k] = rep.cellmask[off + k];
            s->blk[j].cells += rep.ncell[off + k];
        }
        off += s->blk[j].nsat;
    }
    status2str(end, skip, pad, s->status);
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
        if (pad && st == MCSSR_ST_MASK) cap_st1 = new_st1(pos);
        switch (st) {
            case MCSSR_ST_MASK: i = decode_mcssr_mask(&rep, i); break;
            case MCSSR_ST_OC  : i = decode_mcssr_oc (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_CC  : i = decode_mcssr_cc (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_CB  : i = decode_mcssr_cb (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_PB  : i = decode_mcssr_pb (&rep, dummy_ssr, i, 0); break;
            case MCSSR_ST_URA : i = decode_mcssr_ura(&rep, dummy_ssr, i, 0); break;
        }
        no++;
        if (cap_st1) { /* ST1: record it, the following messages use its mask */
            finish_st1(cap_st1, pos, i, skip, no == *lastend ? pad : "");
            cur_st1 = (int)(cap_st1 - st1s);
            cap_st1 = NULL;
        }
        else if (pad && cur_st1 >= 0 && i >= 0 && st1s[cur_st1].rlen[st] < 0) {
            st1s[cur_st1].rlen[st] = i - pos; /* first message with this mask */
        }
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

/* satellite name prefix of the Compact SSR GNSS ID */
static const char *sat_prefix(int id)
{
    switch (id) {
        case 0: return "G";
        case 1: return "R";
        case 2: return "E";
        case 3: case 7: return "C";
        case 4: return "J";
    }
    return "?";
}

/* satellite ID (1-40) is set in the satellite mask */
static int blk_has_sat(const st1blk_t *b, int id)
{
    int n = MCSSR_MAX_SATMASK - id;

    return n >= 32 ? (b->svhi >> (n - 32)) & 1 : (b->svlo >> n) & 1;
}

/* index of satellite ID in the block (-1: not set) */
static int blk_sat_index(const st1blk_t *b, int id)
{
    int i, k = 0;

    for (i = 1; i <= MCSSR_MAX_SATMASK; i++) {
        if (!blk_has_sat(b, i)) continue;
        if (i == id) return k;
        k++;
    }
    return -1;
}

/* GNSS block of the given GNSS ID */
static const st1blk_t *find_blk(const st1_t *s, int gnssid)
{
    int j;

    for (j = 0; j < s->nblk; j++) if (s->blk[j].gnssid == gnssid) return s->blk + j;
    return NULL;
}

/* message length of a sub type derived from the ST1 mask (Table 4.2.2-1) */
static int st1_bits(const st1_t *s, int st)
{
    int j, n = 0, nsat = 0, cells = 0;

    for (j = 0; j < s->nblk; j++) {
        nsat  += s->blk[j].nsat;
        cells += s->blk[j].cells;
        if (st == 1) n += 61 + (s->blk[j].cmaflg ? s->blk[j].nsat * s->blk[j].nsig : 0);
        if (st == 2) n += (s->blk[j].gnssid == MCSSR_SYS_GAL ? 51 : 49) * s->blk[j].nsat;
    }
    switch (st) {
        case 1: return 49 + n;
        case 2: return 37 + n;
        case 3: return 37 + 15 * nsat;
        case 4: return 37 + 11 * cells;
        case 5: return 37 + 17 * cells;
        case 7: return 37 + 6 * nsat;
    }
    return -1;
}

/* total number of satellites of an ST1 */
static int st1_nsat(const st1_t *s)
{
    int j, n = 0;

    for (j = 0; j < s->nblk; j++) n += s->blk[j].nsat;
    return n;
}

/* differences of an ST1 mask from the previous ST1 of the same satellite */
static void mask_changes(const st1_t *p, const st1_t *c, char *out)
{
    const st1blk_t *pb, *cb;
    const char *name;
    char *q = out, nbuf[32], b1[20], b2[20];
    int j, id, n, pk;

    *q = '\0';
    if (p->iod != c->iod) q += sprintf(q, " / IOD SSR %u->%u", p->iod, c->iod);
    for (j = 0; j < c->nblk; j++) {
        cb = c->blk + j;
        name = gnss_name(cb->gnssid, nbuf);
        if (!(pb = find_blk(p, cb->gnssid))) { q += sprintf(q, " / %s added", name); continue; }
        for (n = 0, id = 1; id <= MCSSR_MAX_SATMASK; id++) {
            if (blk_has_sat(cb, id) == blk_has_sat(pb, id)) continue;
            if (n++ == 0) q += sprintf(q, " / %s:", name);
            q += sprintf(q, " %c%s%02d", blk_has_sat(cb, id) ? '+' : '-',
                         sat_prefix(cb->gnssid), id);
        }
        if (pb->sigmask != cb->sigmask) {
            bin2str(pb->sigmask, 16, b1);
            bin2str(cb->sigmask, 16, b2);
            q += sprintf(q, " / %s: Signal mask %s->%s", name, b1, b2);
        }
        if (pb->cmaflg != cb->cmaflg) {
            q += sprintf(q, " / %s: Cell-mask Flag %d->%d", name, pb->cmaflg, cb->cmaflg);
        }
        if (pb->sigmask != cb->sigmask) continue;
        for (n = 0, id = 1; id <= MCSSR_MAX_SATMASK; id++) {
            if (!blk_has_sat(cb, id) || (pk = blk_sat_index(pb, id)) < 0) continue;
            if (pk >= MCSSR_MAX_SATMASK) continue;
            if (pb->cellmask[pk] == cb->cellmask[blk_sat_index(cb, id)]) continue;
            if (n++ == 0) q += sprintf(q, " / %s: Cell mask changed", name);
            q += sprintf(q, " %s%02d", sat_prefix(cb->gnssid), id);
        }
    }
    for (j = 0; j < p->nblk; j++) {
        if (find_blk(c, p->blk[j].gnssid)) continue;
        q += sprintf(q, " / %s removed", gnss_name(p->blk[j].gnssid, nbuf));
    }
    if (out[0]) memmove(out, out + 3, strlen(out + 3) + 1); /* drop leading " / " */
}

/* "GPS 26 / GLONASS 13 / ..." */
static void nsat_per_gnss(const st1_t *s, char *str)
{
    char buf[32];
    int j;

    *str = '\0';
    for (j = 0; j < s->nblk; j++) {
        str += sprintf(str, "%s%s %d", j ? " / " : "", gnss_name(s->blk[j].gnssid, buf),
                       s->blk[j].nsat);
    }
}

/* changes column of the overview, prev[] tracks the last ST1 per SVID */
static void change_str(int n, const int *prev, char *str)
{
    const st1_t *s = st1s + n;
    char *p = str;

    *p = '\0';
    if (strcmp(s->status, "OK")) p += sprintf(p, "[%s] ", s->status);
    if (prev[s->svid] < 0) sprintf(p, "(first ST1 of this satellite)");
    else {
        mask_changes(st1s + prev[s->svid], s, p);
        if (!*p) sprintf(p, "No change");
    }
}

/* sbfMALIB_05.log: overview of every ST1 and the details of each */
static void write_log5(FILE *fp)
{
    static const int sts[] = {1, 2, 3, 4, 5, 7};
    static const char *formula[] = {
        "49 + sum(61 + Ncell)", "37 + sum(49 or 51 (Galileo) x Nsat)",
        "37 + 15 x Nsat", "37 + 11 x sum(signals x sats)",
        "37 + 17 x sum(signals x sats)", "37 + 6 x Nsat"
    };
    const st1_t *s;
    const st1blk_t *b;
    char prn[16], ts[64], gs[64], ns[512], ch[4096], buf[32], bin[20];
    int prev[256], i, j, k, id, w = 13, nchg = 0, nerr = 0, nskip = 0, d;

    for (i = 0; i < 256; i++) prev[i] = -1;
    for (i = 0; i < nst1; i++) {
        change_str(i, prev, ch);
        if (prev[st1s[i].svid] >= 0 && strcmp(ch, "No change")) nchg++;
        if (strstr(st1s[i].status, "Decode error")) nerr++;
        if (strstr(st1s[i].status, "Found after skipping")) nskip++;
        prev[st1s[i].svid] = i;
        nsat_per_gnss(st1s + i, ns);
        if ((int)strlen(ns) > w) w = (int)strlen(ns);
    }
    fprintf(fp, "MADOCA-PPP-3 overview (every ST1 in the file, decoded by MALIB)\n\n");
    fprintf(fp, "Number of ST1                    : %d\n", nst1);
    fprintf(fp, "Mask changed from previous ST1   : %d\n", nchg);
    fprintf(fp, "ST1 with decode error            : %d\n", nerr);
    fprintf(fp, "ST1 found after skipping bits    : %d\n\n", nskip);

    fprintf(fp, "%4s  %-4s  %16s  %-24s  %3s  %4s  %-*s  %5s  %-35s  %s\n", "#",
            "SVID", "SF TOW Start [s]", "GPS Epoch Time", "IOD", "Nsys", w,
            "Nsat per GNSS", "Total", "Derived length [bit]: ST1-5, ST7",
            "Changes from previous ST1");
    for (i = 0; i < 256; i++) prev[i] = -1;
    for (i = 0; i < nst1; i++) {
        s = st1s + i;
        svid2str(s->svid, prn);
        towday2str(s->ep, ts);
        nsat_per_gnss(s, ns);
        change_str(i, prev, ch);
        prev[s->svid] = i;
        fprintf(fp, "%4d  %-4s  %16.3f  %-24s  %3u  %4u  %-*s  %5d  ", i + 1, prn,
                s->tow_s * 0.001, ts, s->iod, s->nsys, w, ns, st1_nsat(s));
        for (j = 0; j < 6; j++) fprintf(fp, "%5d%s", st1_bits(s, sts[j]), j < 5 ? " " : "");
        fprintf(fp, "  %s\n", ch);
    }

    for (i = 0; i < 256; i++) prev[i] = -1;
    for (i = 0; i < nst1; i++) {
        s = st1s + i;
        svid2str(s->svid, prn);
        change_str(i, prev, ch);
        prev[s->svid] = i;
        time2str(gpst2time(s->week, s->tow_s * 0.001), gs, 3);
        towday2str(s->ep, ts);

        fprintf(fp, "\n==== ST1 #%d - %s / SF TOW %.3f s (%s) / IOD SSR %u ====\n",
                i + 1, prn, s->tow_s * 0.001, gs, s->iod);
        fprintf(fp, "Status (MALIB)             : %s\n", s->status);
        fprintf(fp, "Changes from previous ST1  : %s\n", ch);
        fprintf(fp, "Message Number             : %d\n", RTCM_MN_CSSR);
        fprintf(fp, "Message Sub Type ID        : %d\n", MCSSR_ST_MASK);
        fprintf(fp, "GPS Epoch Time 1s          : %s\n", ts);
        fprintf(fp, "SSR Update Interval        : %u\n", s->udi);
        fprintf(fp, "Multiple Message Indicator : %u\n", s->mmi);
        fprintf(fp, "IOD SSR                    : %u\n", s->iod);
        fprintf(fp, "No. of GNSS (Nsys)         : %u\n", s->nsys);
        fprintf(fp, "Total sats (Nsat)          : %d\n", st1_nsat(s));
        if (s->rlen[1] >= 0) fprintf(fp, "Message length             : %d bit (read by MALIB)\n", s->rlen[1]);
        else fprintf(fp, "Message length             : - (decode error)\n");

        fprintf(fp, "\n  %-16s  %-20s  %4s  %-23s  %4s  %14s  %5s  %18s\n", "GNSS ID",
                "Satellite mask (hex)", "Nsat", "Signal mask (hex / bin)", "Nsig",
                "Cell-mask Flag", "Ncell", "Block length [bit]");
        for (j = 0; j < s->nblk; j++) {
            b = s->blk + j;
            bin2str(b->sigmask, 16, bin);
            sprintf(ns, "%d %s", b->gnssid, gnss_name(b->gnssid, buf));
            k = b->cmaflg ? b->nsat * b->nsig : 0;
            fprintf(fp, "  %-16s  %02X%08X            %4d  %04X / %s  %4d  %14d  %5d  %18d\n",
                    ns, (unsigned int)b->svhi, (unsigned int)b->svlo, b->nsat,
                    b->sigmask, bin, b->nsig, b->cmaflg, k, 61 + k);
            fprintf(fp, "    Satellites :");
            for (id = 1; id <= MCSSR_MAX_SATMASK; id++) {
                if (blk_has_sat(b, id)) fprintf(fp, " %s%02d", sat_prefix(b->gnssid), id);
            }
            fprintf(fp, "\n    Cell mask  :");
            if (!b->cmaflg) fprintf(fp, " (none: all sats x all signals)");
            else {
                for (k = 0, id = 1; id <= MCSSR_MAX_SATMASK; id++) {
                    if (!blk_has_sat(b, id) || k >= MCSSR_MAX_SATMASK) continue;
                    bin2str((unsigned int)b->cellmask[k++], b->nsig, bin);
                    fprintf(fp, " %s%02d:%s", sat_prefix(b->gnssid), id, bin);
                }
            }
            fprintf(fp, "\n");
        }

        fprintf(fp, "\n  Message lengths derived from this ST1, and read by MALIB with this mask\n");
        fprintf(fp, "  %-8s  %-10s  %-36s  %12s  %16s\n", "Sub Type", "Message",
                "Formula", "Length [bit]", "MALIB read [bit]");
        for (j = 0; j < 6; j++) {
            d = st1_bits(s, sts[j]);
            fprintf(fp, "  ST%-6d  %-10s  %-36s  %12d  ", sts[j], st_name(sts[j]),
                    formula[j], d);
            if (s->rlen[sts[j]] < 0) fprintf(fp, "%16s\n", "-");
            else fprintf(fp, "%16d%s\n", s->rlen[sts[j]],
                         s->rlen[sts[j]] != d ? "  <- differs" : "");
        }
    }
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
    FILE *fp, *ofp1, *ofp2, *ofp5;
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
        !(ofp3 = fopen(OUTFILE3, "w")) || !(ofp4 = fopen(OUTFILE4, "w")) ||
        !(ofp5 = fopen(OUTFILE5, "w"))) {
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
    write_log5(ofp5);
    fclose(ofp5);
    free(st1s);

    fprintf(stderr, "file          : %s\n", file);
    fprintf(stderr, "output        : %s (%d rows), %s (%d rows)\n",
            OUTFILE1, n1, OUTFILE2, n2);
    fprintf(stderr, "                %s (%d rows), %s (%d rows)\n",
            OUTFILE3, n3, OUTFILE4, n4);
    fprintf(stderr, "                %s (%d ST1)\n", OUTFILE5, nst1);
    if (nmis > 0) {
        fprintf(stderr, "warning       : %d subframes: replay differs from MALIB run\n", nmis);
    }
    fprintf(stderr, "QZSRawL6      : %d packets (L6E: %d, Parity NG: %d)\n", n1, n2, nng);
    fprintf(stderr, "skipped       : CRC error %d, short block %d\n", ncrc, nshort);

    free_raw(&raw);
    free_rtcm(&rtcm);
    return n1 > 0 ? 0 : 1;
}
