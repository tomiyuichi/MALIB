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
*
* mdccssr.c is included here to read its assembly state (_mcssr), and
* decode_qzss_l6emsg() is wrapped by the linker (-Wl,--wrap) to observe each
* call from septentrio.c. The MALIB sources are not modified.
*
* usage  : sbfMALIB file.sbf
* return : 0: ok, 1: no QZSRawL6 block found, 2: usage/file error
*-----------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
static FILE  *ofp3;
static int    n3;   /* rows in sbfMALIB_03.csv */

/* little-endian readers, same as septentrio.c */
static uint16_t U2(const uint8_t *p) {uint16_t a; memcpy(&a,p,2); return a;}
static uint32_t U4(const uint8_t *p) {uint32_t a; memcpy(&a,p,4); return a;}

static void usage(void)
{
    fprintf(stderr, "usage: sbfMALIB file.sbf\n"
                    "  writes %s, %s and %s to the current directory\n",
                    OUTFILE1, OUTFILE2, OUTFILE3);
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

/* linker wrap of decode_qzss_l6emsg(): track the subframe assembly of MALIB */
extern int __real_decode_qzss_l6emsg(rtcm_t *rtcm);

int __wrap_decode_qzss_l6emsg(rtcm_t *rtcm)
{
    int mb = _mcssr.maxframe, fb = _mcssr.frame, ret, start, saved;

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
        write_row3(ret < 0 ? "Complete: decode error" : "Complete");
    }
    return ret;
}

int main(int argc, char **argv)
{
    FILE *fp, *ofp1, *ofp2;
    gtime_t t0 = {0};
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
        !(ofp3 = fopen(OUTFILE3, "w"))) {
        fprintf(stderr, "error: cannot open output file\n");
        return 2;
    }
    init_raw(&raw, STRFMT_SEPT);
    init_rtcm(&rtcm);
    init_mcssr(t0); /* input_sbff() also runs the MALIB L6E decoder */

    fprintf(ofp1, "#,SVID,WN,TOW [s],GPST,Source,RxCh,Parity,RSCnt,L6 PRN,"
            "Vendor,MsgType (hex),Alert,NAV Bits (hex)\n");
    fprintf(ofp2, "#,SVID,WN,TOW [s],GPST,Parity,Preamble,PRN,Vendor,Facility,"
            "Corr. Svc,NavMsgExt,Subframe,Alert,"
            "\"Data Part (hex, 1695 bit)\",\"RS Code (hex, 256 bit)\"\n");
    fprintf(ofp3, "#,SVID,L6 PRN,Facility,WN,TOW Start [s],GPST Start,"
            "TOW End [s],GPST End,Packets,Kind,Bit Length,Status,MsgNum,SubType,"
            "Epoch Time,UI / MMI,IOD SSR,Subframe Data (hex)\n");

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

    fprintf(stderr, "file          : %s\n", file);
    fprintf(stderr, "output        : %s (%d rows), %s (%d rows)\n",
            OUTFILE1, n1, OUTFILE2, n2);
    fprintf(stderr, "                %s (%d rows)\n", OUTFILE3, n3);
    fprintf(stderr, "QZSRawL6      : %d packets (L6E: %d, Parity NG: %d)\n", n1, n2, nng);
    fprintf(stderr, "skipped       : CRC error %d, short block %d\n", ncrc, nshort);

    free_raw(&raw);
    free_rtcm(&rtcm);
    return n1 > 0 ? 0 : 1;
}
