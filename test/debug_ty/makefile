# makefile for MALIB debug tools
#
#   make clean all
#   ./sbfMALIB file.sbf    (writes ./sbfMALIB_01.csv - 04.csv, ./sbfMALIB_05.log)
#
# The MALIB sources in ../../src are built as is. sbfMALIB.c includes
# mdccssr.c itself and wraps decode_qzss_l6emsg() and trace() with the GNU
# linker.
# Options follow app/consapp/rtkrcv/gcc/makefile.

SRC    = ../../src

OPTS   = -DTRACE -DENAGLO -DENAGAL -DENAQZS -DENACMP -DENAIRN -DNFREQ=5 -DNEXOBS=5
CFLAGS = -Wall -O2 -ansi -pedantic -Wno-unused-but-set-variable -Wno-unused-result -I$(SRC) $(OPTS) -g
LDLIBS = -lm -lrt -lpthread

PROGS  = sbfMALIB

# MALIB sources needed by the SBF reader and the L6E decoder
MALIB_SRCS = $(SRC)/rtkcmn.c $(SRC)/rcvraw.c $(SRC)/rtcm.c $(SRC)/rtcm2.c \
             $(SRC)/rtcm3.c $(SRC)/rtcm3e.c $(SRC)/rtcm3lcl.c $(SRC)/lclcmn.c \
             $(SRC)/ephemeris.c $(SRC)/sbas.c $(SRC)/preceph.c \
             $(SRC)/stream.c $(SRC)/solution.c $(SRC)/geoid.c \
             $(SRC)/rcv/binex.c $(SRC)/rcv/crescent.c $(SRC)/rcv/javad.c \
             $(SRC)/rcv/novatel.c $(SRC)/rcv/nvs.c $(SRC)/rcv/rt17.c \
             $(SRC)/rcv/septentrio.c $(SRC)/rcv/skytraq.c $(SRC)/rcv/ss2.c \
             $(SRC)/rcv/ublox.c

all: $(PROGS)

sbfMALIB: sbfMALIB.c $(SRC)/mdccssr.c $(MALIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(MALIB_SRCS) -Wl,--wrap=decode_qzss_l6emsg,--wrap=trace $(LDLIBS)

clean:
	rm -f $(PROGS) *.o *.trace

.PHONY: all clean
