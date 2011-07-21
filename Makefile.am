#$Id: Makefile.am 246 2008-09-04 20:32:13Z gregor $

#bin_PROGRAMS = tm broSendPkts tm_q querybm
bin_PROGRAMS = tm $(BROCCOLI_PROGS)
EXTRA_PROGRAMS = broSendPkts querybm

EXTRA_DIST = Documentation/* tm-query/* ptmalloc2/* tm.conf autogen.sh

# DO NOT USE TABS AS INDENTATION!! F**KING AUTOMAKE WILL MAKE F**KING STUPID
# THINGS AND WILL NOT EVEN WARN. SPACES SEEM OK THOUGH.
# AAAARRRRGGGGHHHH !!!!!
if USE_PTMALLOC
 noinst_LIBRARIES = libptmalloc_tm.a
 libptmalloc_tm_a_SOURCES = ptmalloc2/malloc.c ptmalloc2/malloc-stats.c 
 libptmalloc_tm_a_CFLAGS = -DUSE_TSD_DATA_HACK -D_REENTRANT -Iptmalloc2/sysdeps/pthread -Iptmalloc2/sysdeps/generic -Iptmalloc2 #-DTHREAD_STATS=1
 tm_LDADD = libptmalloc_tm.a @LIBREADLINE@
else
 tm_LDADD = @LIBREADLINE@
endif

tm_SOURCES = main.cc Connection.cc Connections.cc Fifo.cc FifoDisk.cc FifoMem.cc Hash.cc IndexField.cc LogFile.cc Query.cc Queue.cc Storage.cc conf_scanner.ll conf_parser.yy cmd_scanner.ll cmd_parser.yy rmtconsole.cc IndexHash.cc DynClass.cc BroccoliComm.cc
#tm_LDFLAGS = -lpthread -lpcre -lpcrecpp


# the .cc files here only contain templated code
noinst_HEADERS= BroccoliComm.hh conf.h Connection.hh Connections.hh DiskIndex.hh DynClass.hh FifoDisk.hh Fifo.hh FifoMem.hh Hash.hh IndexEntry.hh IndexField.hh IndexHash.hh Index.hh jhash3.h LogFile.hh packet_headers.h Query.hh Queue.hh Storage.hh tm.h types.h util.h ptmalloc2/malloc.h Index.cc Queue.cc DiskIndex.cc ptmalloc2/sysdeps/pthread/malloc-machine.h ptmalloc2/sysdeps/pthread/thread-st.h ptmalloc2/sysdeps/generic/malloc-machine.h ptmalloc2/sysdeps/generic/thread-st.h ptmalloc2/sysdeps/generic/atomic.h 


broSendPkts_SOURCES = broSendPkts.cc
broSendPkts_LIBS = pcap broccoli

querybm_SOURCES = querybm.cc
querybm_LIBS = -lbroccoli -lpcap

#tm_q_SOURCES = tm_q.cc IndexField.cc Connection.cc
#tm_q_LIBS = []

AM_YFLAGS=-d
BUILT_SOURCES=conf_parser.h cmd_parser.h



clean-local: 
	rm -f cmd_scanner.cc cmd_parser.cc cmd_parser.h conf_scanner.cc conf_paser.cc conf_parser.h
#tm_LIBADD = @YYLIB@

#EXTRA_tm_SOURCES = conf_parser.cc
