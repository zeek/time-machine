======================
Installing TimeMachine
======================

Prerequisites
=============

TimeMachine requires the following libraries and tools to be 
installed before you begin:

    * Libpcap                           http://www.tcpdump.org

TimeMachine can make use of some optional libraries and tools if they 
are found at build time:

    * libbroccoli (for working in conjunction with Bro)  http://www.bro-ids.org

Installing From Source
======================

::

    ./configure
    make
    make install

If you have Bro installed in it's default <prefix> of
/usr/local/bro, then this configure command will build
timemachine with Bro support.

    ./configure --with-broccoli=/usr/local/bro
