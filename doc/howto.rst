
=================
Using TimeMachine
=================

TimeMachine is typically run as a single binary along with a configuration
file.  This document explains how to understand the configuration file
to make TimeMachine work like you want it to and begins to explain some
of the fundamentals of working with TimeMachine at runtime.

.. contents::

Configuration File
==================

The Time Machine is customized by a configuration file which contains
a number of user configuration options.  This includes general options
such as logfile names, capture device settings as well as the
configuration of storage classes with the respective parameters.

By default, the configuration file is called 'timemachine.cfg' and is read
from the config file installation directory.  This can be overridden by 
the -c command line option (see `Command Line Options`_ section below).

The configuration file is structured in sections.  Options for a
section are grouped by curly brackets and are separated by semicolons.
There is exactly one main section, and a number of class configuration
sections.  For better orientation, see the example timemachine.cfg file 
in the timemachine package.

Main section options
********************

  device "<devname>"
    Directs the Time Machine to start capturing packets from the specified
    device.

  read_tracefile "<filename>"
    Instead of fetching packets from a capture interface, the Time Machine
    can also read a trace file in libpcap format and act like these packets
    come from the network.  The packets from the file are read in as fast as
    they can be processed.

  filter "<tcpdump filter string>"
    Applies a global filter to the packets to be captured.  This filter is
    evaluated before any classification takes place.  It is specified in
    tcpdump(1) format.

  console 0|1
    Determine whether a command line interface should be displayed on the
    controlling terminal of the tm process.  This CLI can be used to issue
    timemachine commands (see below).

  daemon 0|1
    Run the timemachine as a daemon in background mode. Incompatible with
    console. 

  workdir "<path>"
    Determine the working directory where all class storage files and index
    files should be kept.  This directory must exist upon timemachine startup.

  classdir_format "<path_with_formatting_directives>"
    Optionally specify default directory where class storage files should be kept.
    This directory will be created if it doesn't already exist.

    If ``{class_name}`` appears in the format, it expands to ``class_classid`` for the
    classid specified for the class.

    If ``{class_id}`` appears in the format, it expands to ``classid`` for the
    classid specified for the class.

    If ``{newest_timestamp:XXX}`` appears in the format, the time formatting directive
    ``XXX`` is expanded using the timestamp of the earliest packet written to the file
    using strftime formatting interpretation ( http://fmtlib.net/latest/api.html#time-api )

  filename_format "<name_with_formatting_directives>"
    Optionally specify filename pattern where a class storage file will be written.
    This file naming pattern should have enough time resolution so that newly
    created files don't overwrite old ones.  E.g. it could have a seconds level resolution.
    
    The ``{class_name}`` ``{class_id}`` and ``{newest_timestamp}`` directives can be used.

  indexdir "<path>"
    Path, absolute or relative to 'workdir' (see above), where the 
    disk indexes will reside. This directory must exist upon timemachine startup.
    It is a performance gain to place the index database files on different
    disk than the class storage files.

  logfile "<filename>"
    Direct log output to the named file. It will be placed in workdir.

  log_interval <number>
    Specify the frequency of statistical output to the logfile (log interval
    in seconds).

  log_level <number>
    Specify the level at which to log.  10=DEBUG, 20=NOTE(default), 30=WARN, 40=ERROR

  conn_timeout <number>
    Determine the inactivity timeout in seconds for connections before they
    are deleted from the timemachine's connection table.

  max_subscriptions <number>
    Maximum number of subscriptions to allow.  0 for no limit.

  queryfiledir "<path>"
    Path, absolute or relative to 'workdir' (see above), where query result
    files will be created.  This directory must exist upon timemachine startup.

  rmtconsole 0|1
    Start a remote console listener. This will listen on a network socket
    for incomming connections. When connected a remote user can issue 
    timemachine commands as could be done from the local console, i.e. use
    telnet to connect. 
    Please note, that this connection is not authenticated and not 
    encrypted. Use with care.

  rmtconsole_port <number>
    The local port to listen for incoming remote console connections.
    Default is 42042.
    
  rmtconsole_listen_addr <ip address>
    The IP address to listen for incoming remote console connections.
    Default is 127.0.0.1. Hostnames cannot be used. A value of 0.0.0.0 will
    listen on all interfaces.

  bro_listen 0|1 
    Start a Bro listener. This will listen on a network socket for
    incoming connections from a remote Bro or a Broccoli client. See
    the tm-query sub-directory for an example client which uses this
    interface to issue queries to the timemachine from the command line.
    
  bro_listen_port <number>
    The local port to listen for incoming Bro connections.
    Default is 47757.
    
  bro_listen_addr <ip address>
    The IP address to listen for incoming Bro connections. Default
    is 127.0.0.1. Hostnames cannot be used. A value of 0.0.0.0 will
    listen on all interfaces.

  index "<index_name>" [disk]
    Enable the index named <index_name>. Currently supported indexes are
    "connection4", "connection3", "connection2", and "ip". You need to
    enable an index in order to use it for queries. The keyword disk enables
    the disk index for this index. Only indexes with an enabled disk index
    can perform on disk queries. 
    Disabling indexes can safe significant CPU time and disabling disk indexes
    can reduce disk usage. 


Class section
*************

A class section in the configuration file is started by::

  class "<classid>"

and followed by a set of options grouped by curly braces, individually
separated by semicolons.  <number> generally can be expressed by suffixes
'K' or 'k', 'M' or 'm' and 'G' or 'g' for Kilo, Mega and Giga,
respectively.

The following values are available for configuration::

  filter "<tcpdump filter string>"
    Define the filter that is used to determine the packets that
    go to this class.  Exactly as the main section filter, this is in 
    tcpdump filter string format.

  precedence <number>
    Whenever a packet matches two or more classes with the same filter
    string (see above), the highest class precedence number determines
    which class the packet goes to.

  cutoff <number>|no
    For this class, stop recording when more than <number> bytes have been
    transmitted by any single connection.  The keyword 'no' disables cutoff
    for this class.

  disk <number>
    Allocate disk storage of <number> bytes for this class.  Files for this
    storage are kept in 'workdir' (see above).

  filesize <number>
    Any of the files that make up the disk storage is <number> bytes in
    size.

  mem <number>
    Allocate RAM storage of <number> bytes in size.

  pkts_to_disk 2
    The moment packets are to be evicted from the RAM buffers to disk,
    this number determines how many packets to move at a single step.

  dyn_timeout <double>
    The timeout for dynamic classes. If a dynamic rule for an  IP Adresses
    is pointing to this class, the dynamic rule be removed dyn_timeout
    seconds after the rule has been set. 

  classdir_format "<path_with_formatting_directives>"
    Overrides main classdir_format for this class.

  filename_format "<name_with_formatting_directives>"
    Overrides main filename_format for this class.


Connection Table
================

The TimeMachine knows of connections.  A connection herein is defined
as a flow of packets characterized by the 5-tuple of (layer 4
protocol, source ip, source port, destination ip, destination port);
for protocols other than TCP and UDP source and destination ports are
not applicable (they are set to zero in the connection's identifier).
Connections are bidirectional, i.e. packets in the 'forward' and
'return' direction are accounted to a single connection.

Associated with every connection is a set of variables that keep track
of the state of the connection: number of bytes, number of packets
transmitted by the connection, and timestamp of last packet of the
connection.  A connection table entry is also optionally associated a
flag to suspend the connection size cutoff, and is optionally marked
to be subscribed to a timemachine client.

The timemachine keeps state of connections in a connection table in RAM.  Old
connections are evicted from this table when their last packet arrival
time is more than a configured timeout in the past (see configuration
option 'conn_timeout' above).  The eviction of connections can be
inhibited for a selective connection by issuing the command
suspend_timeout (see `TimeMachine Commands`_ below).


Subscribing
===========

A Time Machine user can subscribe for a connection.  This means the user
requests to be delivered all future packets for this connection
without having to query explicitly for them.  
A subscription is valid as long as the connection's state is kept in the
timemachine's connection table.
A subscription is issued using the query command with the subscribe flag.
ONLY connection4 indexes are subscribe-able at the moment.



TimeMachine Commands
====================

User commands can be issued to the Time Machine either on the local 
console (the controlling terminal) line interface of the timemachine 
process (see also 'console' option in `Configuration File`_ above), 
by connecting to the remote console e.g. using telnet (telnet localhost 
42042), or by issuing the commands using a Broccoli connection (e.g., from Bro).

Query command
*************

The query command is used to perform a number of engine manipulations
and packet extractions.

Full query grammar::

  query <queryresult> <queryspec> [ <query-flags> ]
  <queryresult> ::= feed <broid> tag <tag> | to_file "<filename>"
  <queryspec> ::= index <indexname> "<key-specification>" 
  <query-flags> ::= start <timestamp> end <timestamp> | mem_only | subscribe

The flags can be given in order and they can be combined. 

Query the indexes for the given index key. The result of a query
can either be sent to a remote Bro system or to a file in the
local filesystem. 
The index to query is specified by the keyword index followed
by the name of the index. This name corresponds to the
name that is returned by the getIndexNameStatic() method. 
Examples are connection4, connection3, ip, etc.
Finally the key to search is specified by 
<key-specification>. The sematics of the key spec is defined
by the index itself. For example a valid spec for connection4 
would be "tcp 1.2.3.4:80 5.6.7.8:88"
The <query-flags> enables one to restrict the search or to set
a subsciption (see above). Currently only connection4 querys 
support the subscribe flag, other indexes will silently ignore
the flag. 
When mem_only is specified, only the index entries stored in RAM 
are searched and only packets from the memory ringbuffer are 
returned. 
The timestamps enable one, to specify a timespan. Only packets
falling in this timespan will be returned. timestamps and mem_only
can be combined. The result will be the intersection of both 
(i.e. only packets from memory, that fall into the specified
timeframe).
The timespan has not been tested extensively.

Examples::

    query to_file "file1.pcap" index connection4 "tcp 1.2.3.4:80 5.6.7.8:1025" subscribe
    query to_file "file1.pcap" index connection4 "tcp 1.2.3.4:80 5.6.7.8:1025" 
    query to_file "file1a.pcap" index connection4 "tcp 1.2.3.4:80 5.6.7.8:1025" mem_only
    query to_file "file1a.pcap" index connection4 "tcp 1.2.3.4:80 5.6.7.8:1025" mem_only subscribe start 1163668495 end     1163669900
    query to_file "file2.pcap" index connection3 "tcp 1.2.3.4  5.6.7.8:1025"
    query to_file "file2a.pcap" index connection3 "tcp 1.2.3.4  5.6.7.8:1025" start 1163668495 end 1163669900 
    query to_file "file3.pcap" index connection2 "1.2.3.4   5.6.7.8"
    query to_file "file4.pcap" index ip "1.2.3.4"

After issuing these queries the specified files will be present in the queries 
directory containing the packets matching the query.

Other commands
**************

suspend_cutoff "<proto> <ip>:<port> <ip>:<port>"
  Disable cutoff for a connection. If a connection cutoff is supended, all 
  packets will get recorded and the cutoff value is ignored.

unsuspend_cutoff "<proto> <ip>:<port> <ip>:<port>"
  Remove the supension of the cutoff for one connection.

suspend_timeout "<proto> <ip>:<port> <ip>:<port>"
  Inhibit the eviction of the specified connection from the connection
  table (as described in the section `Connection Table`_ above).

unsuspend_timeout "<proto> <ip>:<port> <ip>:<port>"
  Remove the 'suspend_timeout' flag on the connection so that it will
  get evicted from the connection table as soon as the regular timeout
  mechanism comes into effect (also see the section `Connection Table`_
  above).

show conn "tcp 1.2.3.4:80 7.8.9.1:1042"
  Display information available on the specified connection in the timemachine's
  connection table (see `Connection Table`_ above).

show conn sample
  Display a sample of the newest and oldest connections from the timemachine's
  connection table (see `Connection Table`_ above).
  NOTE/TODO: this function reads the connection table without locking. 
  This might result in race conditions and in the worst case to a 
  segfault. Use with care!

set_dyn_class <ip> <classname> [orig|resp]
  Sets a rule for a dynamic class. Whenever a new connection with
  <ip> is seen, the class for this connection will be <classname> and
  not the class defined by the config file.
  Dynamic class rules are automatically deleted after a certain time. 
  The dyn_timeout option of a class specifies, how long a dynamic
  class rule stays effective. 
  If orig or resp are given, then only connection that originated from
  <ip> (in the case of orig) respectively only connections that go to <ip> 
  (in the case of resp) are assigned to the dynamic class.
  If two rules (one with orig and one with resp) would match a new packet, 
  the one with orig take precedence.
  If several rules for the same IP are set, the latest rule will overwrite all
  earlier rules.

unset_dyn_class <ip>
  Unset a dynamic class rule before it automatically expires on its own.


Command Line Options
====================

The TimeMachine accepts the following command line options.  Command
line options override the according configuration file settings.

-i <interface>  Directs the Time Machine to start capturing packets from the
                specified device.  Cf. 'device' configuration directive in 
                `Configuration File`_ section.
-r <filename>   Read packets from specified tracefile rather than Cf. 
                'read_tracefile' configuration directive in 
                `Configuration File`_ section.
-f <filter>     Apply global BPF filter.  Cf. 'filter' configuration
                directive in `Configuration File`_ section.
-c <filename>   Read configuration file (see `Configuration File`_ section 
                above) from specified file rather than from the default
                file.

