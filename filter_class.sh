#!/bin/sh

export LD_LIBRARY_PATH=/usr/local/lib
TCPDUMP=/usr/local/sbin/tcpdump

CLASS="tcp"
FILTER=""
OUTFILE="filter.pcap"

while getopts 'f:c:dw:' opt
  do
  case $opt in
      f) FILTER="$OPTARG";;
      c) CLASS="$OPTARG";;
      w) OUTFILE="$OPTARG";;
      d) DEBUG=1;;
  esac
done
if [ $DEBUG ] ; then
    echo class $CLASS
    echo filter $FILTER
fi

for f in class_${CLASS}_* ;
do
  if [ $DEBUG ] ; then
      echo $TCPDUMP -n -r $f -w tmp/$f.tmp $FILTER ...
  fi
  $TCPDUMP -n -r $f -w tmp/$f.tmp $FILTER
done
find tmp/ -name '*.tmp' -size 24c -exec rm {} \;
cat tmp/*.tmp > tmp/all.tmp
if [ $DEBUG ] ; then
    echo $TCPDUMP -n -r tmp/all.tmp -w tmp/$OUTFILE ...
fi
$TCPDUMP -n -r tmp/all.tmp -w tmp/$OUTFILE
rm -f tmp/*.tmp
