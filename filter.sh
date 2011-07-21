#!/bin/sh
FILTER='host 131.159.14.43'
for f in class_* ; do tcpdump -r $f -w filt_${f} $FILTER ; done
find . -name 'filt_*' -size 24c -exec rm {} \;
cat filt_* > filt
rm filt_*
