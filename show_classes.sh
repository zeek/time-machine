#!/bin/sh

classes=$(ls class_* | perl -ne 's/_[0-9a-f]+$//; print;' | uniq)

for c in $classes
do
  echo class $c:
  du -ck ${c}_* | grep total
  ls -l ${c}_* | head -n 1
done

