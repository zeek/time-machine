#!/bin/sh

NAME=tm-linux
SLEEP=900

while true
do
  echo "`date` `ps -C $NAME u | grep -v USER | awk '{print $5 \" \" $6}'`"
  sleep $SLEEP
done
