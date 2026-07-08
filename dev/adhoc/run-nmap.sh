#! /bin/bash

HERE=$(readlink -e "$(dirname "$BASH_SOURCE")")
cd "$HERE"

mkdir -p nmap
cd nmap

for NAME in \
  example1.com \
  example2.com ;
do
  nmap \
    -vv --script=ssl-cert \
    -oX "$NAME".nmap.xml \
    "$NAME" \
    > "$NAME".nmap
done
