#! /bin/bash

HERE=$(readlink -e "$(dirname "$BASH_SOURCE")")
cd "$HERE"

mkdir -p dig
cd dig

for TYPE in A AAAA ANY ; do
  for NAME in \
    example1.com \
    example2.com ;
  do
    echo "=== $TYPE ===" >> "$NAME".dig
    dig "$NAME" "$TYPE" >> "$NAME".dig
  done
done
