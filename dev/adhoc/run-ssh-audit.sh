#! /bin/bash

HERE=$(readlink -e "$(dirname "$BASH_SOURCE")")
cd "$HERE"

mkdir -p ssh-audit
cd ssh-audit

for NAME in \
  example1.com \
  example2.com ;
do
  ssh-audit > "$NAME".ssh-audit
  ssh-audit --json "$NAME" > "$NAME".ssh-audit.json
done
