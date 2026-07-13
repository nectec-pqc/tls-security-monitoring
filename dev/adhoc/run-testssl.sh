#! /bin/bash

HERE=$(readlink -e "$(dirname "$BASH_SOURCE")")
cd "$HERE"

mkdir -p testssl
cd testssl

for NAME in \
  example1.com \
  example2.com ;
do
  testssl \
    --jsonfile-pretty "$NAME".json \
    --htmlfile "$NAME".html \
    --user-agent 'testssl.sh run by apiwat.cha [at] nectec.or.th please contact for exclusion or feedback' \
    "$NAME" \
    > "$NAME".stdout
done
