#! /bin/bash

# Get shell into testssl.sh container
# with current working directory mounted.

docker run \
  --rm -it \
  -w /home/testssl/workdir \
  -v $(pwd):/home/testssl/workdir \
  --entrypoint bash \
  ghcr.io/testssl/testssl.sh \
  "$@"
