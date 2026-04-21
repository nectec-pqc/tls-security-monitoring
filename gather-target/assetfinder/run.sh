#! /bin/bash

# Mount current directory into a shell with assetfinder command

HERE=$(readlink -e "$(dirname "$BASH_SOURCE")")

docker compose -f "$HERE"/docker-compose.yaml run \
  --rm \
  --user $(id -u):$(id -g) \
  assetfinder
