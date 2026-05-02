# TLS Security Monitoring

> Toolkit to continuously monitor TLS security settings of multiple targets and
> extract statistical insights.

# Usage

## Pre-requisite

The easiest way to use the toolkit is via docker.

- Linux user can [install Docker Engine](https://docs.docker.com/engine/install/) directly.
- Windows user can install Docker Engine through
  [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/)

To get into container environment with TLS security toolkit install, run:

```shell
docker compose run --build --rm cli
```

For development environment where you can use dev tools and automated tests,
use `dev-cli` service instead like this:

```shell
docker compose run --build --rm dev-cli
```

The rest of "Usage" section assumes you are already inside container
environment.

## `tlssec` CLI

`tlssec` is the main command that contains multiple subcommands for taking
actions with the toolkit such as starting a scan or displaying statistics.
For more information, run:

```shell
tlssec --help
```
