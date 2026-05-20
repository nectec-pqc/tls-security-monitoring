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

The rest of "Usage" section assumes you are already inside container
environment.

## `tlssec` CLI

`tlssec` is the main command that contains multiple subcommands for taking
actions with the toolkit such as starting a scan or displaying statistics.
For more information, run:

```shell
tlssec --help
```

## Analysis image

Once database is populated with scan results,
you may start jupyter lab server to do datascience analysis on it by running:

```shell
docker compose up analysis
```

The server will output access URL on startup that looks something like:

```
http://127.0.0.1:8888/lab?token=f28e0902840883301afb40562d771b38c31016593bfa2671
```

which you can paste into local browser to access jupyter lab.
Inside the lab's working directory, please take a look at `notebooks/QUICK-START.ipynb`
notebook and others in the same subdirectory for a guide on how to perform
analysis and display statistics from tlssec database.

# Development

For development environment where you can use dev tools and automated tests,
use `dev-cli` service instead like this:

```shell
docker compose run --build --rm dev-cli
```

Python source code will be mounted inside container so you can live edit and
execute new version immediately without rebuilding container image.

## Testing

In dev environment, run:

```shell
pytest /opt/app/
```

to execute all automated tests within the app.

# Directory Structure

`src` directory contains source code which are split into:

```
src
├── tests       - For automated tests
└── tlssec      - For tlssec package, the main application code
```

Inside `tlssec` we have:

```
tlssec
├── __init__.py             - Empty (marks it as a package)
├── cli
│   ├── __init__.py         - CLI commands (click)
│   └── cli_state.py        - Shared state object passed between commands
├── core
│   ├── model
│   │   ├── __init__.py     - Re-exports all models
│   │   ├── scan.py         - Scan data model
│   │   └── target.py       - Target (domain) data model
│   └── operation.py        - Business logic (DB operations)
├── database
│   ├── __init__.py         - Empty
│   ├── database.py         - Database connection wrapper
│   └── sqlmodel.py         - Custom SQLModel base class
└── settings.py             - App configuration (env vars)
```
