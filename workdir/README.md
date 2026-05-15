This directory is mounted inside `tlssec` containers to provide
persistent working directory that is accessible from outside container.
This also preserve shell history across multiple uses.

Everything in this directory except this README.md file is untracked by git.

Processes inside container will have trouble accessing working directory if this
mount location is not acccessible by user ID 1000.
