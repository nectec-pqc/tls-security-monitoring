This directory is mounted inside `tlssec` containers as the home directory to
provide persistent working directory that is accessible from outside container.
This also preserve shell history, cache, and generated data across multiple uses
even if the container was removed.

Everything in this directory is untracked by git except for this README.md file
and some configuration files.

Processes inside container will have trouble accessing working directory if this
mount location is not acccessible by user ID 1000.
