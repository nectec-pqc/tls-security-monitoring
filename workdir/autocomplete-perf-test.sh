#! /bin/bash

# Time how fast CLI autocomplete runs

# Words currently on command line
COMP_WORDS=(tlssec "")
# Which word is to be completed
COMP_CWORD=1
# Stores autocomplete result
COMPREPLY=()
# Invoke autocomplete directly
time _tlssec_completion "tlssec"

echo "--- Autocomplete Choices Found: ---"
echo "${COMPREPLY[@]}"
