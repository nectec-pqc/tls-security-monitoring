# Regenerate this code with:
#
#     _TLSSEC_COMPLETE=bash_source tlssec > ~/.tlssec-bash-autocomplete.bash
#
# TODO: Autocomplete is currently quite slow. Try limitting CLI startup time.
_tlssec_completion() {
    local IFS=$'\n'
    local response

    response=$(env COMP_WORDS="${COMP_WORDS[*]}" COMP_CWORD=$COMP_CWORD _TLSSEC_COMPLETE=bash_complete $1)

    for completion in $response; do
        IFS=',' read type value <<< "$completion"

        if [[ $type == 'dir' ]]; then
            COMPREPLY=()
            compopt -o dirnames
        elif [[ $type == 'file' ]]; then
            COMPREPLY=()
            compopt -o default
        elif [[ $type == 'plain' ]]; then
            COMPREPLY+=($value)
        fi
    done

    return 0
}

_tlssec_completion_setup() {
    complete -o nosort -F _tlssec_completion tlssec
}

_tlssec_completion_setup;
