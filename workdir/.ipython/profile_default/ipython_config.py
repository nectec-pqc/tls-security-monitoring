# Disable jedi autocomplete and fallback to simple autocomplete
# because jedi is stuck when trying autocomplete on custom `tlssec` module
# FIXME: make jedi work
c.IPCompleter.use_jedi = False
