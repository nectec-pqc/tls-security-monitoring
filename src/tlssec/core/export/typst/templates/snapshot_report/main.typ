#import "modules/style.typ"
#import "modules/data_manipulation.typ": load
#import "modules/templates.typ"

#show: style.init
#let data = load()

#include "front_sections.typ"

#templates.endpoint_discovery_section(data)
#templates.post_quantum_readiness_section(data)
#templates.detailed_results_section(data)
