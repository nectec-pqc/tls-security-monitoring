#import "style.typ"


#let render_testssl_stdout(stdout) = {
  style.ansi-render(
    stdout,
    font: none,
    size: .65em,
  )
}


#let endpoint_discovery_section(data) = [
  = Endpoint Discovery

  #align(center)[
    #table(
      columns: 6,
      table.header[*Domain*][*IP address*][*Port*][*Service*][*Version*][*Scan \ Result*],
      ..data.map(group => {
        let ((display_hostname, ip), members) = group
        (
          table.cell(rowspan: members.len(), rotate(-90deg, reflow: true, raw(display_hostname))),
          table.cell(rowspan: members.len(), rotate(-90deg, reflow: true, raw(ip))),
          ..members.map(member => {
            (
              [#member.port],
              [#member.display_service],
              [#member.service_info],
              (
                if member.scan_result.len() > 0 [
                  #ref(member.label)
                ] else [
                  not scanned
                ]
              ),
            )
          }),
        )
      }).flatten(),
    )
  ]

  *หมายเหตุ:*

  - ค้นหา port ที่เปิดอยู่ด้วยวิธี TCP SYNC ผ่าน `nmap`
]


// TODO: Shorten algorithm names.
// testssl output too is unnecessarily long.
#let summarize_certs_algorithm(certs) = [
  #align(left)[
    #enum(
      ..certs.map(cert => enum.item[
        key: #raw(cert.key_algorithm),
        sig: #raw(cert.signature_algorithm)
      ])
    )
  ]
]


#let post_quantum_readiness_section(data) = [
  = Post-Quantum Readiness Summary

  #align(center)[
    #show table.cell: it => {
      if it.y > 0 {
        set text(size: 0.7em)
        it
      } else {
        it
      }
    }
    #table(
      columns: 4,
      table.header[*Endpoint*][*QS Key Establishment*][*QS Encryption*][*QS Server Authentication*],
      ..data
        .map(x => x.at(1))
        .flatten()
        .filter(x => x.scan_result.len() > 0)
        .map(endpoint => {
          let cells = ()
          let testssl = endpoint.scan_result.at("testssl", default: none)
          if testssl != none {
            cells += (
              endpoint.socket_reference,
              (
                if testssl.qs.key_establishment.safe.len() == 0 [
                  #text(fill: red, weight: "bold")[Not Offered (NOT OK)] \
                  #testssl.qs.key_establishment.unsafe.map(raw).join(", ")
                ] else [
                  #text(fill: green, weight: "bold")[Offered (OK)] \
                  #testssl.qs.key_establishment.safe.map(raw).join(", ")
                  #if testssl.qs.key_establishment.unsafe.len() != 0 [
                    \
                    #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                    #testssl.qs.key_establishment.unsafe.map(raw).join(", ")
                  ]
                ]
              ),
              (
                if testssl.qs.symmetric_encryption.safe.len() == 0 [
                  #text(fill: red, weight: "bold")[Not Offered (NOT OK)] \
                  #testssl.qs.symmetric_encryption.unsafe.map(raw).join(", ")
                ] else [
                  #text(fill: green, weight: "bold")[Offered (OK)] \
                  #testssl.qs.symmetric_encryption.safe.map(raw).join(", ")
                  #if testssl.qs.symmetric_encryption.unsafe.len() != 0 [
                    \
                    #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                    #testssl.qs.symmetric_encryption.unsafe.map(raw).join(", ")
                  ]
                ]
              ),
              (
                if testssl.qs.server_certificate.safe in (none, ()) [
                  #text(fill: orange, weight: "bold")[Not Offered (WARN)] \
                  #summarize_certs_algorithm(testssl.qs.server_certificate.unsafe)
                ] else [
                  #text(fill: green, weight: "bold")[Offered (OK)] \
                  #summarize_certs_algorithm(testssl.qs.server_certificate.safe)
                  #if testssl.qs.server_certificate.unsafe not in (none, ()) [
                    \
                    #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                    #summarize_certs_algorithm(testssl.qs.server_certificate.unsafe)
                  ]
                ]
              ),
            )
          }
          let ssh_audit = endpoint.scan_result.at("ssh_audit", default: none)
          if ssh_audit != none {
            cells += (
              endpoint.socket_reference,
              (
                if ssh_audit.qs.key_establishment.safe.len() == 0 [
                  #text(fill: red, weight: "bold")[Not Offered (NOT OK)] \
                  #ssh_audit.qs.key_establishment.unsafe.map(raw).join(", ")
                ] else [
                  #text(fill: green, weight: "bold")[Offered (OK)] \
                  #ssh_audit.qs.key_establishment.safe.map(raw).join(", ")
                  #if ssh_audit.qs.key_establishment.unsafe.len() != 0 [
                    \
                    #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                    #ssh_audit.qs.key_establishment.unsafe.map(raw).join(", ")
                  ]
                ]
              ),
              (
                if ssh_audit.qs.symmetric_encryption.safe.len() == 0 [
                  #text(fill: red, weight: "bold")[Not Offered (NOT OK)] \
                  #ssh_audit.qs.symmetric_encryption.unsafe.map(raw).join(", ")
                ] else [
                  #text(fill: green, weight: "bold")[Offered (OK)] \
                  #ssh_audit.qs.symmetric_encryption.safe.map(raw).join(", ")
                  #if ssh_audit.qs.symmetric_encryption.unsafe.len() != 0 [
                    \
                    #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                    #ssh_audit.qs.symmetric_encryption.unsafe.map(raw).join(", ")
                  ]
                ]
              ),
              (
                if ssh_audit.qs.host_key_algorithm.safe.len() == 0 [
                  #text(fill: orange, weight: "bold")[Not Offered (WARN)] \
                  #ssh_audit.qs.host_key_algorithm.unsafe.map(raw).join(", ")
                ] else [
                  #text(fill: green, weight: "bold")[Offered (OK)] \
                  #ssh_audit.qs.host_key_algorithm.safe.map(raw).join(", ")
                  #if ssh_audit.qs.host_key_algorithm.unsafe.len() != 0 [
                    \
                    #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                    #ssh_audit.qs.host_key_algorithm.unsafe.map(raw).join(", ")
                  ]
                ]
              ),
            )
          }
          return cells
        })
        .flatten(),
    )
  ]
]


#let explain_qs_support(
  what,
  subtitle: none,
  safe: none,
  unsafe: none,
  safe_explanation: none,
) = (
  [
    Quantum-safe #what
    #if subtitle != none [
      \ (#subtitle)
    ]
  ],
  [
    #if safe in (none, ()) [
      #text(fill: red, weight: "bold")[Not Offered (NOT OK)] \
      Does not support any quantum-safe #{what}.
      #if unsafe not in (none, ()) [
        Only the following non-quantum-safe alternatives are supported:
        #unsafe.map(raw).join(", ")
      ]
    ] else [
      #text(fill: green, weight: "bold")[Offered (OK)] \
      Support the following quantum-safe
      #{
        what
        [s]
        if safe_explanation != none {
          [ ]
          safe_explanation
        }
      }:
      #safe.map(raw).join(", ")
      #if unsafe not in (none, ()) [

        #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
        Still allow the following non-quantum-safe #{what}s as fallbacks:
        #unsafe.map(raw).join(", ")
      ]
    ]
  ],
)


#let explain_certs_qs(certs) = [
  #align(left)[
    #enum(
      ..certs.map(cert => enum.item[
        A certificate
        #if "serial" in cert [
          with serial number: #raw(cert.serial)
        ] \
        is using
        #{
          let list = ()
          list = (
            [
              #if not cert.safe_key_algorithm [
                #text(fill: orange)[non quantum-safe]
              ] else [
                #text(fill: green)[quantum-safe]
              ]
              key algorithm:
              #raw(cert.key_algorithm)
            ],
            [
              #if not cert.safe_signature_algorithm [
                #text(fill: orange)[non quantum-safe]
              ] else [
                #text(fill: green)[quantum-safe]
              ]
              signature algorithm:
              #raw(cert.signature_algorithm)
            ],
          )
          list.join("\nand ")
        }
      ])
    )
  ]
]


#let detailed_results_section(data) = [
  = Detailed Results

  #for endpoint in (
    data
      .map(x => x.at(1))
      .flatten()
      .filter(x => x.scan_result.len() > 0)
  ) [
    #let testssl = endpoint.scan_result.at("testssl", default: none)
    #let ssh_audit = endpoint.scan_result.at("ssh_audit", default: none)

    #heading(
      level: 2,
      [
        Endpoint:
        #endpoint.display_service
        on
        #endpoint.socket_reference
      ],
    )
    #endpoint.label

    #figure(
      table(
        columns: 2,
        [Domain Name], [#raw(endpoint.display_hostname)],
        [IP Address], [
          #raw(endpoint.ip)
          #if testssl != none and testssl.ip != endpoint.ip [

            `testssl.sh` targets the domain, \
            but was routed to #raw(testssl.ip) instead.
          ]
        ],
        [Port], [#endpoint.port],
        [Service], [#endpoint.display_service],
        [Version], [#endpoint.service_info],
      ),
    )

    เครื่องมือที่ใช้ (Tool Dependencies):

    #if testssl != none [
      - https://testssl.sh/
    ]
    #if ssh_audit != none [
      - https://github.com/jtesta/ssh-audit
    ]

    === Post-Quantum Readiness

    #if testssl != none [
      #align(center)[
        #table(
          columns: (1fr, 2fr),
          table.header[*Topic*][*Result*],
          ..explain_qs_support(
            [key establishment algorithm],
            ..testssl.qs.key_establishment,
          ),
          ..explain_qs_support(
            [encryption algorithm],
            ..testssl.qs.symmetric_encryption,
            safe_explanation: "with large enough symmetric key size",
          ),

          [Quantum-safe certificate signature algorithm \ (server authentication)],
          (
            if testssl.qs.server_certificate.safe in (none, ()) [
              #text(fill: orange, weight: "bold")[Not Offered (WARN)] \
              No server certificate was found whose signature algorithm and key
              algorithm are both quantum-safe.

              #explain_certs_qs(testssl.qs.server_certificate.unsafe)
            ] else [
              #text(fill: green, weight: "bold")[Offered (OK)] \

              #explain_certs_qs(testssl.qs.server_certificate.safe)
              #if testssl.qs.server_certificate.unsafe not in (none, ()) [

                #text(fill: orange, weight: "bold")[Not Enforced (WARN)] \
                Still allow the following unsafe certificates:

                #explain_certs_qs(testssl.qs.server_certificate.unsafe)

                Whether the quantum-safe certificate will be served to client
                depends on client capabilities and server's preference.
              ]
            ]
          ),
        )
      ]

      #if testssl.at("raw_text", default: none) != none [
        === Supplementary Findings

        #render_testssl_stdout(testssl.raw_text)
      ]
    ]

    #if ssh_audit != none [
      #align(center)[
        #table(
          columns: (1fr, 2fr),
          table.header[*Topic*][*Result*],
          ..explain_qs_support(
            [key establishment algorithm],
            ..ssh_audit.qs.key_establishment,
          ),
          ..explain_qs_support(
            [encryption algorithm],
            ..ssh_audit.qs.symmetric_encryption,
            safe_explanation: "with large enough symmetric key size",
          ),
          ..explain_qs_support(
            [host key algorithm],
            subtitle: [server authentication],
            ..ssh_audit.qs.host_key_algorithm,
          ),
        )
      ]

      #if ssh_audit.at("raw", default: none) != none [
        === Supplementary Findings

        #for (kind, header) in (
          ("enc", "Encryption Algorithms"),
          ("kex", "Key Establishment Algorithms"),
          ("key", "Host Key Algorithms"),
          //("fingerprints", "Fingerprints"),
          ("mac", "Message Authentication Code Algorithms"),
        ) {
          let entries = ssh_audit.raw.at(kind)
          strong(header)
          align(center)[
            #table(
              columns: 2,
              align: left,
              stroke: none,
              ..entries.enumerate().map(((entry_id, entry)) => {
                let fill = if calc.odd(entry_id) { rgb("EAF2F5") } else { none }
                (
                  table.cell(
                    rowspan: entry.notes.values().map(messages => messages.len()).sum(),
                    fill: fill,
                    entry.algorithm,
                  ),
                  ..entry.notes.pairs().map(((severity, messages)) => (
                    ..messages.map(message => table.cell(
                      text(
                        fill: (
                          if severity == "fail" {red}
                          else if severity == "warn" {orange}
                          else {black}
                        ),
                        [\[#severity\]: #message],
                      ),
                      fill: fill,
                    )),
                  )).flatten(),
                )
              }).flatten(),
            )
          ]
        }
      ]
    ]
  ]
]
