#import "@preview/polylux:0.4.0": *

#let init(body) = {
  set page(
    paper: "presentation-16-9",
    header: toolbox.all-sections((sections, current) => {
      if current != [] {
        align(top)[
          #rect(
            fill: gradient.linear(maroon.darken(40%), maroon, angle: 90deg),
            width: 100%,
            height: 100%,
            outset: (x: 100%),
          )[
            #align(bottom)[
              #text(fill: white)[
                #strong(current)
                #h(1fr)
                #text(size: .5em)[
                  #toolbox.slide-number / #toolbox.last-slide-number
                ]
              ]
            ]
          ]
        ]
      }
    }),
  )
  set text(
    size: 20pt,
    font: ("Sarabun", "Libertinus Serif"),
  )
  show heading.where(level: 1): set text(size: 1.4 * 25pt)
  show heading: set text(fill: maroon)

  body
}


#let section(name, subtitle: none) = slide[
  #set page(header: none, footer: none, margin: 0pt)
  #set align(horizon)
  #set text(size: 2.4em)
  #toolbox.register-section(name)

  #grid(
    columns: (1fr, 3fr),
    inset: 10pt,
    align: (right, left),
    fill: (
      gradient.linear(maroon.darken(40%), maroon, angle: 90deg),
      white,
    ),
    [#block(height: 100%)],
    [
      #text(weight: "bold", fill: maroon)[#name]
      #if subtitle != none [

        #text(.7em, fill: maroon)[#subtitle]
      ]
    ],
  )
]
