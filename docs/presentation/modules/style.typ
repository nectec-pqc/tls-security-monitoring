#import "@preview/polylux:0.4.0": *


#let init(body) = {
  set page(paper: "presentation-16-9")
  set text(
    size: 20pt,
    font: ("Sarabun", "Libertinus Serif"),
  )
  show heading.where(level: 1): set text(size: 1.4 * 25pt)

  body
}
