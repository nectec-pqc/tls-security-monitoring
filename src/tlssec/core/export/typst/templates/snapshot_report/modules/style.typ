#import "@preview/ansi-render:0.9.1": ansi-render as original-ansi-render


#let raw_boxing = state("raw_boxing", true)


#let init(body) = {
  set heading(numbering: "1.1)")
  set text(font: ("Sarabun", "Libertinus Serif"))

  show raw: it => context {
    if raw_boxing.get() {
      box(
        fill: rgb("ddd"),
        inset: 2pt,
        radius: 2pt,
        it
      )
    } else {
      it
    }
  }

  set heading(
    supplement: sym.section,
  )

  // Color text based on content
  show table.cell: it => {
    // Highlight severity level of findings
    show regex("^HIGH$"): text.with(fill: red, weight: "bold")
    show regex("^WARN$"): text.with(fill: orange, weight: "bold")
    // fade out unimportant entries
    show regex("^no service|not scanned|-$"): text.with(weight: "extralight")
    it
  }

  set table(align: center + horizon)

  body
}


#let ansi-render(string, ..args) = {
  string = string.replace("\u{1b}[m", "\u{1b}[0m")
  [
    #raw_boxing.update(false)
    #original-ansi-render(string, ..args)
    #raw_boxing.update(true)
  ]
}
