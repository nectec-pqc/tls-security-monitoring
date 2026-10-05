from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    ContentSwitcher,
    Footer,
    Header,
    Input,
    OptionList,
)
from textual.widgets.option_list import Option

from .page.endpoints import EndpointsPage
from .page.placeholder import PlaceholderPage


class Tui(App):
    TITLE = "TLSSEC: TLS Security Monitoring"

    CSS = """
    #sidebar {
        width: 24; height: 100%;
        border: solid $primary;
        background: $panel;
    }
    #pages { width: 1fr; height: 100%; padding: 1 2; }
    """

    BINDINGS = [
        Binding("slash", "focus_search", "Search"),
        Binding("r", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
    ]

    # (page id, sidebar label) -- order = sidebar order
    PAGES = [
        ("endpoints", "Endpoints"),
        ("tags", "Tags"),
        ("scans", "Scans"),
        ("cboms", "CBOMs"),
        ("opinions", "Opinions"),
        ("statistics", "Statistics"),
        ("import", "Import"),
        ("export", "Export"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield OptionList(
                *[
                    Option(label, id = pid)
                    for pid, label in self.PAGES
                ],
                id = "sidebar",
            )
            with ContentSwitcher(initial = "endpoints", id = "pages"):
                yield EndpointsPage(id = "endpoints")
                for pid, label in self.PAGES:
                    if pid in ['endpoints']:
                        continue
                    yield PlaceholderPage(label, id = pid)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#sidebar", OptionList).highlighted = 0
        self.query_one("#sidebar").focus()

    # Switch pages as soon as a sidebar item is highlighted (arrow keys / click)
    def on_option_list_option_highlighted(
        self, event: OptionList.OptionHighlighted
    ) -> None:
        if event.option_list.id == "sidebar" and event.option.id:
            self.query_one(ContentSwitcher).current = event.option.id

    def goto_page(self, page_id: str) -> None:
        """Navigate programmatically (keeps the sidebar highlight in sync)."""
        sidebar = self.query_one("#sidebar", OptionList)
        sidebar.highlighted = sidebar.get_option_index(page_id)

    def on_option_list_option_selected(
        self, event: OptionList.OptionSelected
    ) -> None:
        if event.option_list.id == "sidebar" and event.option.id:
            # NOTE: `on_option_list_option_highlighted` should already switch
            # current page so switching now is not necessary, but it is here to
            # guard against future changes so it can work independently.
            self.query_one(ContentSwitcher).current = event.option.id
            self.screen.focus_next("#pages *")

    def action_focus_search(self) -> None:
        if self.query_one(ContentSwitcher).current == "endpoints":
            self.query_one(EndpointsPage).focus_search()

    def action_refresh(self) -> None:
        if self.query_one(ContentSwitcher).current == "endpoints":
            self.query_one(EndpointsPage).refresh_data()
