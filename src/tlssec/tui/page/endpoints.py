from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    DataTable,
    Footer,
    Input,
    Label,
    Select,
)

import tlssec.core.operation as op
import tlssec.core.model as m


def _fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "-"


class RelatedModal(ModalScreen[str | None]):
    """Popup from selecting an endpoint.

    List actions to be done on selected endpoint. 
    """

    BINDINGS = [Binding("escape", "cancel", "Close")]

    DEFAULT_CSS = """
    RelatedModal { align: center middle; }
    RelatedModal > Vertical {
        width: 50; height: auto; padding: 1 2;
        border: thick $primary; background: $surface;
    }
    RelatedModal Label { margin-bottom: 1; }
    """

    def __init__(self, endpoint: m.Endpoint) -> None:
        super().__init__()
        self.endpoint = endpoint

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(
                f"[b]Hostname:[/b] {self.endpoint.hostname}\n"
                f"[b]Port:[/b] {self.endpoint.port}"
            )
            yield Select(
                [("See related scans", "scans"),
                 ("See related tags", "tags")],
                prompt = "With this endpoint ...",
                id = "related",
            )
        yield Footer()

    def on_select_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str):  # ignore the blank/"no selection" value
            self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class EndpointsPage(Vertical):
    DEFAULT_CSS = """
    EndpointsPage Input { margin-bottom: 1; }
    EndpointsPage DataTable { height: 1fr; }
    """

    COLUMNS = (
        "ID",
        "IP",
        "Hostname",
        "Port",
        "Path",
        "Transport",
        "App",
        "Service",
        "TLS",
        "First seen",
        "Last seen",
    )

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rows: dict[int, m.Endpoint] = {}

    def compose(self) -> ComposeResult:
        yield Input(
            placeholder = "Search endpoints (press / to focus)...",
            id = "search",
        )
        yield DataTable(
            id = "endpoint-table",
            cursor_type = "row",
            zebra_stripes = True,
        )

    def on_mount(self) -> None:
        self.query_one(DataTable).add_columns(*self.COLUMNS)
        self.refresh_data()

    # -- loading -----------------------------------------------------------
    @work(thread = True, exclusive = True)
    def refresh_data(self) -> None:
        # TODO: filter, page, limit
        rows = op.select_endpoints(self.app.state.db.session)
        rows = [
            # TODO: bring sqlmodel back to use **row.model_dump()
            m.Endpoint.model_validate(row)
            for row in rows
        ]
        self.app.call_from_thread(self._set_rows, rows)

    def _set_rows(self, rows: list[m.Endpoint]) -> None:
        self._rows = {r.id: r for r in rows}
        self._apply_filter(self.query_one(Input).value)

    # -- filtering ---------------------------------------------------------
    def _apply_filter(self, text: str) -> None:
        terms = text.lower().split()
        table = self.query_one(DataTable)
        table.clear()
        for r in self._rows.values():
            haystack = ' '.join(map(str, (
                r.id,
                r.ip,
                r.hostname,
                r.port,
                r.path,
                r.transport_protocol,
                r.application_protocol,
                r.service_info,
                r.tls_mode,
            ))).lower()
            if all(t in haystack for t in terms):
                table.add_row(
                    r.id,
                    r.ip,
                    r.hostname,
                    r.port,
                    r.path,
                    r.transport_protocol,
                    r.application_protocol,
                    r.service_info,
                    r.tls_mode,
                    r.first_seen,
                    r.last_seen,
                    key = str(r.id),
                )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search":
            self._apply_filter(event.value)

    def focus_search(self) -> None:
        self.query_one(Input).focus()

    # -- selection ---------------------------------------------------------
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        endpoint = self._rows.get(int(event.row_key.value))
        if endpoint is None:
            return

        def after(choice: str | None) -> None:
            if choice:
                # TODO: pass endpoint.id to the target page as a filter
                self.app.notify(f"-> {choice} for endpoint {endpoint.id} (placeholder)")
                self.app.goto_page(choice)

        self.app.push_screen(RelatedModal(endpoint), after)
