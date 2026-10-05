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

@dataclass(slots = True)
class EndpointRow:
    """Plain snapshot of an endpoint, so the UI never touches ORM objects
    (avoids detached-instance errors and keeps DB work off the UI thread)."""

    id: int
    ip: str
    hostname: str
    port: int
    path: str
    transport: str
    app_proto: str
    service_info: str
    tls_mode: str
    first_seen: str
    last_seen: str

    @property
    def label(self) -> str:
        return f"{self.hostname or self.ip or '?'}:{self.port}{self.path}"

    def haystack(self) -> str:
        """Lower-cased text the search box matches against."""
        return " ".join(
            str(v)
            for v in (
                self.id, self.ip, self.hostname, self.port, self.path,
                self.transport, self.app_proto, self.service_info, self.tls_mode,
            )
        ).lower()


def _fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M") if dt else "-"


def load_endpoints() -> list[EndpointRow]:
    """Blocking DB call -- always run it in a worker thread."""
    # --- Replace this stub with the real query: ---------------------------
    # with SessionLocal() as session:
    #     rows = session.scalars(
    #         select(EndpointTable).order_by(EndpointTable.id)
    #     ).all()
    #     return [
    #         EndpointRow(
    #             id=e.id,
    #             ip=str(e.ip) if e.ip else "",
    #             hostname=e.hostname or "",
    #             port=e.port,
    #             path=e.path,
    #             transport=e.transport_protocol,
    #             app_proto=e.application_protocol or "",
    #             service_info=e.service_info or "",
    #             tls_mode=getattr(e.tls_mode, "value", str(e.tls_mode or "")),
    #             first_seen=_fmt_dt(e.first_seen),
    #             last_seen=_fmt_dt(e.last_seen),
    #         )
    #         for e in rows
    #     ]
    # -----------------------------------------------------------------------
    now = datetime.now()
    return [  # demo data so the app runs out of the box
        EndpointRow(68, "10.0.0.5", "api.example.com", 443, "/v2", "tcp", "https",
                    "nginx 1.25", "implicit", _fmt_dt(now), _fmt_dt(now)),
        EndpointRow(69, "10.0.0.6", "db.example.com", 5432, "/", "tcp", "postgres",
                    "PostgreSQL 16", "explicit", _fmt_dt(now), "-"),
        EndpointRow(70, "10.0.0.5", "", 22, "/", "tcp", "ssh",
                    "OpenSSH 9.6", "", _fmt_dt(now), _fmt_dt(now)),
    ]


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

    def __init__(self, endpoint: EndpointRow) -> None:
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
        "Proto",
        "App",
        "Service",
        "TLS",
        "First seen",
        "Last seen",
    )

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._rows: dict[int, EndpointRow] = {}

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
        rows = load_endpoints()
        self.app.call_from_thread(self._set_rows, rows)

    def _set_rows(self, rows: list[EndpointRow]) -> None:
        self._rows = {r.id: r for r in rows}
        self._apply_filter(self.query_one(Input).value)

    # -- filtering ---------------------------------------------------------
    def _apply_filter(self, text: str) -> None:
        terms = text.lower().split()  # every word must match somewhere
        table = self.query_one(DataTable)
        table.clear()
        for r in self._rows.values():
            hay = r.haystack()
            if all(t in hay for t in terms):
                table.add_row(
                    r.id, r.ip, r.hostname, r.port, r.path, r.transport,
                    r.app_proto, r.service_info, r.tls_mode,
                    r.first_seen, r.last_seen,
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
