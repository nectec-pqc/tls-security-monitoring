from textual.widgets import Static


class PlaceholderPage(Static):
    DEFAULT_CSS = "PlaceholderPage { padding: 2 4; }"

    def __init__(self, title: str, **kwargs) -> None:
        super().__init__(f"[b]{title}[/b]\n\nNot implemented yet.", **kwargs)
