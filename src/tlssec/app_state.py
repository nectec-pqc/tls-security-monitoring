from dataclasses import dataclass
from pathlib import Path

from tlssec.settings import Settings
from tlssec.database.database import Database


@dataclass
class AppState:
    config_path: Path | None = None
    settings: Settings | None = None
    db: Database | None = None
