from dataclasses import dataclass

from tlssec.settings import Settings
from tlssec.database.database import Database


@dataclass
class AppState:
    settings: Settings | None = None
    db: Database | None = None
