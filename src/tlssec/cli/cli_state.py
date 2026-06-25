from dataclasses import dataclass

from tlssec.settings import Settings
from tlssec.database.database import Database
from tlssec.core.model.service import Service


@dataclass
class CliState:
    settings: Settings | None = None
    db: Database | None = None
    service: list[Service] | None = None

