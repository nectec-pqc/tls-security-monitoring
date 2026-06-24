from dataclasses import dataclass

from tlssec.settings import Settings
from tlssec.database.database import Database


@dataclass
class CliState:
    settings: Settings | None = None
    db: Database | None = None
    service: None = None
    
