from dataclasses import dataclass, field
from pathlib import Path

from tlssec.core.operation.file import FiletypeRegistry
from tlssec.database.database import Database
from tlssec.settings import Settings


@dataclass
class AppState:
    config_path: Path | None = None
    settings: Settings | None = None
    db: Database | None = None
    filetype_registry: FiletypeRegistry = field(
        default_factory = FiletypeRegistry
    )
