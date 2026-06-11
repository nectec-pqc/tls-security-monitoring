from datetime import datetime
from typing import Optional, Literal
from enum import Enum

from pydantic import (
        BaseModel, 
        IPvAnyAddress, 
        ConfigDict, 
        Field as PydanticField,
)
from sqlalchemy import (
        Column, 
        Integer, 
        Identity, 
        UniqueConstraint, 
        String, 
        ForeignKey,
        DateTime,
)
from sqlalchemy.orm import (
        Mapped, 
        mapped_column, 
        relationship,
)

from tlssec.database.base import Base
from tlssec.database.types import InetType
from tlssec.core.model.validator import UrlPath

class Protocol(str, Enum):
    tcp = 'tcp'
    udp = 'udp'
    http = 'http'
    https = 'https'



