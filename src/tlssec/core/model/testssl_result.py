from pydantic import BaseModel
from datetime import datetime

class EndPoint(BaseModel):
    endPointID : int 
    partOfService : int
    scheme : str
    hostName : str
    IPv4 : str # in postgrase they have inet and cidr for optimzed store ip let look lather
    IPv6 : str # in case of dual stack
    port : int
    path : str
    validAfter : datetime # use to track date that this end point start to alive 
    validBefore : datetime # use to track date that this end poin die


class Scan(BaseModel):
    scanID : int
