from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Column, Integer, Identity
from sqlmodel import Field  
from tlssec.database.sqlmodel import SQLModel


class EndPoint(SQLModel):
    endPointID : int = Field(
            sa_column=Column(Integer, Identity(always=True), primary_key=True),
            ) 
    partOfService : int = Field(
            foreign_key="service.serviceID",
            index=True
            )
    scheme : str = Field(
            description="What protocol/encryption they handel"
            )
    hostName : str
    IPv4 : str # in postgrase they have inet and cidr for optimzed store ip let look lather
    port : int
    path : str = Field(
            description="testssl do scan at connection level, so URL is inrelavant")
    validAfter : datetime # use to track date that this end point start to alive 
    validBefore : datetime # use to track date that this end poin die

class Scan(SQLModel):
    scanID : int = Field(
            sa_column=Column(Integer, Identity(always=True), primary_key=True)
            )
    endPointID : int = Field(
            index=True,
            foreign_key="end_point.endPointID"
            )
    param : dict | None = Field(
            default = None,
            sa_type = JSONB,
            description = "How testssl got call, option and arguemnt supply to testssl"
            )
    result : dict | list = Field(sa_type=JSONB)
    start : datetime
    timeTaken : int

class Service(SQLModel):
    serviceID : int = Field(
            sa_column=Column(Integer, Identity(always=True), primary_key=True)
            )

class Service_Tag_Map(SQLModel): 
    serviceID : int  = Field(
            primary_key=True,
            foreign_key="service.serviceID"
            )
    tagID : int = Field(
            primary_key=True,
            foreign_key="service_tag.tagID"
            )

class ServiceTag(SQLModel):
    tagID : int = Field(
        sa_column=Column(Integer, Identity(always=True), primary_key=True)
    )
    parentID : int | None = Field(
        default=None,
        foreign_key="service_tag.tagID"  
        )
    name : str
    description : str | None = None
    
