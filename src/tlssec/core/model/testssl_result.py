from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy import Column, Integer, Identity
from sqlmodel import Field  
from tlssec.database.sqlmodel import SQLModel


class EndPoint(SQLModel):
    endPointID : int = Field(
            sa_column=Column(Integer, Identity(always=True), primary_key=True),
            index=True
            ) 
    partOfService : int = Field(
            foreign_key="Service.serviceID",
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
            index=True,
            sa_column=Column(Integer, Identity(always=True), primary_key=True)
            )
    endPointID : int = Field(
            index=True,
            foreign_key="EndPoint.endPointID"
            )
    param : dict | None = Field(
            default = None,
            description = "How testssl got call, option and arguemnt supply to testssl"
            )
    result : dict | list = Field(sa_type=JSONB)
    start : datetime
    timeTaken : int

class Service(SQLModel):
    serviceID : int

class child_Service_Tag(SQLModel):
    tagID : int = Field(
            sa_column=Column(Integer, Identity(always=True), primary_key=True),
            index=True
            )
    ParentID : int = Field(
            index=True,
            foreign_key="parent_Service_Tag.tagID"
            )
    name : str
    description : str

class parent_Service_Tag(SQLModel):
    tagID : int = Field(
            sa_column=Column(Integer, Identity(always=True), primary_key=True),
            index=True
            )
    name : str
    description : str


class Service_Tag_Map(SQLModel): 
    serviceID : int  = Field(
            index=True,
            )
    tagID : int = Field(
            index=True,
            )


    
