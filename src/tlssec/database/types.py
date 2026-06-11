from sqlalchemy import TypeDecorator
from sqlalchemy.dialects.postgresql import INET
from pydantic import IPvAnyAddress

class InetType(TypeDecorator):
    """
    Maps PostgreSQL INET column to/from pydantic IPvAnyAddress.
    
    do two job 
    - when send to PostgreSQL it will convery IPvAnyAddress from pydantic to plain string 
    - when get from PostgreSQL it convert plain string to IPvAnyAddress 
        
    """
    impl = INET
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return IPvAnyAddress(value)
