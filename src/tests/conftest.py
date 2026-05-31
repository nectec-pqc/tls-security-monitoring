import pytest
from sqlmodel import (
    Session,
    delete,
)

from tlssec.database.database import Database
import tlssec.core.model as model


# Only setup database parameters once for the whole test run.
# We might change this later if there is a test that neesd different settings than others.
@pytest.fixture(scope = 'session')
def database():
    return Database()


@pytest.fixture(name = 'session')
def empty_database_session(database):
    connection = database.engine.connect()
    transaction = connection.begin()
    with Session(bind = connection, join_transaction_mode = 'create_savepoint') as session:
        session.exec(delete(model.ServiceTagMapTable))
        session.exec(delete(model.ServiceTagTable))
        session.exec(delete(model.ServiceTable))
        yield session
    transaction.rollback()
    connection.close()

