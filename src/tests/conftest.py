from pathlib import Path

import pytest
from sqlalchemy.orm import Session
from sqlalchemy import delete

from tlssec.database.database import Database
import tlssec.core.model as model


@pytest.fixture(scope='session')
def database():
    return Database()


@pytest.fixture(name='session')
def empty_database_session(database):
    connection = database.engine.connect()
    transaction = connection.begin()
    with Session(bind=connection, join_transaction_mode='create_savepoint') as session:
        session.execute(delete(model.ServiceTagMapTable))
        session.execute(delete(model.ServiceTagTable))
        session.execute(delete(model.ServiceTable))
        yield session
    transaction.rollback()
    connection.close()


@pytest.fixture(scope='session')
def cache_dir():
    path = Path.home() / '.cache/tlssec/test'
    path.mkdir(parents=True, exist_ok=True)
    return path
