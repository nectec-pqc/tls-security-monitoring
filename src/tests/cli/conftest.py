import pytest
from click.testing import CliRunner

from tlssec.database.database import Database


@pytest.fixture
def cli_runner(session, monkeypatch):
    """
        This fix two problem
        1. inject session into cli, let us have easy way to access to session since our cli alwyas create they own session
        2. from using session fixture we get the rollback affect. Clean product DB
    """
    monkeypatch.setattr(Database, 'session', property(lambda self: session))
    return CliRunner()
