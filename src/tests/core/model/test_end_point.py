from contextlib import nullcontext
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

import tlssec.core.model as m

NOW = datetime(2025, 1, 1, tzinfo=timezone.utc)
LATER = datetime(2025, 6, 1, tzinfo=timezone.utc)

def make_service(session, name='test_service'):
    svc = m.ServiceTable(name=name, hostname='example.com')
    session.add(svc)
    session.flush()
    return svc


def make_endpoint(session, service, **overrides):
    defaults = dict(
        part_of_service_id=service.id,
        hostname='target.example.com',
        port=443,
        path='/',
        protocol='tcp',
        first_seen=NOW,
        last_seen=NOW,
    )
    ep = m.EndPointTable(**(defaults | overrides))
    session.add(ep)
    session.flush()
    return ep
