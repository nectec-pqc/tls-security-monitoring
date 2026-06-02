import pytest
from sqlmodel import select

import tlssec.core.model as m


@pytest.mark.xfail(reason = 'automatic parent tag inclusion is not yet implemented')
def test_add_existing_uniquely_named_tags_to_services(session):
    tags = [
        m.ServiceTagTable(
            name = 'mime-type',
            children = [
                m.ServiceTagTable(name = 'html'),
                m.ServiceTagTable(name = 'json'),
                m.ServiceTagTable(name = 'pdf'),
            ],
        ),
        m.ServiceTagTable(name = 'company-a'),
    ]
    tags = {tag.name: tag for tag in tags}
    services = {
        'backend': m.ServiceTable(
            description = 'Company A backend servers',
            tags = [tags['company-a'], tags['mime-type'].children['json']],
        ),
        'static': m.ServiceTable(
            description = 'Company A static web asset servers',
            tags = [tags['company-a'], tags['mime-type'].children['html']],
        ),
    }
    session.add_all(services.values())
    session.flush()

    # TODO: parent `mime-type` tag needs to be automatically applied
    # Lookup tags given service
    session.refresh(services['backend'])
    assert {tag.name for tag in services['backend'].tags} == {'company-a', 'mime-type', 'json'}
    session.refresh(services['static'])
    assert {tag.name for tag in services['static'].tags} == {'company-a', 'mime-type', 'html'}
    # Lookup services given tag
    session.refresh(tags['mime-type']['pdf'])
    assert len(tags['mime-type']['pdf'].services) == 0
