import tlssec.core.model as m
from tlssec.core.operation import find_new_endpoints, endpoint_identity_key


def _ep(hostname=None, ip=None, port=443, transport='tcp'):
    return m.Endpoint(
        hostname=hostname, ip=ip, port=port,
        transport_protocol=transport, tls_mode=m.TlsMode.implicit,
    )


def test_identity_prefers_hostname_over_ip():
    assert endpoint_identity_key(_ep(hostname='ex.com', ip='10.0.0.1')) == ('ex.com', 443, 'tcp')
    # IP-only endpoints still key on the IP.
    assert endpoint_identity_key(_ep(ip='10.0.0.1')) == ('10.0.0.1', 443, 'tcp')


def test_rotating_ip_same_hostname_is_not_new():
    existing = [_ep(hostname='ex.com', ip='10.0.0.1')]
    # Next discovery run: the load balancer handed nmap a different backend IP.
    discovered = [_ep(hostname='ex.com', ip='10.0.0.2')]
    assert find_new_endpoints(discovered, existing) == []


def test_new_port_on_known_host_is_still_new():
    existing = [_ep(hostname='ex.com', ip='10.0.0.1', port=443)]
    discovered = [_ep(hostname='ex.com', ip='10.0.0.1', port=8443)]
    new = find_new_endpoints(discovered, existing)
    assert [e.port for e in new] == [8443]


def test_ip_only_endpoints_match_on_ip():
    existing = [_ep(ip='10.0.0.1')]
    discovered = [_ep(ip='10.0.0.1'), _ep(ip='10.0.0.9')]
    new = find_new_endpoints(discovered, existing)
    assert [str(e.ip) for e in new] == ['10.0.0.9']
