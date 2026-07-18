import subprocess
from pathlib import Path
from textwrap import dedent

import pytest
import ssh_audit.exitcodes

from tlssec.core.ssh_audit import SshAudit


@pytest.fixture(scope = 'module')
def current_ssh_server(cache_dir):
    server_config_dir = (cache_dir / 'current_ssh_server').resolve()
    server_config_dir.mkdir(parents = True, exist_ok = True)

    private_key_path = server_config_dir / 'ssh_host_ed25519_key'
    private_key_path.unlink(missing_ok = True)

    public_key_path = private_key_path.with_suffix('.pub')
    public_key_path.unlink(missing_ok = True)

    subprocess.run(
        [
            'ssh-keygen',
            '-t', 'ed25519',
            '-f', 'ssh_host_ed25519_key',
            '-N', '',
        ],
        cwd = server_config_dir,
        check = True,
        timeout = 1,
    )

    sshd_config_path = server_config_dir / 'sshd_config'
    sshd_config_path.unlink(missing_ok = True)

    with open(sshd_config_path, 'w') as f:
        f.write(dedent(f"""
            Port 2222
            ListenAddress 127.0.0.1
            PidFile {server_config_dir / 'sshd.pid'}
            HostKey {server_config_dir / 'ssh_host_ed25519_key'}
            PasswordAuthentication yes
            PermitRootLogin no
        """))

    proc = subprocess.Popen(
        [
            '/usr/sbin/sshd', '-D', '-e',
            '-f', str(sshd_config_path),
        ],
        cwd = server_config_dir,
        stdout = subprocess.DEVNULL,
        stderr = subprocess.PIPE,
    )
    for line in proc.stderr:
        if line.startswith(b'Server listening on'):
            break
    yield proc
    try:
        proc.terminate()
        proc.wait(timeout = 1)
    except subprocess.TimeoutExpired:
        with proc:
            proc.kill()


# TODO: add connection error and success cases
@pytest.mark.regen_case
async def test_generate_ssh_audit_json(
    current_ssh_server,
):
    out_path = Path(__file__).parent / 'result_cases/failure.ssh_audit.json'
    out_path.parent.mkdir(parents = True, exist_ok = True)

    completed_process = await SshAudit.scan('127.0.0.1:2222')
    assert completed_process.returncode == ssh_audit.exitcodes.FAILURE

    with open(out_path, 'w') as f:
        for line in completed_process.stdout:
            f.write(line)
