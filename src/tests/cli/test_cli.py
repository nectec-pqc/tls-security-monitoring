from click.testing import CliRunner
from tlssec.cli import cli


def test_cli_home():
  runner = CliRunner()
  result = runner.invoke(cli)
  assert result.exit_code == 2, 'Expect "usage error" due to no subcommand selected'
