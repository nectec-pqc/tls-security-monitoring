import click

from .colored_help import ColoredGroup, ColoredCommand
from .cli_state import CliState


@click.group(cls = ColoredGroup)
def show():
    """Show system status"""
    pass


@show.command()
def version():
    """Show CLI version"""
    from importlib.metadata import version
    print(version('tlssec'))


@show.command(
    name = 'settings',
    cls = ColoredCommand,
)
@click.pass_context
def show_settings(ctx):
    """Show effective settings

    (after merging defaults, environment variable, cli options together.)
    """
    state = ctx.find_object(CliState)
    print(state.settings.model_dump_json(indent=2))
