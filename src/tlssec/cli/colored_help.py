from click_help_colors import HelpColorsGroup, HelpColorsCommand


THEME = {
    'help_headers_color': 'yellow',
    'help_options_color': 'cyan',
}


class ColoredGroup(HelpColorsGroup):
    def __init__(self, *args, **kwargs):
        kwargs.update(THEME)
        super().__init__(*args, **kwargs)


class ColoredCommand(HelpColorsCommand):
    def __init__(self, *args, **kwargs):
        kwargs.update(THEME)
        super().__init__(*args, **kwargs)
