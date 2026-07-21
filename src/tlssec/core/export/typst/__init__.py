from pathlib import Path
from shutil import copytree, ignore_patterns


class TypstTemplates:
    @staticmethod
    def init(
        name: str,
        target_path: Path,
        *,
        include_tests = False,
    ) -> None:
        """Initialize typst report project of given `name` at the given `target_path`"""
        templates_path = (Path(__file__).parent / 'templates').resolve()
        template_path = (templates_path / name).resolve()
        if (
            not template_path.is_relative_to(templates_path)
            or not template_path.is_dir()
        ):
            raise ValueError('Invalid template name')

        ignores = ['.*']
        if not include_tests:
            ignores.append('test*.typ')

        copytree(
            template_path,
            target_path,
            dirs_exist_ok = True,
            ignore = ignore_patterns(*ignores),
        )
