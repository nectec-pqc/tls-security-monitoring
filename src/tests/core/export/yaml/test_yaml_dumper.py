import pytest
import yaml

from tlssec.core.export.yaml import YamlDumper


@pytest.mark.parametrize(
    'data, expected',
    [
        pytest.param(
            {'f', 'a', 't'},
            '- a\n- f\n- t\n',
            id = 'set is serialized as sorted list',
        ),
        pytest.param(
            {'z', 1},
            (lambda s: set(yaml.safe_load(s)) == {'z', 1}),
            id = 'if item in set is unsortable, just list in default (undefined) order',
        ),
        pytest.param(
            ['0123456789'*4] * 2,
            (lambda s: len(s) < 80 and yaml.safe_load(s) == (['0123456789'*4] * 2)),
            id = 'deduplicated long repeated strings using anchor',
        ),
        pytest.param(
            ['a0123456789'] * 2,
            '- a0123456789\n- a0123456789\n',
            id = 'short strings are allowed to be duplicated',
        ),
    ],
)
def test_yaml_dumper(data, expected):
    result = yaml.dump(data, Dumper = YamlDumper)
    if isinstance(expected, str):
        assert result == expected
    else:
        assert expected(result)
