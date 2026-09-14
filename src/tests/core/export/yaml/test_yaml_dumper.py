import pytest
import yaml

from tlssec.core.export.yaml import YamlDumper


@pytest.mark.parametrize(
    'data, expected',
    [
        pytest.param(
            set(('f', 'a', 't')),
            '- a\n- f\n- t\n',
            id = 'set is serialized as sorted list',
        ),
        pytest.param(
            set(('z', 1)),
            '- z\n- 1\n',
            id = 'if item in set is unsortable, just list in original order',
        ),
        pytest.param(
            ['a0123456789012345678900123456789001234567890'] * 2,
            # This is a bit fragile. I don't really care what the anchor is named.
            '- &id001 a0123456789012345678900123456789001234567890\n- *id001\n',
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
    assert result == expected
