import yaml


class YamlDumper(yaml.SafeDumper):
    """Custom YAML serializer for tlssec exports.

    - Serialize set as list (sorted if possible)
    - Use anchor to deduplicate long strings
    """
    pass


YamlDumper.add_representer(
    set,
    (
        lambda dumper, data:
            dumper.represent_list(sorted(data))
    ),
)
