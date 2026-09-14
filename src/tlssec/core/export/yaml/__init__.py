import yaml


class YamlDumper(yaml.SafeDumper):
    """Custom YAML serializer for tlssec exports.

    - Serialize set as list (sorted if possible)
    - Use anchor to deduplicate long strings
    """
    def ignore_aliases(self, data):
        # Enforce anchors on strings long characters
        if isinstance(data, str) and len(data) > 20:
            return False
        return super().ignore_aliases(data)


YamlDumper.add_representer(
    set,
    (
        lambda dumper, data:
            dumper.represent_list(sorted(data))
    ),
)
