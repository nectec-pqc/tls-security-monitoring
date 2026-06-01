# Patch `sqlmodel` to support relationship using `attribute_keyed_dict`.
# The feature is already being worked on,
# but not yet merged into official release.
# See https://github.com/fastapi/sqlmodel/pull/1287
# TODO: Remove once official release support the feature.
import sqlmodel._compat

def patch(original):
    def patched(
        name: str,
        rel_info: "RelationshipInfo",
        annotation: Any,
    ) -> Any:
        from typing import get_origin, get_args
        origin = get_origin(annotation)
        use_annotation = annotation
        if origin is dict:
            args = get_args(annotation)
            if len(args) != 2:
                raise ValueError(
                    f"dict relationship field '{name}' has {len(args)} "
                    "type arguments.  Exactly two required (e.g., dict[str, "
                    "Model])"
                )
            use_annotation = args[1]
        return original(name = name, rel_info = rel_info, annotation = use_annotation)
    return patched

sqlmodel._compat.get_relationship_to = patch(sqlmodel._compat.get_relationship_to)

del patch
del sqlmodel._compat
