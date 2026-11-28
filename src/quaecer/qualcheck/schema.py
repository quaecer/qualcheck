# SPDX-License-Identifier: Apache-2.0
"""Validate the declared local schema vocabulary without a network resolver."""

import json
import re
from importlib.metadata import distribution
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urldefrag, urljoin

from ._jcs import dumps

BASE = "https://quaecer.github.io/specs/qualification/1.0/"
LIMIT = 2 * 1024 * 1024
_MAP = {"required", "properties", "additionalProperties"}
_SEQUENCE = {"items", "minItems", "maxItems", "contains", "uniqueItems"}
_STRING = {"minLength", "maxLength", "pattern"}
_NUMBER = {"minimum", "maximum"}
_OTHER = {
    "$id",
    "$schema",
    "$defs",
    "$ref",
    "title",
    "description",
    "format",
    "contentEncoding",
    "type",
    "const",
    "enum",
    "allOf",
    "anyOf",
    "oneOf",
    "if",
    "then",
    "else",
}
_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "boolean": bool,
    "null": type(None),
}


def _reject_number(_: str) -> NoReturn:
    raise ValueError("only interoperable integers are permitted")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON member")
        result[name] = value
    return result


def decode(data: bytes) -> Any:
    if len(data) > LIMIT:
        raise ValueError("request size exceeds the limit")
    document = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_object,
        parse_float=_reject_number,
        parse_constant=_reject_number,
    )
    dumps(document)
    return document


class Catalogue:
    """An offline catalogue of recognized schema objects (QUAL-REQ-001)."""

    def __init__(self, documents: dict[str, Any], assets: Path | None = None) -> None:
        self.documents = documents
        self.assets = assets

    @classmethod
    def load(cls, local: Path | None) -> "Catalogue":
        """Open the current specification's data from its installed wheel or checkout."""
        if local is None:
            resource = distribution("quaecer-spec-qualification").locate_file(
                "quaecer/spec_qualification/_assets/schema",
            )
            local = Path(str(resource))
        definitions = {}
        for path in sorted(local.glob("*.schema.json")):
            document = decode(path.read_bytes())
            name = document["$id"]
            if name != BASE + path.name or name in definitions:
                raise ValueError("unrecognized schema identity")
            definitions[name] = document
        return cls(definitions, local.parent)

    def context(self, name: str) -> Any:
        """Read the exact local context; a request never chooses a remote source."""
        if self.assets is None or name not in {"evidence", "result"}:
            raise ValueError("context is unavailable")
        document = decode((self.assets / "context" / (name + ".jsonld")).read_bytes())
        return document["@context"]

    def accepts(self, name: str, message: Any) -> bool:
        """Check a JSON value against a named schema in the local mandate."""
        uri = BASE + name + ".schema.json"
        return self._allowed(message, self.documents[uri], uri)

    def _reference(self, name: str, origin: str) -> tuple[Any, str]:
        uri, pointer = urldefrag(urljoin(origin, name))
        node = self.documents[uri]
        if pointer:
            if not pointer.startswith("/"):
                raise ValueError("unrecognized schema reference")
            for part in pointer[1:].split("/"):
                node = node[part.replace("~1", "/").replace("~0", "~")]
        return node, uri

    def _allowed(self, item: Any, schema: Any, origin: str) -> bool:
        if isinstance(schema, bool):
            return schema
        if schema.keys() - (_MAP | _SEQUENCE | _STRING | _NUMBER | _OTHER):
            raise ValueError("unsupported schema keyword")
        if "$ref" in schema:
            referent, uri = self._reference(schema["$ref"], origin)
            if not self._allowed(item, referent, uri):
                return False
        if "type" in schema and type(item) is not _TYPES[schema["type"]]:
            return False
        if "const" in schema and dumps(item) != dumps(schema["const"]):
            return False
        if "enum" in schema and dumps(item) not in {dumps(value) for value in schema["enum"]}:
            return False
        for keyword, expectation in (("allOf", "all"), ("anyOf", "some"), ("oneOf", "one")):
            if keyword in schema:
                options = schema[keyword]
                successes = sum(self._allowed(item, option, origin) for option in options)
                if (
                    (expectation == "all" and successes != len(options))
                    or (expectation == "some" and successes == 0)
                    or (expectation == "one" and successes != 1)
                ):
                    return False
        if "if" in schema:
            branch = "then" if self._allowed(item, schema["if"], origin) else "else"
            if not self._allowed(item, schema.get(branch, True), origin):
                return False
        if isinstance(item, dict):
            fields = schema.get("properties", {})
            if set(schema.get("required", ())) - item.keys():
                return False
            if schema.get("additionalProperties") is False and item.keys() - fields.keys():
                return False
            return all(
                self._allowed(item[key], value, origin)
                for key, value in fields.items()
                if key in item
            )
        if isinstance(item, list):
            if len(item) < schema.get("minItems", 0) or len(item) > schema.get("maxItems", LIMIT):
                return False
            if schema.get("uniqueItems") and len({dumps(value) for value in item}) != len(item):
                return False
            if "items" in schema and not all(
                self._allowed(value, schema["items"], origin) for value in item
            ):
                return False
            return "contains" not in schema or any(
                self._allowed(value, schema["contains"], origin) for value in item
            )
        if isinstance(item, str):
            return schema.get("minLength", 0) <= len(item) <= schema.get("maxLength", LIMIT) and (
                "pattern" not in schema or re.search(schema["pattern"], item) is not None
            )
        if type(item) is int:
            return bool(schema.get("minimum", item) <= item <= schema.get("maximum", item))
        return True
