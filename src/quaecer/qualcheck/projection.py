# SPDX-License-Identifier: Apache-2.0
"""Read the fixed compact graph frames without expanding arbitrary contexts."""

from typing import Any

from ._jcs import dumps
from .schema import BASE, Catalogue


def _plain(value: Any) -> Any:
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        if value.keys() == {"@id"} and value["@id"] in ("qual:Null", BASE + "terms/Null"):
            return None
        if any(key.startswith("@") for key in value):
            raise ValueError("unexpected JSON-LD directive")
        return {key: _plain(item) for key, item in value.items()}
    if value is None:
        raise ValueError("a framed null requires the explicit marker")
    return value


def _unframe(
    supplied: Any,
    context: Any,
    root_type: str,
    member_key: str,
    member_type: str,
) -> dict[str, Any]:
    if (
        not isinstance(supplied, dict)
        or supplied.get("@type") != root_type
        or dumps(supplied.get("@context")) != dumps(context)
        or not isinstance(supplied.get(member_key), list)
    ):
        raise ValueError("frame or context differs from the specification")
    raw = {key: value for key, value in supplied.items() if key not in {"@type", "@context"}}
    members = []
    for item in raw[member_key]:
        if not isinstance(item, dict) or item.get("@type") != member_type:
            raise ValueError("unexpected framed member type")
        members.append({key: value for key, value in item.items() if key != "@type"})
    raw[member_key] = members
    parsed = _plain(raw)
    assert isinstance(parsed, dict)
    return parsed


def from_rdf(
    message: dict[str, Any], catalogue: Catalogue
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract raw request and result from the declared frame (QUAL-REQ-020)."""
    if not catalogue.accepts("rdf-verification-request", message):
        raise ValueError("invalid RDF verification envelope")
    context = catalogue.context("evidence")

    def evidence_frame(frame: dict[str, Any]) -> dict[str, Any]:
        raw = dict(frame)
        raw["evidence"] = _unframe(
            raw.get("evidence"),
            context,
            "qual:Evidence",
            "reports",
            "qual:Observation",
        )
        return raw

    request = dict(message["request"])
    if request.get("profile") == BASE + "transfer-request":
        for name in ("source", "target"):
            side = request.get(name)
            if not isinstance(side, dict):
                raise ValueError("missing framed transfer side")
            request[name] = evidence_frame(side)
    else:
        request = evidence_frame(request)
    result = _unframe(
        message["result"],
        catalogue.context("result"),
        "qual:Result",
        "findings",
        "earl:TestResult",
    )
    return request, result
