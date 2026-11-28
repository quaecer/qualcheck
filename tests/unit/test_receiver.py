# SPDX-License-Identifier: Apache-2.0
"""Checks for offline wire refusals and canonical input (QUAL-REQ-001 and QUAL-REQ-017)."""

import unittest

from quaecer.qualcheck._jcs import dumps
from quaecer.qualcheck.receiver import receive
from quaecer.qualcheck.schema import BASE, Catalogue, decode


class ReceiverTest(unittest.TestCase):
    def test_strict_json_and_unicode(self) -> None:
        for invalid in (b"[1.0]", b'{"r":0,"r":2}', b"[9007199254740992]", b'"\\ud800"'):
            with self.subTest(raw=invalid), self.assertRaises(ValueError):
                decode(invalid)
        self.assertEqual(dumps({"\ue000": 1, "\U00010000": 2}), '{"𐀀":2,"":1}'.encode())

    def test_schema_ref_resolution_stays_local_and_strict(self) -> None:
        root = BASE + "request.schema.json"
        item = BASE + "example.schema.json"
        catalogue = Catalogue(
            {
                root: {
                    "type": "object",
                    "properties": {"value": {"$ref": "example.schema.json#/$defs/number"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
                item: {"$defs": {"number": {"type": "integer", "maximum": 10}}},
            }
        )
        self.assertTrue(catalogue.accepts("request", {"value": 10}))
        for value in ({"value": True}, {"value": 11}, {"value": 10, "extra": ""}, {}):
            with self.subTest(value=value):
                self.assertFalse(catalogue.accepts("request", value))
        self.assertEqual(receive(b'{"value":true}', catalogue), {"status": "invalid"})
