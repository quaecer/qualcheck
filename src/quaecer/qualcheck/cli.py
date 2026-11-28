# SPDX-License-Identifier: Apache-2.0
"""Verify a received scalar assessment offline."""

import argparse
import json
import sys
from pathlib import Path

from .receiver import receive
from .schema import LIMIT, Catalogue


def main() -> int:
    """Run a single assessment or verification command (QUAL-REQ-017)."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["serve-process", "verify"])
    parser.add_argument("--spec-dir", type=Path, help="trusted local schema directory")
    parser.add_argument("--input", type=Path, help="read a request file instead of stdin")
    args = parser.parse_args()
    try:
        catalogue = Catalogue.load(args.spec_dir)
        if args.input is None:
            raw = sys.stdin.buffer.read(LIMIT + 1)
        else:
            with args.input.open("rb") as stream:
                raw = stream.read(LIMIT + 1)
        result = receive(raw, catalogue)
    except (OSError, ValueError, ImportError, LookupError) as error:
        parser.exit(2, f"qualcheck: {error}\n")
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return int(args.operation == "verify" and result != {"status": "verified"})


if __name__ == "__main__":
    raise SystemExit(main())
