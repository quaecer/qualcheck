# Qualcheck

Recompute a received assessment from raw evidence and exact caller
pins. The specification dependency supplies local schemas.
The checker uses the Python standard library and those assets.

```sh
qualcheck serve-process < request.json
qualcheck verify --input verification-envelope.json
```

A verification envelope contains the raw assessment request and the supplied
result. The receiver checks the complete result against its own computation.
The fixed RDF envelope uses installed JSON-LD contexts for the raw evidence
and carried result. Context changes and nested directives fail closed.
An unavailable or unresolved premise cannot establish a positive gate.
The receiver solves the accepted shared-clock constraints, including typed
inventories, and verifies joint omissions and witnessed capture challenges.
An incomplete translation or bounded search leaves the decision unresolved.

Qualcheck shares the clock-constraint encoding for selected readings, aliases
and omissions with Qualifier. Agreement on those cases checks conformance in
the presence of shared code. Qualref derives the constraints separately and
uses Clockcheck to solve them.

The canonicalization primitive is from [Trail of Bits' rfc8785.py 0.1.4](https://github.com/trailofbits/rfc8785.py)
and includes adaptations of Andrew Rundgren's reference implementation.
See [NOTICE](NOTICE) for attribution and [LICENSE-rfc8785.txt](LICENSE-rfc8785.txt)
for the license text.

Apache-2.0.

Copyright 2026 Mariia Steeghs-Turchina
