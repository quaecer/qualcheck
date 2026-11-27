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
The receiver recomputes interval coverage from exact empty commitments,
including shared clocks and joint omission witnesses. Definite forbidden
exposure is evaluated separately. A clock shift that may reconcile the
record, nonempty inventories and capture challenges can leave compatibility
unresolved. Transfer remains deferred.

The canonicalization primitive is from [Trail of Bits' rfc8785.py 0.1.4](https://github.com/trailofbits/rfc8785.py)
and includes adaptations of Andrew Rundgren's reference implementation.
See [NOTICE](NOTICE) for attribution and [LICENSE-rfc8785.txt](LICENSE-rfc8785.txt)
for the license text.

Apache-2.0.

Copyright 2026 Mariia Steeghs-Turchina
