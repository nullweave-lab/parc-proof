# parc-proof

Experimental Rust data model and builder for PARC proof envelopes.

This crate currently provides:

- typed draft proof, evidence, capability, subject, and continuity models;
- base64url challenge encoding with length checks;
- duplicate evidence and missing dependency validation;
- continuity event-reference validation;
- structured construction errors;
- JSON serialization for tests and inspection.

It deliberately does **not** provide signing, Android key attestation, credential validation, canonical signature bytes, network transport, or policy decisions. The cryptographic container is not frozen in `parc-spec`.

## Build

```sh
cargo test
```

## Security status

Pre-release and not production-ready. Callers must not sign the current `to_json_bytes` output as a production protocol without a reviewed canonicalization and cryptographic profile.

## License

Apache License 2.0. See `LICENSE`.
