# Design Boundaries

## Included in this alpha

- Logical proof-envelope model aligned with `parc-spec` draft 0.1.
- Typed capability, evidence, subject, application-binding, and continuity records.
- Structural validation that is useful before signing.
- Explicit errors for malformed local construction.

## Deliberately excluded

- Cryptographic container selection and canonical signature bytes.
- Key generation, Android Keystore, KeyMint, StrongBox, or certificate processing.
- Network challenge acquisition and proof submission.
- Verifier appraisal or relying-party policy.
- Private probes, scoring rules, or production features.

## API stability

All public APIs are alpha. Serialization compatibility is not guaranteed until `parc-spec` freezes a wire profile.
