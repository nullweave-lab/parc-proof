# parc-proof

Runnable experimental PARC proof builder and attester client.

The crate still provides the typed proof model and graph validation, and now also ships `parc-attester`, a command that performs a complete transaction against the reference verifier:

1. request a fresh challenge;
2. collect an explicit host-process evidence summary;
3. construct the logical proof;
4. sign the exact payload with a persisted Ed25519 key;
5. submit it to the verifier;
6. print the structured result.

## Run an attestation transaction

Start `parc-verifier-server`, then run:

```sh
cargo run --release --bin parc-attester -- attest \
  --server http://127.0.0.1:8787 \
  --key-file ./parc-demo-key.json \
  --save-submission ./submission.json
```

Replay the same signed request:

```sh
cargo run --release --bin parc-attester -- submit \
  --server http://127.0.0.1:8787 \
  --submission ./submission.json
```

The first request must return `pass`; the second must return `replayed`.

## Generate a key without submitting

```sh
cargo run --release --bin parc-attester -- keygen --key-file ./parc-demo-key.json
```

On Unix, a newly created key file is opened with mode `0600`. This key is a demo software key, not an Android Keystore or StrongBox key.

## What is real

- actual HTTP challenge-response;
- persisted asymmetric signing keys;
- exact-byte Ed25519 signatures;
- typed proof construction;
- executable evidence collection;
- saved requests that can be used to test replay rejection;
- binary and container builds in CI.

## Security boundary

The current CLI evidence is collected by an ordinary host process and is explicitly marked self-reported. It is useful for exercising the complete protocol and verifier implementation, but it does not establish Android hardware-backed provenance or privileged runtime integrity.

The serialized JSON payload is the runnable demo signature format `parc-demo-ed25519-v1`; it is not yet the final production wire profile.

## License

Apache License 2.0. See `LICENSE`.
