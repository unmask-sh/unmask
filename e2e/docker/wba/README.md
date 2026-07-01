# Web Bot Auth e2e fixtures — PUBLIC TEST MATERIAL, NOT SECRETS

Everything in this directory exists only for the docker e2e suite
(scenario 34).  The "private" keys here protect nothing: they sign/serve a
throwaway operator identity (`https://nginx:9444/`) that is only ever
trusted inside the e2e compose network.

- `signer-ed25519.seed` / `signer.kid` — test bot signing key (hex seed) +
  its JWK thumbprint.  Used by `e2e/lib/wbasign.go`.
- `directory.json` — the operator JWK directory served by the e2e nginx
  container at the RFC 9421 well-known path.
- `ca.crt` / `ca.key` — test CA, baked into the e2e admin image's system
  trust (= the product follows system trust; the test rig provisions it
  like an operator would).
- `operator.crt` / `operator.key` — TLS cert for the fake operator vhost
  (SAN=nginx), signed by the test CA.

Regenerate at will; nothing depends on these exact bytes.
