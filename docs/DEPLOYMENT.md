# Deployment Notes

Use a reverse proxy for TLS termination and set `AEGIS_PRODUCTION_HTTPS_ONLY=true` in production. Disable public docs, restrict CORS, configure trusted hosts, and inject secrets from a secret manager rather than files baked into images.

Recommended production controls:

- Run containers as non-root with dropped Linux capabilities.
- Use read-only root filesystems and writable tmpfs only where needed.
- Put PostgreSQL and Redis on private networks.
- Enable Redis authentication.
- Run Alembic migrations as a separate release job.
- Collect structured JSON logs with redaction enabled.
- Back up PostgreSQL and test restores.
- Rotate service signing keys by adding the new public key, deploying bot signers, then removing the old key after nonce windows expire.

