# Aegis

Aegis is a secure, zero-knowledge credential vault interface for Discord users. Credentials are encrypted by the local client before upload. Discord and the Aegis API are used for account, session, metadata, and encrypted-record workflows only.

Discord is not a safe place to enter passwords. Aegis never asks users to submit plaintext credentials through Discord.

## Security Model

- The master password never leaves the user's device.
- Keys are derived locally with Argon2id.
- Records are encrypted locally with AES-256-GCM using a fresh random nonce per encrypted payload.
- The server stores ciphertext, encrypted metadata, nonces, salts, KDF parameters, timestamps, versions, and ownership identifiers.
- Aegis does not implement password recovery. Locally generated recovery material must be protected by the user.
- Losing both the master password and recovery material can make the vault permanently inaccessible.

Aegis does not claim perfect security. Server compromise may expose ciphertext, metadata, account relationships, timestamps, and operational logs. Weak master passwords may be vulnerable to offline guessing. Python cannot guarantee perfect memory zeroization. Prefer established, independently audited password managers for highly sensitive or production-critical credentials until Aegis receives professional security review.

## License

Aegis uses AGPL-3.0-only. AGPL protects user freedom when the software is offered over a network. Apache-2.0 would be easier for commercial embedding, but AGPL better matches a security service where hosted changes should remain inspectable.

## Local Setup

```bash
uv sync --all-extras
cp .env.example .env
docker compose up -d postgres redis
uv run alembic upgrade head
uv run uvicorn apps.api.main:app --reload
```

Run the bot:

```bash
uv run aegis-bot
```

If slash commands do not appear, invite the bot with both `bot` and
`applications.commands` scopes. For development, set
`discord_development_guild_id` in `config.json` to your Discord server ID and
restart the bot. Guild command sync is immediate; global command sync can take
time to appear in Discord.

Run the client:

```bash
uv run aegis-client configure --api http://localhost:8000
uv run aegis-client init-vault
uv run aegis-client add
uv run aegis-client list
uv run aegis-client copy <record-id> password
uv run aegis-client export-backup backup.json
```

The CLI prompts for secrets with hidden input. Do not pass passwords as command-line arguments.

## Docker Development

```bash
cp .env.example .env
docker compose up --build
```

Services:

- API: `http://localhost:8000/api/v1`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## Environment Variables

Configuration can be provided with `config.json` in the repository root or with `.env`.
`config.json` takes precedence and is ignored by Git because it may contain secrets.
Start from `config.example.json`.

Key settings:

- `AEGIS_ENVIRONMENT`
- `AEGIS_PUBLIC_BASE_URL`
- `AEGIS_DATABASE_URL`
- `AEGIS_REDIS_URL`
- `AEGIS_DISCORD_CLIENT_ID`
- `AEGIS_DISCORD_CLIENT_SECRET`
- `AEGIS_DISCORD_REDIRECT_URI`
- `AEGIS_DISCORD_BOT_TOKEN`
- `AEGIS_DISCORD_DEVELOPMENT_GUILD_ID`
- `AEGIS_TOKEN_HASH_KEY`
- `AEGIS_STATE_SIGNING_KEY`
- `AEGIS_CSRF_SIGNING_KEY`
- `AEGIS_BOT_SIGNING_KEY_ID`
- `AEGIS_BOT_SIGNING_PRIVATE_KEY`
- `AEGIS_BOT_SIGNING_PUBLIC_KEYS`

Never commit real values.

## API Examples

Encrypted record creation uses ciphertext only:

```json
{
  "ciphertext": "base64url-ciphertext",
  "nonce": "base64url-random-nonce",
  "encrypted_metadata": "base64url-ciphertext",
  "metadata_nonce": "base64url-random-nonce",
  "algorithm_version": "AES-256-GCM-v1",
  "kdf_version": 1,
  "schema_version": 1
}
```

Fields such as `password`, `secret`, `plaintext`, `recovery_key`, and `username` are rejected by encrypted-record schemas.

## Commands

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy .
uv run pytest
```

## Architecture

- `apps/api`: FastAPI application and versioned `/api/v1` routes.
- `apps/bot`: discord.py cogs and presentation logic.
- `apps/client`: local encryption CLI.
- `aegis_core`: settings, database models, logging, signing, and shared security utilities.
- `migrations`: Alembic migrations.
- `tests`: unit, integration, and security tests.

The Discord bot must use the FastAPI backend. It must not connect directly to PostgreSQL.

## Known Limitations

- OAuth callback token exchange is structured but uses a local-development numeric-code path in this initial repository.
- Redis-backed distributed rate limiting and distributed service nonce storage are roadmap items; the middleware currently demonstrates the request-signing contract.
- The Discord cogs provide safe command surfaces and warnings, but production client-action creation should be connected to internal API endpoints before launch.
- This code has not received professional security review.

## Audit Recommendations

Before handling real credentials, obtain independent review of the cryptographic format, OAuth/session flow, request signing, deployment configuration, logging pipeline, and client memory/clipboard behavior.

# aegis
