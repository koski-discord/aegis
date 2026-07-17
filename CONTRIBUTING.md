# Contributing

Keep changes small and security-focused. Run:

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy .
uv run pytest
```

Never commit real secrets, realistic user credentials, live Discord tokens, raw authorization headers, or production data. API examples must use ciphertext-only payloads.

