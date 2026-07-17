.PHONY: sync lint format type test migrate api bot

sync:
	uv sync --all-extras

lint:
	uv run ruff check .

format:
	uv run ruff format .

type:
	uv run mypy .

test:
	uv run pytest

migrate:
	uv run alembic upgrade head

api:
	uv run uvicorn apps.api.main:app --host 0.0.0.0 --port 8000 --reload

bot:
	uv run aegis-bot

