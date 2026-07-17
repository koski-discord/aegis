import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import discord

from aegis_core.config import get_settings
from aegis_core.logging import configure_logging
from apps.bot.bot import AegisBot


def normalize_bot_token(token: str) -> str:
    cleaned = token.strip().strip("\"'")
    if cleaned.lower().startswith("bot "):
        cleaned = cleaned[4:].strip()
    return cleaned


def run() -> None:
    settings = get_settings()
    configure_logging("aegis-bot", settings.environment)
    token = normalize_bot_token(settings.discord_bot_token.get_secret_value())
    if not token:
        raise SystemExit("AEGIS_DISCORD_BOT_TOKEN is empty. Add the bot token from the Discord Developer Portal.")
    bot = AegisBot(settings)
    try:
        bot.run(token, log_handler=None)
    except discord.LoginFailure as exc:
        raise SystemExit(
            "Discord rejected AEGIS_DISCORD_BOT_TOKEN. Regenerate the bot token in the Discord "
            "Developer Portal, copy the value from Bot > Token, and replace AEGIS_DISCORD_BOT_TOKEN "
            "in .env. Do not use the client secret, public key, or OAuth token."
        ) from exc


if __name__ == "__main__":
    run()
