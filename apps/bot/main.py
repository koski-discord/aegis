from aegis_core.config import get_settings
from aegis_core.logging import configure_logging
from apps.bot.bot import AegisBot


def run() -> None:
    settings = get_settings()
    configure_logging("aegis-bot", settings.environment)
    bot = AegisBot(settings)
    bot.run(settings.discord_bot_token.get_secret_value(), log_handler=None)


if __name__ == "__main__":
    run()
