import discord
import structlog
from discord.ext import commands

from aegis_core.config import Settings

log = structlog.get_logger()


class AegisBot(commands.Bot):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.messages = True
        intents.message_content = True
        application_id = int(settings.discord_client_id) if settings.discord_client_id.isdecimal() else None
        if application_id is not None:
            super().__init__(
                command_prefix=commands.when_mentioned,
                intents=intents,
                application_id=application_id,
            )
        else:
            super().__init__(command_prefix=commands.when_mentioned, intents=intents)
        self.settings = settings

    async def setup_hook(self) -> None:
        from apps.bot.cogs.account import AccountCog
        from apps.bot.cogs.security import SecurityCog
        from apps.bot.cogs.status import StatusCog
        from apps.bot.cogs.vault import VaultCog

        await self.add_cog(AccountCog(self))
        await self.add_cog(VaultCog(self))
        await self.add_cog(SecurityCog(self))
        await self.add_cog(StatusCog(self))
        if self.settings.environment == "development":
            if self.settings.discord_development_guild_id is not None:
                guild = discord.Object(id=self.settings.discord_development_guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                log.info(
                    "synced_guild_commands",
                    guild_id=self.settings.discord_development_guild_id,
                    command_count=len(synced),
                )
            else:
                synced = await self.tree.sync()
                log.info("synced_global_commands", command_count=len(synced))

    async def on_ready(self) -> None:
        if self.user is None:
            return
        log.info("bot_ready", bot_user=str(self.user), bot_id=self.user.id)
