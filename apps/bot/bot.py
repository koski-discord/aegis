import discord
from discord.ext import commands

from aegis_core.config import Settings


class AegisBot(commands.Bot):
    def __init__(self, settings: Settings) -> None:
        intents = discord.Intents.none()
        intents.guilds = True
        intents.messages = True
        intents.message_content = True
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
            await self.tree.sync()
