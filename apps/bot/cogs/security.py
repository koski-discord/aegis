import re
from contextlib import suppress

import discord
from discord import app_commands
from discord.ext import commands

LIKELY_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+|"
    r"\b[A-Za-z0-9_/\-+=]{32,}\b",
)


class SecurityCog(commands.GroupCog, name="security"):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot or not message.content:
            return
        if LIKELY_SECRET_RE.search(message.content):
            with suppress(discord.Forbidden):
                await message.delete()
            with suppress(discord.Forbidden):
                await message.author.send(
                    "Aegis detected text that looked like a credential and tried to remove it. "
                    "Never paste passwords or recovery material into Discord."
                )

    @app_commands.command(name="activity", description="Show security activity guidance")
    async def activity(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Use the Aegis client or API to review security events.",
            ephemeral=True,
        )

    @app_commands.command(name="alerts", description="Show alert guidance")
    async def alerts(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Security alerts are delivered without secret contents.", ephemeral=True
        )

    @app_commands.command(name="recovery", description="Explain recovery material")
    async def recovery(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Recovery material is generated locally. Losing both it and your master password "
            "can make the vault unrecoverable.",
            ephemeral=True,
        )

    @app_commands.command(name="report", description="Report a security issue")
    async def report(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Report vulnerabilities through SECURITY.md. Do not include live secrets in reports.",
            ephemeral=True,
        )
