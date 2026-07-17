import discord
from discord import app_commands
from discord.ext import commands


class StatusCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="status", description="Show Aegis status")
    async def status(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message("Aegis API status is available at `/api/v1/health`.", ephemeral=True)

    @app_commands.command(name="privacy", description="Show privacy summary")
    async def privacy(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Encryption occurs locally. Server compromise may expose ciphertext, metadata, "
            "timestamps, and account relationships.",
            ephemeral=True,
        )

    @app_commands.command(name="about", description="About Aegis")
    async def about(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Aegis is a zero-knowledge credential vault interface for Discord users.",
            ephemeral=True,
        )
