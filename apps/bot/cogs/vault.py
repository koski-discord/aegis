import discord
from discord import app_commands
from discord.ext import commands


class VaultCog(commands.GroupCog, name="vault"):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @app_commands.command(name="status", description="Show vault status")
    async def status(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Your vault is encrypted locally. Aegis cannot decrypt your vault.",
            ephemeral=True,
        )

    @app_commands.command(name="records", description="Explain how to list encrypted records")
    async def records(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Use the Aegis client to list and decrypt record labels locally.",
            ephemeral=True,
        )

    @app_commands.command(name="add", description="Create a local-client add request")
    async def add(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "This action must be completed using the Aegis client. Never paste a password into Discord.",
            ephemeral=True,
        )

    @app_commands.command(name="edit", description="Create a local-client edit request")
    async def edit(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Open the Aegis client to edit and re-encrypt the record locally.",
            ephemeral=True,
        )

    @app_commands.command(name="remove", description="Remove an encrypted record")
    async def remove(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Use the Aegis client for deletion so you can confirm the encrypted record ID.",
            ephemeral=True,
        )

    @app_commands.command(name="client", description="Show local client guidance")
    async def client(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Install and run `aegis-client`. It encrypts credentials before anything reaches Aegis.",
            ephemeral=True,
        )

    @app_commands.command(name="backup", description="Export an encrypted backup")
    async def backup(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Use `aegis-client export-backup backup.json`. The export contains ciphertext only.",
            ephemeral=True,
        )

    @app_commands.command(name="lock-all", description="Revoke active sessions")
    async def lock_all(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Use the Sessions commands or API to revoke active sessions.",
            ephemeral=True,
        )
