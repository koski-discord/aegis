import discord
from discord import app_commands
from discord.ext import commands


class AccountCog(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    group = app_commands.Group(name="aegis", description="Manage your Aegis account")

    @group.command(name="register", description="Start Aegis account setup")
    async def register(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Create your vault with the Aegis local client. Aegis never asks for passwords in Discord.",
            ephemeral=True,
        )

    @group.command(name="account", description="Show account guidance")
    async def account(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Your Discord user ID is used only as an account identifier. Vault contents stay encrypted locally.",
            ephemeral=True,
        )

    @group.command(name="delete-account", description="Delete your Aegis account")
    async def delete_account(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Account deletion must be confirmed through the API or local client so active sessions can be revoked.",
            ephemeral=True,
        )

    @group.command(name="export-data", description="Export encrypted account data")
    async def export_data(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Use `aegis-client export-backup` to download ciphertext and metadata. Discord will not receive secrets.",
            ephemeral=True,
        )
