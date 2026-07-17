import re
from contextlib import suppress
from typing import Any, cast

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

    def _portal_link(self, path: str = "/verify") -> str:
        settings = cast(Any, self.bot).settings
        return f"{str(settings.public_base_url).rstrip('/')}{path}"

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

    @app_commands.command(name="overview", description="Open your Aegis Verify overview")
    async def overview(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Open Aegis Verify to review factors, devices, recovery codes, and recent activity: {self._portal_link()}",
            ephemeral=True,
        )

    @app_commands.command(name="setup-authenticator", description="Start authenticator-app setup")
    async def setup_authenticator(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Authenticator setup must happen in Aegis Verify. QR codes and setup keys are never sent through Discord: "
            f"{self._portal_link('/verify/authenticator')}",
            ephemeral=True,
        )

    @app_commands.command(name="setup-passkey", description="Start passkey or security-key setup")
    async def setup_passkey(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Passkeys and hardware security keys are set up in Aegis Verify for stronger phishing resistance: "
            f"{self._portal_link('/verify/passkeys')}",
            ephemeral=True,
        )

    @app_commands.command(name="factors", description="Review configured MFA factors")
    async def factors(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Review and manage your Aegis Verify factors here: {self._portal_link('/verify/factors')}",
            ephemeral=True,
        )

    @app_commands.command(name="recovery-codes", description="Manage recovery codes")
    async def recovery_codes(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Recovery codes are shown only in Aegis Verify and should be stored offline, never in Discord: "
            f"{self._portal_link('/verify/recovery-codes')}",
            ephemeral=True,
        )

    @app_commands.command(name="trusted-devices", description="Manage trusted devices")
    async def trusted_devices(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Review trusted devices and revoke stale devices in Aegis Verify: {self._portal_link('/verify/devices')}",
            ephemeral=True,
        )

    @app_commands.command(name="recent-activity", description="Review recent security activity")
    async def recent_activity(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Recent Aegis Verify activity is available here: {self._portal_link('/verify/activity')}",
            ephemeral=True,
        )

    @app_commands.command(name="revoke-device", description="Open trusted-device revocation")
    async def revoke_device(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Device revocation requires confirmation in Aegis Verify: {self._portal_link('/verify/devices')}",
            ephemeral=True,
        )

    @app_commands.command(name="revoke-sessions", description="Open session revocation")
    async def revoke_sessions(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            "Session revocation requires step-up verification in Aegis Verify: "
            f"{self._portal_link('/verify/sessions')}",
            ephemeral=True,
        )

    @app_commands.command(name="disable-factor", description="Open MFA factor disable flow")
    async def disable_factor(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Disabling factors requires strong confirmation in Aegis Verify: {self._portal_link('/verify/factors')}",
            ephemeral=True,
        )

    @app_commands.command(name="report-login", description="Report a suspicious login")
    async def report_login(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            f"Report suspicious login activity in Aegis Verify: {self._portal_link('/verify/report-login')}",
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
