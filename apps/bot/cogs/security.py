import base64
import re
from contextlib import suppress
from io import BytesIO
from typing import Any, cast
from uuid import UUID

import discord
import httpx
from discord import app_commands
from discord.ext import commands

LIKELY_SECRET_RE = re.compile(
    r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S+|"
    r"\b[A-Za-z0-9_/\-+=]{32,}\b",
)


def _embed(title: str, description: str, *, color: int = 0x0969FF) -> discord.Embed:
    embed = discord.Embed(title=title, description=description, color=color)
    embed.set_footer(text="Aegis keeps credentials out of public Discord messages.")
    return embed


class SecurityCog(commands.GroupCog, name="security"):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @property
    def api(self) -> Any:
        return cast(Any, self.bot).api

    def _payload(self, interaction: discord.Interaction, **extra: object) -> dict[str, object]:
        return {"discord_user_id": interaction.user.id, **extra}

    async def _post(self, path: str, payload: dict[str, object]) -> dict[str, Any]:
        try:
            return cast(dict[str, Any], await self.api.post_internal(path, payload))
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text
            raise RuntimeError(f"Aegis API returned {exc.response.status_code}: {detail}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Could not reach the Aegis API: {exc}") from exc

    async def _send_error(self, interaction: discord.Interaction, message: str) -> None:
        embed = _embed("Aegis action failed", message, color=0xFF314F)
        if interaction.response.is_done():
            await interaction.followup.send(embed=embed, ephemeral=True)
        else:
            await interaction.response.send_message(embed=embed, ephemeral=True)

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

    @app_commands.command(name="overview", description="Show your Aegis security overview")
    async def overview(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/overview", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        factors = data.get("factors", [])
        factor_count = len(factors) if isinstance(factors, list) else 0
        embed = _embed("Aegis Security Overview", "Your current Aegis account protection status.")
        embed.add_field(name="MFA factors", value=str(factor_count), inline=True)
        embed.add_field(name="Recovery codes", value=str(data.get("recovery_codes_remaining", 0)), inline=True)
        embed.add_field(name="Trusted devices", value=str(data.get("trusted_devices", 0)), inline=True)
        embed.add_field(name="Active sessions", value=str(data.get("active_sessions", 0)), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="setup-authenticator", description="Start authenticator-app setup in Discord")
    async def setup_authenticator(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/totp/start", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        qr_png = base64.b64decode(str(data["qr_png_base64"]))
        file = discord.File(BytesIO(qr_png), filename="aegis-authenticator-qr.png")
        embed = _embed(
            "Authenticator setup started",
            "Scan the attached QR code with your authenticator app, then run "
            "`/security verify-authenticator` with the enrollment ID and current 6-digit code.",
            color=0x13B769,
        )
        embed.add_field(name="Enrollment ID", value=f"`{data['enrollment_id']}`", inline=False)
        embed.add_field(name="Expires", value=str(data["expires_at"]), inline=False)
        embed.add_field(name="Warning", value=str(data["warning"]), inline=False)
        await interaction.followup.send(embed=embed, file=file, ephemeral=True)

    @app_commands.command(name="verify-authenticator", description="Finish authenticator setup with a 6-digit code")
    @app_commands.describe(enrollment_id="Enrollment ID from setup-authenticator", code="Current 6-digit TOTP code")
    async def verify_authenticator(self, interaction: discord.Interaction, enrollment_id: str, code: str) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            UUID(enrollment_id)
            data = await self._post(
                "/api/v1/internal/bot/totp/verify",
                self._payload(interaction, enrollment_id=enrollment_id, code=code),
            )
        except (ValueError, RuntimeError) as exc:
            await self._send_error(interaction, str(exc))
            return
        codes = data.get("recovery_codes", [])
        code_block = "\n".join(str(item) for item in codes) if isinstance(codes, list) else ""
        embed = _embed(
            "Authenticator enabled",
            "Your authenticator factor is active. Save these recovery codes offline; they are shown once.",
            color=0x13B769,
        )
        embed.add_field(name="Factor ID", value=f"`{data['factor_id']}`", inline=False)
        if code_block:
            embed.add_field(name="Recovery codes", value=f"```text\n{code_block}\n```", inline=False)
        embed.add_field(name="Warning", value=str(data.get("warning", "")), inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="factors", description="List your configured MFA factors")
    async def factors(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/factors", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        factors = data.get("factors", [])
        embed = _embed("MFA Factors", "Configured authentication factors for your Aegis account.")
        if isinstance(factors, list) and factors:
            for factor in factors[:10]:
                embed.add_field(
                    name=f"{factor.get('name', 'Factor')} ({factor.get('type', 'unknown')})",
                    value=f"Status: `{factor.get('status', 'unknown')}`\nID: `{factor.get('id', '')}`",
                    inline=False,
                )
        else:
            embed.description = "No MFA factors are configured yet. Run `/security setup-authenticator`."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="recovery-codes", description="Show recovery-code status")
    async def recovery_codes(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/recovery-codes/status", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        embed = _embed("Recovery Codes", f"Unused recovery codes remaining: `{data.get('unused_count', 0)}`")
        embed.add_field(
            name="Need a new set?",
            value="Run `/security generate-recovery-codes`. Save them offline and delete the Discord response after.",
            inline=False,
        )
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="generate-recovery-codes", description="Generate a new recovery-code set")
    async def generate_recovery_codes(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/recovery-codes/generate", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        codes = data.get("recovery_codes", [])
        code_block = "\n".join(str(item) for item in codes) if isinstance(codes, list) else ""
        embed = _embed("New recovery codes", "These codes are shown once. Store them offline.", color=0xFFB020)
        embed.add_field(name="Codes", value=f"```text\n{code_block}\n```", inline=False)
        embed.add_field(name="Warning", value=str(data.get("warning", "")), inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="challenge", description="Create an MFA challenge")
    async def challenge(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/challenge/start", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        embed = _embed("MFA challenge created", "Verify it with `/security verify-challenge`.")
        embed.add_field(name="Challenge ID", value=f"`{data['challenge_id']}`", inline=False)
        embed.add_field(name="Expires", value=str(data["expires_at"]), inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="verify-challenge", description="Verify an MFA challenge with TOTP")
    @app_commands.describe(challenge_id="Challenge ID from /security challenge", code="Current 6-digit TOTP code")
    async def verify_challenge(self, interaction: discord.Interaction, challenge_id: str, code: str) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            UUID(challenge_id)
            data = await self._post(
                "/api/v1/internal/bot/challenge/verify-totp",
                self._payload(interaction, challenge_id=challenge_id, code=code),
            )
        except (ValueError, RuntimeError) as exc:
            await self._send_error(interaction, str(exc))
            return
        embed = _embed("Challenge verified", "Aegis issued a step-up grant for this action.", color=0x13B769)
        embed.add_field(name="Grant ID", value=f"`{data['grant_id']}`", inline=False)
        embed.add_field(name="Assurance", value=f"`{data['assurance_level']}`", inline=True)
        embed.add_field(name="Expires", value=str(data["expires_at"]), inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="trusted-devices", description="List trusted devices")
    async def trusted_devices(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/devices", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        devices = data.get("devices", [])
        embed = _embed("Trusted Devices", "Devices trusted for Aegis step-up flows.")
        if isinstance(devices, list) and devices:
            for device in devices[:10]:
                embed.add_field(
                    name=str(device.get("name", "Device")),
                    value=(
                        f"Platform: `{device.get('platform') or 'unknown'}`\n"
                        f"Risk: `{device.get('risk_state', 'unknown')}`\n"
                        f"ID: `{device.get('id', '')}`"
                    ),
                    inline=False,
                )
        else:
            embed.description = "No trusted devices are registered yet."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="sessions", description="List recent sessions")
    async def sessions(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/sessions", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        sessions = data.get("sessions", [])
        embed = _embed("Sessions", "Recent Aegis sessions.")
        if isinstance(sessions, list) and sessions:
            for session in sessions[:10]:
                state = "active" if session.get("active") else "inactive"
                embed.add_field(
                    name=f"Session {str(session.get('id', ''))[:8]}",
                    value=f"State: `{state}`\nExpires: `{session.get('expires_at', '')}`",
                    inline=False,
                )
        else:
            embed.description = "No sessions found."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="revoke-sessions", description="Show sessions you can revoke")
    async def revoke_sessions(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/sessions", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        sessions = data.get("sessions", [])
        embed = _embed("Revoke Sessions", "Use these session IDs with the API/client revocation flow.")
        if isinstance(sessions, list) and sessions:
            for session in sessions[:10]:
                state = "active" if session.get("active") else "inactive"
                embed.add_field(
                    name=f"Session {str(session.get('id', ''))[:8]}",
                    value=f"State: `{state}`\nID: `{session.get('id', '')}`",
                    inline=False,
                )
        else:
            embed.description = "No sessions found."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="recent-activity", description="Show recent security activity")
    async def recent_activity(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/events", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        events = data.get("events", [])
        embed = _embed("Recent Security Activity", "Latest Aegis security events.")
        if isinstance(events, list) and events:
            for event in events[:10]:
                embed.add_field(
                    name=str(event.get("type", "event")),
                    value=f"At: `{event.get('created_at', '')}`",
                    inline=False,
                )
        else:
            embed.description = "No security events found yet."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="activity", description="Show recent security activity")
    async def activity(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/events", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        events = data.get("events", [])
        embed = _embed("Recent Security Activity", "Latest Aegis security events.")
        if isinstance(events, list) and events:
            for event in events[:10]:
                embed.add_field(name=str(event.get("type", "event")), value=f"At: `{event.get('created_at', '')}`")
        else:
            embed.description = "No security events found yet."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="revoke-device", description="Show trusted devices you can revoke")
    async def revoke_device(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/devices", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        devices = data.get("devices", [])
        embed = _embed("Revoke Device", "Use these device IDs with the API/client revocation flow.")
        if isinstance(devices, list) and devices:
            for device in devices[:10]:
                embed.add_field(
                    name=str(device.get("name", "Device")),
                    value=f"Risk: `{device.get('risk_state', 'unknown')}`\nID: `{device.get('id', '')}`",
                    inline=False,
                )
        else:
            embed.description = "No trusted devices are registered yet."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="disable-factor", description="Show MFA factors you can disable")
    async def disable_factor(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        try:
            data = await self._post("/api/v1/internal/bot/factors", self._payload(interaction))
        except RuntimeError as exc:
            await self._send_error(interaction, str(exc))
            return
        factors = data.get("factors", [])
        embed = _embed("Disable Factor", "Use these factor IDs with the API/client disable flow.")
        if isinstance(factors, list) and factors:
            for factor in factors[:10]:
                embed.add_field(
                    name=f"{factor.get('name', 'Factor')} ({factor.get('type', 'unknown')})",
                    value=f"Status: `{factor.get('status', 'unknown')}`\nID: `{factor.get('id', '')}`",
                    inline=False,
                )
        else:
            embed.description = "No MFA factors are configured yet."
        await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="setup-passkey", description="Show passkey setup status")
    async def setup_passkey(self, interaction: discord.Interaction) -> None:
        embed = _embed(
            "Passkey setup",
            "Passkey ceremonies require a browser or platform authenticator prompt. "
            "Inside Discord, use `/security factors`, `/security challenge`, and "
            "`/security verify-challenge` for active MFA flows.",
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="report-login", description="Report a suspicious login")
    async def report_login(self, interaction: discord.Interaction) -> None:
        embed = _embed(
            "Suspicious login response",
            "Run `/security sessions` to inspect sessions, `/security recent-activity` to inspect events, "
            "and rotate your authenticator or recovery codes if anything looks wrong.",
            color=0xFFB020,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="alerts", description="Show alert guidance")
    async def alerts(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            embed=_embed("Security Alerts", "Security alerts are delivered without secret contents."),
            ephemeral=True,
        )

    @app_commands.command(name="recovery", description="Explain recovery material")
    async def recovery(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            embed=_embed(
                "Recovery Material",
                "Recovery material is generated locally. Losing both it and your master password "
                "can make the vault unrecoverable.",
            ),
            ephemeral=True,
        )

    @app_commands.command(name="report", description="Report a security issue")
    async def report(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            embed=_embed(
                "Report Security Issue",
                "Report vulnerabilities through SECURITY.md. Do not include live secrets.",
            ),
            ephemeral=True,
        )
