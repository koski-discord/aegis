# ruff: noqa: E501
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["aegis-verify-ui"])

ASSET_DIR = Path(__file__).resolve().parents[1] / "assets"
LOGO_PATH = ASSET_DIR / "aegis-logo.png"

SECTION_TITLES = {
    "authenticator": "Authenticator (TOTP)",
    "passkeys": "Passkeys",
    "factors": "MFA Overview",
    "recovery-codes": "Recovery Codes",
    "devices": "Devices",
    "activity": "Security Events",
    "sessions": "Sessions",
    "report-login": "Report Suspicious Login",
    "dashboard": "Overview",
}

ENDPOINT_GROUPS = [
    (
        "Health",
        "heart",
        [
            ("GET", "/api/v1/health"),
            ("GET", "/api/v1/ready"),
            ("GET", "/api/v1/version"),
        ],
    ),
    (
        "Auth",
        "lock",
        [
            ("GET", "/api/v1/discord/login"),
            ("GET", "/api/v1/discord/callback"),
            ("POST", "/api/v1/device"),
            ("POST", "/api/v1/device/dev-confirm/{device_code}"),
            ("POST", "/api/v1/device/token"),
            ("GET", "/api/v1/me"),
            ("GET", "/api/v1/sessions"),
            ("DELETE", "/api/v1/sessions/{session_id}"),
        ],
    ),
    (
        "Vault",
        "folder",
        [
            ("POST", "/api/v1/vault"),
            ("GET", "/api/v1/vault"),
            ("POST", "/api/v1/vault/records"),
            ("GET", "/api/v1/vault/records"),
            ("GET", "/api/v1/vault/records/{record_id}"),
            ("PUT", "/api/v1/vault/records/{record_id}"),
            ("DELETE", "/api/v1/vault/records/{record_id}"),
            ("GET", "/api/v1/vault/backup"),
            ("POST", "/api/v1/vault/backup"),
        ],
    ),
    (
        "MFA / Aegis Verify",
        "shield",
        [
            ("POST", "/api/v1/mfa/totp/enrollments"),
            ("GET", "/api/v1/mfa/totp/enrollments/{enrollment_id}/qr"),
            ("POST", "/api/v1/mfa/totp/enrollments/{enrollment_id}/verify"),
            ("DELETE", "/api/v1/mfa/totp/enrollments/{enrollment_id}"),
            ("POST", "/api/v1/mfa/challenges"),
            ("POST", "/api/v1/mfa/challenges/{challenge_id}/totp"),
            ("POST", "/api/v1/mfa/challenges/{challenge_id}/recovery-code"),
            ("POST", "/api/v1/mfa/recovery-codes/generate"),
            ("GET", "/api/v1/mfa/recovery-codes/status"),
            ("GET", "/api/v1/mfa/factors"),
            ("DELETE", "/api/v1/mfa/factors/{factor_id}"),
        ],
    ),
    (
        "Passkeys / WebAuthn",
        "key",
        [
            ("POST", "/api/v1/webauthn/registration/options"),
            ("POST", "/api/v1/webauthn/registration/verify"),
            ("POST", "/api/v1/webauthn/authentication/options"),
            ("POST", "/api/v1/webauthn/authentication/verify"),
        ],
    ),
    (
        "Devices",
        "monitor",
        [
            ("GET", "/api/v1/devices"),
            ("PATCH", "/api/v1/devices/{device_id}"),
            ("DELETE", "/api/v1/devices/{device_id}"),
            ("POST", "/api/v1/device-approvals"),
            ("POST", "/api/v1/device-approvals/{approval_id}/approve"),
            ("POST", "/api/v1/device-approvals/{approval_id}/reject"),
        ],
    ),
    (
        "Security / Account",
        "user",
        [
            ("GET", "/api/v1/security/events"),
            ("DELETE", "/api/v1/account"),
        ],
    ),
]

ICONS = {
    "account": '<svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M5 21a7 7 0 0 1 14 0"/></svg>',
    "backup": '<svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/></svg>',
    "challenge": '<svg viewBox="0 0 24 24"><path d="M9 7H5a2 2 0 0 0-2 2v2"/><path d="M15 17h4a2 2 0 0 0 2-2v-2"/><path d="m7 17-4-4 4-4"/><path d="m17 7 4 4-4 4"/></svg>',
    "doc": '<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h5"/></svg>',
    "events": '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>',
    "folder": '<svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
    "heart": '<svg viewBox="0 0 24 24"><path d="M20.8 4.6a5.5 5.5 0 0 0-7.8 0L12 5.6l-1-1a5.5 5.5 0 1 0-7.8 7.8l1 1L12 21l7.8-7.6 1-1a5.5 5.5 0 0 0 0-7.8"/></svg>',
    "key": '<svg viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8-8"/><path d="m15 6 3 3"/><path d="m17 4 3 3"/></svg>',
    "lock": '<svg viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    "menu": '<svg viewBox="0 0 24 24"><path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/></svg>',
    "monitor": '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/><path d="M12 16v4"/></svg>',
    "moon": '<svg viewBox="0 0 24 24"><path d="M21 12.8A8.5 8.5 0 1 1 11.2 3 6.5 6.5 0 0 0 21 12.8z"/></svg>',
    "plus": '<svg viewBox="0 0 24 24"><path d="M12 5v14"/><path d="M5 12h14"/></svg>',
    "records": '<svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8"/><path d="M8 11h8"/><path d="M8 15h5"/></svg>',
    "session": '<svg viewBox="0 0 24 24"><path d="M3 11h18"/><path d="M3 17h18"/><path d="m7 7 5-5 5 5"/><path d="m7 21 5-5 5 5"/></svg>',
    "shield": '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="M12 8v5"/><path d="M12 17h.01"/></svg>',
    "totp": '<svg viewBox="0 0 24 24"><path d="M12 8v5l3 2"/><circle cx="12" cy="12" r="9"/></svg>',
    "user": '<svg viewBox="0 0 24 24"><path d="M20 21a8 8 0 0 0-16 0"/><circle cx="12" cy="7" r="4"/></svg>',
}


def _icon(name: str) -> str:
    return ICONS[name]


def _endpoint_cards() -> str:
    cards = []
    for title, icon, endpoints in ENDPOINT_GROUPS:
        rows = "\n".join(
            f'<div class="endpoint"><strong>{method}</strong><span>{path}</span></div>' for method, path in endpoints
        )
        cards.append(
            f"""
            <article class="endpoint-card">
              <h3><span class="icon card-icon">{_icon(icon)}</span>{title}</h3>
              <div class="endpoint-list">{rows}</div>
            </article>
            """
        )
    return "\n".join(cards)


def _nav_item(label: str, href: str, icon: str, active_section: str, section: str) -> str:
    active = " active" if active_section == section else ""
    return f'<a class="nav-link{active}" href="{href}"><span class="icon">{_icon(icon)}</span>{label}</a>'


def _verify_html(active_section: str = "dashboard") -> str:
    title = SECTION_TITLES.get(active_section, "Overview")
    endpoint_cards = _endpoint_cards()
    nav_items = "\n".join(
        [
            _nav_item("Overview", "/verify", "shield", active_section, "dashboard"),
            '<p class="nav-label">Auth</p>',
            _nav_item("Login", "/api/v1/discord/login", "challenge", active_section, "login"),
            _nav_item("Sessions", "/verify/sessions", "session", active_section, "sessions"),
            _nav_item("Devices", "/verify/devices", "monitor", active_section, "devices"),
            '<p class="nav-label">Vault</p>',
            _nav_item("My Vault", "/api/v1/vault", "folder", active_section, "vault"),
            _nav_item("Records", "/api/v1/vault/records", "records", active_section, "records"),
            _nav_item("Backup", "/api/v1/vault/backup", "backup", active_section, "backup"),
            '<p class="nav-label">Aegis Verify (MFA)</p>',
            _nav_item("MFA Overview", "/verify/factors", "shield", active_section, "factors"),
            _nav_item("Authenticator (TOTP)", "/verify/authenticator", "totp", active_section, "authenticator"),
            _nav_item("Challenges", "/verify/challenges", "challenge", active_section, "challenges"),
            _nav_item("Recovery Codes", "/verify/recovery-codes", "doc", active_section, "recovery-codes"),
            _nav_item("Passkeys", "/verify/passkeys", "key", active_section, "passkeys"),
            '<p class="nav-label">Security</p>',
            _nav_item("Security Events", "/verify/activity", "events", active_section, "activity"),
            _nav_item("Account", "/api/v1/account", "account", active_section, "account"),
            '<p class="nav-label">Developer</p>',
            _nav_item("API Docs", "/docs", "doc", active_section, "docs"),
            _nav_item("OpenAPI JSON", "/openapi.json", "records", active_section, "openapi"),
        ]
    )
    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aegis Verify</title>
  <style>
    :root {
      color-scheme: light;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      --nav: #061a36;
      --nav-2: #00112a;
      --blue: #0969ff;
      --blue-dark: #002d9b;
      --ink: #081b39;
      --muted: #667694;
      --line: #dfe7f2;
      --panel: #ffffff;
      --soft: #f6f9fe;
      --good: #13b769;
      --warn: #ff314f;
    }
    * { box-sizing: border-box; }
    body { margin: 0; background: #f8fbff; color: var(--ink); }
    a { color: inherit; text-decoration: none; }
    .shell { min-height: 100vh; display: grid; grid-template-columns: 280px minmax(0, 1fr); }
    .sidebar {
      position: sticky; top: 0; height: 100vh; padding: 28px 20px;
      background: radial-gradient(circle at 30% 0%, #073d86 0, var(--nav) 32%, var(--nav-2) 100%);
      color: #e8f1ff; display: flex; flex-direction: column; gap: 24px;
    }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 900; font-size: 28px; letter-spacing: 5px; }
    .brand img { width: 46px; height: 46px; object-fit: contain; }
    .collapse { margin-left: auto; color: #8facd3; font-size: 18px; }
    .nav { display: flex; flex-direction: column; gap: 7px; overflow-y: auto; padding-right: 2px; }
    .nav-label { margin: 16px 8px 8px; color: #8ea4c2; text-transform: uppercase; font-size: 12px; letter-spacing: .05em; }
    .nav-link {
      display: flex; align-items: center; gap: 12px; min-height: 46px; padding: 0 12px;
      border-radius: 8px; color: #cbd9ee; font-weight: 650; font-size: 15px;
    }
    .nav-link.active, .nav-link:hover { background: var(--blue); color: white; }
    .help, .user-card {
      border: 1px solid rgba(255,255,255,.16); border-radius: 8px; padding: 16px;
      background: rgba(255,255,255,.04);
    }
    .help { margin-top: auto; }
    .help h3, .user-card strong { margin: 0 0 8px; font-size: 15px; color: white; }
    .help p, .user-card span { margin: 0; color: #b7c8e5; font-size: 13px; line-height: 1.5; }
    .help .doc-button {
      margin-top: 14px; display: flex; align-items: center; justify-content: center; gap: 8px;
      height: 42px; border-radius: 6px; background: rgba(9,105,255,.16); color: white; font-weight: 800;
    }
    .user-card { display: flex; align-items: center; gap: 10px; }
    .user-card img { width: 42px; height: 42px; object-fit: contain; }
    .main { padding: 28px 28px 40px; min-width: 0; }
    .topbar { height: 48px; display: flex; align-items: center; gap: 22px; margin-bottom: 22px; }
    .hamburger { width: 28px; color: var(--ink); }
    .topbar h1 { margin: 0; font-size: 24px; letter-spacing: 0; }
    .system-pill {
      margin-left: auto; display: flex; align-items: center; gap: 8px; border: 1px solid var(--line);
      border-radius: 999px; padding: 9px 15px; background: white; font-size: 13px; font-weight: 800;
    }
    .system-pill i { width: 8px; height: 8px; display: block; border-radius: 999px; background: var(--good); }
    .theme-pill { display: flex; align-items: center; gap: 7px; border-radius: 999px; padding: 8px 10px; background: #edf4ff; color: #6b7891; }
    .hero {
      background:
        linear-gradient(135deg, rgba(9,105,255,.95), rgba(0,36,111,.98)),
        radial-gradient(circle at top right, rgba(255,255,255,.2), transparent 32%);
      color: white; border-radius: 8px; padding: 48px 62px 36px; overflow: hidden; position: relative;
      box-shadow: 0 18px 46px rgba(1, 47, 126, .22);
    }
    .hero:after {
      content: ""; position: absolute; inset: 0;
      background: linear-gradient(135deg, transparent 60%, rgba(255,255,255,.12) 60.2%, transparent 60.7%);
      opacity: .7; pointer-events: none;
    }
    .hero-head { display: flex; align-items: center; gap: 26px; position: relative; z-index: 1; }
    .hero img { width: 106px; height: 106px; object-fit: contain; filter: drop-shadow(0 12px 18px rgba(0,0,0,.24)); }
    .hero h2 { margin: 0 0 8px; font-size: 30px; }
    .hero p { margin: 0; color: #d8e8ff; font-size: 17px; }
    .stats {
      margin-top: 36px; padding-top: 28px; border-top: 1px solid rgba(255,255,255,.16);
      display: grid; grid-template-columns: repeat(5, 1fr); gap: 18px; position: relative; z-index: 1;
    }
    .stat { padding-left: 24px; border-left: 1px solid rgba(255,255,255,.18); }
    .stat:first-child { border-left: 0; padding-left: 0; }
    .stat span { display: block; color: #a6d3ff; font-size: 14px; }
    .stat strong { display: block; margin-top: 8px; font-size: 29px; color: white; }
    .stat .secure { color: #2df284; }
    .grid-2 { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(320px, .75fr); gap: 22px; margin-top: 26px; }
    .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 26px; box-shadow: 0 12px 30px rgba(23,49,84,.05); }
    .panel-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .panel h2 { margin: 0; font-size: 20px; }
    .muted { color: var(--muted); }
    .quick-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
    .quick {
      min-height: 112px; border: 1px solid var(--line); border-radius: 8px; background: white; display: grid;
      place-items: center; align-content: center; gap: 12px; font-weight: 800; color: var(--ink);
    }
    .quick .icon { color: var(--blue); width: 28px; height: 28px; }
    .security-status { display: flex; align-items: center; justify-content: center; gap: 32px; min-height: 216px; }
    .ring {
      width: 118px; height: 118px; border: 9px solid var(--blue); border-radius: 999px; display: grid; place-items: center;
      box-shadow: inset 0 0 0 12px #f1f6ff;
    }
    .ring img { width: 70px; height: 70px; object-fit: contain; }
    .status-copy strong { color: var(--good); font-size: 20px; }
    .status-copy p { max-width: 230px; line-height: 1.55; }
    .link { color: var(--blue); font-weight: 800; }
    .endpoints { margin-top: 26px; }
    .endpoint-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; }
    .endpoint-card { border: 1px solid var(--line); border-radius: 8px; padding: 20px; min-width: 0; }
    .endpoint-card h3 { margin: 0 0 17px; display: flex; align-items: center; gap: 10px; font-size: 17px; }
    .card-icon { color: var(--blue); }
    .endpoint { display: grid; grid-template-columns: 70px minmax(0, 1fr); gap: 12px; align-items: start; padding: 8px 0; }
    .endpoint strong { font-size: 12px; color: #13294b; }
    .endpoint span { min-width: 0; overflow-wrap: anywhere; color: #273b60; font-size: 13px; line-height: 1.35; }
    .events { margin-top: 26px; }
    .event-row, .session-row, .factor-row {
      display: grid; grid-template-columns: 42px minmax(0, 1fr) auto auto; gap: 14px; align-items: center;
      border-top: 1px solid var(--line); padding: 16px 0;
    }
    .event-row:first-of-type, .session-row:first-of-type, .factor-row:first-of-type { border-top: 0; }
    .event-row h3, .session-row h3, .factor-row h3 { margin: 0 0 4px; font-size: 14px; }
    .event-row p, .session-row p, .factor-row p { margin: 0; color: var(--muted); font-size: 13px; }
    .badge { min-width: 76px; text-align: center; border-radius: 6px; padding: 8px 10px; font-size: 12px; font-weight: 800; }
    .success { background: #e8fbf1; color: #0c9e58; }
    .info { background: #eef6ff; color: var(--blue); }
    .warning { background: #fff7e7; color: #c97b00; }
    .danger { color: var(--warn); }
    .bottom-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 22px; margin-top: 26px; }
    footer { margin: 36px 0 4px; display: flex; align-items: center; justify-content: space-between; color: #7890b4; font-size: 13px; }
    .footer-brand { display: flex; align-items: center; gap: 8px; margin: 0 auto; color: var(--blue); font-weight: 900; font-size: 22px; letter-spacing: 4px; }
    .footer-brand img { width: 38px; height: 38px; object-fit: contain; }
    .icon { width: 20px; height: 20px; display: inline-grid; place-items: center; flex: 0 0 auto; }
    .icon svg { width: 100%; height: 100%; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
    @media (max-width: 1100px) {
      .shell { grid-template-columns: 1fr; }
      .sidebar { position: relative; height: auto; }
      .grid-2, .bottom-grid { grid-template-columns: 1fr; }
      .endpoint-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 720px) {
      .main { padding: 18px; }
      .hero { padding: 28px; }
      .hero-head { align-items: flex-start; }
      .hero img { width: 78px; height: 78px; }
      .stats, .quick-grid, .endpoint-grid { grid-template-columns: 1fr; }
      .stat { border-left: 0; padding-left: 0; }
      .event-row, .session-row, .factor-row { grid-template-columns: 36px minmax(0, 1fr); }
      .badge, .event-row time { justify-self: start; grid-column: 2; }
      .system-pill, .theme-pill { display: none; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="sidebar">
      <div class="brand"><img src="/verify/assets/aegis-logo.png" alt="">AEGIS<span class="collapse">&lt;</span></div>
      <nav class="nav">__NAV_ITEMS__</nav>
      <section class="help">
        <h3>Need help?</h3>
        <p>Check our documentation or join the support server</p>
        <a class="doc-button" href="/docs">View Docs <span class="icon">__DOC_ICON__</span></a>
      </section>
      <section class="user-card">
        <img src="/verify/assets/aegis-logo.png" alt="">
        <div><strong>Aegis User</strong><span>user#0001</span></div>
      </section>
    </aside>
    <main class="main">
      <header class="topbar">
        <span class="icon hamburger">__MENU_ICON__</span>
        <h1>__PAGE_TITLE__</h1>
        <div class="system-pill"><span class="icon">__SHIELD_ICON__</span>All systems secure <i></i></div>
        <div class="theme-pill"><span class="icon">__MOON_ICON__</span><span class="icon">__SHIELD_ICON__</span></div>
      </header>
      <section class="hero">
        <div class="hero-head">
          <img src="/verify/assets/aegis-logo.png" alt="">
          <div>
            <h2>Welcome back to Aegis</h2>
            <p>Your data. Your keys. Your control.</p>
          </div>
        </div>
        <div class="stats">
          <div class="stat"><span>Vaults</span><strong>1</strong></div>
          <div class="stat"><span>Records</span><strong>24</strong></div>
          <div class="stat"><span>MFA Status</span><strong class="secure">Secure</strong></div>
          <div class="stat"><span>Devices</span><strong>3</strong></div>
          <div class="stat"><span>Active Sessions</span><strong>2</strong></div>
        </div>
      </section>
      <section class="grid-2">
        <article class="panel">
          <h2>Quick Actions</h2>
          <div class="quick-grid">
            <a class="quick" href="/api/v1/vault/records"><span class="icon">__PLUS_ICON__</span>Create Record</a>
            <a class="quick" href="/verify/authenticator"><span class="icon">__LOCK_ICON__</span>Add MFA Factor</a>
            <a class="quick" href="/api/v1/vault/backup"><span class="icon">__BACKUP_ICON__</span>Generate Backup</a>
            <a class="quick" href="/verify/sessions"><span class="icon">__SESSION_ICON__</span>View Sessions</a>
            <a class="quick" href="/verify/activity"><span class="icon">__EVENTS_ICON__</span>Security Events</a>
            <a class="quick" href="/api/v1/account"><span class="icon">__ACCOUNT_ICON__</span>Account Settings</a>
          </div>
        </article>
        <article class="panel">
          <h2>Security Status</h2>
          <div class="security-status">
            <div class="ring"><img src="/verify/assets/aegis-logo.png" alt=""></div>
            <div class="status-copy">
              <strong>Excellent</strong>
              <p class="muted">All security systems are active and protected.</p>
              <a class="link" href="/verify/activity">View security events -&gt;</a>
            </div>
          </div>
        </article>
      </section>
      <section class="panel endpoints">
        <div class="panel-title">
          <div><h2>Available Endpoints</h2><p class="muted">Explore all available API endpoints</p></div>
          <a class="link" href="/docs">View OpenAPI Docs</a>
        </div>
        <div class="endpoint-grid">__ENDPOINT_CARDS__</div>
      </section>
      <section class="panel events">
        <div class="panel-title"><h2>Recent Security Events</h2><a class="link" href="/verify/activity">View all events -&gt;</a></div>
        <div class="event-row"><span class="icon">__SHIELD_ICON__</span><div><h3>New login detected</h3><p>Windows &bull; Chrome &bull; New York, US</p></div><time>2 minutes ago</time><span class="badge success">Success</span></div>
        <div class="event-row"><span class="icon">__KEY_ICON__</span><div><h3>MFA challenge completed</h3><p>TOTP &bull; Challenge ID: ch_8f3a9d2e</p></div><time>4 minutes ago</time><span class="badge success">Success</span></div>
        <div class="event-row"><span class="icon">__MONITOR_ICON__</span><div><h3>New device authorized</h3><p>Aegis Desktop &bull; Windows 11</p></div><time>12 minutes ago</time><span class="badge info">Info</span></div>
        <div class="event-row"><span class="icon">__DOC_ICON__</span><div><h3>Vault backup created</h3><p>Manual backup &bull; 24 records</p></div><time>1 hour ago</time><span class="badge info">Info</span></div>
        <div class="event-row"><span class="icon danger">__CHALLENGE_ICON__</span><div><h3>Failed login attempt</h3><p>Unknown location</p></div><time>3 hours ago</time><span class="badge warning">Warning</span></div>
      </section>
      <section class="bottom-grid">
        <article class="panel">
          <div class="panel-title"><div><h2>Your Sessions</h2><p class="muted">Manage your active sessions</p></div><a class="link" href="/verify/sessions">View all sessions -&gt;</a></div>
          <div class="session-row"><span class="icon">__MONITOR_ICON__</span><div><h3>Windows &bull; Chrome <span class="badge info">Current</span></h3><p>New York, US &bull; 2 minutes ago</p></div></div>
          <div class="session-row"><span class="icon">__MONITOR_ICON__</span><div><h3>Aegis Desktop</h3><p>1 hour ago</p></div><span class="badge warning">Revoke</span></div>
          <div class="session-row"><span class="icon">__DOC_ICON__</span><div><h3>iPhone • Safari</h3><p>2 days ago</p></div><span class="badge warning">Revoke</span></div>
        </article>
        <article class="panel">
          <div class="panel-title"><div><h2>MFA Status</h2><p class="muted">Manage your authentication factors</p></div><a class="link" href="/verify/factors">Manage -&gt;</a></div>
          <div class="factor-row"><span class="icon">__TOTP_ICON__</span><div><h3>Authenticator App (TOTP)</h3><p>Added on May 20, 2024</p></div><span class="badge success">Active</span></div>
          <div class="factor-row"><span class="icon">__KEY_ICON__</span><div><h3>Passkey (Windows Hello)</h3><p>Added on May 18, 2024</p></div><span class="badge success">Active</span></div>
          <div class="factor-row"><span class="icon">__DOC_ICON__</span><div><h3>Recovery Codes</h3><p>8 of 10 remaining</p></div><span class="badge success">Available</span></div>
        </article>
      </section>
      <footer>
        <span></span>
        <div><div class="footer-brand"><img src="/verify/assets/aegis-logo.png" alt="">AEGIS</div><p>&copy; 2024 Aegis. All rights reserved.</p></div>
        <span>Version 1.0.0</span>
      </footer>
    </main>
  </div>
</body>
</html>"""
    replacements = {
        "__ACCOUNT_ICON__": _icon("account"),
        "__BACKUP_ICON__": _icon("backup"),
        "__CHALLENGE_ICON__": _icon("challenge"),
        "__DOC_ICON__": _icon("doc"),
        "__ENDPOINT_CARDS__": endpoint_cards,
        "__EVENTS_ICON__": _icon("events"),
        "__KEY_ICON__": _icon("key"),
        "__LOCK_ICON__": _icon("lock"),
        "__MENU_ICON__": _icon("menu"),
        "__MONITOR_ICON__": _icon("monitor"),
        "__MOON_ICON__": _icon("moon"),
        "__NAV_ITEMS__": nav_items,
        "__PAGE_TITLE__": title,
        "__PLUS_ICON__": _icon("plus"),
        "__SESSION_ICON__": _icon("session"),
        "__SHIELD_ICON__": _icon("shield"),
        "__TOTP_ICON__": _icon("totp"),
    }
    for key, value in replacements.items():
        html = html.replace(key, value)
    return html


@router.get("/verify/assets/aegis-logo.png", include_in_schema=False)
async def aegis_logo() -> FileResponse:
    return FileResponse(LOGO_PATH, media_type="image/png")


@router.get("/verify", response_class=HTMLResponse)
async def verify_dashboard() -> HTMLResponse:
    return _verify_response("dashboard")


@router.get("/verify/{active_section}", response_class=HTMLResponse)
async def verify_section(active_section: str) -> HTMLResponse:
    return _verify_response(active_section)


def _verify_response(active_section: str) -> HTMLResponse:
    return HTMLResponse(
        _verify_html(active_section),
        headers={
            "Cache-Control": "no-store, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": (
                "default-src 'self'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            ),
        },
    )
