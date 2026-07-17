from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["aegis-verify-ui"])

def _verify_html(active_section: str = "dashboard") -> str:
    section_titles = {
        "authenticator": "Authenticator apps",
        "passkeys": "Passkeys",
        "factors": "Security factors",
        "recovery-codes": "Recovery codes",
        "devices": "Trusted devices",
        "activity": "Recent security events",
        "sessions": "Sessions",
        "report-login": "Report suspicious login",
        "dashboard": "Account protection dashboard",
    }
    title = section_titles.get(active_section, "Account protection dashboard")
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aegis Verify</title>
  <style>
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #18202a; }
    main { max-width: 1120px; margin: 0 auto; padding: 32px 20px 48px; }
    header { display: flex; justify-content: space-between; align-items: center; gap: 20px; }
    h1 { font-size: 32px; margin: 0; letter-spacing: 0; }
    h2 { font-size: 18px; margin: 0 0 14px; }
    p { color: #4b5563; line-height: 1.55; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-top: 24px; }
    .panel { background: #fff; border: 1px solid #d8dee8; border-radius: 8px; padding: 18px; }
    .status { font-weight: 700; color: #126f44; }
    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
    button { border: 1px solid #1f2937; background: #1f2937; color: white; border-radius: 6px; padding: 9px 12px; }
    button.secondary { background: white; color: #1f2937; }
    ul { padding-left: 18px; color: #374151; }
    @media (prefers-color-scheme: dark) {
      body { background: #101418; color: #eef2f7; }
      .panel { background: #171d24; border-color: #2f3946; }
      p, ul { color: #bdc7d5; }
      button.secondary { background: #171d24; color: #eef2f7; border-color: #526071; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>Aegis Verify</h1>
        <p class="status">__AEGIS_VERIFY_TITLE__</p>
      </div>
      <button>Refresh</button>
    </header>
    <section class="grid">
      <article class="panel">
        <h2>Recommended action</h2>
        <p>Passkeys provide stronger phishing resistance. Add a passkey or hardware security key when available.</p>
        <div class="actions"><button>Add passkey</button><button class="secondary">Use authenticator app</button></div>
      </article>
      <article class="panel">
        <h2>Authenticator apps</h2>
        <p>Scan this code using Google Authenticator or another compatible app during setup.</p>
        <p>Aegis will never ask you to paste this setup key into Discord.</p>
      </article>
      <article class="panel">
        <h2>Recovery codes</h2>
        <p>Recovery codes are shown once and must be stored offline. They are not backup passwords.</p>
        <div class="actions"><button class="secondary">Generate new set</button></div>
      </article>
      <article class="panel">
        <h2>Trusted devices</h2>
        <p>Trusted devices expire and require periodic reverification. Revoke devices you no longer recognize.</p>
      </article>
      <article class="panel">
        <h2>Recent security events</h2>
        <ul>
          <li>TOTP enrollment started</li>
          <li>Passkey registered</li>
          <li>Recovery code used</li>
        </ul>
      </article>
      <article class="panel">
        <h2>Security boundaries</h2>
        <p>
          TOTP protects your Aegis account but does not encrypt your vault.
          Your vault master password remains separate.
        </p>
      </article>
    </section>
  </main>
</body>
</html>""".replace("__AEGIS_VERIFY_TITLE__", title)


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
            "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        },
    )
