# Aegis Verify Authentication

Aegis Verify is the multifactor authentication subsystem inside Aegis. It protects account and security workflows; it does not encrypt or recover a user's zero-knowledge vault.

## Architecture

Aegis Verify supports authenticator-app TOTP, passkeys and hardware security keys through WebAuthn/FIDO2, single-use recovery codes, trusted devices, existing-device approval, and short-lived step-up grants. Each verification challenge is bound to a user, purpose, expiration time, attempt limit, and requested resource when applicable.

Sensitive actions declare an internal assurance level:

- `aal1`: primary account authentication.
- `aal2`: primary authentication plus TOTP or recovery-code verification.
- `aal3`: primary authentication plus a passkey or hardware security key.

These labels are Aegis policy names, not formal certification claims.

## Authenticator Apps

TOTP follows RFC 6238 using PyOTP. The default profile is compatible with Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden Authenticator, Aegis Authenticator, Authy-compatible TOTP apps, and other standards-compliant authenticator apps:

- Issuer: `Aegis`
- Digits: `6`
- Period: `30`
- Algorithm: `SHA1` for broad compatibility

Google Authenticator compatibility does not mean Google operates or receives Aegis authentication data.

## QR Code Sensitivity

The QR code contains the shared TOTP enrollment secret. Anyone who copies the QR code or manual setup key may be able to generate valid codes. Aegis never sends QR codes, setup keys, TOTP codes, or recovery codes through Discord.

QR responses use `Cache-Control: no-store, private` and are intended only for the authenticated Aegis portal or trusted local client. Enrollment secrets expire quickly and are invalidated after completion or cancellation.

## TOTP Server Trust Limitation

The server must briefly decrypt a TOTP secret to verify a submitted code. This is different from the Aegis password vault: TOTP is not zero-knowledge in the same way as encrypted vault records. TOTP protects the Aegis account, but it does not encrypt the user's vault.

TOTP is also vulnerable to real-time phishing. Passkeys and hardware security keys should be preferred when available.

## Secret Storage And Key Rotation

TOTP secrets are encrypted at rest with envelope encryption. A dedicated MFA key-encryption key wraps a per-record data-encryption key. Associated data binds the ciphertext to the account ID, factor ID, factor type, and encryption version.

MFA encryption keys must be kept outside PostgreSQL and loaded from protected configuration or a secret manager. Key versions are stored with each record so future rotation can decrypt with an old key and re-encrypt with the current key without requiring users to reenroll.

## Recovery Codes

Recovery codes contain at least 128 bits of random entropy, are shown once, and are stored only as protected hashes. They must be kept offline. Recovery codes are single-use and are replaced as a complete set when regenerated.

Do not store recovery codes in Discord, email, screenshots, chat logs, or source control. Losing every factor may result in account loss.

## Passkeys And Security Keys

Passkeys and hardware security keys use WebAuthn/FIDO2 through a maintained library. Aegis stores public credential information only: credential ID, public key, user handle, sign count, transport hints, attachment metadata when available, friendly name, and timestamps. Aegis never stores a WebAuthn private key.

Registration and authentication ceremonies validate relying-party ID, expected origin, challenge, user presence, user verification, credential ownership, expiration, and one-time challenge consumption.

## Trusted Devices And Approval

Trusted devices use server-side records with expiration and revocation. They are not permanent MFA bypasses. Existing-device approval is reserved for sensitive actions and must show a matching code, require local confirmation, expire quickly, and be single-use.

Browser fingerprinting alone is not sufficient proof of device identity.

## Account Recovery

Supported recovery paths are recovery code plus primary authentication, passkey or hardware security key, approval from an existing trusted device, or a delayed recovery process. Delayed recovery must notify trusted devices and security channels, apply a waiting period, and restrict destructive actions.

Recovering the Aegis account cannot recover a forgotten vault master password.

## Clock Synchronization

TOTP verification uses server UTC time. Production deployments must use reliable time synchronization, monitor drift, and treat unsafe drift as an MFA service health failure. Aegis must not widen the TOTP validation window to hide clock problems.

## Administrative Boundaries

Administrators, bot owners, moderators, and support staff must not reveal TOTP secrets, QR codes, recovery-code values, WebAuthn challenges, cookies, session tokens, or authorization headers. Security events must record actions without storing secret values.

## Incident Response

If MFA-secret exposure is suspected:

1. Disable or replace the affected factor after strong reauthentication.
2. Regenerate recovery codes.
3. Revoke risky sessions and trusted devices.
4. Review security events.
5. Rotate MFA encryption keys if server-side key exposure is possible.
6. Document the exposure and notify affected users through configured security channels.

