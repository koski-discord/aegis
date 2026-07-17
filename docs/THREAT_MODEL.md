# Aegis Threat Model

Aegis is designed so the server stores ciphertext and operational metadata, not plaintext vault contents.

## Trusted Components

- The user's local machine while the Aegis client is running.
- The local client binary and its dependencies.
- The user's chosen master password strength.
- The operating system clipboard and terminal environment.

## Not Trusted With Plaintext

- Discord messages, slash commands, embeds, modals, buttons, and direct messages.
- The Aegis API, database, Redis, logs, and administrators.
- Discord server administrators.
- Database and API operators.

## Server Compromise

A server compromise may expose ciphertext, encrypted metadata, salts, KDF parameters, timestamps, account relationships, session metadata, IP-related infrastructure logs, and security-event history. Weak master passwords remain vulnerable to offline guessing if encrypted vault data is stolen.

## Limitations

Python cannot guarantee perfect memory zeroization. Clipboard clearing is best-effort. Aegis has not received professional security review. Losing the master password and recovery material can make the vault permanently inaccessible.

