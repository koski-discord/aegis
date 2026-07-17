# Security Policy

Report vulnerabilities privately to the maintainers. Do not open public issues containing exploit details, live secrets, tokens, recovery material, or user data.

Aegis is an early open-source implementation and has not received a professional security audit. Use established, independently audited password managers for highly sensitive or production-critical credentials until this project has been reviewed.

## Core Rule

Aegis must never receive plaintext credentials. If you find a path where a password, master password, recovery key, or derived encryption key reaches Discord, the API, logs, URLs, exceptions, or storage, treat it as a critical vulnerability.

## Expected Response

Maintainers should acknowledge reports within 72 hours, investigate in a private branch, publish fixes with tests, and credit reporters when safe to do so.

