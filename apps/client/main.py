import argparse
import asyncio
import getpass
import json
import os
import time
from contextlib import suppress
from pathlib import Path

import pyperclip

from apps.client.api.client import AegisApiClient, encrypted_payload_from_api
from apps.client.crypto import (
    DEFAULT_KDF_PARAMS,
    decrypt_record,
    derive_key,
    encrypt_record,
    generate_recovery_material,
)
from apps.client.crypto.vault import new_salt
from apps.client.models.records import LocalProfile, PlainRecord

PROFILE_PATH = Path(os.environ.get("AEGIS_CLIENT_PROFILE", "aegis.local.json"))


def load_profile() -> LocalProfile:
    if not PROFILE_PATH.exists():
        raise SystemExit("Run `aegis-client configure` first.")
    return LocalProfile.model_validate_json(PROFILE_PATH.read_text())


def save_profile(profile: LocalProfile) -> None:
    PROFILE_PATH.write_text(profile.model_dump_json(indent=2))
    with suppress(OSError):
        PROFILE_PATH.chmod(0o600)


def prompt_record(existing_label: str | None = None) -> PlainRecord:
    label = existing_label or input("Record label: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password (hidden): ")
    url = input("URL: ").strip()
    notes = input("Notes: ").strip()
    return PlainRecord(label=label, username=username, password=password, url=url, notes=notes)


def unlock_key(profile: LocalProfile) -> bytes:
    if profile.kdf_salt is None:
        raise SystemExit("No vault salt is configured. Run `aegis-client init-vault`.")
    master = getpass.getpass("Master password (hidden): ")
    try:
        return derive_key(master, profile.kdf_salt, profile.kdf_params)
    finally:
        master = ""


async def configure(args: argparse.Namespace) -> None:
    save_profile(LocalProfile(api_base_url=args.api, access_token=getpass.getpass("API access token (hidden): ")))
    print("Profile saved. The token is stored locally; protect this file.")


async def init_vault(_: argparse.Namespace) -> None:
    profile = load_profile()
    salt = new_salt()
    master = getpass.getpass("New master password (hidden): ")
    confirm = getpass.getpass("Confirm master password (hidden): ")
    if master != confirm:
        raise SystemExit("Master passwords did not match.")
    key = derive_key(master, salt, DEFAULT_KDF_PARAMS)
    metadata = encrypt_record(
        key,
        PlainRecord(label="vault metadata", password=generate_recovery_material()),
    )
    client = AegisApiClient(profile.api_base_url, profile.access_token)
    await client.create_vault(salt=salt, params=DEFAULT_KDF_PARAMS, metadata=metadata)
    profile.kdf_salt = salt
    profile.kdf_params = DEFAULT_KDF_PARAMS
    save_profile(profile)
    print("Vault initialized. Losing both your master password and recovery material is permanent.")


async def add_record(_: argparse.Namespace) -> None:
    profile = load_profile()
    key = unlock_key(profile)
    payload = encrypt_record(key, prompt_record())
    result = await AegisApiClient(profile.api_base_url, profile.access_token).create_record(payload)
    print(f"Encrypted record stored: {result['id']}")


async def list_records(_: argparse.Namespace) -> None:
    profile = load_profile()
    key = unlock_key(profile)
    records = await AegisApiClient(profile.api_base_url, profile.access_token).list_records()
    for item in records:
        payload = encrypted_payload_from_api(item)
        metadata = decrypt_record(key, payload)
        print(f"{item['id']}  {metadata.label}  v{item['record_version']}")


async def copy_field(args: argparse.Namespace) -> None:
    profile = load_profile()
    key = unlock_key(profile)
    client = AegisApiClient(profile.api_base_url, profile.access_token)
    payload = encrypted_payload_from_api(await client.get_record(args.record_id))
    record = decrypt_record(key, payload)
    value = record.username if args.field == "username" else record.password
    pyperclip.copy(value)
    print(f"Copied {args.field}; clipboard will clear in {args.clear_after} seconds.")
    await asyncio.sleep(args.clear_after)
    if pyperclip.paste() == value:
        pyperclip.copy("")
        print("Clipboard cleared.")


async def update_record(args: argparse.Namespace) -> None:
    profile = load_profile()
    key = unlock_key(profile)
    client = AegisApiClient(profile.api_base_url, profile.access_token)
    current = await client.get_record(args.record_id)
    payload = encrypt_record(key, prompt_record())
    await client.update_record(args.record_id, payload, int(current["record_version"]))
    print("Encrypted record updated.")


async def delete_record(args: argparse.Namespace) -> None:
    profile = load_profile()
    if input(f"Delete encrypted record {args.record_id}? Type DELETE: ") != "DELETE":
        raise SystemExit("Cancelled.")
    await AegisApiClient(profile.api_base_url, profile.access_token).delete_record(args.record_id)
    print("Encrypted record deleted.")


async def export_backup(args: argparse.Namespace) -> None:
    profile = load_profile()
    backup = await AegisApiClient(profile.api_base_url, profile.access_token).export_backup()
    Path(args.output).write_text(json.dumps(backup, indent=2))
    print(f"Encrypted backup written to {args.output}. It contains ciphertext and operational metadata.")


async def recovery(_: argparse.Namespace) -> None:
    if input("Reveal new recovery material in this terminal? Type REVEAL: ") != "REVEAL":
        raise SystemExit("Cancelled.")
    print(generate_recovery_material())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis-client")
    sub = parser.add_subparsers(required=True)
    configure_cmd = sub.add_parser("configure")
    configure_cmd.add_argument("--api", default="http://localhost:8000")
    configure_cmd.set_defaults(func=configure)
    sub.add_parser("init-vault").set_defaults(func=init_vault)
    sub.add_parser("add").set_defaults(func=add_record)
    sub.add_parser("list").set_defaults(func=list_records)
    copy_cmd = sub.add_parser("copy")
    copy_cmd.add_argument("record_id")
    copy_cmd.add_argument("field", choices=["username", "password"])
    copy_cmd.add_argument("--clear-after", type=int, default=20)
    copy_cmd.set_defaults(func=copy_field)
    update_cmd = sub.add_parser("update")
    update_cmd.add_argument("record_id")
    update_cmd.set_defaults(func=update_record)
    delete_cmd = sub.add_parser("delete")
    delete_cmd.add_argument("record_id")
    delete_cmd.set_defaults(func=delete_record)
    backup_cmd = sub.add_parser("export-backup")
    backup_cmd.add_argument("output")
    backup_cmd.set_defaults(func=export_backup)
    sub.add_parser("recovery").set_defaults(func=recovery)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    started = time.monotonic()
    asyncio.run(args.func(args))
    if time.monotonic() - started > 900:
        print("Session exceeded the recommended activity window; run a fresh command for more work.")


if __name__ == "__main__":
    main()
