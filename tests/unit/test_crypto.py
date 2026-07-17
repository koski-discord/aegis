import pytest

from apps.client.crypto.vault import (
    DEFAULT_KDF_PARAMS,
    decrypt_record,
    derive_key,
    encrypt_record,
    new_salt,
)
from apps.client.models.records import PlainRecord


def test_encrypt_decrypt_round_trip() -> None:
    salt = new_salt()
    key = derive_key("correct horse battery staple", salt, DEFAULT_KDF_PARAMS)
    record = PlainRecord(label="mail", username="alice", password="not-real", url="https://example.test")

    encrypted = encrypt_record(key, record)
    decrypted = decrypt_record(key, encrypted)

    assert decrypted == record
    assert encrypted.ciphertext != encrypted.encrypted_metadata
    assert encrypted.nonce != encrypted.metadata_nonce


def test_wrong_master_password_fails() -> None:
    salt = new_salt()
    good_key = derive_key("right password", salt, DEFAULT_KDF_PARAMS)
    bad_key = derive_key("wrong password", salt, DEFAULT_KDF_PARAMS)
    encrypted = encrypt_record(good_key, PlainRecord(label="mail", password="not-real"))

    with pytest.raises(ValueError, match="decryption failed"):
        decrypt_record(bad_key, encrypted)


def test_nonce_uniqueness_for_many_encryptions() -> None:
    salt = new_salt()
    key = derive_key("master", salt, DEFAULT_KDF_PARAMS)
    nonces = {
        encrypt_record(key, PlainRecord(label=f"record-{index}", password="not-real")).nonce for index in range(100)
    }

    assert len(nonces) == 100
