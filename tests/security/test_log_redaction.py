from aegis_core.logging import redact_mapping


def test_sensitive_values_are_redacted() -> None:
    redacted = redact_mapping(
        {
            "authorization": "Bearer token",
            "nested": {"password": "secret", "safe": "value"},
            "ciphertext": "stored but not logged",
        }
    )

    assert redacted["authorization"] == "[redacted]"
    assert redacted["nested"]["password"] == "[redacted]"
    assert redacted["nested"]["safe"] == "value"
    assert redacted["ciphertext"] == "[redacted]"
