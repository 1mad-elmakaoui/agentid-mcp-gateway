"""Hashing and the credential vault."""

from __future__ import annotations

import pytest

from agentid.config import Settings
from agentid.credentials.vault import LocalVault, SecretMaterial
from agentid.errors import CredentialError
from agentid.identity.secrets import hash_password, hash_secret, random_token, verify


def test_password_hash_round_trip() -> None:
    encoded = hash_password("correct horse battery staple")
    assert verify("correct horse battery staple", encoded)
    assert not verify("wrong password", encoded)


def test_password_hash_is_salted() -> None:
    assert hash_password("same") != hash_password("same")


def test_verify_rejects_malformed_hashes() -> None:
    assert not verify("x", None)
    assert not verify("x", "not-a-hash")
    assert not verify("x", "scrypt$pw$zz$zz")


def test_secret_hash_round_trip() -> None:
    secret = random_token()
    encoded = hash_secret(secret)
    assert verify(secret, encoded)
    assert not verify(secret + "x", encoded)


def test_vault_seals_and_opens(settings: Settings) -> None:
    vault = LocalVault(settings)
    sealed = vault.seal({"api_key": "super-secret"})
    assert "super-secret" not in sealed
    assert vault.open(sealed) == {"api_key": "super-secret"}


def test_vault_rejects_foreign_ciphertext(settings: Settings) -> None:
    other = LocalVault(Settings(secret_key="a-completely-different-key"))
    sealed = other.seal({"api_key": "secret"})
    with pytest.raises(CredentialError) as exc:
        LocalVault(settings).open(sealed)
    assert exc.value.code == "credential_undecryptable"


def test_secret_material_never_reprs_its_value() -> None:
    secret = SecretMaterial(kind="api_key", value="top-secret")
    assert "top-secret" not in repr(secret)
    assert "top-secret" not in str(secret)
    assert secret.redacted()["value"] == "***redacted***"
