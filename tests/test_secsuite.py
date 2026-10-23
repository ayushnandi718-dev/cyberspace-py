"""Tests for the security audit toolkit."""

from __future__ import annotations

import hashlib

import pytest

from secsuite.cracking import recover
from secsuite.hash import (
    HASH_ALGORITHMS,
    BackendMissing,
    hash_bytes,
    hash_text,
    identify_hash,
    is_supported_hash,
    verify_hash,
)
from secsuite.kdf import describe_hash, measure, recommendation
from secsuite.md4 import md4, ntlm_hash
from secsuite.password import analyse, estimate_entropy, verdict_for
from secsuite.wordlist import (
    RULES,
    apply_rule,
    generate,
    per_target_words,
    rule_by_name,
)


def test_md4_matches_the_vectors_of_rfc_1320() -> None:
    assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"
    assert (
        md4(b"abcdefghijklmnopqrstuvwxyz").hex()
        == "d79e1c308aa5bbcdeea8ed63df412da9"
    )
    assert (
        md4(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ).hex()
        == "043f8582f241db351ce627e153e7f0e4"
    )


def test_the_ntlm_hash_is_md4_over_utf16() -> None:
    assert ntlm_hash("password") == "8846f7eaee8fb117ad06bdd830b7586c"
    assert ntlm_hash("P@ssw0rd") == md4("P@ssw0rd".encode("utf-16-le")).hex()


def test_a_hash_is_computed_with_the_named_algorithm() -> None:
    result = hash_text("abc", "sha256")
    assert result.hex == hashlib.sha256(b"abc").hexdigest()
    assert result.length == 32
    assert result.as_dict()["algorithm"] == "sha256"


def test_an_unknown_algorithm_is_refused() -> None:
    with pytest.raises(ValueError):
        hash_bytes(b"abc", "rot13")
    for algorithm in HASH_ALGORITHMS:
        assert hash_bytes(b"abc", algorithm).length > 0


def test_a_short_hex_string_is_an_md5_or_an_ntlm_hash() -> None:
    identifications = identify_hash("0" * 32)
    kinds = [identification.kind for identification in identifications]
    assert "md5" in kinds
    assert "ntlm" in kinds


def test_a_long_hex_string_is_a_sha256_or_its_alikes() -> None:
    identifications = identify_hash("a" * 64)
    assert identifications[0].kind == "sha256"
    assert identifications[0].candidates == ["sha256", "sha3_256", "blake2s"]


def test_a_bcrypt_hash_is_recognised() -> None:
    import bcrypt

    value = bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=4)).decode()
    identifications = identify_hash(value)
    assert identifications[0].kind == "bcrypt"
    assert identifications[0].confidence == "high"


def test_an_unknown_value_is_unknown() -> None:
    identifications = identify_hash("not a hash at all")
    assert identifications[0].kind == "unknown"
    assert not is_supported_hash("not a hash at all")
    assert is_supported_hash("a" * 64)


def test_a_plain_digest_verifies() -> None:
    digest = hashlib.sha256(b"password").hexdigest()
    assert verify_hash(digest, "password")
    assert not verify_hash(digest, "wrong")


def test_a_bcrypt_hash_verifies() -> None:
    import bcrypt

    value = bcrypt.hashpw(b"password", bcrypt.gensalt(rounds=4)).decode()
    assert verify_hash(value, "password")
    assert not verify_hash(value, "wrong")


def test_an_ntlm_hash_verifies_only_as_an_ntlm_hash() -> None:
    value = ntlm_hash("password")
    assert verify_hash(value, "password", kind="ntlm")
    assert not verify_hash(value, "password", kind="md5")
    assert not verify_hash(value, "wrong", kind="ntlm")


def test_the_kind_narrows_the_verification() -> None:
    digest = hashlib.md5(b"password").hexdigest()
    assert verify_hash(digest, "password", kind="md5")
    assert not verify_hash(digest, "password", kind="sha1")


def test_a_missing_backend_is_an_error_not_a_wrong_password(monkeypatch) -> None:
    """A verifier that cannot run must not look like a wrong candidate."""
    monkeypatch.setattr("secsuite.hash._bcrypt_verify", lambda value, password: None)
    value = "$2b$04$" + "x" * 53
    with pytest.raises(BackendMissing):
        verify_hash(value, "password", kind="bcrypt")


def test_a_recovery_names_the_missing_backend(monkeypatch) -> None:
    monkeypatch.setattr("secsuite.hash._bcrypt_verify", lambda value, password: None)
    value = "$2b$04$" + "x" * 53
    with pytest.raises(BackendMissing):
        recover(value, ["password"], kind="bcrypt")


def test_the_cli_reports_a_missing_backend(monkeypatch, capsys) -> None:
    from secsuite.cli import main

    monkeypatch.setattr("secsuite.hash._bcrypt_verify", lambda value, password: None)
    value = "$2b$04$" + "x" * 53
    assert main(["recover", value, "password", "--kind", "bcrypt"]) == 2
    assert "bcrypt" in capsys.readouterr().err


def test_a_recovery_accepts_options_before_the_candidates() -> None:
    """``recover HASH --kind md5 alice`` must not drop ``alice``."""
    from secsuite.cli import main

    digest = hashlib.md5(b"alice").hexdigest()
    assert main(["recover", digest, "--kind", "md5", "alice"]) == 0


def test_an_unknown_option_is_still_refused() -> None:
    from secsuite.cli import main

    with pytest.raises(SystemExit):
        main(["identify", "--nope"])


def test_a_common_password_is_weak() -> None:
    report = analyse("password")
    assert report.length == 8
    assert "very weak" in report.verdict or "weak" in report.verdict
    assert report.weaknesses
    assert report.suggestions


def test_a_long_passphrase_is_strong() -> None:
    report = analyse("correct horse battery staple")
    assert report.entropy > 60
    assert report.verdict in ("strong", "very strong")


def test_the_entropy_of_a_password_is_never_negative() -> None:
    assert estimate_entropy("") == 0.0
    assert estimate_entropy("aaaaaa") >= 0.0


def test_a_weak_password_is_reported_as_such() -> None:
    assert verdict_for(0) == "very weak"
    assert verdict_for(50) == "fair"
    assert verdict_for(90) == "very strong"


def test_the_rules_mutate_a_word() -> None:
    assert apply_rule("acme", rule_by_name("upper")) == ["ACME"]
    assert apply_rule("acme", rule_by_name("capitalise")) == ["Acme"]
    assert apply_rule("acme", rule_by_name("leet")) == ["@cm3"]
    assert "acme1" in apply_rule("acme", rule_by_name("append-digit"))
    assert "acme2020" in apply_rule("acme", rule_by_name("append-year"))
    assert "!acme" in apply_rule("acme", rule_by_name("prepend"))
    assert apply_rule("acme", rule_by_name("double")) == ["acmeacme"]


def test_an_unknown_rule_is_refused() -> None:
    with pytest.raises(KeyError):
        apply_rule("acme", rule_by_name("no-such-rule"))


def test_a_candidate_list_starts_with_the_word_itself() -> None:
    candidates = list(generate(["acme"], [rule_by_name("upper")]))
    assert candidates[0] == "acme"
    assert "ACME" in candidates


def test_the_words_of_a_target_name() -> None:
    words = per_target_words("vpn.example.com", ["alice"])
    assert "vpn" in words
    assert "example" in words
    assert "alice" in words
    assert len(words) == len(set(words))


def test_every_rule_has_a_name() -> None:
    assert {rule.name for rule in RULES} >= {
        "lower",
        "capitalise",
        "upper",
        "leet",
        "append-digit",
        "append-year",
        "prepend",
        "double",
    }


def test_a_bcrypt_hash_reports_its_cost() -> None:
    report = describe_hash("$2b$12$" + "a" * 53)
    assert report.kind == "bcrypt"
    assert report.parameters["cost"] == 12
    assert report.guidance == 12
    assert "at or above" in report.advice


def test_a_pbkdf2_hash_reports_its_rounds() -> None:
    report = describe_hash("$pbkdf2-sha256$1000$" + "a" * 64)
    assert report.kind == "pbkdf2-sha256"
    assert report.rounds == 1000
    assert "below the guidance" in report.advice


def test_a_hash_without_parameters_says_so() -> None:
    report = describe_hash("a" * 64)
    assert report.kind == "unknown"
    assert report.rounds == 0


def test_the_recommendation_of_an_unknown_kind() -> None:
    assert "no published guidance" in recommendation("made-up", 10)


def test_a_derivation_can_be_timed() -> None:
    result = measure("pbkdf2-sha256", "password", 1000)
    assert result["kind"] == "pbkdf2-sha256"
    assert result["seconds"] >= 0
    assert result["per_second"] > 0


def test_a_recovery_finds_the_password() -> None:
    digest = hashlib.sha256(b"acme2024").hexdigest()
    result = recover(digest, ["acme", "acme2024", "other"])
    assert result.found
    assert result.plaintext == "acme2024"
    assert result.tested == 2
    assert result.rate >= 0


def test_a_recovery_that_fails_reports_how_many_it_tried() -> None:
    digest = hashlib.sha256(b"nothing").hexdigest()
    result = recover(digest, ["a", "b", "c"])
    assert not result.found
    assert result.tested == 3


def test_a_recovery_stops_at_its_limit() -> None:
    digest = hashlib.sha256(b"z").hexdigest()
    result = recover(digest, ["a", "b", "z"], limit=2)
    assert not result.found
    assert result.stopped_early
    assert result.tested == 2


def test_a_recovery_with_a_kind_only_tries_that_format() -> None:
    value = ntlm_hash("acme")
    result = recover(value, ["acme"], kind="ntlm")
    assert result.found
    result = recover(value, ["acme"], kind="md5")
    assert not result.found
