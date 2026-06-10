"""Validator unit tests for IOC Analyzer."""

from __future__ import annotations

from analyzer.validator import detect_ioc_type


def test_detects_ipv4() -> None:
    assert detect_ioc_type("8.8.8.8") == "IPv4"


def test_detects_ipv6() -> None:
    assert detect_ioc_type("2001:4860:4860::8888") == "IPv6"


def test_detects_domain() -> None:
    assert detect_ioc_type("google.com") == "Domain"


def test_detects_url() -> None:
    assert detect_ioc_type("https://example.com/login") == "URL"


def test_detects_md5() -> None:
    assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "MD5"


def test_detects_sha1() -> None:
    assert detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "SHA1"


def test_detects_sha256() -> None:
    assert (
        detect_ioc_type(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
        == "SHA256"
    )


def test_detects_email() -> None:
    assert detect_ioc_type("analyst@example.org") == "Email"


def test_unknown_invalid_indicator() -> None:
    assert detect_ioc_type("bad value !!!") == "Unknown"
