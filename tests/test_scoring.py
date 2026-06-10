"""Scoring and parsing tests for IOC Analyzer."""

from __future__ import annotations

from pathlib import Path

from analyzer.classifier import classify_ioc
from analyzer.parser import load_iocs
from analyzer.scoring import (
    apply_abuseipdb_score_adjustments,
    apply_vt_score_adjustments,
    score_ioc,
)


def test_private_ip_scores_low() -> None:
    score, reasons = score_ioc("10.0.0.5", "IPv4")
    assert score == 5
    assert "Private or local IP range" in reasons


def test_public_ip_scores_medium() -> None:
    score, _ = score_ioc("8.8.8.8", "IPv4")
    assert score == 25


def test_suspicious_keyword_domain_scores_high() -> None:
    score, reasons = score_ioc("secure-login-check.xyz", "Domain")
    assert score == 60
    assert "Suspicious top-level domain" in reasons


def test_hash_scores_consistently() -> None:
    score, _ = score_ioc("44d88612fea8a8f36de82e1278abb02f", "MD5")
    assert score == 50


def test_vt_adjustments_increase_score() -> None:
    score, reasons = score_ioc(
        "example.com",
        "Domain",
        vt_reputation={
            "vt_enabled": True,
            "malicious_votes": 11,
            "suspicious_votes": 2,
            "harmless_votes": 1,
            "reputation": -5,
        },
    )
    assert score == 80
    assert any("VirusTotal" in reason for reason in reasons)


def test_vt_adjustments_cap_score() -> None:
    adjusted_score, reasons = apply_vt_score_adjustments(
        85,
        {
            "vt_enabled": True,
            "malicious_votes": 30,
            "suspicious_votes": 0,
            "harmless_votes": 0,
            "reputation": -1,
        },
    )
    assert adjusted_score == 100
    assert len(reasons) == 2


def test_abuseipdb_adjustments_increase_score() -> None:
    adjusted_score, reasons = apply_abuseipdb_score_adjustments(
        25,
        {
            "enabled": True,
            "abuse_confidence_score": 92,
            "country_code": "NL",
            "usage_type": "Data Center/Web Hosting/Transit",
            "total_reports": 154,
        },
    )
    assert adjusted_score == 65
    assert any("AbuseIPDB" in reason for reason in reasons)


def test_classifier_maps_to_malicious() -> None:
    assert classify_ioc(90, "URL") == "Malicious"


def test_parser_loads_txt(tmp_path: Path) -> None:
    sample = tmp_path / "iocs.txt"
    sample.write_text("8.8.8.8\n\nexample.com\n", encoding="utf-8")
    assert load_iocs(sample) == ["8.8.8.8", "example.com"]


def test_parser_loads_csv(tmp_path: Path) -> None:
    sample = tmp_path / "iocs.csv"
    sample.write_text("ioc\n8.8.8.8,example.com\n", encoding="utf-8")
    assert load_iocs(sample) == ["ioc", "8.8.8.8", "example.com"]
