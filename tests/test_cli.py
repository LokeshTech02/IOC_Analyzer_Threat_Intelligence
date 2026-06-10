"""CLI integration-oriented tests."""

from __future__ import annotations

import json
from pathlib import Path

import main


def test_analyze_ioc_returns_complete_result() -> None:
    result = main.analyze_ioc("wallet-support-secure.xyz")
    assert result["type"] == "Domain"
    assert result["risk_score"] == 70
    assert result["severity"] == "High"
    assert result["classification"] == "Suspicious"
    assert "crypto_scam" in result["threat_context"]
    assert result["virustotal"] == {"vt_enabled": False}
    assert result["abuseipdb"] == {"enabled": False}
    assert result["finding_summary"] == ""
    assert result["malware_confidence"] == ""


def test_html_report_contains_summary() -> None:
    metadata = {
        "scan_name": "phishing_case",
        "scan_time": "2026-06-09 20:15:30 UTC",
        "input_file": "sample_data/sample_iocs.txt",
        "virustotal_enabled": False,
        "abuseipdb_enabled": False,
        "output_files": {
            "json": "exports/phishing_case.json",
            "csv": "exports/phishing_case.csv",
            "html": "reports/phishing_case.html",
        },
    }
    results = [
        {
            "ioc": "44d88612fea8a8f36de82e1278abb02f",
            "type": "MD5",
            "risk_score": 100,
            "severity": "Critical",
            "classification": "Malicious",
            "reasons": ["File hash requires enrichment context"],
            "threat_context": [],
            "finding_summary": "VirusTotal reports 54 of 66 security vendors detecting this file as malicious.",
            "malware_confidence": "Very High",
            "virustotal": {
                "vt_enabled": True,
                "malicious_votes": 54,
                "suspicious_votes": 0,
                "harmless_votes": 12,
                "reputation": -9,
                "popular_threat_label": "trojan.zenpak/graftor",
                "threat_categories": ["trojan", "banker", "ransomware"],
                "malware_families": ["zenpak", "graftor", "dridex"],
                "detection_ratio": "54/66",
                "last_analysis_date": "2026-06-07",
            },
            "abuseipdb": {"enabled": False},
        }
    ]
    html = main.build_html_report(results, metadata)
    assert "Threat Category Distribution" in html
    assert "Top Malware Families" in html
    assert "Detection Ratio Summary" in html
    assert "Top Malicious Hashes" in html


def test_export_json_round_trip(tmp_path: Path) -> None:
    output = tmp_path / "results.json"
    results = [
        {
            "ioc": "8.8.8.8",
            "type": "IPv4",
            "risk_score": 25,
            "severity": "Low",
            "classification": "Unknown",
            "reasons": ["Publicly routable IP address"],
            "threat_context": [],
            "finding_summary": "",
            "malware_confidence": "",
            "virustotal": {"vt_enabled": False},
            "abuseipdb": {"enabled": False},
        }
    ]
    main.export_json(results, output)
    assert json.loads(output.read_text(encoding="utf-8"))[0]["ioc"] == "8.8.8.8"


def test_export_csv_flattens_virustotal_fields(tmp_path: Path) -> None:
    output = tmp_path / "results.csv"
    results = [
        {
            "ioc": "44d88612fea8a8f36de82e1278abb02f",
            "type": "MD5",
            "risk_score": 100,
            "severity": "Critical",
            "classification": "Malicious",
            "reasons": ["File hash requires enrichment context"],
            "threat_context": [],
            "finding_summary": "VT summary",
            "malware_confidence": "Very High",
            "virustotal": {
                "vt_enabled": True,
                "malicious_votes": 54,
                "suspicious_votes": 0,
                "harmless_votes": 12,
                "reputation": -9,
                "popular_threat_label": "trojan.zenpak/graftor",
                "threat_categories": ["trojan", "banker", "ransomware"],
                "malware_families": ["zenpak", "graftor", "dridex"],
                "detection_ratio": "54/66",
                "last_analysis_date": "2026-06-07",
            },
            "abuseipdb": {"enabled": False},
        }
    ]
    main.export_csv(results, output)
    contents = output.read_text(encoding="utf-8")
    assert "popular_threat_label" in contents
    assert "malware_families" in contents
    assert "detection_ratio" in contents
    assert "malware_confidence" in contents
    assert "virustotal" not in contents


def test_analyze_ioc_with_vt_disabled_enrichment(monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    result = main.analyze_ioc("https://invoice-alerts.example.com", use_virustotal=True)
    assert "phishing_lure" in result["threat_context"]
    assert result["virustotal"] == {"vt_enabled": False}


def test_login_url_remains_low_unknown() -> None:
    result = main.analyze_ioc("https://example.com/login")
    assert result["severity"] == "Low"
    assert result["classification"] == "Unknown"


def test_unique_scan_name_appends_suffix(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(main, "EXPORTS_DIR", tmp_path / "exports")
    monkeypatch.setattr(main, "REPORTS_DIR", tmp_path / "reports")
    main.EXPORTS_DIR.mkdir()
    main.REPORTS_DIR.mkdir()
    (main.EXPORTS_DIR / "incident1.json").write_text("[]", encoding="utf-8")
    unique_name = main.ensure_unique_scan_name("incident1")
    assert unique_name == "incident1_2"
