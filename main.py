"""CLI entry point for the IOC Analyzer application."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from analyzer.abuseipdb import get_abuseipdb_reputation
from analyzer.classifier import classify_ioc
from analyzer.parser import load_iocs
from analyzer.scoring import score_ioc
from analyzer.threat_context import derive_threat_context
from analyzer.validator import detect_ioc_type
from analyzer.virustotal import (
    HASH_TYPES,
    build_finding_summary,
    calculate_malware_confidence,
    get_vt_reputation,
    test_vt_connection,
)

BASE_DIR = Path(__file__).resolve().parent
EXPORTS_DIR = BASE_DIR / "exports"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
LAST_SCAN_PATH = EXPORTS_DIR / ".last_scan.json"


def configure_logging() -> None:
    """Configure file and console logging."""
    LOGS_DIR.mkdir(exist_ok=True)
    log_file = LOGS_DIR / "analysis.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def severity_from_score(score: int) -> str:
    """Map a numeric score to a severity label."""
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def sanitize_scan_name(scan_name: str) -> str:
    """Normalize scan names for file-safe output."""
    sanitized = re.sub(r"[^A-Za-z0-9_-]+", "_", scan_name.strip())
    sanitized = sanitized.strip("_")
    return sanitized or generate_scan_name()


def generate_scan_name(timestamp: datetime | None = None) -> str:
    """Generate a timestamp-based scan name."""
    current = timestamp or datetime.now()
    return current.strftime("scan_%Y%m%d_%H%M%S")


def resolve_scan_name(scan_name: str | None) -> str:
    """Resolve a user-supplied or generated scan name."""
    if scan_name:
        return sanitize_scan_name(scan_name)
    return generate_scan_name()


def ensure_unique_scan_name(scan_name: str) -> str:
    """Avoid overwriting prior scan outputs by appending a suffix when needed."""
    candidate = scan_name
    counter = 1
    while any(
        path.exists()
        for path in (
            EXPORTS_DIR / f"{candidate}.json",
            EXPORTS_DIR / f"{candidate}.csv",
            REPORTS_DIR / f"{candidate}.html",
        )
    ):
        counter += 1
        candidate = f"{scan_name}_{counter}"
    return candidate


def build_scan_paths(scan_name: str) -> dict[str, Path]:
    """Return the canonical artifact paths for a scan."""
    return {
        "json": EXPORTS_DIR / f"{scan_name}.json",
        "csv": EXPORTS_DIR / f"{scan_name}.csv",
        "html": REPORTS_DIR / f"{scan_name}.html",
    }


def save_last_scan_metadata(metadata: dict[str, Any]) -> None:
    """Persist metadata for the most recent scan."""
    LAST_SCAN_PATH.parent.mkdir(exist_ok=True)
    LAST_SCAN_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def load_last_scan_metadata() -> dict[str, Any]:
    """Load metadata for the most recent scan."""
    if not LAST_SCAN_PATH.exists():
        raise FileNotFoundError("No scan metadata found. Run `python main.py analyze <file>` first.")
    return json.loads(LAST_SCAN_PATH.read_text(encoding="utf-8"))


def load_scan_results(scan_name: str | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Load a prior scan's results and metadata."""
    metadata = load_last_scan_metadata()
    if scan_name:
        resolved_name = sanitize_scan_name(scan_name)
        paths = build_scan_paths(resolved_name)
        if not paths["json"].exists():
            raise FileNotFoundError(f"Scan results not found for `{resolved_name}`.")
        metadata = {
            "scan_name": resolved_name,
            "scan_time": metadata.get("scan_time", ""),
            "input_file": metadata.get("input_file", ""),
            "virustotal_enabled": metadata.get("virustotal_enabled", False),
            "abuseipdb_enabled": metadata.get("abuseipdb_enabled", False),
            "output_files": {key: str(value) for key, value in paths.items()},
        }
    json_path = Path(metadata["output_files"]["json"])
    with json_path.open("r", encoding="utf-8") as handle:
        return json.load(handle), metadata


def get_scan_metadata(
    scan_name: str,
    input_file: str,
    vt_enabled: bool,
    abuseipdb_enabled: bool,
    paths: dict[str, Path],
    scan_time: str,
) -> dict[str, Any]:
    """Build reusable scan metadata."""
    return {
        "scan_name": scan_name,
        "input_file": input_file,
        "scan_time": scan_time,
        "virustotal_enabled": vt_enabled,
        "abuseipdb_enabled": abuseipdb_enabled,
        "output_files": {key: str(value) for key, value in paths.items()},
    }


def analyze_ioc(
    ioc: str,
    use_virustotal: bool = False,
    use_abuseipdb: bool = False,
) -> dict[str, Any]:
    """Analyze a single IOC and return normalized findings."""
    ioc_type = detect_ioc_type(ioc)
    vt_reputation = get_vt_reputation(ioc, ioc_type) if use_virustotal else {"vt_enabled": False}
    abuseipdb_reputation = (
        get_abuseipdb_reputation(ioc, ioc_type) if use_abuseipdb else {"enabled": False}
    )
    score, reasons = score_ioc(
        ioc,
        ioc_type,
        vt_reputation=vt_reputation,
        abuseipdb_reputation=abuseipdb_reputation,
    )
    severity = severity_from_score(score)
    classification = classify_ioc(score, ioc_type)
    malware_confidence = (
        calculate_malware_confidence(int(vt_reputation.get("malicious_votes", 0)))
        if ioc_type in HASH_TYPES
        else ""
    )
    finding_summary = build_finding_summary(vt_reputation, ioc_type)
    return {
        "ioc": ioc,
        "type": ioc_type,
        "risk_score": score,
        "severity": severity,
        "classification": classification,
        "reasons": reasons,
        "threat_context": derive_threat_context(ioc, ioc_type),
        "finding_summary": finding_summary,
        "malware_confidence": malware_confidence,
        "virustotal": vt_reputation,
        "abuseipdb": abuseipdb_reputation,
    }


def export_json(results: list[dict[str, Any]], output_path: Path) -> None:
    """Export results to JSON."""
    output_path.parent.mkdir(exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)


def export_csv(results: list[dict[str, Any]], output_path: Path) -> None:
    """Export results to CSV."""
    output_path.parent.mkdir(exist_ok=True)
    fieldnames = [
        "ioc",
        "type",
        "risk_score",
        "severity",
        "classification",
        "reasons",
        "threat_context",
        "finding_summary",
        "malware_confidence",
        "vt_enabled",
        "malicious_votes",
        "suspicious_votes",
        "harmless_votes",
        "reputation",
        "popular_threat_label",
        "threat_categories",
        "malware_families",
        "detection_ratio",
        "last_analysis_date",
        "abuseipdb_enabled",
        "abuse_confidence_score",
        "country_code",
        "usage_type",
        "total_reports",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            serialized = dict(row)
            serialized["reasons"] = "; ".join(row["reasons"])
            serialized["threat_context"] = "; ".join(row["threat_context"])
            vt_reputation = row.get("virustotal", {})
            abuseipdb = row.get("abuseipdb", {})
            serialized.pop("virustotal", None)
            serialized.pop("abuseipdb", None)
            serialized["vt_enabled"] = vt_reputation.get("vt_enabled", False)
            serialized["malicious_votes"] = vt_reputation.get("malicious_votes", 0)
            serialized["suspicious_votes"] = vt_reputation.get("suspicious_votes", 0)
            serialized["harmless_votes"] = vt_reputation.get("harmless_votes", 0)
            serialized["reputation"] = vt_reputation.get("reputation", 0)
            serialized["popular_threat_label"] = vt_reputation.get("popular_threat_label", "")
            serialized["threat_categories"] = "; ".join(vt_reputation.get("threat_categories", []))
            serialized["malware_families"] = "; ".join(vt_reputation.get("malware_families", []))
            serialized["detection_ratio"] = vt_reputation.get("detection_ratio", "")
            serialized["last_analysis_date"] = vt_reputation.get("last_analysis_date", "")
            serialized["abuseipdb_enabled"] = abuseipdb.get("enabled", False)
            serialized["abuse_confidence_score"] = abuseipdb.get("abuse_confidence_score", 0)
            serialized["country_code"] = abuseipdb.get("country_code", "")
            serialized["usage_type"] = abuseipdb.get("usage_type", "")
            serialized["total_reports"] = abuseipdb.get("total_reports", 0)
            writer.writerow(serialized)


def build_html_report(results: list[dict[str, Any]], metadata: dict[str, Any]) -> str:
    """Generate an executive HTML report for a scan."""
    total_iocs = len(results)
    type_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    classification_counts: Counter[str] = Counter()
    threat_context_counts: Counter[str] = Counter()
    vt_enabled_count = 0
    vt_malicious_votes = 0
    vt_suspicious_votes = 0
    vt_harmless_votes = 0
    detection_ratios: list[str] = []
    threat_category_counts: Counter[str] = Counter()
    malware_family_counts: Counter[str] = Counter()
    malicious_hashes: list[dict[str, Any]] = []
    abuse_enabled_count = 0
    abuse_total_reports = 0
    abuse_average_confidence = 0.0
    abuse_confidence_values: list[int] = []

    for item in results:
        type_counts[item["type"]] += 1
        severity_counts[item["severity"]] += 1
        classification_counts[item["classification"]] += 1
        for context in item.get("threat_context", []):
            threat_context_counts[context] += 1

        vt_reputation = item.get("virustotal", {})
        if vt_reputation.get("vt_enabled"):
            vt_enabled_count += 1
        vt_malicious_votes += int(vt_reputation.get("malicious_votes", 0))
        vt_suspicious_votes += int(vt_reputation.get("suspicious_votes", 0))
        vt_harmless_votes += int(vt_reputation.get("harmless_votes", 0))
        if vt_reputation.get("detection_ratio"):
            detection_ratios.append(str(vt_reputation["detection_ratio"]))
        for category in vt_reputation.get("threat_categories", []):
            threat_category_counts[str(category)] += 1
        for family in vt_reputation.get("malware_families", []):
            malware_family_counts[str(family)] += 1
        if item["type"] in HASH_TYPES and int(vt_reputation.get("malicious_votes", 0)) > 0:
            malicious_hashes.append(item)

        abuseipdb = item.get("abuseipdb", {})
        if abuseipdb.get("enabled"):
            abuse_enabled_count += 1
            abuse_total_reports += int(abuseipdb.get("total_reports", 0))
            abuse_confidence_values.append(int(abuseipdb.get("abuse_confidence_score", 0)))

    if abuse_confidence_values:
        abuse_average_confidence = sum(abuse_confidence_values) / len(abuse_confidence_values)

    top_risks = sorted(results, key=lambda entry: entry["risk_score"], reverse=True)[:10]
    top_malicious_hashes = sorted(
        malicious_hashes,
        key=lambda entry: int(entry.get("virustotal", {}).get("malicious_votes", 0)),
        reverse=True,
    )[:10]

    def render_rows(items: Counter[str]) -> str:
        return "".join(
            f"<tr><td>{key}</td><td>{value}</td></tr>"
            for key, value in sorted(items.items(), key=lambda pair: pair[0])
        )

    top_risk_rows = "".join(
        (
            f"<tr><td>{item['ioc']}</td><td>{item['type']}</td>"
            f"<td>{item['risk_score']}</td><td>{item['severity']}</td>"
            f"<td>{item['classification']}</td><td>{', '.join(item.get('threat_context', [])) or 'None'}</td></tr>"
        )
        for item in top_risks
    )

    malicious_hash_rows = "".join(
        (
            f"<tr><td>{item['ioc']}</td><td>{item['type']}</td>"
            f"<td>{item.get('virustotal', {}).get('detection_ratio', '')}</td>"
            f"<td>{item.get('malware_confidence', '')}</td>"
            f"<td>{item.get('virustotal', {}).get('popular_threat_label', '')}</td></tr>"
        )
        for item in top_malicious_hashes
    ) or "<tr><td colspan='5'>None</td></tr>"

    output_file_rows = "".join(
        f"<tr><td>{label.upper()}</td><td>{path}</td></tr>"
        for label, path in metadata["output_files"].items()
    )
    threat_context_rows = render_rows(threat_context_counts) or "<tr><td>None</td><td>0</td></tr>"
    threat_category_rows = render_rows(threat_category_counts) or "<tr><td>None</td><td>0</td></tr>"
    malware_family_rows = render_rows(malware_family_counts) or "<tr><td>None</td><td>0</td></tr>"
    vt_status = "Enabled" if metadata.get("virustotal_enabled") else "Disabled"
    abuse_status = "Enabled" if metadata.get("abuseipdb_enabled") else "Disabled"
    detection_ratio_summary = ", ".join(detection_ratios[:5]) if detection_ratios else "None"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IOC Analyzer Executive Report</title>
  <style>
    :root {{
      --bg: #f3f6f9;
      --panel: #ffffff;
      --ink: #17212b;
      --accent: #0f5b78;
      --accent-soft: #dbeff7;
      --shadow: 0 16px 40px rgba(15, 91, 120, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background:
        radial-gradient(circle at top left, rgba(15, 91, 120, 0.12), transparent 30%),
        linear-gradient(135deg, #eef7fb 0%, var(--bg) 45%, #e8eef4 100%);
      color: var(--ink);
      line-height: 1.6;
    }}
    .container {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }}
    .hero, .card, table {{
      background: var(--panel);
      border-radius: 20px;
      box-shadow: var(--shadow);
    }}
    .hero {{
      background: linear-gradient(135deg, #083344, #0f5b78 60%, #4a7892);
      color: #fff;
      padding: 32px;
      margin-bottom: 24px;
    }}
    .hero h1 {{ margin: 0 0 8px; font-size: 2.2rem; }}
    .hero p {{ margin: 0; color: rgba(255, 255, 255, 0.88); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    .card {{ padding: 20px; }}
    .card h2, .card h3 {{ margin-top: 0; }}
    .metric {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--accent);
      margin: 0;
    }}
    .section {{ margin-top: 24px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
    }}
    th, td {{
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid #e2e8f0;
    }}
    th {{
      background: var(--accent-soft);
      color: var(--accent);
    }}
    tr:last-child td {{ border-bottom: none; }}
  </style>
</head>
<body>
  <div class="container">
    <section class="hero">
      <h1>IOC Analyzer Executive Report</h1>
      <p>Scan {metadata['scan_name']} completed at {metadata['scan_time']}.</p>
    </section>

    <section class="grid">
      <div class="card">
        <h2>Total IOCs</h2>
        <p class="metric">{total_iocs}</p>
      </div>
      <div class="card">
        <h2>High / Critical</h2>
        <p class="metric">{sum(1 for item in results if item['severity'] in {'High', 'Critical'})}</p>
      </div>
      <div class="card">
        <h2>VirusTotal</h2>
        <p class="metric">{vt_status}</p>
      </div>
      <div class="card">
        <h2>AbuseIPDB</h2>
        <p class="metric">{abuse_status}</p>
      </div>
    </section>

    <section class="section card">
      <h2>Executive Summary</h2>
      <p>
        IOC Analyzer processed {total_iocs} indicators for scan <strong>{metadata['scan_name']}</strong>.
        Results include deterministic validation, threat context analysis, local risk scoring, and optional VirusTotal and AbuseIPDB enrichment.
      </p>
    </section>

    <section class="section">
      <div class="grid">
        <div class="card">
          <h3>IOC Type Distribution</h3>
          <table>
            <thead><tr><th>Type</th><th>Count</th></tr></thead>
            <tbody>{render_rows(type_counts)}</tbody>
          </table>
        </div>
        <div class="card">
          <h3>Severity Distribution</h3>
          <table>
            <thead><tr><th>Severity</th><th>Count</th></tr></thead>
            <tbody>{render_rows(severity_counts)}</tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="grid">
        <div class="card">
          <h3>Threat Context Summary</h3>
          <table>
            <thead><tr><th>Threat Context</th><th>Count</th></tr></thead>
            <tbody>{threat_context_rows}</tbody>
          </table>
        </div>
        <div class="card">
          <h3>Classification Breakdown</h3>
          <table>
            <thead><tr><th>Classification</th><th>Count</th></tr></thead>
            <tbody>{render_rows(classification_counts)}</tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="grid">
        <div class="card">
          <h3>VirusTotal Summary</h3>
          <table>
            <thead><tr><th>Metric</th><th>Value</th></tr></thead>
            <tbody>
              <tr><td>Status</td><td>{vt_status}</td></tr>
              <tr><td>IOCs Enriched</td><td>{vt_enabled_count}</td></tr>
              <tr><td>Total Malicious Votes</td><td>{vt_malicious_votes}</td></tr>
              <tr><td>Total Suspicious Votes</td><td>{vt_suspicious_votes}</td></tr>
              <tr><td>Total Harmless Votes</td><td>{vt_harmless_votes}</td></tr>
              <tr><td>Detection Ratio Summary</td><td>{detection_ratio_summary}</td></tr>
            </tbody>
          </table>
        </div>
        <div class="card">
          <h3>AbuseIPDB Summary</h3>
          <table>
            <thead><tr><th>Metric</th><th>Value</th></tr></thead>
            <tbody>
              <tr><td>Status</td><td>{abuse_status}</td></tr>
              <tr><td>IOCs Enriched</td><td>{abuse_enabled_count}</td></tr>
              <tr><td>Total Reports</td><td>{abuse_total_reports}</td></tr>
              <tr><td>Average Confidence</td><td>{abuse_average_confidence:.1f}</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="grid">
        <div class="card">
          <h3>Threat Category Distribution</h3>
          <table>
            <thead><tr><th>Category</th><th>Count</th></tr></thead>
            <tbody>{threat_category_rows}</tbody>
          </table>
        </div>
        <div class="card">
          <h3>Top Malware Families</h3>
          <table>
            <thead><tr><th>Family</th><th>Count</th></tr></thead>
            <tbody>{malware_family_rows}</tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="section">
      <h2>Top Malicious Hashes</h2>
      <table>
        <thead>
          <tr>
            <th>IOC</th>
            <th>Type</th>
            <th>Detection Ratio</th>
            <th>Malware Confidence</th>
            <th>Popular Threat Label</th>
          </tr>
        </thead>
        <tbody>{malicious_hash_rows}</tbody>
      </table>
    </section>

    <section class="section">
      <h2>Top High-Risk IOCs</h2>
      <table>
        <thead>
          <tr>
            <th>IOC</th>
            <th>Type</th>
            <th>Risk Score</th>
            <th>Severity</th>
            <th>Classification</th>
            <th>Threat Context</th>
          </tr>
        </thead>
        <tbody>{top_risk_rows}</tbody>
      </table>
    </section>

    <section class="section">
      <div class="grid">
        <div class="card">
          <h3>Scan Metadata</h3>
          <table>
            <thead><tr><th>Field</th><th>Value</th></tr></thead>
            <tbody>
              <tr><td>Scan Name</td><td>{metadata['scan_name']}</td></tr>
              <tr><td>Scan Time</td><td>{metadata['scan_time']}</td></tr>
              <tr><td>Input File</td><td>{metadata['input_file']}</td></tr>
            </tbody>
          </table>
        </div>
        <div class="card">
          <h3>Output Files Generated</h3>
          <table>
            <thead><tr><th>Artifact</th><th>Path</th></tr></thead>
            <tbody>{output_file_rows}</tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</body>
</html>
"""


def handle_analyze(
    input_file: str,
    scan_name: str | None = None,
    use_virustotal: bool = False,
    use_abuseipdb: bool = False,
) -> int:
    """Analyze a TXT or CSV file containing IOC values."""
    source = Path(input_file)
    resolved_scan_name = ensure_unique_scan_name(resolve_scan_name(scan_name))
    paths = build_scan_paths(resolved_scan_name)
    vt_enabled = use_virustotal and bool(os.getenv("VT_API_KEY"))
    abuseipdb_enabled = use_abuseipdb and bool(os.getenv("ABUSEIPDB_API_KEY"))
    scan_time = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    results = [
        analyze_ioc(
            value,
            use_virustotal=use_virustotal,
            use_abuseipdb=use_abuseipdb,
        )
        for value in load_iocs(source)
    ]
    metadata = get_scan_metadata(
        scan_name=resolved_scan_name,
        input_file=str(source),
        vt_enabled=vt_enabled,
        abuseipdb_enabled=abuseipdb_enabled,
        paths=paths,
        scan_time=scan_time,
    )
    export_json(results, paths["json"])
    export_csv(results, paths["csv"])
    paths["html"].parent.mkdir(exist_ok=True)
    paths["html"].write_text(build_html_report(results, metadata), encoding="utf-8")
    save_last_scan_metadata(metadata)
    logging.info(
        "Analyzed %s IOCs from %s | scan=%s | vt=%s | abuseipdb=%s",
        len(results),
        source,
        resolved_scan_name,
        "enabled" if vt_enabled else "disabled",
        "enabled" if abuseipdb_enabled else "disabled",
    )
    print(f"Analyzed {len(results)} IOCs.")
    print(f"Scan Name: {resolved_scan_name}")
    print(f"VirusTotal Enabled: {'Yes' if vt_enabled else 'No'}")
    print(f"AbuseIPDB Enabled: {'Yes' if abuseipdb_enabled else 'No'}")
    print(f"JSON export: {paths['json']}")
    print(f"CSV export: {paths['csv']}")
    print(f"HTML report: {paths['html']}")
    return 0


def handle_export(scan_name: str | None = None) -> int:
    """Ensure JSON and CSV artifacts exist for a named or latest scan."""
    results, metadata = load_scan_results(scan_name)
    json_path = Path(metadata["output_files"]["json"])
    csv_path = Path(metadata["output_files"]["csv"])
    if not json_path.exists():
        export_json(results, json_path)
    if not csv_path.exists():
        export_csv(results, csv_path)
    logging.info("Export verified for scan %s", metadata["scan_name"])
    print(f"JSON export: {json_path}")
    print(f"CSV export: {csv_path}")
    return 0


def handle_report(scan_name: str | None = None) -> int:
    """Ensure the HTML report exists for a named or latest scan."""
    results, metadata = load_scan_results(scan_name)
    report_path = Path(metadata["output_files"]["html"])
    if not report_path.exists():
        report_path.parent.mkdir(exist_ok=True)
        report_path.write_text(build_html_report(results, metadata), encoding="utf-8")
    logging.info("Report verified for scan %s at %s", metadata["scan_name"], report_path)
    print(f"HTML report: {report_path}")
    return 0


def handle_test_vt() -> int:
    """Validate VirusTotal API configuration."""
    status = test_vt_connection()
    if status == "missing":
        logging.warning("VirusTotal API key missing during test-vt")
        print("API key missing")
        return 0

    logging.info("VirusTotal API key detected during test-vt")
    print("API key detected")
    if status == "success":
        logging.info("VirusTotal connection test completed successfully")
        print("Connection successful")
        return 0

    logging.error("VirusTotal API request failed during test-vt")
    print("API request failed")
    return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description="IOC Analyzer validates, classifies, and reports on cybersecurity indicators."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze IOC input data.")
    analyze_parser.add_argument("input_file", help="Path to a TXT or CSV file of IOCs.")
    analyze_parser.add_argument("scan_name", nargs="?", help="Optional human-readable scan name.")
    analyze_parser.add_argument(
        "--vt",
        action="store_true",
        help="Enable VirusTotal API enrichment when VT_API_KEY is configured.",
    )
    analyze_parser.add_argument(
        "--abuseipdb",
        action="store_true",
        help="Enable AbuseIPDB enrichment when ABUSEIPDB_API_KEY is configured.",
    )

    export_parser = subparsers.add_parser("export", help="Verify JSON and CSV exports for a scan.")
    export_parser.add_argument("scan_name", nargs="?", help="Optional scan name. Defaults to last scan.")

    report_parser = subparsers.add_parser("report", help="Verify the HTML report for a scan.")
    report_parser.add_argument("scan_name", nargs="?", help="Optional scan name. Defaults to last scan.")

    subparsers.add_parser("test-vt", help="Validate the configured VirusTotal API key.")
    return parser


def main() -> int:
    """Application entry point."""
    configure_logging()
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "analyze":
            return handle_analyze(
                args.input_file,
                scan_name=args.scan_name,
                use_virustotal=args.vt,
                use_abuseipdb=args.abuseipdb,
            )
        if args.command == "export":
            return handle_export(args.scan_name)
        if args.command == "report":
            return handle_report(args.scan_name)
        if args.command == "test-vt":
            return handle_test_vt()
    except Exception as exc:  # pragma: no cover - defensive CLI safety net
        logging.exception("Unhandled application error: %s", exc)
        parser.exit(status=1, message=f"Error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
