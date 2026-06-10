"""Threat classification logic for IOC Analyzer."""

from __future__ import annotations


def classify_ioc(score: int, ioc_type: str) -> str:
    """Map numeric scores and detection confidence to a threat class."""
    if ioc_type == "Unknown":
        return "Unknown"
    if score >= 85:
        return "Malicious"
    if score >= 55:
        return "Suspicious"
    if score >= 20:
        return "Unknown"
    return "Benign"
