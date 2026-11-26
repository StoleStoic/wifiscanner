"""Optional Claude-powered analysis on top of the rule engine.

Needs the `anthropic` package and an API key (Settings, or the ANTHROPIC_API_KEY
environment variable). Only a compact summary of the scan is sent.
"""

from __future__ import annotations

import json
from typing import Any

from .analysis import PRIORITIES

CATEGORIES = ["Security", "Connectivity", "Performance", "Configuration"]
ARTICLES = ["rogue-ap", "unauthorized-ap", "accidental-association", "rogue-client", "open-network",
            "weak-encryption", "wps", "wpa3", "pmf", "consistent-config", "signal-strength", "roaming",
            "channel-width", "channel-planning", "interference", "channel-utilization", "client-load",
            "legacy-rates", "wifi-generations", "hidden-ssid", "bands", "getting-started"]

SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "notes": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": CATEGORIES},
                "priority": {"type": "string", "enum": PRIORITIES},
                "title": {"type": "string"},
                "detail": {"type": "string"},
                "article": {"type": "string", "enum": ARTICLES},
                "bssid": {"type": "string"},
            },
            "required": ["category", "priority", "title", "detail", "article", "bssid"],
            "additionalProperties": False}},
    },
    "required": ["summary", "notes"],
    "additionalProperties": False,
}

SYSTEM = """You are the analysis engine inside a personal home WiFi scanner. The owner is not a network \
engineer. You receive one snapshot: the access points their Windows PC can hear, which ones they have \
authorized as their own, the current connection, devices found on their LAN, and the notes a rule engine \
already produced.

Write the notes a senior wireless engineer would add after looking at this home's airspace as a whole: \
things the per-network rules miss, such as channel plans across the owner's own APs, a band that is better \
left unused, what the combination of findings implies, or which single change would help most. Do not \
repeat a rule note unless you are correcting or sharpening it. Every note must rest on values present in \
the snapshot; cite them (channel, dBm, BSSID). If the snapshot does not support any further finding, \
return an empty notes list.

Each note: a short title, then a detail of two to four plain sentences ending with the concrete action to \
take in the router or on the PC. Set bssid to the access point it concerns, or an empty string. Pick the \
closest article slug. The summary is two or three sentences on the overall state of the network, most \
urgent matter first. Distances in the snapshot are rough path-loss estimates; treat them as such."""

KEEP = ["ssid", "bssid", "vendor", "band", "channel", "width", "rssi", "snr", "generation", "security",
        "pmf", "wps", "stations", "utilization", "cci", "aci", "connected", "k", "v", "r", "hidden"]


def build_snapshot(nets: list[dict], conn: dict | None, threats: dict, rule_notes: list[dict],
                   lan: list[dict]) -> dict[str, Any]:
    cls = {t["bssid"]: (t["cls"], t["distance"]["m"]) for t in threats["aps"]}
    aps = []
    for n in sorted(nets, key=lambda x: -x["rssi"])[:120]:
        a = {k: n.get(k) for k in KEEP}
        a["class"], a["est_distance_m"] = cls.get(n["bssid"], ("unclassified", None))
        aps.append(a)
    return {
        "connection": conn, "access_points": aps, "home_ssids": threats["home_ssids"],
        "threat_events": threats["events"], "unknown_lan_devices": threats["clients"],
        "lan_device_count": len(lan),
        "rule_notes": [{k: r[k] for k in ("category", "priority", "title", "detail")} for r in rule_notes],
    }


def analyze(snapshot: dict, api_key: str = "", model: str = "claude-opus-5-5") -> dict[str, Any]:
    try:
        import anthropic
    except ImportError:
        return {"error": "The 'anthropic' package is not installed. Run: pip install anthropic"}
    try:
        client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        response = client.beta.messages.create(
            model=model,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            thinking={"type": "adaptive"},
            system=SYSTEM,
            output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
            messages=[{"role": "user", "content": json.dumps(snapshot, default=str)}],
        )
    except anthropic.AuthenticationError:
        return {"error": "The Anthropic API key was rejected. Check it in Settings."}
    except anthropic.RateLimitError:
        return {"error": "Rate limited by the Anthropic API. Try again in a minute."}
    except anthropic.APIStatusError as e:
        return {"error": f"Anthropic API error ({e.status_code}): {e.message}"}
    except anthropic.APIConnectionError:
        return {"error": "Could not reach the Anthropic API. Check the internet connection."}
    except anthropic.AnthropicError as e:  # e.g. no credentials configured
        return {"error": str(e)}
    if response.stop_reason == "refusal":
        return {"error": "The model declined to analyse this snapshot."}
    if response.stop_reason == "max_tokens":
        return {"error": "The analysis was cut off before it finished. Try again."}
    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        data = json.loads(text)
    except ValueError:
        return {"error": "The analysis came back in an unexpected format."}
    for n in data.get("notes", []):
        n["source"] = "claude"
        n["bssid"] = n.get("bssid") or None
    return {"summary": data.get("summary", ""), "notes": data.get("notes", []), "model": response.model}
