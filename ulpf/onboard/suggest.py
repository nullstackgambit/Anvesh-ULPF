"""Mapping suggestions: deterministic by default, optional local LLM.

THE LLM IS NEVER THE SOURCE OF TRUTH. Every suggestion -- deterministic or
LLM -- is only written into a *draft* and must pass the same gate (lint
against the vendored OCSF schema, real-Vector compile, tests) and a human
approval. If no LLM endpoint is configured the feature is simply off.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import asdict, dataclass, field

from ..ocsf import Ocsf, default as default_ocsf
from ..spec import TYPE_COMPAT
from .infer import FieldStats

# OCSF destination -> (accepted source-name patterns, required inferred types)
SYNONYMS: list[tuple[str, str, set[str]]] = [
    ("src_endpoint.ip", r"^(src|srcip|src_ip|source|source_ip|sip|src_addr|client|client_ip|clientip|id\.orig_h|orig_h|saddr)$", {"ip"}),
    ("dst_endpoint.ip", r"^(dst|dstip|dst_ip|dest|dest_ip|destination|destination_ip|dip|dst_addr|server|server_ip|id\.resp_h|resp_h|daddr)$", {"ip"}),
    ("src_endpoint.port", r"^(sport|srcport|src_port|source_port|spt|s_port|orig_p|id\.orig_p|client_port)$", {"int_small"}),
    ("dst_endpoint.port", r"^(dport|dstport|dst_port|dest_port|destination_port|dpt|d_port|resp_p|id\.resp_p|server_port|port)$", {"int_small"}),
    ("connection_info.protocol_name", r"^(proto|protocol|transport|ip_proto_name)$", {"string"}),
    ("connection_info.protocol_num", r"^(proto|protocol|ip_proto|protocol_id|proto_num)$", {"int_small"}),
    ("traffic.bytes_out", r"^(bytes_out|sent|sentbyte|sentbytes|bytes_sent|tx|tx_bytes|out|orig_bytes|bytes_toserver)$", {"int_small", "long"}),
    ("traffic.bytes_in", r"^(bytes_in|rcvd|rcvdbyte|received|bytes_received|rx|rx_bytes|in|resp_bytes|bytes_toclient)$", {"int_small", "long"}),
    ("traffic.packets_out", r"^(packets_out|pkts_sent|sentpkt|tx_pkts|orig_pkts)$", {"int_small", "long"}),
    ("traffic.packets_in", r"^(packets_in|pkts_received|rcvdpkt|rx_pkts|resp_pkts)$", {"int_small", "long"}),
    ("actor.user.name", r"^(user|username|usr|usrname|suser|src_user|account)$", {"string"}),
    ("device.hostname", r"^(host|hostname|devname|device|device_name|gw|gateway)$", {"string"}),
    ("firewall_rule.uid", r"^(rule|rule_id|ruleid|policy|policy_id|policyid|acl)$", {"string", "int_small", "long"}),
    ("message", r"^(msg|message|description|desc)$", {"string"}),
    ("connection_info.uid", r"^(session|session_id|sessionid|conn_id|flow_id|uid)$", {"string", "int_small", "long"}),
]
TIME_NAMES = re.compile(r"^(ts|time|timestamp|@timestamp|date|datetime|eventtime|event_time)$", re.I)
ACTION_NAMES = re.compile(r"^(action|verdict|decision|disposition|act|result)$", re.I)
ALLOW_WORDS = {"allow", "allowed", "permit", "permitted", "accept", "accepted", "pass", "passed", "ok", "success"}
DENY_WORDS = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "refuse", "refused"}


@dataclass
class Suggestion:
    source: str
    to: str
    type: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    origin: str = "deterministic"
    transform: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def field_entry(self) -> dict:
        e = {"to": self.to, "type": self.type}
        if self.transform:
            e["transform"] = self.transform
        return e


def _dsl_type(inferred: str, dest_type: str) -> str | None:
    if inferred == "ip":
        return "ip"
    if inferred == "mac":
        return "mac"
    if inferred in ("int_small", "long"):
        if dest_type == "port_t":
            return "port"
        if dest_type in ("long_t",):
            return "long"
        if dest_type in ("integer_t",):
            return "int"
        if dest_type.endswith("string_t") or dest_type == "string_t":
            return "string"
    if inferred == "string":
        return "string"
    return None


def _real(fs: FieldStats) -> list[str]:
    return [v for v in fs.values if v not in ("", "-")]


def deterministic(fields: dict[str, FieldStats], cls: str, profiles: list[str], o: Ocsf | None = None) -> list[Suggestion]:
    """Name-synonym + value-type matching. A suggestion is only made when the
    destination exists in the vendored OCSF class (with these profiles) and
    the inferred value type is compatible with the destination type."""
    o = o or default_ocsf()
    out: list[Suggestion] = []
    taken: set[str] = set()
    for name, fs in fields.items():
        for dest, pat, types in SYNONYMS:
            if dest in taken or not re.match(pat, name, re.I) or fs.type not in types:
                continue
            try:
                attr = o.resolve(cls, dest, profiles)
            except KeyError:
                continue
            t = _dsl_type(fs.type, attr.type)
            if t is None or attr.type not in TYPE_COMPAT.get(t, set()):
                continue
            real = _real(fs)
            # ip/port destinations carry the strongest value evidence; counters
            # (int/long) next; free strings are only name evidence.
            conf = 0.9 if dest.endswith((".ip", ".port")) else (0.85 if t in ("int", "long") else 0.75)
            sg = Suggestion(name, dest, t, conf,
                            [f"name {name!r} matches the {dest} synonym list",
                             f"{len(real)}/{len(fs.values)} non-empty values, all inferred as {fs.type}"])
            if dest == "connection_info.protocol_name" and any(v != v.lower() for v in real):
                sg.transform = "lower"
                sg.reasons.append("OCSF protocol_name is the lowercase IANA keyword; values are not lowercase")
            out.append(sg)
            taken.add(dest)
            break
    # positional fallback: exactly two unclaimed IP fields -> first src, second dst
    ips = [n for n, fs in fields.items() if fs.type == "ip" and n not in {s.source for s in out}]
    if len(ips) == 2 and "src_endpoint.ip" not in taken and "dst_endpoint.ip" not in taken:
        out.append(Suggestion(ips[0], "src_endpoint.ip", "ip", 0.4, ["first of two IP-valued fields (positional guess)"]))
        out.append(Suggestion(ips[1], "dst_endpoint.ip", "ip", 0.4, ["second of two IP-valued fields (positional guess)"]))
    return out


def time_candidates(fields: dict[str, FieldStats]) -> list[dict]:
    """Timestamp-typed fields; a field qualifies by name or by being the only
    timestamp-valued field."""
    ts_fields = [n for n, f in fields.items() if f.type == "timestamp"]
    out = []
    for name in ts_fields:
        fs = fields[name]
        if not (TIME_NAMES.match(name) or len(ts_fields) == 1):
            continue
        entry = {"field": name, "format": fs.time_format}
        if fs.time_format and "%" in fs.time_format:
            entry["timezone"] = "UTC"
            if "%Y" not in fs.time_format:
                entry["year"] = "infer"
        reason = f"{name!r}: all values match {fs.time_format}" + ("" if TIME_NAMES.match(name) else " (only timestamp-valued field)")
        out.append({"entry": entry, "reasons": [reason],
                    "review": [] if fs.time_format in ("rfc3339",) or not entry.get("timezone") else
                    ["timestamp has no zone: confirm the source clock is UTC or set timezone"]})
    return out


def action_enum(fields: dict[str, FieldStats], cls: str) -> dict | None:
    """A low-cardinality string field whose values are allow/deny words.

    Detection is by VALUES (a name like `action` only raises confidence), so a
    positional header column qualifies as well. Activity ids are only proposed
    for network_activity (6 Traffic, 5 Refuse) -- that choice is POLICY and is
    flagged for review.
    """
    best = None
    for name, fs in fields.items():
        if fs.type != "string" or not (1 <= fs.distinct <= 12):
            continue
        real = _real(fs)
        values = sorted(set(real))
        known = [v for v in values if v.lower() in ALLOW_WORDS | DENY_WORDS]
        if not known:
            continue
        share = sum(1 for v in real if v.lower() in ALLOW_WORDS | DENY_WORDS) / max(len(real), 1)
        if share < 0.8 and not ACTION_NAMES.match(name):
            continue
        score = share + (0.5 if ACTION_NAMES.match(name) else 0)
        if best is None or score > best[0]:
            best = (score, name, values, share)
    if best is None:
        return None
    _, name, values, share = best
    mp = {}
    for v in values:
        lv = v.lower()
        if lv in ALLOW_WORDS:
            mp[v] = {"action_id": 1, "disposition_id": 1}
            if cls == "network_activity":
                mp[v]["activity_id"] = 6
        elif lv in DENY_WORDS:
            mp[v] = {"action_id": 2, "disposition_id": 2}
            if cls == "network_activity":
                mp[v]["activity_id"] = 5
    dflt = {"action_id": 99, "disposition_id": 99}
    missing = {"action_id": 0, "disposition_id": 0}
    if cls == "network_activity":
        dflt["activity_id"], missing["activity_id"] = 99, 0
    return {"enum": {"source": name, "case_insensitive": True, "map": mp, "default": dflt, "missing": missing},
            "reasons": [f"{name!r}: {len(values)} distinct values, {share:.0%} of samples are allow/deny words {sorted(mp)}"
                        + (f"; name {name!r} is an action-like name" if ACTION_NAMES.match(name) else "; detected by values (no name evidence)")],
            "review": ["POLICY: allow -> activity Traffic(6), deny -> activity Refuse(5); confirm against vendor semantics"
                       if cls == "network_activity" else "confirm the allow/deny vocabulary"]}


# ------------------------------------------------------------- optional LLM
def llm_enabled() -> bool:
    return bool(os.environ.get("ULPF_LLM_URL"))


def llm_suggestions(fields: dict[str, FieldStats], cls: str, profiles: list[str], o: Ocsf | None = None,
                    *, timeout: float = 60) -> list[Suggestion]:
    """Ask an OpenAI-compatible endpoint (e.g. a local llama.cpp/vLLM server).

    Only localhost URLs are accepted (air-gap rule: no external API in the
    processing path). The reply is parsed defensively; every suggestion is
    validated against the vendored OCSF schema before it is even returned.
    """
    url = os.environ.get("ULPF_LLM_URL", "")
    if not url:
        return []
    host = urllib.request.urlparse(url).hostname or ""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("ULPF_LLM_URL must point to a local endpoint (127.0.0.1/localhost)")
    o = o or default_ocsf()
    summary = {n: {"type": fs.type, "examples": fs.examples[:3]} for n, fs in fields.items()}
    prompt = ("Map these log fields to OCSF 1.9.0 attribute paths of class " + cls +
              ". Answer ONLY with a JSON list of objects {source, to, confidence, reason}. Fields: " + json.dumps(summary))
    body = json.dumps({"model": os.environ.get("ULPF_LLM_MODEL", "local"), "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (localhost only, checked above)
        reply = json.loads(r.read())
    text = reply["choices"][0]["message"]["content"]
    m = re.search(r"\[.*\]", text, re.S)
    items = json.loads(m.group(0)) if m else []
    out = []
    for it in items if isinstance(items, list) else []:
        src, dest = str(it.get("source", "")), str(it.get("to", ""))
        if src not in fields:
            continue
        try:
            attr = o.resolve(cls, dest, profiles)
        except KeyError:
            continue  # invented / wrong path: discarded by deterministic validation
        t = _dsl_type(fields[src].type, attr.type)
        if t is None or attr.type not in TYPE_COMPAT.get(t, set()) or attr.enum:
            continue
        conf = float(it.get("confidence", 0.5))
        out.append(Suggestion(src, dest, t, min(max(conf, 0.0), 0.8),  # never above deterministic evidence
                              [f"LLM: {str(it.get('reason', ''))[:200]}", f"validated: {dest} exists ({attr.type}), type {t}"],
                              origin="llm"))
    return out
