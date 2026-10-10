"""Template mining with drain3 (in memory only) and safe template matching.

drain3's persistence uses jsonpickle, which can instantiate objects when a
tampered state file is loaded (ADR-009). ULPF therefore never loads drain3
state: mined templates are stored as plain JSON and matched with
`template_regex`, a pure re-implementation of "tokens equal or <*>".
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

MASKS = [
    (r"((?<=[^A-Za-z0-9])|^)(\d{1,3}\.){3}\d{1,3}((?=[^A-Za-z0-9])|$)", "IP"),
    (r"((?<=[^A-Za-z0-9])|^)([\-\+]?\d+)((?=[^A-Za-z0-9])|$)", "NUM"),
]


@dataclass
class Template:
    id: int
    text: str
    count: int
    examples: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def mine(messages: list[str], *, sim_th: float = 0.4, depth: int = 4, max_examples: int = 3,
         extra_delimiters: tuple[str, ...] = ()) -> list[Template]:
    """Cluster messages into templates. `extra_delimiters` split tokens in
    addition to whitespace (drain3 replaces them by spaces, so such templates
    are for display; `template_pattern` needs whitespace-only templates)."""
    from drain3 import TemplateMiner
    from drain3.masking import MaskingInstruction
    from drain3.template_miner_config import TemplateMinerConfig

    cfg = TemplateMinerConfig()
    cfg.drain_sim_th = sim_th
    cfg.drain_depth = depth
    cfg.profiling_enabled = False
    cfg.drain_extra_delimiters = list(extra_delimiters)
    cfg.masking_instructions = [MaskingInstruction(p, m) for p, m in MASKS]
    cfg.mask_prefix, cfg.mask_suffix = "<", ">"
    tm = TemplateMiner(persistence_handler=None, config=cfg)
    examples: dict[int, list[str]] = {}
    for msg in messages:
        r = tm.add_log_message(msg)
        ex = examples.setdefault(r["cluster_id"], [])
        if len(ex) < max_examples:
            ex.append(msg)
    out = [Template(c.cluster_id, c.get_template(), c.size, examples.get(c.cluster_id, [])) for c in tm.drain.clusters]
    return sorted(out, key=lambda t: -t.count)


_PARAM = re.compile(r"<[A-Z*]+>")


def template_regex(template: str) -> re.Pattern:
    """Whitespace-tokenised template -> regex; <*>, <IP>, <NUM> match one token."""
    parts = []
    for tok in template.split():
        if _PARAM.fullmatch(tok):
            parts.append(r"\S+")
        else:
            # a token may contain a mask inside (e.g. "port=<NUM>")
            pieces = _PARAM.split(tok)
            masks = _PARAM.findall(tok)
            rx = ""
            for i, piece in enumerate(pieces):
                rx += re.escape(piece)
                if i < len(masks):
                    rx += r"[^\s]+?" if i < len(masks) - 1 or pieces[-1] else r"\S+"
            parts.append(rx)
    return re.compile(r"^\s*" + r"\s+".join(parts) + r"\s*$")


def match_template(message: str, templates: list[dict]) -> int | None:
    for t in templates:
        if template_regex(t["text"]).match(message):
            return t["id"]
    return None


def template_pattern(template: str) -> tuple[str, list[str]]:
    """Template -> anchored regex with a named group per parameter (p1, p2, ...).

    Valid for both Python `re` and VRL's Rust regex (no look-around). Literal
    tokens must match exactly; tokens are separated by runs of whitespace.
    """
    from .infer import rx_escape

    groups: list[str] = []
    parts = []
    for tok in template.split():
        pieces = _PARAM.split(tok)
        masks = _PARAM.findall(tok)
        rx = ""
        for i, piece in enumerate(pieces):
            rx += rx_escape(piece)
            if i < len(masks):
                groups.append(f"p{len(groups) + 1}")
                last = i == len(masks) - 1 and not pieces[-1]
                rx += f"(?P<{groups[-1]}>\\S+)" if last else f"(?P<{groups[-1]}>\\S+?)"
        parts.append(rx)
    return "^" + r"\s+".join(parts) + "$", groups
