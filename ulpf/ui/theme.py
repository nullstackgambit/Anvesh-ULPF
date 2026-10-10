"""Visual layer of the operator UI: page CSS, the header, menu and footer
markup, status tiles, live-feed rows and the Overview chart.

Everything renders offline: no web fonts or scripts are fetched (Noto Sans is
used when installed, else the system UI font), and the HTML here is static
(links and anchors only).
"""
from __future__ import annotations

import base64
import datetime as dt
from html import escape

PRIMARY_50, PRIMARY_600, PRIMARY_700, PRIMARY_800, PRIMARY_900, PRIMARY_950 = (
    "#f2efff", "#4a2bc2", "#3d239f", "#301c7d", "#24145c", "#1a0e3d")
SAFFRON, FLAG_GREEN = "#ff9933", "#138808"
NEUTRAL = {0: "#ffffff", 50: "#fafafa", 100: "#f5f5f5", 200: "#e5e5e5", 300: "#d9d9d9", 400: "#a1a1a1",
           500: "#737373", 600: "#525252", 700: "#404040", 900: "#171717"}
# status -> (icon/accent, tinted background, text) colours; never used for
# chart series (those are in .streamlit/config.toml)
STATUS = {
    "success": ("#128937", "#f2fcef", "#00522c"),
    "warning": ("#fa8c16", "#fff7e6", "#ad4e00"),
    "error": ("#db372d", "#fff8f8", "#8a1a16"),
    "info": ("#13c2c2", "#e6fffb", "#006d75"),
}
FONT = ("'Noto Sans', 'Segoe UI', system-ui, -apple-system, Roboto, 'Helvetica Neue', Arial, "
        "'Noto Sans Devanagari', 'Nirmala UI', Mangal, sans-serif")
TEXT_SIZES = {"sm": 14, "md": 16, "lg": 18}
IST = dt.timezone(dt.timedelta(hours=5, minutes=30), "IST")
HINDI_NAME = "सार्वभौमिक लॉग पूर्व-प्रसंस्करण फ्रेमवर्क"
ENGLISH_NAME = "Universal Log Pre-processing Framework"

_ICONS = {  # 24x24 outline icons (stroke = currentColor)
    "success": '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.6 2.6L16 9.7"/>',
    "warning": '<path d="M12 3.5l9 16H3z"/><path d="M12 10v4.2"/><circle cx="12" cy="17.2" r=".6" fill="currentColor"/>',
    "error": '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><circle cx="12" cy="7.8" r=".6" fill="currentColor"/>',
}


def _img(svg: str, size: int, alt: str = "") -> str:
    # st.html sanitises its HTML and removes inline <svg>; an <img> with a
    # data: URI is kept (and needs no network)
    uri = "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()
    return f'<img class="ulpf-icon" src="{uri}" width="{size}" height="{size}" alt="{escape(alt)}">'


def icon(kind: str, size: int = 18, color: str | None = None) -> str:
    """Status icon in its status colour; decorative (the label beside it carries the meaning)."""
    c = color or STATUS[kind][0]
    return _img(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2" '
                f'stroke-linecap="round" stroke-linejoin="round">{_ICONS[kind].replace("currentColor", c)}</svg>', size)


def mark(size: int = 52) -> str:
    """ULPF mark: a shield holding three log lines."""
    return _img(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
                f'<path d="M24 3l17 6v13c0 11-7.4 19.4-17 23C14.4 41.4 7 33 7 22V9z" fill="{PRIMARY_600}"/>'
                f'<path d="M24 7.2l13 4.6V22c0 8.6-5.6 15.3-13 18.4C16.6 37.3 11 30.6 11 22V11.8z" fill="#fff"/>'
                f'<rect x="16" y="15" width="16" height="3.2" rx="1.6" fill="{SAFFRON}"/>'
                f'<rect x="16" y="21.4" width="12" height="3.2" rx="1.6" fill="{PRIMARY_600}"/>'
                f'<rect x="16" y="27.8" width="14" height="3.2" rx="1.6" fill="{FLAG_GREEN}"/></svg>', size, alt="ULPF logo")


def css(text_size: str) -> str:
    root_px = TEXT_SIZES.get(text_size, 16)
    return "<style>" + _CSS.replace("@@FONT@@", FONT) + f"html {{ font-size: {root_px}px !important; }}</style>"


def _qs(page: str, ts: str) -> str:
    return f"?page={escape(page)}&amp;ts={escape(ts)}"


def header(*, page: str, ts: str, collector: str, ocsf: str, health: dict[str, str], now: dt.datetime) -> str:
    sizes = "".join(
        f'<a href="{_qs(page, k)}" class="{"on" if k == ts else ""}" aria-label="{label}"'
        f'{" aria-current=true" if k == ts else ""}>{txt}</a>'
        for k, txt, label in (("sm", "A−", "Decrease text size"), ("md", "A", "Normal text size"),
                              ("lg", "A+", "Increase text size")))
    pills = "".join(
        f'<span class="ulpf-pill {"ok" if v == "healthy" else "bad"}">'
        f'{icon("success" if v == "healthy" else "error", 15)}{escape(k)}: {escape(v)}</span>'
        for k, v in health.items())
    return f"""
<div class="ulpf-band ulpf-tricolour" aria-hidden="true"><span></span><span></span><span></span></div>
<div class="ulpf-band ulpf-utility">
  <div class="ulpf-utility-left">Collector <b>{escape(collector)}</b><span class="sep">|</span>OCSF {escape(ocsf)}<span class="sep">|</span>Data refreshed {now.astimezone(IST):%d %b %Y, %H:%M} IST</div>
  <nav class="ulpf-utility-right" aria-label="Accessibility">
    <a href="#main-content" class="ulpf-skip">Skip to main content</a><span class="sep">|</span>
    <span class="ulpf-sizes" role="group" aria-label="Text size">{sizes}</span>
  </nav>
</div>
<header class="ulpf-band ulpf-header">
  <a class="ulpf-brand" href="{_qs("overview", ts)}">
    {mark()}
    <span class="ulpf-brand-text">
      <span class="ulpf-hi" lang="hi">{HINDI_NAME}</span>
      <span class="ulpf-en">{ENGLISH_NAME}</span>
      <span class="ulpf-tag">Security log pre-processing console · raw-first, lossless, OCSF {escape(ocsf)}</span>
    </span>
  </a>
  <div class="ulpf-status" aria-label="System status">{pills}</div>
</header>"""


def page_head(*, title: str, lede: str, page: str, ts: str) -> str:
    crumb = (f'<a href="{_qs("overview", ts)}">Home</a><span aria-hidden="true">›</span>'
             if page != "overview" else "")
    return f"""
<div id="main-content" class="ulpf-pagehead" tabindex="-1">
  <nav class="ulpf-crumb" aria-label="Breadcrumb">{crumb}<span aria-current="page">{escape(title)}</span></nav>
  <h1 class="ulpf-title">{escape(title)}</h1>
  <p class="ulpf-lede">{escape(lede)}</p>
</div>"""


def status_rows(rows: list[tuple[str, str, str, int]], total: int) -> str:
    """rows: (status kind, label, description, count) -> labelled meters."""
    out = []
    for kind, label, desc, n in rows:
        accent, _, text = STATUS[kind]
        share = (n / total) if total else 0.0
        out.append(f"""
<div class="ulpf-srow">
  <span class="ulpf-sicon" style="color:{accent}">{icon(kind, 20)}</span>
  <div class="ulpf-sbody">
    <div class="ulpf-sline"><span class="ulpf-slabel">{escape(label)}</span>
      <span class="ulpf-sval">{n:,}<span class="ulpf-sshare" style="color:{text}">{share:.1%}</span></span></div>
    <div class="ulpf-meter" role="img" aria-label="{escape(label)}: {share:.1%} of events">
      <span style="width:{max(share * 100, 0.6 if n else 0):.2f}%;background:{accent}"></span></div>
    <div class="ulpf-sdesc">{escape(desc)}</div>
  </div>
</div>""")
    return '<div class="ulpf-status-list">' + "".join(out) + "</div>"


def check_list(checks: list[tuple[bool, str, list[str]]]) -> str:
    items = []
    for ok, name, details in checks:
        kind = "success" if ok else "error"
        accent, bg, text = STATUS[kind]
        det = "".join(f"<li>{escape(d)}</li>" for d in details[:20])
        items.append(f'<li class="ulpf-check" style="background:{bg}"><span style="color:{accent}">{icon(kind, 18)}</span>'
                     f'<div><b style="color:{text}">{"PASS" if ok else "FAIL"}</b> · {escape(name)}'
                     f'{f"<ul>{det}</ul>" if det else ""}</div></li>')
    return '<ul class="ulpf-checks">' + "".join(items) + "</ul>"


# ------------------------------------------------------------- live feed
_STATUS_VIEW = {"parsed": ("success", "Parsed"), "partial": ("warning", "Partial"),
                "fallback": ("info", "Unrecognised"), "failed": ("error", "Failed")}


def status_view(status: str | None) -> tuple[str, str]:
    return _STATUS_VIEW.get(status or "", ("info", status or "unknown"))


def _get(d, path: str):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def ist_time(iso: str | None) -> str:
    """HH:MM:SS IST of an ISO UTC timestamp (ingest times carry nanoseconds)."""
    try:
        t = dt.datetime.strptime((iso or "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return iso or ""
    return t.astimezone(IST).strftime("%H:%M:%S")


def raw_text(d: dict) -> str:
    """The received line for display: control characters shown as middle dots."""
    raw = d.get("raw_data")
    if raw is None:
        return f"<{_get(d, 'ulpf.raw.len') or '?'} bytes, not valid UTF-8: exact bytes in the raw archive>"
    if not raw.strip():
        return f"<{len(raw)} whitespace character{'s' if len(raw) != 1 else ''}>" if raw else "<empty line>"
    return "".join(c if c.isprintable() else "·" for c in raw)


def _endpoint(ep) -> str:
    if not isinstance(ep, dict) or not ep.get("ip"):
        return ""
    return f"{ep['ip']}:{ep['port']}" if ep.get("port") is not None else ep["ip"]


def summary(d: dict) -> tuple[str, str]:
    """(headline, detail) of a normalized event for the feed."""
    st = _get(d, "ulpf.status")
    if st == "fallback":
        return "Base Event", "no approved spec matched · kept for onboarding"
    if st == "failed":
        return "Kept unparsed", ", ".join(_get(d, "ulpf.reasons") or ["failed"])
    src, dst = _endpoint(d.get("src_endpoint")), _endpoint(d.get("dst_endpoint"))
    parts = [f"{src or '?'} → {dst or '?'}" if src or dst else None, _get(d, "http_request.http_method"),
             d.get("action") or d.get("disposition")]
    return str(d.get("class_name") or ""), " · ".join(str(p) for p in parts if p)


def _lineage_order(item: tuple[str, object]) -> int:
    """Direct source-field mappings first (easiest to follow), then enums, derived values, constants."""
    v = str(item[1])
    return 3 if v == "const" else 2 if v.startswith("derived:") else 1 if v.startswith("enum:") else 0


FLASH_S = 2.6   # highlight of a newly arrived feed row (keep in step with the ulpf-flash keyframes)


def feed_rows(events: list[dict], ages: dict[str, float] | None = None) -> str:
    """Newest events, one row each. `ages` (seconds since each event first
    appeared in the feed) keeps a new row's highlight running smoothly across
    the once-a-second redraws: the fade resumes at its current position."""
    ages = ages or {}
    head = ('<div class="ulpf-feed-row ulpf-feed-head" aria-hidden="true"><span>Time (IST)</span><span>Status</span>'
            '<span>Source · format</span><span>Received line</span><span></span><span>Normalized to OCSF</span></div>')
    rows = []
    for d in events:
        kind, label = status_view(_get(d, "ulpf.status"))
        _, bg, text = STATUS[kind]
        uid = _get(d, "metadata.uid") or ""
        product = _get(d, "metadata.product.name") or "unknown"
        raw = raw_text(d)
        headline, detail = summary(d)
        age = ages.get(uid, FLASH_S)
        flash = f' new" style="animation-delay:-{age:.2f}s' if age < FLASH_S else ""
        rows.append(
            f'<div class="ulpf-feed-row{flash}">'
            f'<span class="ulpf-feed-time">{ist_time(_get(d, "ulpf.ingest.time"))}</span>'
            f'<span><span class="ulpf-chip" style="background:{bg};color:{text}">{icon(kind, 14)}{label}</span></span>'
            f'<span class="ulpf-feed-src"><b>{escape("Unknown" if product == "unknown" else product)}</b>'
            f'<span class="ulpf-fmt">{escape(_get(d, "ulpf.format") or "")}</span></span>'
            f'<code class="ulpf-feed-raw" title="{escape(raw[:2000])}">{escape(raw[:240])}</code>'
            f'<span class="ulpf-feed-arrow" aria-hidden="true">→</span>'
            f'<span class="ulpf-feed-out"><b>{escape(headline)}</b><span>{escape(detail)}</span></span></div>')
    if not rows:
        rows.append('<div class="ulpf-feed-empty">No events yet. They appear here about two seconds after they '
                    'are received.</div>')
    return '<div class="ulpf-feed">' + head + "".join(rows) + "</div>"


def _dl(rows: list[tuple[str, object]]) -> str:
    return '<dl class="ulpf-kv">' + "".join(f"<dt>{escape(k)}</dt><dd>{escape(str(v))}</dd>"
                                          for k, v in rows if v not in (None, "", "None")) + "</dl>"


def pipeline_steps(d: dict, *, ocsf: str) -> str:
    """One event's way through the pipeline: received -> recognised -> normalized -> lineage."""
    u = d.get("ulpf") or {}
    status = u.get("status")
    kind, label = status_view(status)
    ing, rawm, parser = u.get("ingest") or {}, u.get("raw") or {}, u.get("parser") or {}
    peer = (ing.get("peer") or {}).get("ip") or (ing.get("peer") or {}).get("file")
    s1 = (f"<pre>{escape(raw_text(d)[:1500])}</pre>"
          + _dl([("Size", f"{rawm.get('len', '?')} bytes"), ("Transport", f"{ing.get('transport', '?')} from {peer or '?'}"),
                 ("SHA-256", (rawm.get("sha256") or "")[:20] + "…"), ("Kept", "byte for byte in the raw archive")]))
    if status in ("parsed", "partial"):
        s2 = _dl([("Format", u.get("format")), ("Fingerprint", u.get("fingerprint")),
                  ("Spec", f"{parser.get('id')} v{parser.get('version')}"), ("Result", label)])
        cov = u.get("coverage") or {}
        s3 = _dl([("Class", f"{d.get('class_name')} ({d.get('class_uid')})"), ("Activity", d.get("activity_name")),
                  ("Source", _endpoint(d.get("src_endpoint"))), ("Destination", _endpoint(d.get("dst_endpoint"))),
                  ("Protocol", _get(d, "connection_info.protocol_name")), ("Action", d.get("action") or d.get("disposition")),
                  ("Device", _get(d, "device.hostname")),
                  ("Fields", f"{cov.get('mapped', 0)} mapped · {cov.get('unmapped', 0)} kept unmapped · "
                             f"{cov.get('empty', 0)} empty")])
    else:
        s2 = (_dl([("Format", u.get("format")), ("Fingerprint", u.get("fingerprint")), ("Spec", "none matched"),
                   ("Reasons", ", ".join(u.get("reasons") or []))])
              + '<p class="muted">The fingerprint groups it on Unknown sources &amp; onboarding, where a spec can be '
                "drafted from it.</p>")
        s3 = _dl([("Class", "Base Event (0)"), ("Result", label),
                  ("Kept", "the received line and every layer the pre-parser detected (in unmapped)")])
    lineage = sorted((u.get("lineage") or {}).items(), key=_lineage_order)
    if lineage:
        shown = lineage[:9]
        s4 = ('<ul class="ulpf-lineage">'
              + "".join(f'<li><code class="to">{escape(k)}</code> ← <code class="from">{escape(str(v))}</code></li>'
                        for k, v in shown)
              + (f'<li class="muted">+{len(lineage) - len(shown)} more</li>' if len(lineage) > len(shown) else "")
              + "</ul>")
    else:
        s4 = '<p class="muted">No field mappings yet: nothing is discarded, and the event waits for a spec.</p>'
    steps = [("1 · Received", s1), ("2 · Recognised", s2), (f"3 · Normalized to OCSF {escape(ocsf)}", s3),
             ("4 · Field lineage", s4)]
    return ('<div class="ulpf-steps">'
            + "".join(f'<section class="ulpf-step"><h4>{t}</h4>{b}</section>' for t, b in steps) + "</div>")


def footer(*, pages: list[tuple[str, str]], page: str, ts: str, version: str, ocsf: str, collector: str, alias: str,
           now: dt.datetime) -> str:
    links = "".join(f'<li><a href="{_qs(slug, ts)}">{escape(label)}</a></li>' for slug, label in pages)
    sizes = " ".join(f'<a href="{_qs(page, k)}">{t}</a>' for k, t in (("sm", "A−"), ("md", "A"), ("lg", "A+")))
    return f"""
<footer class="ulpf-band ulpf-footer">
  <div class="ulpf-fgrid">
    <div class="ulpf-fbrand">
      <div class="ulpf-fname">{mark(40)}<span><span lang="hi">{HINDI_NAME}</span><b>{ENGLISH_NAME}</b></span></div>
      <p>Every received byte is archived first and sealed (Merkle tree, Ed25519, hash chain). Events are normalized to
      OCSF {escape(ocsf)}; anything that could not be mapped is kept, and every value is traceable to its source field.</p>
    </div>
    <div><h2>Sections</h2><ul>{links}</ul></div>
    <div><h2>This deployment</h2><ul>
      <li>Collector: {escape(collector)}</li><li>Index alias: {escape(alias)}</li>
      <li>OCSF schema {escape(ocsf)}</li><li>ULPF {escape(version)}</li></ul></div>
    <div><h2>Accessibility</h2><ul>
      <li><a href="#main-content">Skip to main content</a></li><li>Text size: {sizes}</li></ul></div>
  </div>
  <div class="ulpf-fbottom">
    <span>ULPF {escape(version)} · Apache License 2.0</span>
    <span>Page generated {now.astimezone(IST):%d %b %Y, %H:%M} IST</span>
  </div>
</footer>"""


def bar_chart(values: dict[str, int], *, category: str, measure: str, color: str = PRIMARY_600, text_size: str = "md"):
    """One-series horizontal bar chart: sorted, thin bars with 4px rounded
    ends, value labels at the bar ends, hairline grid, hover tooltip. Chart
    text follows the A-/A/A+ setting (Vega font sizes are in pixels)."""
    import altair as alt

    k = TEXT_SIZES.get(text_size, 16) / 16

    rows = [{category: k, measure: v} for k, v in sorted(values.items(), key=lambda kv: -kv[1])]
    top = max(values.values()) if values else 1
    y = alt.Y(f"{category}:N", sort=None, title=None,
              scale=alt.Scale(paddingInner=0.38, paddingOuter=0.2),
              axis=alt.Axis(domain=False, ticks=False, labelPadding=10, labelLimit=int(200 * k), labelFontSize=13 * k,
                            labelColor=NEUTRAL[700]))
    x = alt.X(f"{measure}:Q", title=None, scale=alt.Scale(domain=[0, top * 1.16], nice=False),
              axis=alt.Axis(domain=False, ticks=False, grid=True, gridColor=NEUTRAL[200], format="~s", tickCount=5,
                            labelColor=NEUTRAL[500], labelFontSize=11 * k))
    tip = [alt.Tooltip(f"{category}:N", title=category.capitalize()), alt.Tooltip(f"{measure}:Q", title=measure.capitalize(), format=",")]
    base = alt.Chart(alt.Data(values=rows)).encode(y=y, x=x, tooltip=tip)
    bars = base.mark_bar(color=color, cornerRadiusEnd=4)
    labels = base.mark_text(align="left", baseline="middle", dx=6, color=NEUTRAL[700], fontSize=12 * k).encode(
        text=alt.Text(f"{measure}:Q", format=","))
    return ((bars + labels).properties(height=max(150, int(32 * k * len(rows))), background="transparent")
            .configure(font=FONT).configure_view(stroke=None))


_CSS = """
:root {
  --ulpf-gutter: clamp(1rem, 3vw, 2.75rem);
  --ulpf-primary: #4a2bc2; --ulpf-primary-50: #f2efff; --ulpf-primary-700: #3d239f;
  --ulpf-primary-800: #301c7d; --ulpf-primary-950: #1a0e3d;
  --ulpf-saffron: #ff9933; --ulpf-green: #138808; --ulpf-amber: #e89c30;
  --ulpf-text: #171717; --ulpf-text-2: #525252; --ulpf-muted: #737373;
  --ulpf-border: #e5e5e5; --ulpf-soft: #fafafa;
  --ulpf-mono: 'Noto Sans Mono', 'DejaVu Sans Mono', Menlo, Consolas, monospace;
}
/* hide Streamlit's toolbar, decoration and sidebar */
[data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stDecoration"],
[data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], [data-testid="stExpandSidebarButton"],
[data-testid="stHeaderActionElements"] { display: none !important; }
[data-testid="stAppViewContainer"], [data-testid="stMain"] { background: #fff; }
[data-testid="stMain"] { overflow-x: hidden; }
[data-testid="stMainBlockContainer"] { padding: 0 var(--ulpf-gutter) 0 !important; max-width: none !important; }
.st-key-ulpf_top { gap: 0 !important; }
.ulpf-band { margin: 0 calc(-1 * var(--ulpf-gutter)); padding: 0 var(--ulpf-gutter); font-family: @@FONT@@; }
a:focus-visible, [tabindex]:focus-visible { outline: 3px solid var(--ulpf-amber); outline-offset: 2px; }

/* top strip + utility bar */
.ulpf-tricolour { display: flex; height: 5px; padding: 0 !important; }
.ulpf-tricolour span { flex: 1; } .ulpf-tricolour span:nth-child(1) { background: var(--ulpf-saffron); }
.ulpf-tricolour span:nth-child(2) { background: #fff; } .ulpf-tricolour span:nth-child(3) { background: var(--ulpf-green); }
.ulpf-utility { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: .25rem 1rem;
  background: var(--ulpf-primary-950); color: #e5e5e5; font-size: .8rem; min-height: 2.1rem; }
.ulpf-utility b { color: #fff; font-weight: 600; }
.ulpf-utility .sep { color: #6a5f8f; margin: 0 .6rem; }
.ulpf-utility a { color: #fff; text-decoration: none; }
.ulpf-utility a:hover { text-decoration: underline; }
.ulpf-utility-right { display: flex; align-items: center; }
.ulpf-sizes { display: inline-flex; gap: .25rem; }
.ulpf-sizes a { display: inline-block; min-width: 1.7rem; text-align: center; padding: .05rem .3rem; border: 1px solid #5d5585;
  border-radius: 4px; line-height: 1.35; font-weight: 600; }
.ulpf-sizes a.on { background: #fff; color: var(--ulpf-primary-950); border-color: #fff; }

/* header */
.ulpf-header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: .75rem 1.5rem;
  background: #fff; padding-top: .9rem !important; padding-bottom: .9rem !important; border-bottom: 1px solid var(--ulpf-border); }
.ulpf-brand { display: flex; align-items: center; gap: .9rem; text-decoration: none !important; }
.ulpf-brand-text { display: flex; flex-direction: column; line-height: 1.25; }
.ulpf-hi { color: var(--ulpf-primary-800); font-size: .95rem; font-weight: 600; }
.ulpf-en { color: var(--ulpf-text); font-size: 1.45rem; font-weight: 700; letter-spacing: -.01em; }
.ulpf-tag { color: var(--ulpf-text-2); font-size: .82rem; margin-top: .1rem; }
.ulpf-status { display: flex; gap: .5rem; flex-wrap: wrap; }
.ulpf-pill { display: inline-flex; align-items: center; gap: .35rem; font-size: .8rem; font-weight: 600; padding: .3rem .7rem;
  border-radius: 999px; border: 1px solid; text-transform: capitalize; }
.ulpf-pill.ok { color: #00522c; background: #f2fcef; border-color: #beefbb; }
.ulpf-pill.bad { color: #8a1a16; background: #fff8f8; border-color: #ffb3ae; }
.ulpf-icon { flex: none; }

/* menu bar (the page radio; Streamlit 1.65 markup: radiogroup > div > label[stRadioOption]) */
.st-key-ulpf_nav { background: var(--ulpf-primary-700); margin: 0 calc(-1 * var(--ulpf-gutter)) !important;
  width: calc(100% + 2 * var(--ulpf-gutter)) !important; max-width: none !important;
  padding: 0 var(--ulpf-gutter); box-shadow: 0 2px 4px rgba(26, 14, 61, .18); }
.st-key-ulpf_nav [data-testid="stRadio"] { margin: 0; }
.st-key-ulpf_nav [role="radiogroup"] { gap: 0 !important; flex-wrap: wrap; }
.st-key-ulpf_nav [role="radiogroup"] > div { margin: 0 !important; padding: 0 !important; }
.st-key-ulpf_nav [data-testid="stRadioOption"] { margin: 0 !important; padding: .78rem 1.05rem .66rem !important;
  cursor: pointer; border-bottom: 3px solid transparent; transition: background .15s; }
.st-key-ulpf_nav [data-testid="stRadioOption"] > div > div:first-child { display: none !important; }
.st-key-ulpf_nav [data-testid="stRadioOption"] p { color: #fff !important; font-weight: 600; font-size: .92rem; margin: 0; }
.st-key-ulpf_nav [data-testid="stRadioOption"]:hover { background: rgba(255, 255, 255, .1); }
.st-key-ulpf_nav [data-testid="stRadioOption"][data-selected="true"] { background: rgba(255, 255, 255, .14);
  border-bottom-color: var(--ulpf-saffron); }
.st-key-ulpf_nav [data-testid="stRadioOption"]:has(input:focus-visible) { outline: 3px solid var(--ulpf-amber);
  outline-offset: -3px; }
@media (max-width: 640px) {   /* phones: one swipeable menu row instead of four wrapped rows */
  .st-key-ulpf_nav [role="radiogroup"] { flex-wrap: nowrap !important; overflow-x: auto; scrollbar-width: none; }
  .st-key-ulpf_nav [role="radiogroup"]::-webkit-scrollbar { display: none; }
  .st-key-ulpf_nav [data-testid="stRadioOption"] { padding: .7rem .8rem .58rem !important; white-space: nowrap; }
  .ulpf-utility-left { display: none; }
}

/* page head */
.ulpf-pagehead { padding: 1.4rem 0 .4rem; font-family: @@FONT@@; outline: none; }
.ulpf-crumb { font-size: .82rem; color: var(--ulpf-muted); display: flex; gap: .45rem; align-items: center; }
.ulpf-crumb a { color: var(--ulpf-primary); text-decoration: none; } .ulpf-crumb a:hover { text-decoration: underline; }
.ulpf-title { font-size: 1.85rem !important; font-weight: 700 !important; color: var(--ulpf-text) !important;
  margin: .35rem 0 0 !important; padding: 0 !important; line-height: 1.25 !important; }
.ulpf-title::after { content: ""; display: block; width: 3.25rem; height: 4px; border-radius: 2px; margin-top: .55rem;
  background: linear-gradient(90deg, var(--ulpf-saffron) 0 50%, var(--ulpf-green) 50% 100%); }
.ulpf-lede { color: var(--ulpf-text-2); font-size: .98rem; margin: .7rem 0 0; max-width: 62rem; }

/* section headings, cards, metrics */
[data-testid="stHeading"] h3 { font-size: 1.08rem !important; font-weight: 700 !important; color: var(--ulpf-text);
  padding: 0 0 .5rem !important; margin-bottom: .1rem; border-bottom: 1px solid var(--ulpf-border); }
[data-testid="stHeading"] h3::before { content: ""; display: inline-block; width: 4px; height: .95em; margin-right: .55rem;
  vertical-align: -.1em; border-radius: 2px; background: var(--ulpf-primary); }
.st-key-ulpf_page [data-testid="stVerticalBlockBorderWrapper"], .st-key-ulpf_page [data-testid="stVerticalBlock"][class*="st-key-card"] {
  border-color: var(--ulpf-border) !important; box-shadow: 0 1px 2px rgba(23, 23, 23, .06), 0 1px 3px rgba(23, 23, 23, .04); background: #fff; }
[data-testid="stMetric"] { background: #fff; border-left: 4px solid var(--ulpf-primary) !important; }
[data-testid="stMetricLabel"] p { text-transform: uppercase; letter-spacing: .04em; font-size: .74rem !important;
  font-weight: 600; color: var(--ulpf-text-2); }
[data-testid="stMetricValue"] { font-weight: 700; color: var(--ulpf-text); text-transform: capitalize; }
button[data-baseweb="tab"] p { font-weight: 600; }

/* status meters (overview) and check lists (archive integrity) */
.ulpf-status-list { display: flex; flex-direction: column; gap: 1rem; font-family: @@FONT@@; padding: .2rem 0; }
.ulpf-srow { display: flex; gap: .75rem; align-items: flex-start; }
.ulpf-sicon { margin-top: .1rem; }
.ulpf-sbody { flex: 1; min-width: 0; }
.ulpf-sline { display: flex; justify-content: space-between; align-items: baseline; gap: .5rem; }
.ulpf-slabel { font-weight: 600; color: var(--ulpf-text); }
.ulpf-sval { font-weight: 700; color: var(--ulpf-text); }
.ulpf-sshare { font-weight: 600; font-size: .8rem; margin-left: .5rem; font-variant-numeric: tabular-nums; }
.ulpf-meter { height: 6px; background: var(--ulpf-border); border-radius: 3px; margin: .4rem 0 .3rem; overflow: hidden; }
.ulpf-meter span { display: block; height: 100%; border-radius: 3px; }
.ulpf-sdesc { font-size: .8rem; color: var(--ulpf-muted); }
.ulpf-checks { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: .5rem; font-family: @@FONT@@; }
.ulpf-check { display: flex; gap: .6rem; align-items: flex-start; padding: .6rem .8rem; border-radius: 6px; }
.ulpf-check ul { margin: .3rem 0 0; padding-left: 1.1rem; font-size: .82rem; color: var(--ulpf-text-2); }

/* footer */
.ulpf-footer { background: var(--ulpf-primary-950); color: #d9d9d9; margin-top: 3rem; padding-top: 2.2rem !important;
  border-top: 4px solid var(--ulpf-saffron); }
.ulpf-fgrid { display: grid; grid-template-columns: minmax(16rem, 2fr) repeat(3, minmax(10rem, 1fr)); gap: 1.75rem 2.5rem; }
@media (max-width: 900px) { .ulpf-fgrid { grid-template-columns: 1fr 1fr; } .ulpf-fbrand { grid-column: 1 / -1; } }
.ulpf-footer h2 { color: #fff !important; font-size: .9rem !important; font-weight: 700 !important; text-transform: uppercase;
  letter-spacing: .05em; margin: 0 0 .7rem !important; padding: 0 !important; }
.ulpf-footer ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: .45rem; font-size: .85rem; }
.ulpf-footer a { color: #fff; text-decoration: none; } .ulpf-footer a:hover { text-decoration: underline; }
.ulpf-footer p { font-size: .85rem; line-height: 1.55; margin: .8rem 0 0; color: #c9c4dc; }
.ulpf-fname { display: flex; gap: .7rem; align-items: center; }
.ulpf-fname > span { display: flex; flex-direction: column; color: #e5e5e5; font-size: .85rem; }
.ulpf-fname b { color: #fff; font-size: 1.02rem; }
.ulpf-fbottom { display: flex; justify-content: space-between; flex-wrap: wrap; gap: .4rem 1.5rem; margin-top: 2rem;
  padding: 1rem 0 1.2rem; border-top: 1px solid #3a2f63; font-size: .78rem; color: #b9b3cf; }

/* live feed */
.ulpf-feed { display: flex; flex-direction: column; border: 1px solid var(--ulpf-border); border-radius: 8px;
  overflow: hidden; font-family: @@FONT@@; }
.ulpf-feed-row { display: grid; grid-template-columns: 5.2rem 8.4rem 10rem minmax(0, 1.15fr) 1.2rem minmax(0, 1fr);
  align-items: center; gap: .7rem; padding: .5rem .85rem; border-top: 1px solid var(--ulpf-border); background: #fff;
  font-size: .85rem; }
.ulpf-feed-row:first-child { border-top: 0; }
.ulpf-feed-head { background: var(--ulpf-primary-50); color: #24145c; font-size: .7rem; font-weight: 700;
  text-transform: uppercase; letter-spacing: .05em; padding-top: .45rem; padding-bottom: .45rem; }
.ulpf-feed-row.new { animation: ulpf-flash 2.6s ease-out; }
@keyframes ulpf-flash { 0% { background: #ffebd6; box-shadow: inset 4px 0 0 var(--ulpf-saffron); }
  100% { background: #fff; box-shadow: inset 4px 0 0 transparent; } }
@media (prefers-reduced-motion: reduce) { .ulpf-feed-row.new { animation: none; box-shadow: inset 4px 0 0 var(--ulpf-saffron); } }
.ulpf-feed-time { color: var(--ulpf-muted); font-variant-numeric: tabular-nums; }
.ulpf-chip { display: inline-flex; align-items: center; gap: .3rem; padding: .14rem .55rem; border-radius: 999px;
  font-weight: 600; font-size: .76rem; white-space: nowrap; }
.ulpf-feed-src { display: flex; flex-direction: column; line-height: 1.25; min-width: 0; }
.ulpf-feed-src b { color: var(--ulpf-text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ulpf-fmt { font-family: var(--ulpf-mono); font-size: .72rem; color: var(--ulpf-primary-800); }
.ulpf-feed-raw { font-family: var(--ulpf-mono); font-size: .76rem; color: var(--ulpf-text-2); background: var(--ulpf-soft);
  border: 1px solid var(--ulpf-border); border-radius: 4px; padding: .18rem .45rem; white-space: nowrap; overflow: hidden;
  text-overflow: ellipsis; }
.ulpf-feed-arrow { color: var(--ulpf-primary); font-weight: 700; text-align: center; }
.ulpf-feed-out { display: flex; flex-direction: column; line-height: 1.3; min-width: 0; color: var(--ulpf-text); }
.ulpf-feed-out b { font-weight: 600; }
.ulpf-feed-out span { color: var(--ulpf-text-2); font-size: .8rem; overflow-wrap: anywhere; }
.ulpf-feed-empty { padding: 1.2rem; color: var(--ulpf-muted); text-align: center; }
@media (max-width: 900px) {
  .ulpf-feed-row { grid-template-columns: 4.4rem minmax(0, 1fr); }
  .ulpf-feed-src, .ulpf-feed-raw, .ulpf-feed-out { grid-column: 1 / -1; }
  .ulpf-feed-arrow, .ulpf-feed-head { display: none; }
}

/* parsing, step by step */
.ulpf-steps { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1.6rem; font-family: @@FONT@@; }
.ulpf-step { position: relative; border: 1px solid var(--ulpf-border); border-top: 4px solid var(--ulpf-primary);
  border-radius: 8px; padding: .75rem .9rem .85rem; background: #fff; min-width: 0; }
.ulpf-step:not(:last-child)::after { content: "→"; position: absolute; right: -1.25rem; top: 42%; color: var(--ulpf-primary);
  font-weight: 700; font-size: 1.1rem; }
.ulpf-step h4 { margin: 0 0 .55rem !important; padding: 0 !important; font-size: .78rem !important; font-weight: 700 !important;
  text-transform: uppercase; letter-spacing: .05em; color: var(--ulpf-primary-800) !important; }
.ulpf-step pre { white-space: pre-wrap; word-break: break-all; font-family: var(--ulpf-mono); font-size: .74rem;
  background: var(--ulpf-soft); border: 1px solid var(--ulpf-border); border-radius: 4px; padding: .45rem .55rem;
  margin: 0 0 .6rem; max-height: 9rem; overflow: auto; color: var(--ulpf-text); }
.ulpf-kv { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: .28rem .7rem; font-size: .8rem; margin: 0; }
.ulpf-kv dt { color: var(--ulpf-muted); white-space: nowrap; }
.ulpf-kv dd { margin: 0; color: var(--ulpf-text); overflow-wrap: anywhere; }
.ulpf-lineage { list-style: none; margin: 0; padding: 0; font-size: .78rem; display: flex; flex-direction: column; gap: .32rem; }
.ulpf-lineage code { font-family: var(--ulpf-mono); font-size: .73rem; background: none; padding: 0; }
.ulpf-lineage .to { color: var(--ulpf-text); } .ulpf-lineage .from { color: var(--ulpf-primary-800); }
.ulpf-step .muted { color: var(--ulpf-muted); font-size: .78rem; margin: .5rem 0 0; }
@media (max-width: 1100px) { .ulpf-steps { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
  .ulpf-step::after { display: none; } }
@media (max-width: 640px) { .ulpf-steps { grid-template-columns: 1fr; } }
"""
