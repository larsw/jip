#!/usr/bin/env python3
"""Build the GitHub Pages site for the jip: vocabulary from vocab/jip.ttl.

    python3 scripts/build-vocab-site.py [OUTPUT_DIR]      (default: build/vocab-site)

Writes:
    index.html   the vocabulary as a web page, with the RDF embedded as JSON-LD
    jip.ttl      the vocabulary as Turtle (copied unchanged)
    jip.jsonld   the vocabulary as JSON-LD
    jip.nt       the vocabulary as N-Triples

Needs rdflib (pip install rdflib==7.6.0). The GitHub Actions workflow
.github/workflows/pages.yml runs this script and publishes the result.
"""

import html
import json
import os
import shutil
import sys
from pathlib import Path

from rdflib import Graph, Literal, URIRef
from rdflib.namespace import DCTERMS, OWL, RDF, RDFS

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "vocab" / "jip.ttl"
REPO_URL = os.environ.get("JIP_REPO_URL", "https://github.com/larsw/jip")

JIP = "https://larsw.github.io/jip#"
ONTOLOGY = URIRef(JIP[:-1])
VANN = "http://purl.org/vocab/vann/"
SD = "http://www.w3.org/ns/sparql-service-description#"
SD_FUNCTION = URIRef(SD + "Function")

PROPERTY_TYPES = {OWL.ObjectProperty, OWL.DatatypeProperty, RDF.Property}

CSS = """
:root { --fg: #1d1d1f; --muted: #5f6368; --bg: #ffffff; --panel: #f5f5f3; --line: #dcdcd8;
        --accent: #00548f; --code: #7a3b00; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e8e8e6; --muted: #a3a7ad; --bg: #161718; --panel: #1f2123; --line: #34373a;
          --accent: #7cb7ea; --code: #e9a96b; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
       font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width: 52rem; margin: 0 auto; padding: 2.5rem 1rem 4rem; }
h1 { font-size: 1.9rem; line-height: 1.2; margin: 0 0 0.4rem; color: var(--accent); }
h2 { font-size: 1.35rem; margin: 2.6rem 0 0.8rem; padding-bottom: 0.3rem; border-bottom: 1px solid var(--line); }
h3 { font-size: 1.05rem; margin: 0 0 0.3rem; }
a { color: var(--accent); }
code { font: 0.92em/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--code);
       overflow-wrap: anywhere; }
.lead { color: var(--muted); margin: 0 0 1.4rem; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 0.3rem 1rem; margin: 0 0 1.4rem; }
dl.meta dt { color: var(--muted); }
dl.meta dd { margin: 0; overflow-wrap: anywhere; }
nav ul { columns: 2 14rem; padding-left: 1.1rem; margin: 0.4rem 0 0; }
section.term { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
               padding: 1rem 1.1rem; margin: 0 0 0.9rem; scroll-margin-top: 1rem; }
section.term:target { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent); }
section.term p { margin: 0.4rem 0; }
section.term dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.15rem 0.9rem; margin: 0.5rem 0 0; }
section.term dt { color: var(--muted); }
section.term dd { margin: 0; overflow-wrap: anywhere; }
.iri { color: var(--muted); font-size: 0.9rem; margin: 0 0 0.4rem; overflow-wrap: anywhere; }
footer { margin-top: 3rem; color: var(--muted); font-size: 0.9rem; }
"""


def esc(text):
    return html.escape(str(text), quote=True)


def local(term):
    return str(term)[len(JIP):]


def curie(g, term):
    try:
        return g.namespace_manager.normalizeUri(term)
    except Exception:
        return f"<{term}>"


def link(g, term):
    """A link to a term: in-page anchor for jip: terms, the IRI itself otherwise."""
    if isinstance(term, Literal):
        return esc(term)
    s = str(term)
    href = "#" + local(term) if s.startswith(JIP) else s
    return f'<a href="{esc(href)}"><code>{esc(curie(g, term))}</code></a>'


def paragraphs(text):
    """Turtle long strings are wrapped; blank lines separate paragraphs."""
    blocks, current = [], []
    for line in str(text).splitlines():
        if line.strip():
            current.append(line.strip())
        elif current:
            blocks.append(" ".join(current))
            current = []
    if current:
        blocks.append(" ".join(current))
    return "".join(f"<p>{esc(b)}</p>" for b in blocks)


def objects(g, s, p):
    return sorted(g.objects(s, p), key=str)


def term_html(g, term):
    label = g.value(term, RDFS.label)
    types = objects(g, term, RDF.type)
    rows = [("Type", ", ".join(link(g, t) for t in types))]
    for name, pred in (("Subclass of", RDFS.subClassOf), ("Domain", RDFS.domain),
                       ("Range", RDFS.range), ("See also", RDFS.seeAlso)):
        vals = objects(g, term, pred)
        if vals:
            rows.append((name, ", ".join(link(g, v) for v in vals)))
    dl = "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in rows)
    return (f'<section class="term" id="{esc(local(term))}">'
            f'<h3><code>jip:{esc(local(term))}</code>'
            + (f" &middot; {esc(label)}" if label else "") + "</h3>"
            f'<div class="iri">{esc(term)}</div>'
            f"{paragraphs(g.value(term, RDFS.comment) or '')}"
            f"<dl>{dl}</dl></section>")


def groups(g):
    terms = sorted({s for s in g.subjects() if isinstance(s, URIRef) and str(s).startswith(JIP)},
                   key=lambda t: local(t).lower())
    classes, properties, functions, other = [], [], [], []
    for t in terms:
        types = set(g.objects(t, RDF.type))
        if OWL.Class in types or RDFS.Class in types:
            classes.append(t)
        elif types & PROPERTY_TYPES:
            properties.append(t)
        elif SD_FUNCTION in types:
            functions.append(t)
        else:
            other.append(t)
    return [("classes", "Classes", classes),
            ("properties", "Properties", properties),
            ("functions", "SPARQL functions", functions),
            ("context", "Context symbols", other)]


def json_ld(g):
    context = {p: str(ns) for p, ns in g.namespaces()
               if p in ("jip", "rdf", "rdfs", "owl", "xsd", "dcterms", "vann", "prov", "sd", "ja", "tdb2")}
    return json.loads(g.serialize(format="json-ld", context=context, auto_compact=True))


def page(g, embedded):
    ont = ONTOLOGY
    title = g.value(ont, DCTERMS.title) or "jip vocabulary"
    meta = [
        ("Namespace", f"<code>{esc(JIP)}</code>"),
        ("Preferred prefix", f"<code>{esc(g.value(ont, URIRef(VANN + 'preferredNamespacePrefix')))}:</code>"),
        ("Version", esc(g.value(ont, OWL.versionInfo))),
        ("Creator", esc(g.value(ont, DCTERMS.creator))),
        ("Created", esc(g.value(ont, DCTERMS.created))),
        ("Formats", '<a href="jip.ttl">Turtle</a> &middot; <a href="jip.jsonld">JSON-LD</a> '
                    '&middot; <a href="jip.nt">N-Triples</a>'),
        ("Source", f'<a href="{esc(REPO_URL)}">{esc(REPO_URL)}</a>'),
    ]
    sections, toc = [], []
    for key, heading, terms in groups(g):
        if not terms:
            continue
        toc.append(f'<li><a href="#{key}">{esc(heading)}</a>: '
                   + ", ".join(f'<a href="#{esc(local(t))}"><code>{esc(local(t))}</code></a>' for t in terms)
                   + "</li>")
        sections.append(f'<h2 id="{key}">{esc(heading)}</h2>' + "".join(term_html(g, t) for t in terms))
    data = json.dumps(embedded, indent=2, ensure_ascii=False).replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<meta name="description" content="RDF vocabulary for persistent TDB2 data versions and signed PROV-O certificates of SPARQL results.">
<link rel="alternate" type="text/turtle" href="jip.ttl">
<link rel="alternate" type="application/ld+json" href="jip.jsonld">
<link rel="alternate" type="application/n-triples" href="jip.nt">
<style>{CSS}</style>
<script type="application/ld+json">
{data}
</script>
</head>
<body>
<main>
<h1>{esc(title)}</h1>
<p class="lead">{esc(" ".join(str(g.value(ont, DCTERMS.description) or "").split()))}</p>
<dl class="meta">{"".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta)}</dl>
<nav><strong>Terms</strong><ul>{"".join(toc)}</ul></nav>
{"".join(sections)}
<footer>Generated from <a href="jip.ttl">jip.ttl</a>.</footer>
</main>
</body>
</html>
"""


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "build" / "vocab-site"
    g = Graph()
    g.parse(SOURCE, format="turtle")
    if (ONTOLOGY, RDF.type, OWL.Ontology) not in g:
        sys.exit(f"{SOURCE}: no owl:Ontology <{ONTOLOGY}>")
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE, out / "jip.ttl")
    embedded = json_ld(g)
    (out / "jip.jsonld").write_text(json.dumps(embedded, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out / "jip.nt").write_text(g.serialize(format="nt"), encoding="utf-8")
    (out / "index.html").write_text(page(g, embedded), encoding="utf-8")
    print(f"{len(g)} triples -> {out}")


if __name__ == "__main__":
    main()
