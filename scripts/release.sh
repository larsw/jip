#!/usr/bin/env bash
# Release jena-intrinsic-provenance: version numbers, build and tests, whitepaper PDF, vocabulary
# site, tag, GitHub release.
#
#   scripts/release.sh prepare <version>
#   scripts/release.sh publish <version> [--next <version>] [--notes <file>] [--dry-run]
#
# A release has a manual step in the middle, because the whitepaper's listings and demo table
# show the output of a demo run of the release itself:
#
#   1. scripts/release.sh prepare 0.13.0
#        Sets 0.13.0 everywhere (Maven POMs, README, DESIGN, Docker image tags, whitepaper title,
#        the vocabulary's owl:versionInfo and dcterms:modified). Nothing is committed.
#   2. scripts/demo.sh --reset
#        Then update the whitepaper's listings and demo table from the output and demo-out/.
#   3. scripts/release.sh publish 0.13.0 --next 0.14.0
#        - mvn clean verify
#        - the whitepaper PDF (scripts/build-whitepaper.sh)
#        - the vocabulary site (scripts/build-vocab-site.py), as a release asset; pushing
#          vocab/ to main also makes the GitHub Pages workflow publish it at https://larsw.xyz/jip/
#        - commit "Release <version>", annotated tag v<version>, push main and the tag
#        - GitHub release v<version> with the whitepaper PDF, the repository at the tag (zip)
#          and the vocabulary site (zip); notes from --notes, or the commit subjects since the
#          previous tag
#        - with --next: set <next>-SNAPSHOT, build, commit "Bump version to ...", push
#      --dry-run stops after the builds: nothing is committed, tagged or pushed.
#
# Needs: git, gh (authenticated), mvn, python3, latexmk (or WHITEPAPER_DOCKER=1, see
# scripts/build-whitepaper.sh), zip. The vocabulary site needs rdflib; if python3 can't import
# it, a virtual environment with rdflib==7.6.0 is created in build/.venv-vocab.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
REPO_SLUG="larsw/jip"

die() { echo "release: $*" >&2; exit 1; }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# quiet <log> <command...>: run with output to a log; show its tail and stop if it fails.
quiet() {
  local log=$1; shift
  mkdir -p "$(dirname "$log")"
  "$@" > "$log" 2>&1 || { tail -40 "$log" >&2; die "failed: $* (full log: $log)"; }
}

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

[[ $# -ge 2 ]] || usage
CMD=$1; VERSION=$2; shift 2
NEXT=""; NOTES=""; DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --next) [[ $# -ge 2 ]] || die "--next needs a version"; NEXT=$2; shift ;;
    --notes) [[ $# -ge 2 ]] || die "--notes needs a file"; NOTES=$2; shift ;;
    --dry-run) DRY_RUN=1 ;;
    *) usage ;;
  esac
  shift
done
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be X.Y.Z, got '$VERSION'"
[[ -z "$NEXT" || "$NEXT" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--next must be X.Y.Z, got '$NEXT'"
[[ -z "$NOTES" || -f "$NOTES" ]] || die "no notes file $NOTES"

current_version() {
  python3 -I - <<'PY'
import re
s = open("pom.xml").read()
print(re.search(r"<artifactId>jena-intrinsic-provenance-parent</artifactId>\s*<version>([^<]+)</version>", s).group(1))
PY
}

# set_version <maven-version>: Maven version (X.Y.Z or X.Y.Z-SNAPSHOT) everywhere it appears.
# Docker image tags and the whitepaper title use X.Y.Z; the vocabulary's owl:versionInfo and
# dcterms:modified change only for a release.
set_version() {
  python3 -I - "$(current_version)" "$1" "$(date +%F)" <<'PY'
import pathlib, re, sys
old, new, today = sys.argv[1:4]
base_old, base_new = old.removesuffix("-SNAPSHOT"), new.removesuffix("-SNAPSHOT")
release = not new.endswith("-SNAPSHOT")

def edit(path, subs, required=True):
    p = pathlib.Path(path)
    s = p.read_text()
    t = s
    for pat, rep in subs:
        t = re.sub(pat, rep, t)
    if t == s and required and old != new:
        sys.exit(f"release: nothing to change in {path}")
    p.write_text(t)

v = re.escape(old)
for pom in ["pom.xml", "jip-verifier/pom.xml", "jip-verifier-cli/pom.xml", "jip-fuseki/pom.xml"]:
    edit(pom, [(rf"<version>{v}</version>", f"<version>{new}</version>")])
edit("README.md", [(rf"jip-verifier-{v}\.jar", f"jip-verifier-{new}.jar"),
                   (rf"jena-intrinsic-provenance:{re.escape(base_old)}\b", f"jena-intrinsic-provenance:{base_new}")])
edit("docs/DESIGN.md", [(rf"`xyz\.larsw:\*:{v}`", f"`xyz.larsw:*:{new}`")])
for f in ["docker-compose.yml", "docker/Dockerfile", "docker/signer/Dockerfile", "scripts/demo.sh"]:
    edit(f, [(rf"(jena-intrinsic-provenance|jip-signer):{re.escape(base_old)}\b", rf"\g<1>:{base_new}")],
         required=base_old != base_new)
edit("docs/whitepaper/whitepaper.tex",
     [(rf"Proof-of-concept report, jena-intrinsic-provenance {re.escape(base_old)}\b",
       f"Proof-of-concept report, jena-intrinsic-provenance {base_new}")], required=base_old != base_new)
if release:
    def vocab(s):
        s = re.sub(r'owl:versionInfo "[^"]*"', f'owl:versionInfo "{new}"', s)
        if "dcterms:modified" in s:
            s = re.sub(r'dcterms:modified "[^"]*"\^\^xsd:date', f'dcterms:modified "{today}"^^xsd:date', s)
        else:
            s = re.sub(r'(dcterms:created "[^"]*"\^\^xsd:date ;\n)', rf'\1    dcterms:modified "{today}"^^xsd:date ;\n', s)
        return s
    p = pathlib.Path("vocab/jip.ttl")
    p.write_text(vocab(p.read_text()))
print(f"version {old} -> {new}")
PY
}

# Files that prepare and set_version change, and the whitepaper (updated by hand from the demo).
ALLOWED_CHANGES='^(pom\.xml|jip-verifier/pom\.xml|jip-verifier-cli/pom\.xml|jip-fuseki/pom\.xml|README\.md|docs/DESIGN\.md|docker-compose\.yml|docker/Dockerfile|docker/signer/Dockerfile|scripts/demo\.sh|vocab/jip\.ttl|docs/whitepaper/.*)$'

check_repo() {
  [[ "$(git rev-parse --abbrev-ref HEAD)" == main ]] || die "not on main"
  local other
  other=$(git status --porcelain | awk '{print $NF}' | grep -Ev "$ALLOWED_CHANGES" || true)
  [[ -z "$other" ]] || die "uncommitted changes outside the release files:"$'\n'"$other"
  git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null && die "tag v$VERSION exists"
  git fetch -q origin main
  [[ "$(git rev-list --count HEAD..origin/main)" == 0 ]] || die "main is behind origin/main; pull first"
}

build_vocab_site() {
  local py=python3
  if ! python3 -c "import rdflib" 2>/dev/null; then
    if [[ ! -x build/.venv-vocab/bin/python ]]; then
      echo "rdflib not found; creating build/.venv-vocab"
      python3 -m venv build/.venv-vocab
      build/.venv-vocab/bin/pip install --quiet rdflib==7.6.0
    fi
    py=build/.venv-vocab/bin/python
  fi
  rm -rf build/vocab-site
  quiet build/release-logs/vocab-site.log "$py" scripts/build-vocab-site.py build/vocab-site
  tail -1 build/release-logs/vocab-site.log
}

case "$CMD" in
  prepare)
    [[ "$(current_version)" == "$VERSION-SNAPSHOT" ]] || die "expected version $VERSION-SNAPSHOT, found $(current_version)"
    step "Set version $VERSION"
    set_version "$VERSION"
    cat <<EOF

Next:
  scripts/demo.sh --reset
  update the whitepaper's listings and demo table from the demo output and demo-out/
  scripts/release.sh publish $VERSION --next <next version>
EOF
    ;;

  publish)
    [[ "$(current_version)" == "$VERSION" ]] || die "version is $(current_version); run 'scripts/release.sh prepare $VERSION' first"
    command -v gh >/dev/null && gh auth status >/dev/null 2>&1 || die "gh is not installed or not authenticated"
    command -v zip >/dev/null || die "zip is not installed"
    step "Checks"
    check_repo
    PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || true)
    echo "releasing $VERSION (previous tag: ${PREV_TAG:-none})"

    step "Build and test (mvn clean verify)"
    quiet build/release-logs/mvn.log mvn -B clean verify
    grep -aE 'Tests run: [0-9]+, Failures: [0-9]+, Errors: [0-9]+, Skipped: [0-9]+$' build/release-logs/mvn.log | sed 's/^\[INFO\] /  /'

    step "Whitepaper"
    quiet build/release-logs/whitepaper.log scripts/build-whitepaper.sh --clean
    grep -aqE "Overfull|undefined" docs/whitepaper/build/whitepaper.log \
      && echo "warning: the whitepaper log has overfull boxes or undefined references" >&2

    step "Vocabulary site"
    build_vocab_site

    DIST=build/release-$VERSION
    rm -rf "$DIST" && mkdir -p "$DIST"
    cp docs/whitepaper/build/whitepaper.pdf "$DIST/jip-$VERSION-whitepaper.pdf"
    (cd build/vocab-site && zip -q -r "$ROOT/$DIST/jip-$VERSION-vocab-site.zip" .)

    if [[ $DRY_RUN == 1 ]]; then
      step "Dry run: stopping before commit, tag and push"
      ls -l "$DIST"
      exit 0
    fi

    step "Commit and tag v$VERSION"
    git add -A
    git commit -q -m "Release $VERSION" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
    git tag -a "v$VERSION" -m "v$VERSION"
    git archive --format=zip --prefix="jip-$VERSION/" -o "$DIST/jip-$VERSION.zip" "v$VERSION"

    step "Push"
    git push -q origin main
    git push -q origin "v$VERSION"

    step "GitHub release v$VERSION"
    if [[ -z "$NOTES" ]]; then
      NOTES=$DIST/notes.md
      {
        echo "Release $VERSION of jena-intrinsic-provenance."
        echo
        echo "## Changes${PREV_TAG:+ since $PREV_TAG}"
        echo
        git log --no-merges --format='- %s' ${PREV_TAG:+"$PREV_TAG..v$VERSION"} | grep -vE '^- (Release|Bump version)' || true
      } > "$NOTES"
    fi
    {
      cat "$NOTES"
      echo
      echo "## Assets"
      echo
      echo "- \`jip-$VERSION-whitepaper.pdf\`: the whitepaper, built from \`docs/whitepaper/whitepaper.tex\`"
      echo "- \`jip-$VERSION.zip\`: the repository at tag v$VERSION"
      echo "- \`jip-$VERSION-vocab-site.zip\`: the vocabulary site, as published at https://larsw.xyz/jip/"
    } > "$DIST/release-notes.md"
    gh release create "v$VERSION" -R "$REPO_SLUG" --title "v$VERSION" --notes-file "$DIST/release-notes.md" --verify-tag \
      "$DIST/jip-$VERSION-whitepaper.pdf" "$DIST/jip-$VERSION.zip" "$DIST/jip-$VERSION-vocab-site.zip"

    if [[ -n "$NEXT" ]]; then
      step "Next version $NEXT-SNAPSHOT"
      set_version "$NEXT-SNAPSHOT"
      quiet build/release-logs/mvn-next.log mvn -B -o verify -DskipTests
      git add -A
      git commit -q -m "Bump version to $NEXT-SNAPSHOT" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
      git push -q origin main
    fi

    step "Done"
    gh release view "v$VERSION" -R "$REPO_SLUG" --json url --jq .url
    gh run list -R "$REPO_SLUG" --workflow pages.yml -L 1 --json status,url --jq '.[] | "vocabulary site: \(.status) \(.url)"' 2>/dev/null || true
    ;;

  *) usage ;;
esac
