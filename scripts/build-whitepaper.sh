#!/usr/bin/env bash
# Build the whitepaper PDF from docs/whitepaper/whitepaper.tex.
#
#   scripts/build-whitepaper.sh [--clean]
#
#   --clean   delete earlier build output first
#
# Needs TeX Live with latexmk, pdflatex and biber, and the packages listed in the preamble
# (all part of a full TeX Live installation). Without a local TeX installation, set
# WHITEPAPER_DOCKER=1 to build inside a TeX Live container image instead; TEXLIVE_IMAGE
# selects the image (default texlive/texlive:latest, several GB).
#
# Output: docs/whitepaper/build/whitepaper.pdf
set -euo pipefail

cd "$(dirname "$0")/../docs/whitepaper"
OUT=build

if [[ "${1:-}" == "--clean" ]]; then
  rm -rf "$OUT"
fi
mkdir -p "$OUT"

LATEXMK=(latexmk -pdf -silent -interaction=nonstopmode -halt-on-error -file-line-error
         -outdir="$OUT" whitepaper.tex)

status=0
if [[ "${WHITEPAPER_DOCKER:-0}" == 1 ]]; then
  docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/work" -w /work \
    "${TEXLIVE_IMAGE:-texlive/texlive:latest}" "${LATEXMK[@]}" || status=$?
elif command -v latexmk >/dev/null 2>&1; then
  "${LATEXMK[@]}" || status=$?
else
  echo "latexmk not found. Install TeX Live, or run with WHITEPAPER_DOCKER=1." >&2
  exit 1
fi

if [[ $status -ne 0 ]]; then
  echo "Build failed; see docs/whitepaper/$OUT/whitepaper.log" >&2
  exit "$status"
fi

# Unresolved references or citations leave the build "successful"; treat them as errors.
if grep -E -q "There were undefined (references|citations)|Citation .* undefined|Reference .* undefined" "$OUT/whitepaper.log"; then
  echo "Unresolved references or citations; see docs/whitepaper/$OUT/whitepaper.log" >&2
  exit 1
fi

echo "PDF: docs/whitepaper/$OUT/whitepaper.pdf"
