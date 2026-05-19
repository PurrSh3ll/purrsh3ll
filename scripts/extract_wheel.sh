#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# extract_wheel.sh
# Extracts the QTermWidget wheel from the local .venv into dist/
# Run this once as a developer before creating a GitHub Release.
#
# Usage:
#   bash scripts/extract_wheel.sh
#
# Output:
#   dist/qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl
#   → Upload this file to GitHub Releases as a binary asset.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/.venv"
DIST_DIR="$PROJECT_DIR/dist"
WHEEL_NAME="qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"

echo "==> PurrSh3ll — QTermWidget wheel extractor"
echo ""

# ── Checks ────────────────────────────────────────────────────────────────────

if [[ ! -d "$VENV_DIR" ]]; then
    echo "ERROR: .venv not found at $VENV_DIR"
    echo "       Run the project at least once to create the virtual environment."
    exit 1
fi

SITE_PACKAGES=$(find "$VENV_DIR/lib" -maxdepth 2 -name "site-packages" -type d | head -1)
if [[ -z "$SITE_PACKAGES" ]]; then
    echo "ERROR: site-packages not found inside .venv"
    exit 1
fi

SO_FILE="$SITE_PACKAGES/QTermWidget.abi3.so"
if [[ ! -f "$SO_FILE" ]]; then
    echo "ERROR: QTermWidget.abi3.so not found in $SITE_PACKAGES"
    echo "       Make sure QTermWidget is installed in .venv."
    exit 1
fi

# ── Extract ───────────────────────────────────────────────────────────────────

mkdir -p "$DIST_DIR"
OUT="$DIST_DIR/$WHEEL_NAME"

PYTHON="$VENV_DIR/bin/python3"
if [[ ! -x "$PYTHON" ]]; then
    PYTHON="python3"
fi

"$PYTHON" - <<PYEOF
import zipfile, os, sys

site = "$SITE_PACKAGES"
out  = "$OUT"
dist_info = "qtermwidget-2.2.0.dist-info"

files = {
    "QTermWidget.abi3.so":
        f"{site}/QTermWidget.abi3.so",
    "PyQt6/bindings/QTermWidget/QTermWidget.toml":
        f"{site}/PyQt6/bindings/QTermWidget/QTermWidget.toml",
    "PyQt6/bindings/QTermWidget/qtermwidget.sip":
        f"{site}/PyQt6/bindings/QTermWidget/qtermwidget.sip",
}

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for arc, real in files.items():
        if not os.path.exists(real):
            print(f"WARNING: missing {real} — skipping", file=sys.stderr)
            continue
        zf.write(real, arc)
    dist_src = f"{site}/{dist_info}"
    if os.path.isdir(dist_src):
        for fname in sorted(os.listdir(dist_src)):
            zf.write(f"{dist_src}/{fname}", f"{dist_info}/{fname}")

size_kb = os.path.getsize(out) / 1024
print(f"OK  {out}  ({size_kb:.1f} KB)")
PYEOF

echo ""
echo "==> Done."
echo ""
echo "    Next steps:"
echo "    1. Go to GitHub → your repo → Releases → Create a new release"
echo "    2. Tag it (e.g. v1.0.0)"
echo "    3. Drag-and-drop the file below into 'Attach binaries':"
echo ""
echo "       $DIST_DIR/$WHEEL_NAME"
echo ""
echo "    4. After publishing, update WHEEL_URL in install.sh with the asset URL:"
echo "       https://github.com/YOUR_USER/purrsh3ll/releases/download/v1.0.0/$WHEEL_NAME"
echo ""
