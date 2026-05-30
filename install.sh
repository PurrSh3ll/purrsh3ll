#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PurrSh3ll — Lite Installer
# Installs the core application only (no Ollama, Docker images, or AI skills).
# Supported: Kali Linux, Debian 12+, Ubuntu 22.04+ (x86_64)
#
# Usage:
#   bash install.sh              # install without voice support
#   bash install.sh --voice      # include voice/audio dependencies
#
# For the full installation (Ollama, Open WebUI, WebMap, AI skills):
#   bash install_full.sh
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/PurrSh3ll/purrsh3ll.git"
INSTALL_DIR="$HOME/purrsh3ll"
VENV_DIR="$INSTALL_DIR/.venv"

WHEEL_URL="https://github.com/PurrSh3ll/purrsh3ll/releases/download/v1.0.0/qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"
WHEEL_NAME="qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"

VOICE=false
[[ "${1:-}" == "--voice" ]] && VOICE=true

# ── Colors ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN} ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  !${NC}  $*"; }
die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

# ── Header ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}  PurrSh3ll — Lite Installer${NC}"
echo "  ──────────────────────────────────────────"
echo "  Core app only. For Ollama, Open WebUI, WebMap"
echo "  and AI skills run: bash install_full.sh"
echo ""

# ── System checks ─────────────────────────────────────────────────────────────

if [[ ! -f /etc/debian_version ]]; then
    die "Unsupported OS. PurrSh3ll requires Debian, Kali Linux, or Ubuntu."
fi

ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    die "Unsupported architecture: $ARCH. Only x86_64 is currently supported."
fi

PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
    die "python3 not found. Install it with: sudo apt install python3"
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt 3 || ( "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 9 ) ]]; then
    die "Python 3.9+ required. Found: $PY_VERSION"
fi
success "Python $PY_VERSION"

# ── System dependencies ───────────────────────────────────────────────────────

info "Installing system dependencies..."

APT_PACKAGES=(
    # Qt6 runtime
    libqt6core6t64
    libqt6gui6
    libqt6widgets6
    libqt6webenginewidgets6
    libqt6webenginequick6
    # QTermWidget C++ library
    libqtermwidget6-2
    qtermwidget-data
    # OpenGL (required by Qt)
    libgl1
    libegl1
    # Qt6 Multimedia (required by video viewer — not installed by default on Kali)
    python3-pyqt6.qtmultimedia
    libqt6multimedia6
    # Metadata extraction (required by video viewer for OSINT fields, GPS, codec info)
    libimage-exiftool-perl
    # Python build tools
    python3-dev
    python3-venv
    python3-pip
)

VOICE_PACKAGES=(
    portaudio19-dev
    libsndfile1
    ffmpeg
)

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}" 2>&1 \
    | grep -E "^(Setting up|already)" || true

if [[ "$VOICE" == true ]]; then
    sudo apt-get install -y --no-install-recommends "${VOICE_PACKAGES[@]}" 2>&1 \
        | grep -E "^(Setting up|already)" || true
    success "Voice/audio system packages installed"
else
    warn "Voice packages skipped (use --voice to include them)"
fi

success "System dependencies ready"

# ── Clone repository ──────────────────────────────────────────────────────────

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository already exists — pulling latest changes..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    info "Cloning PurrSh3ll..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
success "Repository at $INSTALL_DIR"

cd "$INSTALL_DIR"

# ── Virtual environment ───────────────────────────────────────────────────────

info "Creating Python virtual environment..."
"$PYTHON" -m venv "$VENV_DIR"
PIP="$VENV_DIR/bin/pip"
"$PIP" install --upgrade pip --quiet
success "Virtual environment ready"

# ── Python dependencies ───────────────────────────────────────────────────────

info "Installing Python packages..."

"$PIP" install --quiet \
    PyQt6 \
    PyQt6-WebEngine \
    pyqt6-sip \
    QtPy \
    watchdog \
    chromadb \
    fastembed \
    onnxruntime \
    huggingface-hub \
    keyring \
    SecretStorage \
    cryptography \
    docker \
    pyfiglet \
    pygame \
    Pillow \
    pydantic \
    requests \
    PyYAML \
    loguru \
    rich \
    numpy \
    pyte \
    markdown2 \
    Pygments \
    jeepney

success "Core packages installed"

if [[ "$VOICE" == true ]]; then
    info "Installing voice packages..."
    "$PIP" install --quiet \
        faster-whisper \
        openwakeword \
        sounddevice \
        scipy
    success "Voice packages installed"
fi

# ── QTermWidget wheel ─────────────────────────────────────────────────────────

info "Installing QTermWidget..."

WHEEL_CACHE="/tmp/$WHEEL_NAME"

if [[ ! -f "$WHEEL_CACHE" ]]; then
    if command -v curl &>/dev/null; then
        curl -fsSL "$WHEEL_URL" -o "$WHEEL_CACHE"
    elif command -v wget &>/dev/null; then
        wget -q "$WHEEL_URL" -O "$WHEEL_CACHE"
    else
        die "Neither curl nor wget found. Cannot download QTermWidget wheel."
    fi
fi

"$PIP" install --quiet "$WHEEL_CACHE"
success "QTermWidget installed"

# ── Desktop shortcut ──────────────────────────────────────────────────────────

DESKTOP_FILE="$HOME/.local/share/applications/purrsh3ll.desktop"
mkdir -p "$(dirname "$DESKTOP_FILE")"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=PurrSh3ll
Comment=AI-powered terminal for penetration testers
Exec=$VENV_DIR/bin/python3 $INSTALL_DIR/main.py
Icon=$INSTALL_DIR/icons/__app_icon.png
Terminal=false
Type=Application
Categories=Security;Network;
EOF
success "Desktop shortcut created"

# ── Launch script ─────────────────────────────────────────────────────────────

LAUNCH_SCRIPT="/usr/local/bin/purrsh3ll"
sudo tee "$LAUNCH_SCRIPT" > /dev/null <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python3" "$INSTALL_DIR/main.py" "\$@"
EOF
sudo chmod +x "$LAUNCH_SCRIPT"
success "Launch command installed: purrsh3ll"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}  Installation complete! (Lite)${NC}"
echo ""
echo "  Run PurrSh3ll:"
echo -e "    ${BOLD}purrsh3ll${NC}"
echo ""
if [[ "$VOICE" == false ]]; then
    echo -e "  ${YELLOW}Voice support was not installed.${NC}"
    echo "  To add it later:  bash install.sh --voice"
    echo ""
fi
echo "  To install Ollama, Open WebUI, WebMap and AI skills:"
echo -e "    ${BOLD}bash install_full.sh${NC}"
echo ""
