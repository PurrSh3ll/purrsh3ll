#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PurrSh3ll — Installer
# Supported: Kali Linux, Debian 12+, Ubuntu 22.04+ (x86_64)
#
# Usage:
#   bash install.sh              # standard install
#   bash install.sh --no-voice   # skip voice/audio dependencies
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/YOUR_USER/purrsh3ll.git"
INSTALL_DIR="$HOME/purrsh3ll"
VENV_DIR="$INSTALL_DIR/.venv"

# After uploading the wheel to GitHub Releases, replace this URL:
WHEEL_URL="https://github.com/YOUR_USER/purrsh3ll/releases/download/v1.0.0/qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"
WHEEL_NAME="qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"

VOICE=true
[[ "${1:-}" == "--no-voice" ]] && VOICE=false

# ── Colors ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN} ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  !${NC}  $*"; }
die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

# ── System checks ─────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}  PurrSh3ll Installer${NC}"
echo "  ──────────────────────────────────────────"
echo ""

# OS check
if [[ ! -f /etc/debian_version ]]; then
    die "Unsupported OS. PurrSh3ll requires Debian, Kali Linux, or Ubuntu."
fi

# Architecture check
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    die "Unsupported architecture: $ARCH. Only x86_64 is currently supported."
fi

# Python check
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
    # Python build tools
    python3-dev
    python3-venv
    python3-pip
)

VOICE_PACKAGES=(
    # Audio (sounddevice / OpenWakeWord)
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
    success "Voice/audio packages installed"
else
    warn "Skipping voice packages (--no-voice)"
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

# ── Desktop shortcut (optional) ───────────────────────────────────────────────

DESKTOP_FILE="$HOME/.local/share/applications/purrsh3ll.desktop"
mkdir -p "$(dirname "$DESKTOP_FILE")"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Name=PurrSh3ll
Comment=AI-powered terminal for penetration testers
Exec=$VENV_DIR/bin/python3 $INSTALL_DIR/main.py
Icon=$INSTALL_DIR/icons/app_icon.png
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
echo -e "${GREEN}${BOLD}  Installation complete!${NC}"
echo ""
echo "  Run PurrSh3ll:"
echo -e "    ${BOLD}purrsh3ll${NC}              (from anywhere)"
echo -e "    ${BOLD}cd $INSTALL_DIR && .venv/bin/python3 main.py${NC}"
echo ""
if [[ "$VOICE" == false ]]; then
    echo -e "  ${YELLOW}Voice support was skipped.${NC}"
    echo "  To enable it later:"
    echo "    $PIP install faster-whisper openwakeword sounddevice scipy"
    echo "    sudo apt install portaudio19-dev libsndfile1 ffmpeg"
    echo ""
fi
