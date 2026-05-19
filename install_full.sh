#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PurrSh3ll — Full Installer
# Installs the core application AND all optional open-source components:
#   • Ollama          — local LLM inference server
#   • aichat          — CLI frontend for LLMs (multi-provider)
#   • Docker          — container runtime (if not already installed)
#   • Open WebUI      — web UI for Ollama (pulled as Docker image)
#   • WebMap          — Nmap result visualizer (pulled as Docker image)
#   • AI Skills       — awesome-claude-skills-security + claude-code-pentest
#
# Supported: Kali Linux, Debian 12+, Ubuntu 22.04+ (x86_64)
#
# Usage:
#   bash install_full.sh              # full install with voice support
#   bash install_full.sh --no-voice   # skip voice/audio dependencies
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/YOUR_USER/purrsh3ll.git"
INSTALL_DIR="$HOME/purrsh3ll"
VENV_DIR="$INSTALL_DIR/.venv"

WHEEL_URL="https://github.com/YOUR_USER/purrsh3ll/releases/download/v1.0.0/qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"
WHEEL_NAME="qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"

# aichat — update version number when a new release is available
AICHAT_VERSION="0.27.0"
AICHAT_URL="https://github.com/sigoden/aichat/releases/download/v${AICHAT_VERSION}/aichat-v${AICHAT_VERSION}-x86_64-unknown-linux-musl.tar.gz"

# Docker image tags
OPENWEBUI_IMAGE="ghcr.io/open-webui/open-webui:main"
WEBMAP_IMAGE="reborntc/webmap"

VOICE=true
[[ "${1:-}" == "--no-voice" ]] && VOICE=false

# ── Colors ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN} ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  !${NC}  $*"; }
die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

# ── Header ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}  PurrSh3ll — Full Installer${NC}"
echo "  ──────────────────────────────────────────"
echo "  Installs: core app + Ollama + aichat +"
echo "  Docker + Open WebUI + WebMap + AI skills"
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
    # Python build tools
    python3-dev
    python3-venv
    python3-pip
    # Misc tools used by optional installers
    curl
    ca-certificates
    gnupg
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
    warn "Voice packages skipped (--no-voice)"
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

info "Initializing AI skill submodules..."
git -C "$INSTALL_DIR" submodule update --init --recursive
success "Skills ready (awesome-claude-skills-security, claude-code-pentest)"

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

# ── Ollama ────────────────────────────────────────────────────────────────────

if command -v ollama &>/dev/null; then
    success "Ollama already installed ($(ollama --version 2>/dev/null || echo 'unknown version'))"
else
    info "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    success "Ollama installed"
fi

# ── aichat ───────────────────────────────────────────────────────────────────

if command -v aichat &>/dev/null; then
    success "aichat already installed ($(aichat --version 2>/dev/null || echo 'unknown version'))"
else
    info "Installing aichat v${AICHAT_VERSION}..."
    AICHAT_TMP=$(mktemp -d)
    if command -v curl &>/dev/null; then
        curl -fsSL "$AICHAT_URL" -o "$AICHAT_TMP/aichat.tar.gz"
    else
        wget -q "$AICHAT_URL" -O "$AICHAT_TMP/aichat.tar.gz"
    fi
    tar -xzf "$AICHAT_TMP/aichat.tar.gz" -C "$AICHAT_TMP"
    sudo install -m 755 "$AICHAT_TMP/aichat" /usr/local/bin/aichat
    rm -rf "$AICHAT_TMP"
    success "aichat installed → /usr/local/bin/aichat"
fi

# ── Docker ────────────────────────────────────────────────────────────────────

if command -v docker &>/dev/null; then
    success "Docker already installed ($(docker --version))"
else
    info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    warn "Docker installed. You may need to log out and back in for group membership to take effect."
    warn "Or run: newgrp docker"
fi

# ── Open WebUI Docker image ───────────────────────────────────────────────────

info "Pulling Open WebUI Docker image..."
if sudo docker pull "$OPENWEBUI_IMAGE" 2>&1 | tail -1 | grep -qE "Pull complete|up to date|Status: Image"; then
    success "Open WebUI image ready"
else
    docker pull "$OPENWEBUI_IMAGE"
    success "Open WebUI image ready"
fi

# ── WebMap Docker image ───────────────────────────────────────────────────────

info "Pulling WebMap Docker image..."
if sudo docker pull "$WEBMAP_IMAGE" 2>&1 | tail -1 | grep -qE "Pull complete|up to date|Status: Image"; then
    success "WebMap image ready"
else
    docker pull "$WEBMAP_IMAGE"
    success "WebMap image ready"
fi

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
echo -e "${GREEN}${BOLD}  Installation complete! (Full)${NC}"
echo ""
echo "  Run PurrSh3ll:"
echo -e "    ${BOLD}purrsh3ll${NC}"
echo ""
echo "  Installed components:"
echo -e "    ${GREEN}✓${NC}  Core application"
echo -e "    ${GREEN}✓${NC}  AI skills (submodules)"
echo -e "    ${GREEN}✓${NC}  Ollama"
echo -e "    ${GREEN}✓${NC}  aichat"
echo -e "    ${GREEN}✓${NC}  Docker"
echo -e "    ${GREEN}✓${NC}  Open WebUI image (${OPENWEBUI_IMAGE})"
echo -e "    ${GREEN}✓${NC}  WebMap image (${WEBMAP_IMAGE})"
if [[ "$VOICE" == true ]]; then
    echo -e "    ${GREEN}✓${NC}  Voice support"
else
    echo -e "    ${YELLOW}–${NC}  Voice support skipped"
    echo "       To add later:  bash install_full.sh"
fi
echo ""
echo "  First steps:"
echo "    1. Start Ollama:        ollama serve"
echo "    2. Pull a model:        ollama pull llama3.2"
echo "    3. Launch PurrSh3ll:    purrsh3ll"
echo ""
