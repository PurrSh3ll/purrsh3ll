#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PurrSh3ll — Interactive Installer
# Lets you choose exactly which optional components to install.
# Core app, Python packages and QTermWidget are always installed.
#
# Supported: Kali Linux, Debian 12+, Ubuntu 22.04+ (x86_64)
#
# Usage:
#   bash install_purr.sh          # interactive (whiptail checklist)
#   bash install_purr.sh --auto   # non-interactive (install everything)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/PurrSh3ll/purrsh3ll.git"
INSTALL_DIR="$HOME/purrsh3ll"
VENV_DIR="$INSTALL_DIR/.venv"

WHEEL_URL="https://github.com/PurrSh3ll/purrsh3ll/releases/download/v1.0.0/qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"
WHEEL_NAME="qtermwidget-2.2.0-cp39-abi3-manylinux_2_28_x86_64.whl"

# aichat — update version number when a new release is available
AICHAT_VERSION="0.27.0"
AICHAT_URL="https://github.com/sigoden/aichat/releases/download/v${AICHAT_VERSION}/aichat-v${AICHAT_VERSION}-x86_64-unknown-linux-musl.tar.gz"

OPENWEBUI_IMAGE="ghcr.io/open-webui/open-webui:main"
WEBMAP_IMAGE="reborntc/webmap"

AUTO=false
[[ "${1:-}" == "--auto" ]] && AUTO=true

# ── Colors & helpers ──────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN} ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  !${NC}  $*"; }
die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

run_with_spinner() {
    local label="$1"; shift
    local spin=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    printf "${CYAN}==>${NC} ${BOLD}%s${NC} " "$label"
    "$@" >/tmp/_purrsh3ll_install.log 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}==>${NC} ${BOLD}%s${NC} %s " "$label" "${spin[$i]}"
        i=$(( (i+1) % ${#spin[@]} ))
        sleep 0.1
    done
    wait "$pid"
    local rc=$?
    printf "\r${CYAN}==>${NC} ${BOLD}%s${NC}   \n" "$label"
    return $rc
}

print_plan() {
    echo -e "${BOLD}  Installation plan:${NC}"
    echo -e "    ${GREEN}✓${NC}  Core application (always)"
    [[ "$INSTALL_VOICE"     == true ]]  && echo -e "    ${GREEN}✓${NC}  Voice support"     || echo -e "    ${YELLOW}–${NC}  Voice support     (skipped)"
    [[ "$INSTALL_SKILLS"    == true ]]  && echo -e "    ${GREEN}✓${NC}  AI Skills"         || echo -e "    ${YELLOW}–${NC}  AI Skills         (skipped)"
    [[ "$INSTALL_OLLAMA"    == true ]]  && echo -e "    ${GREEN}✓${NC}  Ollama"            || echo -e "    ${YELLOW}–${NC}  Ollama            (skipped)"
    [[ "$INSTALL_AICHAT"    == true ]]  && echo -e "    ${GREEN}✓${NC}  aichat"            || echo -e "    ${YELLOW}–${NC}  aichat            (skipped)"
    [[ "$INSTALL_DOCKER"    == true ]]  && echo -e "    ${GREEN}✓${NC}  Docker"            || echo -e "    ${YELLOW}–${NC}  Docker            (skipped)"
    [[ "$INSTALL_OPENWEBUI" == true ]]  && echo -e "    ${GREEN}✓${NC}  Open WebUI image"  || echo -e "    ${YELLOW}–${NC}  Open WebUI image  (skipped)"
    [[ "$INSTALL_WEBMAP"    == true ]]  && echo -e "    ${GREEN}✓${NC}  WebMap image"      || echo -e "    ${YELLOW}–${NC}  WebMap image      (skipped)"
    echo ""
}

# ── Header ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}  PurrSh3ll — Interactive Installer${NC}"
echo "  ──────────────────────────────────────────"
if [[ "$AUTO" == true ]]; then
    echo "  Mode: automatic — all components will be installed."
else
    echo "  Use SPACE to toggle components, ENTER to confirm."
fi
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

# ── Component selection ───────────────────────────────────────────────────────

INSTALL_VOICE=false
INSTALL_SKILLS=false
INSTALL_OLLAMA=false
INSTALL_AICHAT=false
INSTALL_DOCKER=false
INSTALL_OPENWEBUI=false
INSTALL_WEBMAP=false

if [[ "$AUTO" == true ]]; then

    INSTALL_VOICE=true
    INSTALL_SKILLS=true
    INSTALL_OLLAMA=true
    INSTALL_AICHAT=true
    INSTALL_DOCKER=true
    INSTALL_OPENWEBUI=true
    INSTALL_WEBMAP=true
    print_plan

else

    if ! command -v whiptail &>/dev/null; then
        die "whiptail not found. Install it with: sudo apt install whiptail"
    fi

    CHOICES=$(whiptail \
        --title "PurrSh3ll — Interactive Installer" \
        --checklist \
"Select optional components to install.
Core app, Python packages and QTermWidget
are always installed regardless of selection.

SPACE = toggle   |   ENTER = confirm" \
        22 68 7 \
        "voice"     "Voice support  (wake word + speech-to-text)"   ON \
        "skills"    "AI Skills      (pentest + security submodules)" ON \
        "ollama"    "Ollama         (local LLM inference server)"    ON \
        "aichat"    "aichat         (multi-provider CLI frontend)"   ON \
        "docker"    "Docker         (container runtime)"             ON \
        "openwebui" "Open WebUI     (web UI for Ollama — Docker)"    ON \
        "webmap"    "WebMap         (Nmap visualizer — Docker)"      ON \
        3>&1 1>&2 2>&3) || { echo ""; warn "Installation cancelled."; exit 0; }

    [[ "$CHOICES" == *'"voice"'*     ]] && INSTALL_VOICE=true
    [[ "$CHOICES" == *'"skills"'*    ]] && INSTALL_SKILLS=true
    [[ "$CHOICES" == *'"ollama"'*    ]] && INSTALL_OLLAMA=true
    [[ "$CHOICES" == *'"aichat"'*    ]] && INSTALL_AICHAT=true
    [[ "$CHOICES" == *'"docker"'*    ]] && INSTALL_DOCKER=true
    [[ "$CHOICES" == *'"openwebui"'* ]] && INSTALL_OPENWEBUI=true
    [[ "$CHOICES" == *'"webmap"'*    ]] && INSTALL_WEBMAP=true

    # Open WebUI and WebMap require Docker — enable it automatically if needed
    if [[ "$INSTALL_OPENWEBUI" == true || "$INSTALL_WEBMAP" == true ]]; then
        if [[ "$INSTALL_DOCKER" == false ]]; then
            INSTALL_DOCKER=true
            warn "Open WebUI / WebMap require Docker — Docker added to plan."
        fi
    fi

    echo ""
    print_plan

fi

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
    # Metadata extraction (audio/video/PDF viewer — OSINT fields, GPS, codec info)
    libimage-exiftool-perl
    # Network tools
    curl
    ca-certificates
    gnupg
    # Python build tools
    python3-dev
    python3-venv
    python3-pip
)

VOICE_APT_PACKAGES=(
    portaudio19-dev
    libsndfile1
    ffmpeg
)

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}" 2>&1 \
    | grep -E "^(Setting up|already)" || true

if [[ "$INSTALL_VOICE" == true ]]; then
    sudo apt-get install -y --no-install-recommends "${VOICE_APT_PACKAGES[@]}" 2>&1 \
        | grep -E "^(Setting up|already)" || true
    success "Voice system packages installed"
fi

success "System dependencies ready"

# ── Clone / update repository ─────────────────────────────────────────────────

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository already exists — pulling latest changes..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    info "Cloning PurrSh3ll..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
success "Repository at $INSTALL_DIR"

# ── AI Skills submodules ──────────────────────────────────────────────────────

if [[ "$INSTALL_SKILLS" == true ]]; then
    info "Initializing AI skill submodules..."
    git -C "$INSTALL_DIR" submodule update --init --recursive
    success "AI Skills ready (awesome-claude-skills-security, claude-code-pentest)"
fi

cd "$INSTALL_DIR"

# ── Virtual environment ───────────────────────────────────────────────────────

info "Creating Python virtual environment..."
"$PYTHON" -m venv "$VENV_DIR"
PIP="$VENV_DIR/bin/pip"
"$PIP" install --upgrade pip --quiet
success "Virtual environment ready"

# ── Python packages ───────────────────────────────────────────────────────────

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
    jeepney \
    pymupdf \
    mutagen

success "Core packages installed"

if [[ "$INSTALL_VOICE" == true ]]; then
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

if [[ "$INSTALL_OLLAMA" == true ]]; then
    if command -v ollama &>/dev/null; then
        success "Ollama already installed ($(ollama --version 2>/dev/null || echo 'unknown version'))"
    else
        run_with_spinner "Installing Ollama..." \
            bash -c 'curl -fsSL https://ollama.com/install.sh | sh'
        success "Ollama installed"
    fi
fi

# ── aichat ────────────────────────────────────────────────────────────────────

if [[ "$INSTALL_AICHAT" == true ]]; then
    if command -v aichat &>/dev/null; then
        success "aichat already installed ($(aichat --version 2>/dev/null || echo 'unknown version'))"
    else
        info "Installing aichat v${AICHAT_VERSION}..."
        AICHAT_TMP=$(mktemp -d)
        curl -fsSL "$AICHAT_URL" -o "$AICHAT_TMP/aichat.tar.gz"
        tar -xzf "$AICHAT_TMP/aichat.tar.gz" -C "$AICHAT_TMP"
        sudo install -m 755 "$AICHAT_TMP/aichat" /usr/local/bin/aichat
        rm -rf "$AICHAT_TMP"
        success "aichat installed → /usr/local/bin/aichat"
    fi
fi

# ── Docker ────────────────────────────────────────────────────────────────────

if [[ "$INSTALL_DOCKER" == true ]]; then
    if command -v docker &>/dev/null; then
        success "Docker already installed ($(docker --version))"
    else
        info "Installing Docker..."
        if grep -qi "kali" /etc/os-release 2>/dev/null; then
            sudo apt-get install -y --no-install-recommends docker.io docker-cli containerd 2>&1 \
                | grep -E "^(Setting up|already)" || true
        else
            curl -fsSL https://get.docker.com | sh 2>&1 \
                | grep -E "^(\+|Executing|WARNING)" || true
        fi
        sudo systemctl enable docker --now 2>/dev/null || true
        sudo usermod -aG docker "$USER"
        success "Docker installed"
        warn "You may need to log out and back in for Docker group membership to take effect."
        warn "Or run: newgrp docker"
    fi
fi

# ── Open WebUI Docker image ───────────────────────────────────────────────────

if [[ "$INSTALL_OPENWEBUI" == true ]]; then
    if run_with_spinner "Pulling Open WebUI Docker image..." \
            sudo docker pull --quiet "$OPENWEBUI_IMAGE"; then
        success "Open WebUI image ready"
    else
        warn "Could not pull Open WebUI image — run: sudo docker pull $OPENWEBUI_IMAGE"
    fi
fi

# ── WebMap Docker image ───────────────────────────────────────────────────────

if [[ "$INSTALL_WEBMAP" == true ]]; then
    if run_with_spinner "Pulling WebMap Docker image..." \
            sudo docker pull --quiet "$WEBMAP_IMAGE"; then
        success "WebMap image ready"
    else
        warn "Could not pull WebMap image — run: sudo docker pull $WEBMAP_IMAGE"
    fi
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
echo -e "${GREEN}${BOLD}  Installation complete!${NC}"
echo ""
echo "  Installed components:"
echo -e "    ${GREEN}✓${NC}  Core application"
[[ "$INSTALL_VOICE"     == true ]] && echo -e "    ${GREEN}✓${NC}  Voice support"
[[ "$INSTALL_SKILLS"    == true ]] && echo -e "    ${GREEN}✓${NC}  AI Skills"
[[ "$INSTALL_OLLAMA"    == true ]] && echo -e "    ${GREEN}✓${NC}  Ollama"
[[ "$INSTALL_AICHAT"    == true ]] && echo -e "    ${GREEN}✓${NC}  aichat"
[[ "$INSTALL_DOCKER"    == true ]] && echo -e "    ${GREEN}✓${NC}  Docker"
[[ "$INSTALL_OPENWEBUI" == true ]] && echo -e "    ${GREEN}✓${NC}  Open WebUI image"
[[ "$INSTALL_WEBMAP"    == true ]] && echo -e "    ${GREEN}✓${NC}  WebMap image"
[[ "$INSTALL_VOICE"     == false ]] && echo -e "    ${YELLOW}–${NC}  Voice support     (not installed)"
[[ "$INSTALL_SKILLS"    == false ]] && echo -e "    ${YELLOW}–${NC}  AI Skills         (not installed)"
[[ "$INSTALL_OLLAMA"    == false ]] && echo -e "    ${YELLOW}–${NC}  Ollama            (not installed)"
[[ "$INSTALL_AICHAT"    == false ]] && echo -e "    ${YELLOW}–${NC}  aichat            (not installed)"
[[ "$INSTALL_DOCKER"    == false ]] && echo -e "    ${YELLOW}–${NC}  Docker            (not installed)"
[[ "$INSTALL_OPENWEBUI" == false ]] && echo -e "    ${YELLOW}–${NC}  Open WebUI image  (not installed)"
[[ "$INSTALL_WEBMAP"    == false ]] && echo -e "    ${YELLOW}–${NC}  WebMap image      (not installed)"

echo ""
echo "  Run PurrSh3ll:"
echo -e "    ${BOLD}purrsh3ll${NC}"
echo ""

if [[ "$INSTALL_OLLAMA" == true ]]; then
    echo "  First steps with Ollama:"
    echo "    ollama serve"
    echo "    ollama pull llama3.2"
    echo ""
fi

echo "  Setup guide:"
echo -e "    ${BOLD}cat $INSTALL_DIR/usermodules/FIRST_STEPS.md${NC}"
echo ""
