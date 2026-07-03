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
    "$@" >>/tmp/_purrsh3ll_install.log 2>&1 &
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
    echo -e "    ${GREEN}✓${NC}  Core application     (~1.5 GB — Python venv + PyQt6)"
    [[ "$INSTALL_VOICE"       == true ]]  && echo -e "    ${GREEN}✓${NC}  Voice support        (~500 MB — Whisper + wake word)"  || echo -e "    ${YELLOW}–${NC}  Voice support                           (skipped)"
    [[ "$INSTALL_SKILLS"      == true ]]  && echo -e "    ${GREEN}✓${NC}  AI Skills            (~15 MB  — 7 git repos)"          || echo -e "    ${YELLOW}–${NC}  AI Skills                               (skipped)"
    [[ "$INSTALL_OLLAMA"      == true ]]  && echo -e "    ${GREEN}✓${NC}  Ollama               (~1.5 GB — official install script)" || echo -e "    ${YELLOW}–${NC}  Ollama                                  (skipped)"
    [[ "$INSTALL_AICHAT"      == true ]]  && echo -e "    ${GREEN}✓${NC}  aichat               (~15 MB  — CLI binary)"          || echo -e "    ${YELLOW}–${NC}  aichat                                  (skipped)"
    [[ "$INSTALL_DOCKER"      == true ]]  && echo -e "    ${GREEN}✓${NC}  Docker               (~300 MB — container runtime)"   || echo -e "    ${YELLOW}–${NC}  Docker                                  (skipped)"
    [[ "$INSTALL_OPENWEBUI"   == true ]]  && echo -e "    ${GREEN}✓${NC}  Open WebUI image     (~4.8 GB — Docker image)"        || echo -e "    ${YELLOW}–${NC}  Open WebUI image                        (skipped)"
    [[ "$INSTALL_WEBMAP"      == true ]]  && echo -e "    ${GREEN}✓${NC}  WebMap image         (~1.5 GB — Docker image)"        || echo -e "    ${YELLOW}–${NC}  WebMap image                            (skipped)"
    [[ "$INSTALL_EMBED_MODEL" == true ]]  && echo -e "    ${GREEN}✓${NC}  Embed model          (~220 MB — multilingual MiniLM)" || echo -e "    ${YELLOW}–${NC}  Embed model                             (skipped)"
    echo ""
}

# ── Clear install log ─────────────────────────────────────────────────────────

> /tmp/_purrsh3ll_install.log

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
INSTALL_EMBED_MODEL=false

# Actual install results (set to true only on success)
VOICE_OK=false
SKILLS_OK=false
OLLAMA_OK=false
AICHAT_OK=false
DOCKER_OK=false
OPENWEBUI_OK=false
WEBMAP_OK=false
EMBED_OK=false

if [[ "$AUTO" == true ]]; then

    INSTALL_VOICE=true
    INSTALL_SKILLS=true
    INSTALL_OLLAMA=true
    INSTALL_AICHAT=true
    INSTALL_DOCKER=true
    INSTALL_OPENWEBUI=true
    INSTALL_WEBMAP=true
    INSTALL_EMBED_MODEL=true
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
        22 68 8 \
        "voice"      "Voice support   ~500 MB  (Whisper + wake word)"    ON \
        "skills"     "AI Skills       ~15 MB   (7 git repos)"           ON \
        "ollama"     "Ollama          ~1.5 GB  (LLM inference binary)"  ON \
        "aichat"     "aichat          ~15 MB   (CLI binary)"            ON \
        "embedmodel" "Embed model     ~220 MB  (multilingual MiniLM)"   ON \
        "docker"     "Docker          ~300 MB  (container runtime)"     OFF \
        "openwebui"  "Open WebUI      ~4.8 GB  (Docker image)"          OFF \
        "webmap"     "WebMap          ~1.5 GB  (Docker image)"          OFF \
        3>&1 1>&2 2>&3) || { echo ""; warn "Installation cancelled."; exit 0; }

    [[ "$CHOICES" == *'"voice"'*       ]] && INSTALL_VOICE=true
    [[ "$CHOICES" == *'"skills"'*      ]] && INSTALL_SKILLS=true
    [[ "$CHOICES" == *'"ollama"'*      ]] && INSTALL_OLLAMA=true
    [[ "$CHOICES" == *'"aichat"'*      ]] && INSTALL_AICHAT=true
    [[ "$CHOICES" == *'"docker"'*      ]] && INSTALL_DOCKER=true
    [[ "$CHOICES" == *'"openwebui"'*   ]] && INSTALL_OPENWEBUI=true
    [[ "$CHOICES" == *'"webmap"'*      ]] && INSTALL_WEBMAP=true
    [[ "$CHOICES" == *'"embedmodel"'*  ]] && INSTALL_EMBED_MODEL=true

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

info "Updating package lists..."

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

sudo apt-get update -q 2>&1 | grep -E "^(Get:|Hit:|Ign:)" || true
info "Installing system dependencies..."
sudo apt-get install -y --no-install-recommends "${APT_PACKAGES[@]}" 2>&1 \
    | grep --line-buffered -E "^(Get:|Unpacking|Setting up|Preparing)" || true

if [[ "$INSTALL_VOICE" == true ]]; then
    info "Installing voice system packages..."
    sudo apt-get install -y --no-install-recommends "${VOICE_APT_PACKAGES[@]}" 2>&1 \
        | grep --line-buffered -E "^(Get:|Unpacking|Setting up|Preparing)" || true
    success "Voice system packages installed"
fi

success "System dependencies ready"

# ── Clone / update repository ─────────────────────────────────────────────────

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repository already exists — pulling latest changes..."
    if ! git -C "$INSTALL_DIR" pull --ff-only 2>/dev/null; then
        warn "git pull --ff-only failed (local changes or diverged branch) — skipping update."
        warn "To update manually: cd $INSTALL_DIR && git pull"
    fi
else
    info "Cloning PurrSh3ll..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
success "Repository at $INSTALL_DIR"

# ── AI Skills — cloned on demand from upstream repos ──────────────────────────
# Skill sets are NOT vendored or submoduled in the main repo, so a plain
# `git clone` stays clean (no empty skill folders). The installer clones each
# set here only when AI Skills is selected. All MIT-licensed, upstream repos.
SKILLS_DIR="$INSTALL_DIR/appdata/agent_modes/skills"
SKILL_REPOS=(
    "awesome-claude-skills-security|https://github.com/Eyadkelleh/awesome-claude-skills-security.git"
    "claude-code-pentest|https://github.com/Orizon-eu/claude-code-pentest.git"
    "secskills|https://github.com/trilwu/secskills"
    "cybersecurity-claude-skills|https://github.com/mahmutka/cybersecurity-claude-skills"
    "communitytools|https://github.com/transilienceai/communitytools"
    "claude-code-owasp|https://github.com/agamm/claude-code-owasp"
    "pentest-ai-agents|https://github.com/0xSteph/pentest-ai-agents"
)

if [[ "$INSTALL_SKILLS" == true ]]; then
    info "Cloning AI skill sets..."
    mkdir -p "$SKILLS_DIR"
    _skills_failed=0
    for _entry in "${SKILL_REPOS[@]}"; do
        _name="${_entry%%|*}"; _url="${_entry##*|}"
        _dest="$SKILLS_DIR/$_name"
        if [[ -d "$_dest/.git" ]]; then
            info "  $_name already present — skipping"
            continue
        fi
        rm -rf "$_dest"
        if git clone --depth 1 "$_url" "$_dest" >/dev/null 2>&1; then
            info "  ✓ $_name"
        else
            warn "  ✗ $_name (clone failed: $_url)"
            _skills_failed=$((_skills_failed + 1))
        fi
    done
    if [[ "$_skills_failed" -eq 0 ]]; then
        SKILLS_OK=true
        success "AI Skills ready (${#SKILL_REPOS[@]} skill sets)"
    else
        warn "AI Skills: $_skills_failed of ${#SKILL_REPOS[@]} sets failed to clone"
    fi
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

# Pinned dependencies live in requirements.txt (single source of truth).
"$PIP" install --progress-bar off -r requirements.txt \
    2>&1 | grep -E "^(Collecting|Downloading|Installing collected|Successfully installed|ERROR|error:)" || true

success "Core packages installed"

if [[ "$INSTALL_VOICE" == true ]]; then
    info "Installing voice packages..."
    _voice_pip_out=$("$PIP" install --progress-bar off \
        faster-whisper==1.2.1 \
        openwakeword==0.4.0 \
        sounddevice==0.5.5 \
        scipy==1.17.1 2>&1) && _voice_pip_ok=true || _voice_pip_ok=false
    echo "$_voice_pip_out" | grep -E "^(Collecting|Downloading|Installing collected|Successfully installed|ERROR|error:)" || true
    if [[ "$_voice_pip_ok" == true ]]; then
        VOICE_OK=true
        success "Voice packages installed"
    else
        warn "Voice packages failed to install — voice support will not be available."
    fi
fi

# ── Embedding model (multilingual MiniLM) ────────────────────────────────────

if [[ "$INSTALL_EMBED_MODEL" == true ]]; then
    EMBED_CACHE_DIR="$INSTALL_DIR/appdata/rag/models"
    mkdir -p "$EMBED_CACHE_DIR"
    # Check if model ONNX files already exist to skip re-download
    if find "$EMBED_CACHE_DIR" -name "*.onnx" 2>/dev/null | grep -q .; then
        EMBED_OK=true
        success "Embedding model already present — skipping download"
    elif run_with_spinner "Downloading paraphrase-multilingual-MiniLM-L12-v2..." \
        "$VENV_DIR/bin/python3" -c "
from fastembed import TextEmbedding
import os
cache = '$EMBED_CACHE_DIR'
os.makedirs(cache, exist_ok=True)
list(TextEmbedding('sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2', cache_dir=cache).embed(['warmup']))
"; then
        EMBED_OK=true
        success "Embedding model ready (~220 MB, 50+ languages incl. Polish, German, French…)"
    else
        warn "Could not download embedding model — it will be downloaded automatically on first use."
    fi
fi

# ── QTermWidget wheel ─────────────────────────────────────────────────────────

info "Installing QTermWidget..."
WHEEL_CACHE="/tmp/$WHEEL_NAME"

# Remove cached file if it looks incomplete (< 100 KB — real wheel is ~3 MB)
if [[ -f "$WHEEL_CACHE" ]] && [[ $(stat -c%s "$WHEEL_CACHE" 2>/dev/null || echo 0) -lt 102400 ]]; then
    warn "Cached QTermWidget wheel appears incomplete — re-downloading."
    rm -f "$WHEEL_CACHE"
fi

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
        OLLAMA_OK=true
        success "Ollama already installed ($(ollama --version 2>/dev/null || echo 'unknown version'))"
    else
        # Run in background — timer loop prints elapsed time and any new >>> lines every 10s
        # Up to 3 attempts in case of transient HTTP errors (e.g. 504)
        _ollama_log="/tmp/_purrsh3ll_ollama.log"
        _ollama_attempt=0 _ollama_ok=false
        while [[ $_ollama_attempt -lt 3 ]] && [[ "$_ollama_ok" == false ]]; do
            _ollama_attempt=$((_ollama_attempt + 1))
            if [[ $_ollama_attempt -gt 1 ]]; then
                warn "Retrying Ollama installation (attempt ${_ollama_attempt}/3)..."
                sleep 5
            fi
            info "Installing Ollama (this may take a few minutes)..."
            > "$_ollama_log"
            bash -c 'curl -fsSL https://ollama.com/install.sh | sh' \
                >"$_ollama_log" 2>&1 &
            _ollama_pid=$! _elapsed=0 _log_pos=0
            while kill -0 "$_ollama_pid" 2>/dev/null; do
                sleep 10
                _elapsed=$((_elapsed + 10))
                # Print any new >>> lines that appeared since last check
                _new=$(tail -n +$((_log_pos + 1)) "$_ollama_log" 2>/dev/null | grep -E "^>>>") || true
                _log_pos=$(wc -l < "$_ollama_log" 2>/dev/null || echo 0)
                _pct=$(tr '\r' '\n' < "$_ollama_log" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+%' | tail -1) || true
                if [[ -n "$_new" ]]; then
                    echo "$_new"
                elif [[ -n "$_pct" ]]; then
                    echo -e "  ${CYAN}...${NC} downloading: ${_pct} (${_elapsed}s elapsed)"
                else
                    echo -e "  ${CYAN}...${NC} still installing (${_elapsed}s elapsed)"
                fi
            done
            wait "$_ollama_pid" || true
            cat "$_ollama_log" >> /tmp/_purrsh3ll_install.log
            # Print any remaining >>> lines not yet shown
            tail -n +$((_log_pos + 1)) "$_ollama_log" 2>/dev/null | grep -E "^>>>" || true
            # Check if a network error occurred (retry-able) or if install succeeded
            if command -v ollama &>/dev/null; then
                _ollama_ok=true
            elif grep -qE "curl: \(22\)|HTTP error|504|503|502|500" "$_ollama_log" 2>/dev/null; then
                warn "Network error during Ollama download — will retry..."
            else
                break  # non-network failure, no point retrying
            fi
        done
        if [[ "$_ollama_ok" == true ]]; then
            OLLAMA_OK=true
            success "Ollama installed → $(command -v ollama)"
        else
            warn "Ollama installation failed — check /tmp/_purrsh3ll_install.log"
        fi
    fi
fi

# ── aichat ────────────────────────────────────────────────────────────────────

if [[ "$INSTALL_AICHAT" == true ]]; then
    if command -v aichat &>/dev/null; then
        AICHAT_OK=true
        success "aichat already installed ($(aichat --version 2>/dev/null || echo 'unknown version'))"
    else
        info "Installing aichat v${AICHAT_VERSION}..."
        AICHAT_TMP=$(mktemp -d)
        if curl -fsSL "$AICHAT_URL" -o "$AICHAT_TMP/aichat.tar.gz" 2>>/tmp/_purrsh3ll_install.log \
                && tar -xzf "$AICHAT_TMP/aichat.tar.gz" -C "$AICHAT_TMP" 2>>/tmp/_purrsh3ll_install.log \
                && sudo install -m 755 "$AICHAT_TMP/aichat" /usr/local/bin/aichat 2>>/tmp/_purrsh3ll_install.log; then
            AICHAT_OK=true
            success "aichat installed → /usr/local/bin/aichat"
        else
            warn "aichat installation failed — check /tmp/_purrsh3ll_install.log"
        fi
        rm -rf "$AICHAT_TMP"
    fi
fi

# ── Docker ────────────────────────────────────────────────────────────────────

# Detect Docker regardless of whether user selected it — needed for image pulls
if command -v docker &>/dev/null; then
    DOCKER_OK=true
fi

if [[ "$INSTALL_DOCKER" == true ]]; then
    if [[ "$DOCKER_OK" == true ]]; then
        success "Docker already installed ($(docker --version))"
    else
        # DEBIAN_FRONTEND=noninteractive suppresses the interactive blue debconf screen
        # stderr goes to log, stdout filtered to meaningful apt/installer lines only
        if grep -qi "kali" /etc/os-release 2>/dev/null; then
            info "Installing Docker (docker.io from apt)..."
            sudo DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true \
                apt-get install -y --no-install-recommends docker.io docker-cli \
                2>>/tmp/_purrsh3ll_install.log \
                | grep --line-buffered -E "^(Get:|Unpacking|Setting up|Preparing)" \
                | grep --line-buffered -v "sudo:" \
                | tee -a /tmp/_purrsh3ll_install.log \
                || true
        else
            info "Installing Docker (get.docker.com, this may take a few minutes)..."
            bash -c 'DEBIAN_FRONTEND=noninteractive curl -fsSL https://get.docker.com | sh' \
                2>>/tmp/_purrsh3ll_install.log \
                | grep --line-buffered -E "^(\+|Setting up|Get:|Unpacking|Preparing)" \
                | tee -a /tmp/_purrsh3ll_install.log \
                || true
        fi
        # check binary or dpkg — command -v can miss freshly installed packages
        if [ -x /usr/bin/docker ] || command -v docker &>/dev/null \
                || dpkg -s docker.io 2>/dev/null | grep -q "Status: install ok installed"; then
            DOCKER_OK=true
            success "Docker packages installed"

            # Enable service (non-blocking — does not start it yet)
            info "Enabling Docker service..."
            sudo systemctl enable docker 2>/dev/null || true

            # Start service with timeout; on Kali try iptables-legacy fallback if needed
            info "Starting Docker service (may take a moment)..."
            if timeout 30 sudo systemctl start docker 2>/dev/null; then
                success "Docker service started"
            else
                warn "Docker service did not start — trying iptables-legacy fallback (common on Kali)..."
                sudo update-alternatives --set iptables  /usr/sbin/iptables-legacy  2>/dev/null || true
                sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
                if timeout 30 sudo systemctl start docker 2>/dev/null; then
                    success "Docker service started (iptables-legacy)"
                else
                    warn "Docker service could not start automatically."
                    warn "Start it manually:  sudo systemctl start docker"
                    warn "If iptables error:  sudo update-alternatives --set iptables /usr/sbin/iptables-legacy"
                fi
            fi

            sudo usermod -aG docker "$USER" || true
            success "Docker installed"
            warn "Log out and back in (or run: newgrp docker) for group membership to take effect."
        else
            warn "Docker installation failed — check /tmp/_purrsh3ll_install.log"
        fi
    fi
fi

# ── Open WebUI Docker image ───────────────────────────────────────────────────

if [[ "$INSTALL_OPENWEBUI" == true && "$DOCKER_OK" == true ]]; then
    if sudo docker image inspect "$OPENWEBUI_IMAGE" &>/dev/null; then
        OPENWEBUI_OK=true
        success "Open WebUI image already present locally"
    else
    info "Pulling Open WebUI Docker image (this may take a few minutes)..."
    sudo -v 2>/dev/null || true  # refresh sudo timestamp before long pull
    _docker_log="/tmp/_purrsh3ll_docker_webui.log"
    > "$_docker_log"
    sudo docker pull "$OPENWEBUI_IMAGE" >"$_docker_log" 2>&1 &
    _docker_pid=$! _elapsed=0
    while kill -0 "$_docker_pid" 2>/dev/null; do
        sleep 10
        _elapsed=$((_elapsed + 10))
        _total=$(tr '\r' '\n' < "$_docker_log" 2>/dev/null \
            | grep -oE '^[a-f0-9]{12}:' | sort -u | wc -l) || _total=0
        _layers=$(tr '\r' '\n' < "$_docker_log" 2>/dev/null \
            | grep -cE "Pull complete|Already exists" 2>/dev/null) || _layers=0
        _download=$(tr '\r' '\n' < "$_docker_log" 2>/dev/null \
            | grep "Downloading" | tail -1 \
            | grep -oE '[0-9]+(\.[0-9]+)?(kB|MB|GB)/[0-9]+(\.[0-9]+)?(kB|MB|GB)') || _download=""
        _layers_info="${_layers}/$([[ $_total -gt 0 ]] && echo "$_total" || echo "?") layers done"
        if [[ -n "$_download" ]]; then
            echo -e "  ${CYAN}...${NC} downloading: ${_download} — ${_layers_info} (${_elapsed}s elapsed)"
        elif [[ "$_layers" -gt 0 ]]; then
            echo -e "  ${CYAN}...${NC} ${_layers_info} (${_elapsed}s elapsed)"
        else
            echo -e "  ${CYAN}...${NC} still pulling (${_elapsed}s elapsed)"
        fi
    done
    _docker_exit=0
    wait "$_docker_pid" || _docker_exit=$?
    cat "$_docker_log" >> /tmp/_purrsh3ll_install.log
    tr '\r' '\n' < "$_docker_log" 2>/dev/null | grep "^Status:" || true
    if [[ $_docker_exit -eq 0 ]]; then
        OPENWEBUI_OK=true
        success "Open WebUI image ready"
    else
        warn "Could not pull Open WebUI image — run: sudo docker pull $OPENWEBUI_IMAGE"
    fi
    fi  # end: image not present locally
fi

# ── WebMap Docker image ───────────────────────────────────────────────────────

if [[ "$INSTALL_WEBMAP" == true && "$DOCKER_OK" == true ]]; then
    if sudo docker image inspect "$WEBMAP_IMAGE" &>/dev/null; then
        WEBMAP_OK=true
        success "WebMap image already present locally"
    else
    info "Pulling WebMap Docker image (this may take a few minutes)..."
    sudo -v 2>/dev/null || true  # refresh sudo timestamp before long pull
    _docker_log="/tmp/_purrsh3ll_docker_webmap.log"
    > "$_docker_log"
    sudo docker pull "$WEBMAP_IMAGE" >"$_docker_log" 2>&1 &
    _docker_pid=$! _elapsed=0
    while kill -0 "$_docker_pid" 2>/dev/null; do
        sleep 10
        _elapsed=$((_elapsed + 10))
        _total=$(tr '\r' '\n' < "$_docker_log" 2>/dev/null \
            | grep -oE '^[a-f0-9]{12}:' | sort -u | wc -l) || _total=0
        _layers=$(tr '\r' '\n' < "$_docker_log" 2>/dev/null \
            | grep -cE "Pull complete|Already exists" 2>/dev/null) || _layers=0
        _download=$(tr '\r' '\n' < "$_docker_log" 2>/dev/null \
            | grep "Downloading" | tail -1 \
            | grep -oE '[0-9]+(\.[0-9]+)?(kB|MB|GB)/[0-9]+(\.[0-9]+)?(kB|MB|GB)') || _download=""
        _layers_info="${_layers}/$([[ $_total -gt 0 ]] && echo "$_total" || echo "?") layers done"
        if [[ -n "$_download" ]]; then
            echo -e "  ${CYAN}...${NC} downloading: ${_download} — ${_layers_info} (${_elapsed}s elapsed)"
        elif [[ "$_layers" -gt 0 ]]; then
            echo -e "  ${CYAN}...${NC} ${_layers_info} (${_elapsed}s elapsed)"
        else
            echo -e "  ${CYAN}...${NC} still pulling (${_elapsed}s elapsed)"
        fi
    done
    _docker_exit=0
    wait "$_docker_pid" || _docker_exit=$?
    cat "$_docker_log" >> /tmp/_purrsh3ll_install.log
    tr '\r' '\n' < "$_docker_log" 2>/dev/null | grep "^Status:" || true
    if [[ $_docker_exit -eq 0 ]]; then
        WEBMAP_OK=true
        success "WebMap image ready"
    else
        warn "Could not pull WebMap image — run: sudo docker pull $WEBMAP_IMAGE"
    fi
    fi  # end: image not present locally
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
echo "  Component status:"

_summary_row() {
    local label="$1" size="$2" selected="$3" ok="$4" skip_note="$5"
    if   [[ "$ok"       == true  ]]; then echo -e "    ${GREEN}✓${NC}  ${label} ${size}"
    elif [[ "$selected" == true  ]]; then echo -e "    ${RED}✗${NC}  ${label} (failed — check /tmp/_purrsh3ll_install.log)"
    else                                  echo -e "    ${YELLOW}–${NC}  ${label} ${skip_note}"
    fi
}

echo -e "    ${GREEN}✓${NC}  Core application     (~1.5 GB)"
_summary_row "Voice support       " "(~500 MB)" "$INSTALL_VOICE"       "$VOICE_OK"     "(skipped)"
_summary_row "AI Skills           " "(~15 MB) " "$INSTALL_SKILLS"      "$SKILLS_OK"    "(skipped)"
_summary_row "Ollama              " "(~1.5 GB)" "$INSTALL_OLLAMA"      "$OLLAMA_OK"    "(skipped)"
_summary_row "aichat              " "(~15 MB) " "$INSTALL_AICHAT"      "$AICHAT_OK"    "(skipped)"
_summary_row "Docker              " "(~300 MB)" "$INSTALL_DOCKER"      "$DOCKER_OK"    "(skipped)"
_summary_row "Open WebUI image    " "(~4.8 GB)" "$INSTALL_OPENWEBUI"   "$OPENWEBUI_OK" "(skipped)"
_summary_row "WebMap image        " "(~1.5 GB)" "$INSTALL_WEBMAP"      "$WEBMAP_OK"    "(skipped)"
_summary_row "Embedding model     " "(~220 MB)" "$INSTALL_EMBED_MODEL" "$EMBED_OK"     "(skipped — downloaded on first use)"

echo ""
echo "  Run PurrSh3ll:"
echo -e "    ${BOLD}purrsh3ll${NC}"
echo ""

if [[ "$OLLAMA_OK" == true ]]; then
    echo "  First steps with Ollama:"
    echo "    ollama serve"
    echo "    ollama pull llama3.2"
    echo ""
fi

echo "  Setup guide:"
echo -e "    ${BOLD}cat $INSTALL_DIR/usermodules/FIRST_STEPS.md${NC}"
echo ""
