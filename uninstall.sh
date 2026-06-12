#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# PurrSh3ll — Uninstaller
#
# Usage:
#   bash uninstall.sh          # interactive (whiptail checklist)
#   bash uninstall.sh --auto   # non-interactive (remove everything)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

INSTALL_DIR="$HOME/purrsh3ll"
VENV_DIR="$INSTALL_DIR/.venv"
DESKTOP_FILE="$HOME/.local/share/applications/purrsh3ll.desktop"
LAUNCH_SCRIPT="/usr/local/bin/purrsh3ll"
AICHAT_BIN="/usr/local/bin/aichat"
OPENWEBUI_IMAGE="ghcr.io/open-webui/open-webui:main"
WEBMAP_IMAGE="reborntc/webmap"
ZSHRC="$HOME/.zshrc"

AUTO=false
[[ "${1:-}" == "--auto" ]] && AUTO=true

# ── Colors & helpers ──────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}==>${NC} ${BOLD}$*${NC}"; }
success() { echo -e "${GREEN} ✓${NC}  $*"; }
warn()    { echo -e "${YELLOW}  !${NC}  $*"; }
skipped() { echo -e "${YELLOW}  –${NC}  $*"; }
die()     { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

# ── Header ────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}  PurrSh3ll — Uninstaller${NC}"
echo "  ──────────────────────────────────────────"
if [[ "$AUTO" == true ]]; then
    echo "  Mode: automatic — all components will be removed."
else
    echo "  Use SPACE to toggle items, ENTER to confirm."
fi
echo ""

# ── Safety check ──────────────────────────────────────────────────────────────

if [[ ! -d "$INSTALL_DIR" ]]; then
    die "PurrSh3ll installation not found at $INSTALL_DIR"
fi

# ── Component selection ───────────────────────────────────────────────────────

RM_VENV=false
RM_USERDATA=false
RM_SHORTCUTS=false
RM_ZSHRC=false
RM_AICHAT=false
RM_DOCKER_IMAGES=false
RM_OLLAMA_MODELS=false
RM_APPDIR=false

if [[ "$AUTO" == true ]]; then

    RM_VENV=true
    RM_USERDATA=true
    RM_SHORTCUTS=true
    RM_ZSHRC=true
    RM_AICHAT=true
    RM_DOCKER_IMAGES=true
    RM_OLLAMA_MODELS=true
    RM_APPDIR=true

else

    if ! command -v whiptail &>/dev/null; then
        die "whiptail not found. Install it with: sudo apt install whiptail"
    fi

    CHOICES=$(whiptail \
        --title "PurrSh3ll — Uninstaller" \
        --checklist \
"Select what to remove.
Items marked ON are safe defaults.

SPACE = toggle   |   ENTER = confirm" \
        22 68 8 \
        "venv"          "Python venv         (~1.5 GB)"                  ON  \
        "shortcuts"     "Desktop shortcut + launch command"              ON  \
        "zshrc"         "Shell entries in ~/.zshrc"                      ON  \
        "userdata"      "User data (config, API keys, history, logs)"    OFF \
        "aichat"        "aichat binary       (/usr/local/bin/aichat)"    OFF \
        "dockerimages"  "Docker images       (Open WebUI + WebMap)"      OFF \
        "ollamamodels"  "Ollama models       (pulled models only)"       OFF \
        "appdir"        "Application folder  ($INSTALL_DIR)"             OFF \
        3>&1 1>&2 2>&3) || { echo ""; warn "Uninstall cancelled."; exit 0; }

    [[ "$CHOICES" == *'"venv"'*         ]] && RM_VENV=true
    [[ "$CHOICES" == *'"shortcuts"'*    ]] && RM_SHORTCUTS=true
    [[ "$CHOICES" == *'"zshrc"'*        ]] && RM_ZSHRC=true
    [[ "$CHOICES" == *'"userdata"'*     ]] && RM_USERDATA=true
    [[ "$CHOICES" == *'"aichat"'*       ]] && RM_AICHAT=true
    [[ "$CHOICES" == *'"dockerimages"'* ]] && RM_DOCKER_IMAGES=true
    [[ "$CHOICES" == *'"ollamamodels"'* ]] && RM_OLLAMA_MODELS=true
    [[ "$CHOICES" == *'"appdir"'*       ]] && RM_APPDIR=true

    # Extra confirmation before removing user data or the app folder
    if [[ "$RM_USERDATA" == true ]]; then
        whiptail --title "Warning" --yesno \
"Remove user data?

This will permanently delete:
  • API keys
  • AI configuration
  • Terminal history
  • Chat history
  • Logs

This cannot be undone." 16 54 || RM_USERDATA=false
    fi

    if [[ "$RM_APPDIR" == true ]]; then
        whiptail --title "Warning" --yesno \
"Remove application folder?

$INSTALL_DIR will be deleted entirely,
including all app files and usermodules.

This cannot be undone." 14 54 || RM_APPDIR=false
    fi

    echo ""

fi

# ── Python venv ───────────────────────────────────────────────────────────────

if [[ "$RM_VENV" == true ]]; then
    if [[ -d "$VENV_DIR" ]]; then
        info "Removing Python virtual environment..."
        rm -rf "$VENV_DIR"
        success "Virtual environment removed"
    else
        skipped "Virtual environment not found — skipping"
    fi
fi

# ── Desktop shortcut + launch command ────────────────────────────────────────

if [[ "$RM_SHORTCUTS" == true ]]; then
    if [[ -f "$DESKTOP_FILE" ]]; then
        rm -f "$DESKTOP_FILE"
        success "Desktop shortcut removed"
    else
        skipped "Desktop shortcut not found — skipping"
    fi

    if [[ -f "$LAUNCH_SCRIPT" ]]; then
        sudo rm -f "$LAUNCH_SCRIPT"
        success "Launch command removed (/usr/local/bin/purrsh3ll)"
    else
        skipped "Launch command not found — skipping"
    fi
fi

# ── Shell entries in ~/.zshrc ─────────────────────────────────────────────────

if [[ "$RM_ZSHRC" == true ]]; then
    if [[ -f "$ZSHRC" ]] && grep -q "purrsh3ll\|purrsh3ll\|PURRSH3LL" "$ZSHRC" 2>/dev/null; then
        info "Removing PurrSh3ll entries from ~/.zshrc..."
        # Remove any line that references purrsh3ll (source lines, comments, etc.)
        sed -i '/purrsh3ll/Id' "$ZSHRC"
        success "Shell entries removed from ~/.zshrc"
        warn "Restart your shell or run: source ~/.zshrc"
    else
        skipped "No PurrSh3ll entries found in ~/.zshrc — skipping"
    fi
fi

# ── User data ─────────────────────────────────────────────────────────────────

if [[ "$RM_USERDATA" == true ]]; then
    info "Removing user data..."
    _removed=false

    for _target in \
        "$INSTALL_DIR/appdata/api_keys.json" \
        "$INSTALL_DIR/appdata/api_profiles.json" \
        "$INSTALL_DIR/appdata/app_config.json" \
        "$INSTALL_DIR/appdata/logs" \
        "$INSTALL_DIR/appdata/chat_sessions" \
        "$INSTALL_DIR/appdata/rag/chroma" \
        "$INSTALL_DIR/appdata/rag/models" \
        "$INSTALL_DIR/appdata/scripts_notes" \
        "$INSTALL_DIR/appdata/psnotes.txt"
    do
        if [[ -e "$_target" ]]; then
            rm -rf "$_target"
            _removed=true
        fi
    done

    if [[ "$_removed" == true ]]; then
        success "User data removed"
    else
        skipped "No user data found — skipping"
    fi
fi

# ── aichat ────────────────────────────────────────────────────────────────────

if [[ "$RM_AICHAT" == true ]]; then
    if [[ -f "$AICHAT_BIN" ]]; then
        sudo rm -f "$AICHAT_BIN"
        success "aichat removed"
    else
        skipped "aichat not found — skipping"
    fi
fi

# ── Docker images ─────────────────────────────────────────────────────────────

if [[ "$RM_DOCKER_IMAGES" == true ]]; then
    if command -v docker &>/dev/null; then
        for _img in "$OPENWEBUI_IMAGE" "$WEBMAP_IMAGE"; do
            if sudo docker image inspect "$_img" &>/dev/null 2>&1; then
                info "Removing Docker image: $_img..."
                sudo docker rmi "$_img" && success "Removed: $_img" || warn "Could not remove: $_img"
            else
                skipped "Image not found: $_img"
            fi
        done
    else
        skipped "Docker not installed — skipping image removal"
    fi
fi

# ── Ollama models ─────────────────────────────────────────────────────────────

if [[ "$RM_OLLAMA_MODELS" == true ]]; then
    if command -v ollama &>/dev/null; then
        _models=$(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | grep -v '^$') || _models=""
        if [[ -n "$_models" ]]; then
            info "Removing Ollama models..."
            while IFS= read -r _model; do
                [[ -z "$_model" ]] && continue
                ollama rm "$_model" 2>/dev/null && success "Removed model: $_model" || warn "Could not remove: $_model"
            done <<< "$_models"
        else
            skipped "No Ollama models found — skipping"
        fi
    else
        skipped "Ollama not installed — skipping model removal"
    fi
fi

# ── Application folder ────────────────────────────────────────────────────────

if [[ "$RM_APPDIR" == true ]]; then
    # Resolve real path of this script to avoid deleting ourselves mid-run
    _this_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ "$_this_script" == "$INSTALL_DIR"* ]]; then
        warn "Script is running from inside $INSTALL_DIR — copying uninstaller to /tmp first"
        cp "${BASH_SOURCE[0]}" /tmp/_purrsh3ll_uninstall_tmp.sh
        warn "Application folder will be removed. Uninstaller copy saved to /tmp/_purrsh3ll_uninstall_tmp.sh"
    fi
    info "Removing application folder: $INSTALL_DIR..."
    rm -rf "$INSTALL_DIR"
    success "Application folder removed"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}  Uninstall complete.${NC}"
echo ""
