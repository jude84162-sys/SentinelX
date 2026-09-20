#!/usr/bin/env bash
#
# SentinelX - Installation Script
# Works on: Termux (Android), Linux, macOS, WSL
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/jude84162-sys/SentinelX/main/install.sh | bash
#
#   Or with options:
#   bash install.sh --prefix ~/tools --no-venv

# Note: set -e disabled for Termux compatibility
# set -e

# ============================================================
# Configuration
# ============================================================

REPO="jude84162-sys/SentinelX"
REPO_URL="https://github.com/${REPO}.git"
INSTALL_DIR="${HOME}/SentinelX"
PREFIX="${HOME}/.local/bin"
USE_VENV=true
BRANCH="main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# Helpers
# ============================================================

log() { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

print_banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║      🛡️  SentinelX Installer                 ║${NC}"
    echo -e "${CYAN}║      Modular Enterprise Blue Team Suite      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

# ============================================================
# Detect environment
# ============================================================

detect_env() {
    if [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ]; then
        ENV="termux"
        log "Detected: Termux (Android)"
    elif [ "$(uname)" = "Darwin" ]; then
        ENV="macos"
        log "Detected: macOS"
    elif grep -qi microsoft /proc/version 2>/dev/null; then
        ENV="wsl"
        log "Detected: WSL"
    elif [ "$(uname)" = "Linux" ]; then
        ENV="linux"
        log "Detected: Linux"
    else
        ENV="unknown"
        warn "Unknown environment — proceeding anyway"
    fi
}

# ============================================================
# Install system dependencies
# ============================================================

install_deps() {
    log "Checking Python..."

    if command -v python3 >/dev/null 2>&1; then
        PYTHON="python3"
    elif command -v python >/dev/null 2>&1; then
        PYTHON="python"
    else
        error "Python not found. Install Python 3.8+ first."
        return 1
    fi

    success "Python: $($PYTHON --version 2>&1)"

    log "Checking git..."
    if ! command -v git >/dev/null 2>&1; then
        warn "Git not found. Installing..."
        case "$ENV" in
            termux) pkg install -y git ;;
            linux|wsl) sudo apt-get update && sudo apt-get install -y git ;;
            macos) brew install git ;;
        esac
    fi

    if command -v git >/dev/null 2>&1; then
        success "Git: $(git --version)"
    else
        error "Git installation failed"
        return 1
    fi

    # Termux-specific: termux-api
    if [ "$ENV" = "termux" ]; then
        log "Checking Termux:API..."
        if ! command -v termux-battery-status >/dev/null 2>&1; then
            log "Installing termux-api package..."
            pkg install -y termux-api 2>/dev/null || \
                warn "termux-api install failed (optional)"
        fi
    fi

    return 0
}

# ============================================================
# Clone or update repository
# ============================================================

setup_repo() {
    if [ -d "$INSTALL_DIR" ]; then
        log "Updating existing install at $INSTALL_DIR"
        cd "$INSTALL_DIR" || {
            error "Cannot cd to $INSTALL_DIR"
            return 1
        }
        git pull origin "$BRANCH" 2>/dev/null || \
            warn "git pull failed, using existing files"
    else
        log "Cloning SentinelX to $INSTALL_DIR"
        git clone --depth 1 -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR" || {
            error "Clone failed"
            return 1
        }
        cd "$INSTALL_DIR" || return 1
    fi

    success "Repository ready at $INSTALL_DIR"
    return 0
}

# ============================================================
# Install Python dependencies
# ============================================================

install_python_deps() {
    log "Installing Python packages..."

    cd "$INSTALL_DIR" || return 1

    # --- Virtual environment (not on Termux) ---
    if [ "$USE_VENV" = true ] && [ "$ENV" != "termux" ]; then
        log "Creating virtual environment..."
        $PYTHON -m venv venv 2>/dev/null || {
            warn "venv creation failed, continuing without"
            USE_VENV=false
        }
        if [ "$USE_VENV" = true ] && [ -d "venv" ]; then
            # shellcheck disable=SC1091
            source venv/bin/activate
            PYTHON="$INSTALL_DIR/venv/bin/python"
            success "Virtual environment activated"
        fi
    fi

    # --- Skip pip upgrade on Termux (forbidden) ---
    if [ "$ENV" != "termux" ]; then
        log "Upgrading pip..."
        $PYTHON -m pip install --upgrade pip --quiet 2>/dev/null || \
            warn "pip upgrade failed (continuing)"
    else
        log "Skipping pip upgrade (Termux forbids it)"
    fi

    # --- Core dependencies ---
    log "Installing core deps: psutil phonenumbers requests"

    if $PYTHON -m pip install --quiet psutil phonenumbers requests 2>/dev/null; then
        success "Core deps installed"
    elif $PYTHON -m pip install --break-system-packages --quiet psutil phonenumbers requests 2>/dev/null; then
        success "Core deps installed (break-system mode)"
    else
        warn "Core deps installation failed"
        warn "Try manually: pip install psutil phonenumbers requests"
    fi

    # --- Optional dependencies ---
    log "Installing optional features..."

    # YARA
    if $PYTHON -m pip install --quiet yara-python 2>/dev/null; then
        success "YARA engine enabled"
    elif $PYTHON -m pip install --break-system-packages --quiet yara-python 2>/dev/null; then
        success "YARA engine enabled"
    else
        warn "YARA not installed (optional)"
    fi

    # Rich + PyYAML
    if $PYTHON -m pip install --quiet rich pyyaml 2>/dev/null; then
        success "Rich UI + PyYAML enabled"
    elif $PYTHON -m pip install --break-system-packages --quiet rich pyyaml 2>/dev/null; then
        success "Rich UI + PyYAML enabled"
    else
        warn "Rich UI not installed (optional)"
    fi

    return 0
}

# ============================================================
# Create launcher script
# ============================================================

create_launcher() {
    log "Creating launcher at $PREFIX/sentinelx"

    mkdir -p "$PREFIX" 2>/dev/null || {
        error "Cannot create $PREFIX"
        return 1
    }

    LAUNCHER="$PREFIX/sentinelx"

    if [ "$USE_VENV" = true ] && [ -d "$INSTALL_DIR/venv" ]; then
        cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
source "$INSTALL_DIR/venv/bin/activate"
exec python "$INSTALL_DIR/SentinelX.py" "\$@"
EOF
    else
        cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
exec $PYTHON "$INSTALL_DIR/SentinelX.py" "\$@"
EOF
    fi

    chmod +x "$LAUNCHER" 2>/dev/null || {
        error "Cannot chmod launcher"
        return 1
    }

    success "Launcher created"
    return 0
}

# ============================================================
# Update PATH in shell rc
# ============================================================

update_path() {
    if echo "$PATH" | grep -q "$PREFIX"; then
        success "PATH already includes $PREFIX"
        return 0
    fi

    SHELL_RC="$HOME/.bashrc"
    case "$SHELL" in
        */zsh) SHELL_RC="$HOME/.zshrc" ;;
    esac

    # Check if not already added
    if grep -q "SentinelX" "$SHELL_RC" 2>/dev/null; then
        success "PATH already configured in $SHELL_RC"
        return 0
    fi

    {
        echo ""
        echo "# SentinelX"
        echo "export PATH=\"$PREFIX:\$PATH\""
    } >> "$SHELL_RC" 2>/dev/null || {
        warn "Cannot write to $SHELL_RC"
        return 1
    }

    success "Added $PREFIX to PATH in $SHELL_RC"
    warn "Run: source $SHELL_RC (or restart shell)"
    return 0
}

# ============================================================
# Test installation
# ============================================================

run_test() {
    log "Running quick test..."

    if [ -d "$INSTALL_DIR/venv" ]; then
        TEST_PYTHON="$INSTALL_DIR/venv/bin/python"
    else
        TEST_PYTHON="$PYTHON"
    fi

    if $TEST_PYTHON "$INSTALL_DIR/SentinelX.py" --version >/dev/null 2>&1; then
        success "Test passed"
        return 0
    else
        warn "Test failed — check installation"
        return 1
    fi
}

# ============================================================
# Final message
# ============================================================

final_message() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      ✅  Installation Complete!               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${CYAN}Installed at:${NC} $INSTALL_DIR"
    echo -e "  ${CYAN}Launcher:${NC}     $PREFIX/sentinelx"
    echo ""
    echo -e "  ${CYAN}Quick start:${NC}"
    echo "    source ~/.bashrc"
    echo "    sentinelx --version"
    echo "    sentinelx --env"
    echo "    sentinelx --triage-all"
    echo ""
    echo -e "  ${CYAN}Docs:${NC}"
    echo "    https://github.com/${REPO}"
    echo ""
    echo -e "  ${CYAN}Uninstall:${NC}"
    echo "    rm -rf $INSTALL_DIR $PREFIX/sentinelx"
    echo ""
}

# ============================================================
# Parse arguments
# ============================================================

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --no-venv)
            USE_VENV=false
            shift
            ;;
        --branch)
            BRANCH="$2"
            shift 2
            ;;
        --help|-h)
            echo "SentinelX Installer"
            echo ""
            echo "Usage: bash install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --prefix DIR    Launcher dir (default: ~/.local/bin)"
            echo "  --dir DIR       Project dir (default: ~/SentinelX)"
            echo "  --no-venv       Skip virtual environment"
            echo "  --branch NAME   Git branch (default: main)"
            echo "  --help, -h      Show this help"
            echo ""
            echo "Examples:"
            echo "  bash install.sh"
            echo "  bash install.sh --no-venv"
            echo "  bash install.sh --dir ~/tools/sx"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ============================================================
# Main
# ============================================================

main() {
    print_banner

    detect_env

    install_deps
    if [ $? -ne 0 ]; then
        error "Failed at: install_deps"
        return 1
    fi

    setup_repo
    if [ $? -ne 0 ]; then
        error "Failed at: setup_repo"
        return 1
    fi

    install_python_deps
    # Continue even if some deps failed

    create_launcher
    if [ $? -ne 0 ]; then
        error "Failed at: create_launcher"
        return 1
    fi

    update_path
    # Continue even if PATH update failed

    run_test
    # Continue even if test failed

    final_message
    return 0
}

main
exit $?
