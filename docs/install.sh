#!/bin/sh
# Snag installer script
# Usage: curl -sSL https://abzolute1.github.io/snag/install.sh | sh

set -eu

REPO="Abzolute1/snag"
BINARY_NAME="snag"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

TMP_DIR=""

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1" >&2
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1" >&2
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS with helpful messages for unsupported platforms
detect_os() {
    OS=$(uname -s)
    case "$OS" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "macos" ;;
        MINGW*|MSYS*|CYGWIN*)
            error "Windows detected. Install via PowerShell: powershell -c \"irm https://abzolute1.github.io/snag/install.ps1 | iex\"" ;;
        FreeBSD*)
            error "FreeBSD is not supported. Build from source: cargo install --git https://github.com/${REPO}" ;;
        *)
            error "Unsupported operating system: $OS. See https://github.com/${REPO}/releases" ;;
    esac
}

# Detect architecture with helpful messages for unsupported platforms
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)   echo "x86_64" ;;
        aarch64|arm64)  echo "aarch64" ;;
        armv7*|armhf)
            error "32-bit ARM is not supported. Build from source: cargo install --git https://github.com/${REPO}" ;;
        i386|i686)
            error "32-bit x86 is not supported. Build from source: cargo install --git https://github.com/${REPO}" ;;
        *)
            error "Unsupported architecture: $ARCH. See https://github.com/${REPO}/releases" ;;
    esac
}

# Get latest release version from GitHub with proper error handling
get_latest_version() {
    info "Fetching latest release version..."

    RESPONSE_FILE="${TMP_DIR}/api_response.json"
    HTTP_CODE=$(curl -sS -w '%{http_code}' -o "$RESPONSE_FILE" "$API_URL" 2>/dev/null) || {
        error "Network error: could not reach GitHub API. Check your internet connection."
    }

    case "$HTTP_CODE" in
        200) ;;
        403)
            error "GitHub API rate limit exceeded. Wait a few minutes or download directly from https://github.com/${REPO}/releases" ;;
        404)
            error "No releases found for ${REPO}. The project may not have published a release yet." ;;
        *)
            error "GitHub API returned HTTP $HTTP_CODE. Try downloading from https://github.com/${REPO}/releases" ;;
    esac

    VERSION=$(grep '"tag_name":' "$RESPONSE_FILE" | sed -E 's/.*"v([^"]+)".*/\1/')
    if [ -z "$VERSION" ]; then
        error "Failed to parse version from GitHub API response"
    fi
    echo "$VERSION"
}

# Download and install binary
install_binary() {
    OS=$(detect_os)
    ARCH=$(detect_arch)
    VERSION=$(get_latest_version)

    info "Detected system: ${OS}-${ARCH}"
    info "Latest version: v${VERSION}"

    # Construct download URL
    ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET_NAME}"

    info "Downloading from: ${DOWNLOAD_URL}"

    # Download binary with HTTP status checking
    DOWNLOAD_FILE="${TMP_DIR}/${ASSET_NAME}"
    DL_CODE=$(curl -fSL -w '%{http_code}' -o "$DOWNLOAD_FILE" "$DOWNLOAD_URL" 2>/dev/null) || {
        # curl -f exits non-zero on HTTP errors; check what we got
        if [ -f "$DOWNLOAD_FILE" ]; then
            rm -f "$DOWNLOAD_FILE"
        fi
        error "Download failed. No binary available for ${OS}-${ARCH}. Check https://github.com/${REPO}/releases for available platforms."
    }

    if [ ! -f "$DOWNLOAD_FILE" ] || [ ! -s "$DOWNLOAD_FILE" ]; then
        error "Downloaded file is empty or missing"
    fi

    # Extract binary
    info "Extracting binary..."
    if ! tar -xzf "$DOWNLOAD_FILE" -C "$TMP_DIR" 2>/dev/null; then
        error "Failed to extract archive. The download may be corrupted — try again."
    fi

    if [ ! -f "${TMP_DIR}/${BINARY_NAME}" ]; then
        error "Expected binary '${BINARY_NAME}' not found in archive"
    fi

    chmod +x "${TMP_DIR}/${BINARY_NAME}"

    # Verify the binary runs
    DOWNLOADED_VERSION=$("${TMP_DIR}/${BINARY_NAME}" --version 2>/dev/null) || {
        error "Downloaded binary failed to execute. It may be built for a different platform."
    }
    info "Verified: ${DOWNLOADED_VERSION}"

    # Determine install location
    if [ -w "/usr/local/bin" ]; then
        INSTALL_DIR="/usr/local/bin"
    elif [ -d "$HOME/.local/bin" ]; then
        INSTALL_DIR="$HOME/.local/bin"
        warn "Installing to $INSTALL_DIR (user directory)"
    else
        mkdir -p "$HOME/.local/bin"
        INSTALL_DIR="$HOME/.local/bin"
        warn "Created and installing to $INSTALL_DIR (user directory)"
    fi

    # Install binary
    info "Installing to ${INSTALL_DIR}/${BINARY_NAME}..."

    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        # Need sudo
        info "Need elevated permissions to install to ${INSTALL_DIR}"
        sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Verify installation
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        info "Successfully installed ${BINARY_NAME} v${VERSION}!"
        info "Run '${BINARY_NAME} --help' to get started"
    else
        warn "Installation complete, but ${BINARY_NAME} is not in your PATH"

        # Detect shell config file
        SHELL_RC=""
        EXPORT_LINE=""
        case "${SHELL:-}" in
            */bash)
                SHELL_RC="$HOME/.bashrc"
                EXPORT_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
                ;;
            */zsh)
                SHELL_RC="$HOME/.zshrc"
                EXPORT_LINE="export PATH=\"${INSTALL_DIR}:\$PATH\""
                ;;
            */fish)
                SHELL_RC="$HOME/.config/fish/config.fish"
                EXPORT_LINE="fish_add_path ${INSTALL_DIR}"
                ;;
        esac

        if [ -n "$SHELL_RC" ]; then
            if [ -f "$SHELL_RC" ] && grep -q "${INSTALL_DIR}" "$SHELL_RC" 2>/dev/null; then
                info "${INSTALL_DIR} is already in ${SHELL_RC}"
            else
                # When piped (curl | sh), stdin isn't the keyboard so we can't prompt.
                # Just add it automatically and tell the user what we did.
                if [ -t 0 ]; then
                    printf "${YELLOW}[PROMPT]${NC} Add ${BINARY_NAME} to your PATH in ${SHELL_RC}? (y/n) " >&2
                    read -r REPLY
                    case "$REPLY" in
                        [yY]|[yY][eE][sS])
                            echo "$EXPORT_LINE" >> "$SHELL_RC"
                            info "Added to ${SHELL_RC}. Restart your terminal to use ${BINARY_NAME}."
                            ;;
                        *)
                            info "Skipped. Add it manually:"
                            info "  echo '$EXPORT_LINE' >> $SHELL_RC"
                            ;;
                    esac
                else
                    echo "$EXPORT_LINE" >> "$SHELL_RC"
                    info "Added ${INSTALL_DIR} to ${SHELL_RC}"
                    info "Restart your terminal to use ${BINARY_NAME}."
                fi
            fi
        else
            warn "Could not detect shell. Add ${INSTALL_DIR} to your PATH manually."
        fi
    fi
}

# Main
main() {
    info "Installing ${BINARY_NAME}..."

    # Check for required commands
    for cmd in curl tar uname grep sed; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
        fi
    done

    # Create temp dir early so API response can be saved
    TMP_DIR=$(mktemp -d)

    install_binary
}

main
