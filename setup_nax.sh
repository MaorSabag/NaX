#!/bin/bash
# setup_nax.sh - Build and deploy NaX extenders to an Adaptix Server directory.
#
# Builds the 4 Go server plugins (agent, HTTP listener, SMB listener, service),
# deploys them to Server/extenders/, writes nax_root.conf so the agent plugin
# can find the NaX source tree at runtime, and registers them in profile.yaml.
#
# Usage:
#   ./setup_nax.sh --server /path/to/Server
#   ./setup_nax.sh --server /path/to/Server --action agent
#   ./setup_nax.sh --server /path/to/Server --action prereqs

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

error_exit()  { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info_msg()    { echo -e "${GREEN}[+]${NC} $1"; }
warning_msg() { echo -e "${YELLOW}[!]${NC} $1"; }
step_msg()    { echo -e "${CYAN}[*]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NAX_ROOT="$SCRIPT_DIR"
SERVER_DIR=""
ADAPTIX_SRC=""
ACTION="all"
GO_BIN=""
GOEXPERIMENT=""
SERVER_GO_VERSION=""
SERVER_AXC2_MODULE=""
SERVER_AXC2_VERSION=""

## ========= [ argument parsing ] =========

while [[ $# -gt 0 ]]; do
    case $1 in
        --server)
            SERVER_DIR="$(realpath "$2" 2>/dev/null || echo "$2")"
            shift 2
            ;;
        --adaptix-src)
            ADAPTIX_SRC="$(realpath "$2" 2>/dev/null || echo "$2")"
            shift 2
            ;;
        --action)
            ACTION="$2"
            shift 2
            ;;
        -h|--help)
            ACTION="help"
            shift
            ;;
        *)
            error_exit "Unknown parameter: $1\nRun $0 --help for usage."
            ;;
    esac
done

## ========= [ usage ] =========

if [ "$ACTION" = "help" ] || [ -z "$SERVER_DIR" ]; then
    cat <<EOF
Usage: $0 --server <Server_directory> [--action <action>] [--adaptix-src <dir>]

Required:
  --server <dir>      Path to Adaptix Server directory
                      (contains adaptixserver binary, extenders/, profile.yaml)

Optional:
  --adaptix-src <dir> Path to Adaptix source tree (contains AdaptixServer/go.mod).
                      Used to detect axc2 module version for plugin sync.
                      If omitted, auto-searches common locations.
  --action <action>   Action to perform (default: all)

Actions:
  all                 Check prereqs + sync modules + build all + deploy + register
  plugins             Sync modules + build and deploy all 4 plugins
  agent               Build and deploy agent plugin only
  listener-http       Build and deploy HTTP listener only
  listener-smb        Build and deploy SMB listener only
  service             Build and deploy nax_store service only
  deploy              Deploy only (copy configs, axscripts, templates) - no build
  sync                Sync go.mod files to match server (no build)
  prereqs             Check build prerequisites only

Examples:
  $0 --server /opt/Server
  $0 --server ../Server --action agent
  $0 --server /opt/Server --adaptix-src /opt/AdaptixC2
  $0 --server /opt/Server --action sync
EOF
    [ "$ACTION" = "help" ] && exit 0
    exit 1
fi

## ========= [ validate server directory ] =========

if [ ! -d "$SERVER_DIR" ]; then
    error_exit "Server directory does not exist: $SERVER_DIR"
fi

if [ ! -f "$SERVER_DIR/adaptixserver" ] && [ ! -f "$SERVER_DIR/profile.yaml" ]; then
    error_exit "Not an Adaptix Server directory (no adaptixserver or profile.yaml): $SERVER_DIR"
fi

EXTENDERS_DIR="$SERVER_DIR/extenders"

## ========= [ prerequisites check ] =========

check_prereqs() {
    step_msg "Checking build prerequisites..."
    local missing=()

    command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || missing+=("mingw-w64")
    command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1 || missing+=("mingw-w64-g++")
    command -v nasm    >/dev/null 2>&1 || missing+=("nasm")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v objcopy >/dev/null 2>&1 || missing+=("binutils (objcopy)")
    command -v strings >/dev/null 2>&1 || missing+=("binutils (strings)")

    if [ -x /usr/local/go/bin/go ]; then
        GO_BIN="/usr/local/go/bin/go"
    elif command -v go >/dev/null 2>&1; then
        GO_BIN="$(command -v go)"
    else
        missing+=("go")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        error_exit "Missing prerequisites: ${missing[*]}\n  Install: sudo apt install mingw-w64 nasm binutils python3 golang-go"
    fi

    info_msg "All prerequisites found"
    info_msg "  Go:     $($GO_BIN version 2>/dev/null | head -1)"
    info_msg "  MinGW:  $(x86_64-w64-mingw32-gcc --version 2>/dev/null | head -1)"
    info_msg "  NASM:   $(nasm --version 2>/dev/null | head -1)"
}

## ========= [ GOEXPERIMENT auto-detection ] =========

detect_goexperiment() {
    local server_bin="$SERVER_DIR/adaptixserver"
    if [ ! -f "$server_bin" ]; then
        warning_msg "adaptixserver binary not found - building without GOEXPERIMENT"
        GOEXPERIMENT=""
        return
    fi

    local version_line
    version_line=$($GO_BIN version "$server_bin" 2>/dev/null | head -1)

    if echo "$version_line" | grep -qP 'X:'; then
        GOEXPERIMENT=$(echo "$version_line" | grep -oP '(?<=X:)\S+')
        info_msg "Detected GOEXPERIMENT=$GOEXPERIMENT  (from $(basename "$server_bin"))"
    else
        GOEXPERIMENT=""
        info_msg "Server built without GOEXPERIMENT (plain $(echo "$version_line" | grep -oP 'go\d+\.\d+\.\d+'))"
    fi
}

## ========= [ Go version detection from server binary ] =========

detect_go_version() {
    local server_bin="$SERVER_DIR/adaptixserver"
    if [ ! -f "$server_bin" ]; then
        warning_msg "adaptixserver binary not found - cannot detect Go version"
        return
    fi

    local version_line
    version_line=$(strings "$server_bin" 2>/dev/null | grep -oP '^go\d+\.\d+\.\d+' | head -1)

    if [ -z "$version_line" ]; then
        warning_msg "Could not detect Go version from adaptixserver binary"
        return
    fi

    SERVER_GO_VERSION="${version_line#go}"
    info_msg "Detected server Go version: $SERVER_GO_VERSION"

    local local_go_version
    local_go_version=$($GO_BIN version 2>/dev/null | grep -oP 'go\d+\.\d+\.\d+' | head -1)
    local_go_version="${local_go_version#go}"

    if [ "$local_go_version" != "$SERVER_GO_VERSION" ]; then
        warning_msg "Go version MISMATCH: local=$local_go_version server=$SERVER_GO_VERSION"
        warning_msg "Plugins may fail to load. Install go$SERVER_GO_VERSION to match."
    else
        info_msg "Go version match: $local_go_version"
    fi
}

## ========= [ Adaptix source auto-discovery ] =========

find_adaptix_src() {
    if [ -n "$ADAPTIX_SRC" ] && [ -f "$ADAPTIX_SRC/AdaptixServer/go.mod" ]; then
        return
    fi
    if [ -n "$ADAPTIX_SRC" ] && [ -f "$ADAPTIX_SRC/go.mod" ]; then
        ADAPTIX_SRC="$(dirname "$ADAPTIX_SRC")"
        return
    fi

    local search_paths=(
        "/opt/post-exploitation/Original/AdaptixC2"
        "$(dirname "$NAX_ROOT")/Original/AdaptixC2"
        "$(dirname "$(dirname "$NAX_ROOT")")/AdaptixC2"
        "$HOME/AdaptixC2"
    )

    for path in "${search_paths[@]}"; do
        if [ -f "$path/AdaptixServer/go.mod" ]; then
            ADAPTIX_SRC="$path"
            info_msg "Found Adaptix source at: $ADAPTIX_SRC"
            return
        fi
    done

    warning_msg "Adaptix source not found. Use --adaptix-src to specify location."
    warning_msg "Module sync will use binary inspection only (less reliable)."
}

## ========= [ axc2 module detection ] =========

detect_axc2_module() {
    local server_bin="$SERVER_DIR/adaptixserver"
    if [ -f "$server_bin" ]; then
        local mod_info
        mod_info=$($GO_BIN version -m "$server_bin" 2>/dev/null | grep 'github.com/Adaptix-Framework/axc2')
        if [ -n "$mod_info" ]; then
            SERVER_AXC2_MODULE=$(echo "$mod_info" | awk '{print $2}')
            SERVER_AXC2_VERSION=$(echo "$mod_info" | awk '{print $3}')
            if [ -n "$SERVER_AXC2_MODULE" ] && [ -n "$SERVER_AXC2_VERSION" ]; then
                info_msg "Detected axc2 module: $SERVER_AXC2_MODULE@$SERVER_AXC2_VERSION (from binary)"
                return
            fi
        fi
    fi

    local server_gomod=""
    if [ -n "$ADAPTIX_SRC" ] && [ -f "$ADAPTIX_SRC/AdaptixServer/go.mod" ]; then
        server_gomod="$ADAPTIX_SRC/AdaptixServer/go.mod"
    fi

    if [ -n "$server_gomod" ]; then
        local axc2_line
        axc2_line=$(grep 'github.com/Adaptix-Framework/axc2' "$server_gomod" | grep -v '//' | head -1)

        if [ -n "$axc2_line" ]; then
            SERVER_AXC2_MODULE=$(echo "$axc2_line" | awk '{print $1}')
            SERVER_AXC2_VERSION=$(echo "$axc2_line" | awk '{print $2}')
            warning_msg "Using axc2 from go.mod (no binary): $SERVER_AXC2_MODULE@$SERVER_AXC2_VERSION"
            return
        fi
    fi

    warning_msg "Could not detect axc2 module version"
}

## ========= [ Go module sync ] =========

sync_go_modules() {
    find_go
    find_adaptix_src
    detect_axc2_module
    detect_go_version

    if [ -z "$SERVER_AXC2_MODULE" ] || [ -z "$SERVER_AXC2_VERSION" ]; then
        error_exit "Cannot sync: unable to determine server's axc2 module version.\n  Use --adaptix-src to point to AdaptixC2 source tree."
    fi

    local go_directive="${SERVER_GO_VERSION:-1.26.5}"

    step_msg "Syncing plugin go.mod files to: $SERVER_AXC2_MODULE@$SERVER_AXC2_VERSION (go $go_directive)"

    local plugin_dirs=(
        "$NAX_ROOT/src_server/agent_nonameax"
        "$NAX_ROOT/src_server/listener_nonameax_http"
        "$NAX_ROOT/src_server/listener_nonameax_smb"
        "$NAX_ROOT/src_server/service_nax_store"
    )

    for dir in "${plugin_dirs[@]}"; do
        local plugin_name
        plugin_name=$(basename "$dir")

        if [ ! -f "$dir/go.mod" ]; then
            warning_msg "Skipping $plugin_name: no go.mod"
            continue
        fi

        step_msg "  Syncing $plugin_name..."

        local current_module
        current_module=$(grep -oP 'github\.com/Adaptix-Framework/axc2(/v\d+)?' "$dir/go.mod" | head -1)
        local current_version
        current_version=$(grep 'github.com/Adaptix-Framework/axc2' "$dir/go.mod" | grep -v '//' | head -1 | grep -oP 'v\d+\.\d+\.\d+')

        if [ "$current_module" = "$SERVER_AXC2_MODULE" ] && [ "$current_version" = "$SERVER_AXC2_VERSION" ]; then
            info_msg "    $plugin_name already up-to-date"
            continue
        fi

        sed -i "s|^go .*|go $go_directive|" "$dir/go.mod"

        if [ -n "$current_module" ] && [ "$current_module" != "$SERVER_AXC2_MODULE" ]; then
            info_msg "    Import path change: $current_module → $SERVER_AXC2_MODULE"

            find "$dir" -name '*.go' -exec sed -i "s|\"$current_module\"|\"$SERVER_AXC2_MODULE\"|g" {} \;
            info_msg "    Patched import paths in .go files"
        fi

        sed -i "s|^go .*|go $go_directive|" "$dir/go.mod"
        sed -i "s|$current_module $current_version|$SERVER_AXC2_MODULE $SERVER_AXC2_VERSION|" "$dir/go.mod"

        (cd "$dir" && $GO_BIN get "$SERVER_AXC2_MODULE@$SERVER_AXC2_VERSION" 2>/dev/null)
        (cd "$dir" && $GO_BIN mod tidy 2>/dev/null)

        info_msg "    $plugin_name synced ✓"
    done

    info_msg "Module sync complete"
}

## ========= [ find Go binary ] =========

find_go() {
    if [ -n "$GO_BIN" ]; then
        return
    fi
    if [ -x /usr/local/go/bin/go ]; then
        GO_BIN="/usr/local/go/bin/go"
    elif command -v go >/dev/null 2>&1; then
        GO_BIN="$(command -v go)"
    else
        error_exit "Go compiler not found. Install Go and re-run."
    fi
}

## ========= [ build + deploy functions ] =========

build_deploy_agent() {
    local dest="$EXTENDERS_DIR/agent_nonameax"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Building agent_nonameax plugin..."
    make -C "$NAX_ROOT/src_server" agent \
        SERVER_DIR="$SERVER_DIR" \
        GOEXPERIMENT="$GOEXPERIMENT" \
        GO="$GO_BIN" \
        || error_exit "Failed to build agent plugin"

    echo "$NAX_ROOT" > "$dest/nax_root.conf"
    cp -r "$NAX_ROOT/src_server/agent_nonameax/pe_templates" "$dest/pe_templates" 2>/dev/null || true
    info_msg "Agent deployed to $dest"
    info_msg "  nax_root.conf -> $NAX_ROOT"
}

build_deploy_listener_http() {
    local dest="$EXTENDERS_DIR/listener_nonameax_http"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Building listener_nonameax_http plugin..."
    make -C "$NAX_ROOT/src_server" listener \
        SERVER_DIR="$SERVER_DIR" \
        GOEXPERIMENT="$GOEXPERIMENT" \
        GO="$GO_BIN" \
        || error_exit "Failed to build HTTP listener plugin"

    info_msg "HTTP listener deployed to $dest"
}

build_deploy_listener_smb() {
    local dest="$EXTENDERS_DIR/listener_nonameax_smb"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Building listener_nonameax_smb plugin..."
    make -C "$NAX_ROOT/src_server" listener-smb \
        SERVER_DIR="$SERVER_DIR" \
        GOEXPERIMENT="$GOEXPERIMENT" \
        GO="$GO_BIN" \
        || error_exit "Failed to build SMB listener plugin"

    info_msg "SMB listener deployed to $dest"
}

build_deploy_service() {
    local dest="$EXTENDERS_DIR/service_nax_store"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Building nax_store service plugin..."
    make -C "$NAX_ROOT/src_server" service \
        SERVER_DIR="$SERVER_DIR" \
        GOEXPERIMENT="$GOEXPERIMENT" \
        GO="$GO_BIN" \
        || error_exit "Failed to build service plugin"

    info_msg "Service deployed to $dest"
}

build_deploy_all() {
    build_deploy_agent
    build_deploy_listener_http
    build_deploy_listener_smb
    build_deploy_service
}

## ========= [ deploy-only functions (no build) ] =========

deploy_agent() {
    local dest="$EXTENDERS_DIR/agent_nonameax"
    local src="$NAX_ROOT/src_server/agent_nonameax"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Deploying agent_nonameax configs..."
    cp "$src/ax_config.axs" "$dest/ax_config.axs"
    cp "$src/config.yaml"   "$dest/config.yaml"
    cp -r "$src/pe_templates" "$dest/pe_templates" 2>/dev/null || true
    echo "$NAX_ROOT" > "$dest/nax_root.conf"
    info_msg "Agent configs deployed to $dest"
}

deploy_listener_http() {
    local dest="$EXTENDERS_DIR/listener_nonameax_http"
    local src="$NAX_ROOT/src_server/listener_nonameax_http"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Deploying listener_nonameax_http configs..."
    cp "$src/ax_config.axs" "$dest/ax_config.axs"
    cp "$src/config.yaml"   "$dest/config.yaml"
    info_msg "HTTP listener configs deployed to $dest"
}

deploy_listener_smb() {
    local dest="$EXTENDERS_DIR/listener_nonameax_smb"
    local src="$NAX_ROOT/src_server/listener_nonameax_smb"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Deploying listener_nonameax_smb configs..."
    cp "$src/ax_config.axs" "$dest/ax_config.axs"
    cp "$src/config.yaml"   "$dest/config.yaml"
    info_msg "SMB listener configs deployed to $dest"
}

deploy_service() {
    local dest="$EXTENDERS_DIR/service_nax_store"
    local src="$NAX_ROOT/src_server/service_nax_store"
    mkdir -p "$dest" || error_exit "Failed to create $dest"

    step_msg "Deploying nax_store service configs..."
    cp "$src/ax_config.axs" "$dest/ax_config.axs"
    cp "$src/config.yaml"   "$dest/config.yaml"
    info_msg "Service configs deployed to $dest"
}

deploy_all() {
    deploy_agent
    deploy_listener_http
    deploy_listener_smb
    deploy_service
}

## ========= [ profile.yaml registration ] =========

add_to_profile() {
    local yaml="$SERVER_DIR/profile.yaml"
    if [ ! -f "$yaml" ]; then
        warning_msg "profile.yaml not found - skipping auto-registration"
        return
    fi

    local entries=(
        "extenders/agent_nonameax/config.yaml"
        "extenders/listener_nonameax_http/config.yaml"
        "extenders/listener_nonameax_smb/config.yaml"
        "extenders/service_nax_store/config.yaml"
    )
    local changed=false

    for entry in "${entries[@]}"; do
        if ! grep -qF "$entry" "$yaml"; then
            sed -i "/^  extenders:/a\\    - \"$entry\"" "$yaml"
            info_msg "Registered $entry in profile.yaml"
            changed=true
        fi
    done

    if [ "$changed" = false ]; then
        info_msg "NaX extenders already registered in profile.yaml"
    fi
}

## ========= [ summary ] =========

print_summary() {
    echo ""
    info_msg "Done!"
    echo "================================================================"
    echo "  Action:       $ACTION"
    echo "  NaX Source:   $NAX_ROOT"
    echo "  Server:       $SERVER_DIR"
    echo "  Adaptix Src:  ${ADAPTIX_SRC:-not specified}"
    echo "  GOEXPERIMENT: ${GOEXPERIMENT:-n/a}"
    echo "  Go (local):   ${GO_BIN:-n/a}"
    echo "  Go (server):  ${SERVER_GO_VERSION:-n/a}"
    echo "  axc2 module:  ${SERVER_AXC2_MODULE:-n/a}@${SERVER_AXC2_VERSION:-n/a}"
    echo ""
    echo "  Deployed extenders:"
    [ -f "$EXTENDERS_DIR/agent_nonameax/agent_nonameax.so" ]              && echo "    - agent_nonameax"
    [ -f "$EXTENDERS_DIR/listener_nonameax_http/listener_nonameax_http.so" ] && echo "    - listener_nonameax_http"
    [ -f "$EXTENDERS_DIR/listener_nonameax_smb/listener_nonameax_smb.so" ]   && echo "    - listener_nonameax_smb"
    [ -f "$EXTENDERS_DIR/service_nax_store/nax_store.so" ]                   && echo "    - service_nax_store"
    echo ""
    echo "  Restart adaptixserver to load the new extenders."
    echo "================================================================"
}

## ========= [ main dispatch ] =========

case $ACTION in
    all)
        check_prereqs
        detect_goexperiment
        sync_go_modules
        step_msg "Full install: all 4 plugins"
        build_deploy_all
        add_to_profile
        print_summary
        ;;
    plugins)
        find_go
        detect_goexperiment
        sync_go_modules
        step_msg "Building all 4 plugins (skipping prereq check)"
        build_deploy_all
        add_to_profile
        print_summary
        ;;
    agent)
        find_go
        detect_goexperiment
        sync_go_modules
        build_deploy_agent
        add_to_profile
        print_summary
        ;;
    listener-http)
        find_go
        detect_goexperiment
        sync_go_modules
        build_deploy_listener_http
        add_to_profile
        print_summary
        ;;
    listener-smb)
        find_go
        detect_goexperiment
        sync_go_modules
        build_deploy_listener_smb
        add_to_profile
        print_summary
        ;;
    service)
        find_go
        detect_goexperiment
        sync_go_modules
        build_deploy_service
        add_to_profile
        print_summary
        ;;
    deploy)
        step_msg "Deploy only: copying configs, axscripts, and templates (no build)"
        deploy_all
        add_to_profile
        print_summary
        ;;
    sync)
        find_go
        detect_goexperiment
        sync_go_modules
        ;;
    prereqs)
        check_prereqs
        detect_goexperiment
        ;;
    *)
        error_exit "Unknown action: $ACTION\nRun $0 --help for usage."
        ;;
esac
