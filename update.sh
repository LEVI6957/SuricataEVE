#!/usr/bin/env bash
# =============================================================================
#  update.sh — Update Suricata Auto Block Dashboard
#  Author  : Levi (github.com/LEVI6957)
#  Updates local code from git, rebuilds docker images, and restarts services.
#  Usage: sudo bash update.sh
# =============================================================================
set -uo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${NC}\n"; }

# ── Root Check ───────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run with sudo: sudo bash update.sh"

INSTALL_DIR="/opt/suricata-dashboard"

# If script is run from repo source (not installed location), just copy files
# Otherwise, pull from git if it's a git repo.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ══════════════════════════════════════════════════════════════════════════════
header "1. Update Codebase"
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$SCRIPT_DIR" == "$INSTALL_DIR" ]]; then
    # Running from installed location
    if [ -d ".git" ]; then
        info "Pulling latest changes from git..."
        git fetch origin
        git reset --hard origin/main
        success "Code updated from git."
    else
        warn "Not a git repository."
    fi
else
    # Running from source directory (e.g. ~/SuricataEVE)
    # Use rsync to safely copy files without overwriting configs/data
    if command -v rsync &>/dev/null; then
        info "Syncing files to ${INSTALL_DIR} (excluding configs/logs)..."
        rsync -av --no-perms --exclude='.env' \
             --exclude='dashboard/settings.json' \
             --exclude='dashboard/whitelist.json' \
             --exclude='logs/' \
             --exclude='auto_block/blocked_ips.log' \
             --exclude='auto_block/alert_counts.json' \
             --exclude='.git/' \
             . "$INSTALL_DIR/"
        success "Files synced."
    else
        warn "rsync not found, installing..."
        apt-get install -y -qq rsync
        info "Syncing files..."
        rsync -av --no-perms --exclude='.env' \
             --exclude='dashboard/settings.json' \
             --exclude='dashboard/whitelist.json' \
             --exclude='logs/' \
             --exclude='auto_block/blocked_ips.log' \
             --exclude='auto_block/alert_counts.json' \
             --exclude='.git/' \
             . "$INSTALL_DIR/"
        success "Files synced."
    fi
    
    # Ensure scripts are executable
    chmod +x "$INSTALL_DIR/"*.sh
fi

cd "$INSTALL_DIR" || error "Failed to cd to ${INSTALL_DIR}"

# ══════════════════════════════════════════════════════════════════════════════
header "2. Fix Permissions & Restart"
# ══════════════════════════════════════════════════════════════════════════════

# Hapus kontainer manual yang bentrok (jika user pernah menjalankan dari ~/SuricataEVE)
info "Membersihkan kontainer lama yang berpotensi bentrok..."
for cname in suricata_main evebox_ui auto_block suricata_dashboard; do
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${cname}$"; then
        docker rm -f "$cname" >/dev/null 2>&1 || true
    fi
done

# Fix permissions on logs directory so EveBox (non-root) can access it
if [ -d "logs" ]; then
    info "Fixing permissions for logs directory..."
    chmod -R 755 logs
    chmod 644 logs/eve.json 2>/dev/null || touch logs/eve.json && chmod 644 logs/eve.json
fi

# Pastikan file-file yang di-mount ada sebagai file (mencegah Docker membuatnya sebagai direktori)
for f in "dashboard/settings.json" "dashboard/whitelist.json" "auto_block/alert_counts.json" "auto_block/blocked_ips.log"; do
    if [[ -d "$f" ]]; then
        rm -rf "$f"
    fi
    if [[ ! -f "$f" ]]; then
        mkdir -p "$(dirname "$f")"
        if [[ "$f" == "dashboard/whitelist.json" ]]; then
            echo "[]" > "$f"
        elif [[ "$f" == "dashboard/settings.json" ]]; then
            echo '{"webhook_url":"","threshold":3,"severity":2,"interval":10}' > "$f"
        elif [[ "$f" == "auto_block/alert_counts.json" ]]; then
            echo "{}" > "$f"
        else
            touch "$f"
        fi
    fi
done

info "Rebuilding images (with cache to speed up)..."
docker compose build

info "Restarting services..."
docker compose up -d --remove-orphans

# ══════════════════════════════════════════════════════════════════════════════
header "3. Cleanup"
# ══════════════════════════════════════════════════════════════════════════════

info "Cleaning up unused docker images (dangling)..."
docker image prune -f

echo ""
header "✅ Update Complete!"
echo -e "  🛡️  ${BOLD}Dashboard${NC}  : ${CYAN}http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT:-8080}${NC}"
echo -e "  📊  ${BOLD}EveBox${NC}     : ${CYAN}http://$(hostname -I | awk '{print $1}'):5636${NC}"
echo ""
