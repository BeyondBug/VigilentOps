#!/bin/bash
# SecureGuard — Full setup on Kali Linux
# Run once with internet: bash setup-kali.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     SecureGuard — Kali Linux Setup   ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── 1. Docker ────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    sudo apt-get update -qq
    sudo apt-get install -y docker.io docker-compose-plugin
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker "$USER"
    warn "Docker installed. You may need to log out and back in for group changes."
else
    info "Docker already installed: $(docker --version)"
fi

# ── 2. Python venv + scanner tools ──────────────────────────
info "Setting up Python virtual environment..."
python3 -m venv ~/secureguard/venv
source ~/secureguard/venv/bin/activate

info "Installing Python scanner tools inside venv..."
pip install --quiet semgrep bandit

info "Semgrep: $(semgrep --version)"
info "Bandit:  $(bandit --version 2>&1 | head -1)"

# Auto-activate venv on every terminal open
if ! grep -q "secureguard/venv/bin/activate" ~/.bashrc; then
    echo "source ~/secureguard/venv/bin/activate" >> ~/.bashrc
    info "Added venv auto-activation to ~/.bashrc"
else
    info "venv auto-activation already in ~/.bashrc"
fi

# ── 3. Trivy ────────────────────────────────────────────────
if ! command -v trivy &>/dev/null; then
    info "Installing Trivy..."
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sudo sh -s -- -b /usr/local/bin
    info "Trivy: $(trivy --version | head -1)"
else
    info "Trivy already installed: $(trivy --version | head -1)"
fi

# ── 4. Gitleaks ─────────────────────────────────────────────
if ! command -v gitleaks &>/dev/null; then
    info "Installing Gitleaks..."
    GITLEAKS_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | grep tag_name | cut -d'"' -f4)
    curl -sSfL \
        "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER#v}_linux_x64.tar.gz" \
        | sudo tar -xz -C /usr/local/bin gitleaks
    info "Gitleaks: $(gitleaks version)"
else
    info "Gitleaks already installed: $(gitleaks version)"
fi

# ── 5. Pull Docker images ────────────────────────────────────
info "Pulling Docker images (this takes a few minutes)..."
docker pull gitea/gitea:latest
docker pull postgres:15-alpine
docker pull redis:7-alpine
docker pull jenkins/jenkins:lts
docker pull prom/prometheus:latest
docker pull grafana/grafana:latest
docker pull returntocorp/semgrep:latest
docker pull aquasec/trivy:latest
docker pull zricethezav/gitleaks:latest
info "All Docker images pulled."

# ── 6. Create .env if missing ────────────────────────────────
#if [ ! -f ~/secureguard/.env ]; then
#    [ ! -f ~/secureguard/.env ] && cp ~/secureguard/.env.example ~/secureguard/.env || echo "INFO: .env already exists, skipping"
#    warn ".env created from template — edit it before running docker compose!"
#else
#    info ".env already exists — skipping."
#fi

# ── 7. Done ──────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Setup Complete ✓                        ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Next steps:                                         ║"
echo "║                                                      ║"
echo "║  1. Edit credentials:                                ║"
echo "║     nano ~/secureguard/.env                          ║"
echo "║                                                      ║"
echo "║  2. Start the stack:                                 ║"
echo "║     cd ~/secureguard && docker compose up -d         ║"
echo "║                                                      ║"
echo "║  3. Access services:                                 ║"
echo "║     Gitea      → http://localhost:3000               ║"
echo "║     Jenkins    → http://localhost:8080               ║"
echo "║     API docs   → http://localhost:8000/docs          ║"
echo "║     Dashboard  → http://localhost:3001               ║"
echo "║     Grafana    → http://localhost:3002               ║"
echo "║     Prometheus → http://localhost:9090               ║"
echo "║                                                      ║"
echo "║  4. Configure Gitea webhook:                         ║"
echo "║     URL: http://orchestrator:8000/webhook/gitea      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
