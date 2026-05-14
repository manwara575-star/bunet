#!/usr/bin/env bash
# =============================================================================
# VideoSecurity — VPS Deployment Script
# Run on the production VPS (Ubuntu 24.04)
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/manwara575-star/bunet.git"
INSTALL_DIR="/opt/videosecurity"
COMPOSE_PROJECT="videosecurity"

echo "============================================"
echo "  VideoSecurity — Production Deployment"
echo "============================================"
echo ""

# 1. Clone or pull
if [ -d "$INSTALL_DIR" ]; then
    echo "[*] Updating existing installation..."
    cd "$INSTALL_DIR"
    git fetch --all
    git reset --hard origin/main
else
    echo "[*] Cloning repository..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# 2. Check for .env
if [ ! -f ".env" ]; then
    echo ""
    echo "[!] No .env file found. Creating from template..."
    cp .env.example .env
    echo "[!] IMPORTANT: Edit /opt/videosecurity/.env with your real Bunny API keys!"
    echo "[!] Then re-run this script."
    echo ""
    echo "    nano /opt/videosecurity/.env"
    echo ""
    exit 1
fi

# 3. Build and deploy
echo "[*] Building Docker image..."
docker compose -p "$COMPOSE_PROJECT" build --no-cache

echo "[*] Stopping old containers (if any)..."
docker compose -p "$COMPOSE_PROJECT" down --remove-orphans 2>/dev/null || true

echo "[*] Starting containers..."
docker compose -p "$COMPOSE_PROJECT" up -d

# 4. Wait for health check
echo "[*] Waiting for health check..."
RETRIES=0
MAX_RETRIES=30
until curl -sf --max-time 3 http://localhost:5102/health/ready > /dev/null 2>&1; do
    RETRIES=$((RETRIES + 1))
    if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
        echo "[!] Health check failed after ${MAX_RETRIES} attempts."
        echo "[!] Check logs: docker compose -p $COMPOSE_PROJECT logs -f"
        exit 1
    fi
    sleep 2
    echo "    Waiting... ($RETRIES/$MAX_RETRIES)"
done

echo ""
echo "============================================"
echo "  ✅ VideoSecurity deployed successfully!"
echo "============================================"
echo ""
echo "  Internal URL:  http://localhost:5102"
echo "  Container:     videosecurity-web"
echo "  Data volume:   videosec-data (/data)"
echo "  Logs:          docker compose -p $COMPOSE_PROJECT logs -f"
echo ""
echo "  Next steps:"
echo "  1. Configure Nginx Proxy Manager to route"
echo "     cifm.polytronx.com → http://185.252.233.186:5102"
echo "  2. Enable SSL with Let's Encrypt in NPM"
echo "  3. Log in at https://cifm.polytronx.com/admin"
echo ""
