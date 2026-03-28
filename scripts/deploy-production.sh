#!/bin/bash
# ============================================================
#  Paperclip Deployment Script for DigitalOcean
#  Run on: nanoclaw-prod-01 (68.183.126.50) or any Docker host
#
#  Usage: curl -sSL https://raw.githubusercontent.com/ScaledByDesign/paperclip/master/deploy-paperclip.sh | bash
#     OR: ssh root@68.183.126.50 'bash -s' < deploy-paperclip.sh
# ============================================================
set -euo pipefail

echo "========================================="
echo "  Paperclip Deployment — ScaledByDesign"
echo "========================================="

# ── Pre-flight checks ──
echo "[1/6] Checking prerequisites..."
command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker not found. Install Docker first."; exit 1; }
command -v git    >/dev/null 2>&1 || { apt-get update -y && apt-get install -y git; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: Docker Compose V2 not found."; exit 1; }

echo "  Docker: $(docker --version)"
echo "  Compose: $(docker compose version)"
echo "  Disk: $(df -h / | awk 'NR==2{print $4}') free"
echo "  RAM: $(free -h | awk 'NR==2{print $7}') available"

# ── Clone repo ──
echo ""
echo "[2/6] Cloning ScaledByDesign/paperclip..."
DEPLOY_DIR="/opt/paperclip"
if [ -d "$DEPLOY_DIR" ]; then
  echo "  Directory exists, pulling latest..."
  cd "$DEPLOY_DIR" && git pull origin master
else
  git clone https://github.com/ScaledByDesign/paperclip.git "$DEPLOY_DIR"
  cd "$DEPLOY_DIR"
fi

# ── Detect public IP ──
echo ""
echo "[3/6] Detecting public IP..."
DROPLET_IP=$(curl -s --max-time 5 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || \
             curl -s --max-time 5 https://ifconfig.me 2>/dev/null || \
             hostname -I | awk '{print $1}')
echo "  Public IP: $DROPLET_IP"

# ── Create .env ──
echo ""
echo "[4/6] Creating environment config..."
AUTH_SECRET="sbd-paperclip-auth-$(openssl rand -hex 16)"
cat > .env << ENVEOF
POSTGRES_PASSWORD=paperclip_sbd_2026
PAPERCLIP_PUBLIC_URL=http://${DROPLET_IP}:3100
BETTER_AUTH_SECRET=${AUTH_SECRET}
ENVEOF
echo "  .env created"

# ── Build and deploy ──
echo ""
echo "[5/6] Building and deploying (this takes 3-5 minutes)..."
docker compose -f docker-compose.production.yml up -d --build 2>&1 | tail -20

# ── Verify ──
echo ""
echo "[6/6] Verifying deployment..."
sleep 10  # Wait for services to start

docker compose -f docker-compose.production.yml ps

echo ""
echo "========================================="
echo "  Deployment complete!"
echo ""
echo "  Paperclip URL: http://${DROPLET_IP}:3100"
echo "  Postgres: paperclip_sbd_2026@db:5432/paperclip"
echo "  Auth Secret: ${AUTH_SECRET}"
echo ""
echo "  Check logs: cd /opt/paperclip && docker compose -f docker-compose.production.yml logs -f"
echo "========================================="
