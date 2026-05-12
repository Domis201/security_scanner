#!/bin/bash
set -e

echo "================================================"
echo "  Tinklo Saugumo Skeneris — Instaliavimas"
echo "================================================"
echo ""

# Docker check / install
if ! command -v docker &> /dev/null; then
    echo "[1/5] Docker nerastas. Diegiamas..."
    apt-get update
    apt-get install -y docker.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
else
    echo "[1/5] Docker jau idiegtas."
fi

# Docker Compose check
if ! docker compose version &> /dev/null; then
    echo "[2/5] Docker Compose nerastas. Diegiamas..."
    apt-get install -y docker-compose-plugin
else
    echo "[2/5] Docker Compose jau idiegtas."
fi

# .env file
echo ""
echo "[3/5] Konfiguracija"
if [ ! -f .env ]; then
    read -p "El. pastas (slaptazodzio atkurimui, arba Enter praleisti): " EMAIL
    read -p "Gmail App Password (arba Enter praleisti): " APP_PASS
    echo "EMAIL_HOST_USER=${EMAIL}" > .env
    echo "EMAIL_HOST_PASSWORD=${APP_PASS}" >> .env
    echo ".env failas sukurtas."
else
    echo ".env jau egzistuoja."
fi

# Build & start
echo ""
echo "[4/5] Paleidžiami konteineriai..."
docker compose up -d --build

echo ""
echo "Laukiama kol DB pasiruos (15s)..."
sleep 15

# Migrations
docker compose exec -T backend python manage.py migrate --noinput

# Admin user
echo ""
echo "[5/5] Admin vartotojo kurimas"
read -p "Admin vartotojo vardas [admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -s -p "Admin slaptazodis: " ADMIN_PASS
echo ""
read -p "Admin el. pastas: " ADMIN_EMAIL

docker compose exec -T backend python manage.py shell -c "
from django.contrib.auth.models import User
if not User.objects.filter(username='${ADMIN_USER}').exists():
    User.objects.create_superuser('${ADMIN_USER}', '${ADMIN_EMAIL}', '${ADMIN_PASS}')
    print('Vartotojas sukurtas.')
else:
    print('Vartotojas jau egzistuoja.')
"

echo ""
echo "================================================"
echo "  Instaliavimas baigtas!"
echo "  Atsidarykite: http://localhost:3000"
echo "================================================"
