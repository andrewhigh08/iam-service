#!/bin/bash
set -e

echo "🚀 Starting IAM Service..."

# Переходим в корень проекта
cd "$(dirname "$0")/.."

# Проверяем docker-compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ docker-compose not found"
    exit 1
fi

# Останавливаем старые контейнеры
echo "🛑 Stopping old containers..."
docker-compose down

# Запускаем PostgreSQL
echo "🐘 Starting PostgreSQL..."
docker-compose up -d postgres

echo "⏳ Waiting for PostgreSQL..."
until docker-compose exec -T postgres pg_isready -U iam_user -d iam_db > /dev/null 2>&1; do
    sleep 1
done

# Запускаем Redis
echo "📦 Starting Redis..."
docker-compose up -d redis

echo "⏳ Waiting for Redis..."
until docker-compose exec -T redis redis-cli ping > /dev/null 2>&1; do
    sleep 1
done

echo "✅ Database ready!"
echo "🚀 Starting application..."
go run cmd/api/main.go