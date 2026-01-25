#!/bin/bash
# Скрипт для полного теста
# chmod +x test.sh

# 1. Login admin
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"samdawsonbai@gmail.com","password":"AdminSecret123!"}' \
  | jq -r '.access_token')

echo "✅ Admin token: ${TOKEN:0:20}..."

# 2. List users
echo -e "\n 📋 List users:"
curl -s http://localhost:8080/api/v1/users -H "Authorization: Bearer $TOKEN" | jq '.meta'

# 3. Create user with oneTime password
echo -e "\n 👤 Create test user:"
curl -s -X POST http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "temp@test.com",
    "password": "Temp123!",
    "full_name": "Temp User",
    "role": "viewer",
    "password_type": "onetime"
  }' | jq

# 4. Login with oneTime password
echo -e "\n 🔐🔑 Login with oneTime password:"
curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"temp@test.com","password":"Temp123!"}' | jq


