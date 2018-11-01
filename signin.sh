#!/usr/bin/env bash -x
EMAIL=$1
PASSWORD=$2
API_KEY=$(cat .api_key)
curl "https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key=${API_KEY}" \
-H 'Content-Type: application/json' \
--data-binary "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"returnSecureToken\":true}"
