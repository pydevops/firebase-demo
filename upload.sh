#!/usr/bin/env bash
set -eu
BASE_URL=http://localhost:9999
EMAIL=$1
PASSWORD=$2
FILE1=$3
response=$(curl -s -X POST \
-H "Content-Type: application/json" \
--data-binary "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}" \
$BASE_URL/login)
echo $response
token=$(echo $response | jq -r '.token')
if [[ "$token" != "null" ]]
then
    echo "decode the JWT token"
    echo $token| awk -F. '{print $2}' | base64 --decode
    echo
    curl\
    -H "Content-Type: multipart/form-data" \
    -H "Authorization: Bearer $token" \
    -F "file1=@data/${FILE1}" \
    $BASE_URL/upload

    seconds=25
    echo "wait for $seconds seconds to test token expiry"
    sleep $seconds 
    # testing the token expiry 
    curl\
    -H "Content-Type: multipart/form-data" \
    -H "Authorization: Bearer $token" \
    -F "file1=@data/${FILE1}" \
    $BASE_URL/upload
fi
