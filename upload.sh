#!/usr/bin/env bash
BASE_URL=http://localhost:9999
EMAIL=$1
PASSWORD=$2
FILE1=$3
token=$(curl -s -X POST \
-H "Content-Type: application/json" \
--data-binary "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\"}" \
$BASE_URL/login | jq -r '.token')
if [[ "$token" != "null" ]]
then
    curl\
    -H "Content-Type: multipart/form-data" \
    -H "authorization: Bearer $token" \
    -F "file1=@data/${FILE1}" \
    $BASE_URL/upload
fi
