#!/bin/bash

set -e

TMP_DIR=$(mktemp -d)

echo -n "Email: "
read -r EMAIL
ACME_SERVER="https://acme-v02.api.letsencrypt.org/directory"

# Register the ACME account with lego
echo "Registering ACME account..."
lego --path="$TMP_DIR" \
     --email="$EMAIL" \
     --accept-tos \
     --server="$ACME_SERVER" \
     --domains none \
     --http \
     --http-timeout=1 run > /dev/null 2>&1 || true

# Find the account directory
PRIVATE_KEY=$(find "$TMP_DIR/accounts/" -type f -name "*.key" | head -n 1)
ACCOUNT_JSON=$(find "$TMP_DIR/accounts/" -type f -name "account.json" | head -n 1)

# Check if account was created
if [[ -z "$PRIVATE_KEY" || -z "$ACCOUNT_JSON" ]]; then
    echo "Error: Could not find account details. Registration may have failed."
    exit 1
fi

# Display account details
echo -e "\n🔹 Account Information:"
echo "Email: $(jq .email < "$ACCOUNT_JSON")"
echo "Reg: $(jq .registration.uri < "$ACCOUNT_JSON")"
echo "Key:"
cat "$PRIVATE_KEY"