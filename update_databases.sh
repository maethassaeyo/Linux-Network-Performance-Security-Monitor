#!/bin/bash

# Configuration
DATA_DIR="data"
GEOIP_URL="https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
BLACKLIST_URL="https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

# Ensure data directory exists
mkdir -p "$DATA_DIR"

echo "--- Updating Network Monitor Databases ---"

# 1. Update GeoIP Database
echo "[1/2] Downloading latest GeoIP database..."
curl -L "$GEOIP_URL" -o "$DATA_DIR/GeoLite2-Country.mmdb"
if [ $? -eq 0 ]; then
    echo "✅ GeoIP database updated successfully."
else
    echo "❌ Failed to download GeoIP database."
fi

# 2. Update Malicious IP Blacklist
echo "[2/2] Downloading latest Malicious IP blacklist..."
# We download and filter the ET list (ignoring comments and empty lines)
curl -sL "$BLACKLIST_URL" | grep -v '^#' | grep -v '^$' > "$DATA_DIR/blacklist.txt"
if [ $? -eq 0 ]; then
    echo "✅ Malicious IP blacklist updated successfully ($(wc -l < "$DATA_DIR/blacklist.txt") IPs)."
else
    echo "❌ Failed to download Blacklist."
fi

echo "--- Update Complete ---"
