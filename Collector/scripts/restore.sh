#!/bin/bash

# Change to the directory of the script
cd "$(dirname "${BASH_SOURCE[0]}")"

# Load environment variables from .env file
if [ -f ../.env ]; then
    echo "Loading environment variables from .env"
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # Skip empty lines and comments
        if [ -z "$key" ] || [[ "$key" =~ ^# ]]; then
            continue
        fi
        # Remove leading/trailing whitespace
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs)
        # Export the variable
        export "$key=$value"
        echo "Exported $key"
    done < ../.env
else
    echo "No .env file found"
    exit 1
fi
litestream restore -o ../scar.db --config ../etc/litestream.yml $LITESTREAM_LOCAL_DB_PATH
