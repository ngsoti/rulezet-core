#!/bin/bash

set -e

# --- Config ---
DB_NAME="rulezet"
DB_USER="$(whoami)"

# Detect project root (Rulezet-core)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

BACKUP_DIR="$PROJECT_ROOT/backup/dumps"

# Create directory if missing
mkdir -p "$BACKUP_DIR"

DATE=$(date +%Y-%m-%d_%H-%M)

echo "Creating backup for database '$DB_NAME'..."
pg_dump -U "$DB_USER" -F c "$DB_NAME" > "$BACKUP_DIR/rulezet_$DATE.dump"

echo "Backup saved to $BACKUP_DIR/rulezet_$DATE.dump"
