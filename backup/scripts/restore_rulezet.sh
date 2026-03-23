#!/bin/bash

set -e

# --- Config ---
DB_NAME="rulezet"
DB_USER="$(whoami)"


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

BACKUP_DIR="$PROJECT_ROOT/backup/dumps"


if [ -z "$1" ]; then
  echo "Usage: $0 <backup_filename>"
  echo "Example: $0 rulezet_2025-11-18_15-18.dump"
  exit 1
fi

BACKUP_FILE="$BACKUP_DIR/$1"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "Error: backup file '$BACKUP_FILE' not found in $BACKUP_DIR!"
  exit 1
fi

echo "Starting restoration of database '$DB_NAME' from '$BACKUP_FILE'..."


echo "Dropping existing database '$DB_NAME'..."
dropdb -U "$DB_USER" --if-exists "$DB_NAME"


echo "Creating new empty database '$DB_NAME'..."
createdb -U "$DB_USER" "$DB_NAME"


echo "Restoring backup..."
pg_restore -U "$DB_USER" -d "$DB_NAME" "$BACKUP_FILE"

echo "Database '$DB_NAME' successfully restored from '$BACKUP_FILE'."
