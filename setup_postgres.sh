#!/bin/bash

# === Configuration ===
DB_NAME="rulezet"
DB_USER="$USER"          # Use the current Linux user or change it manually
DB_PASSWORD="password"   # Optional: set if using password-based auth
SESSION_TABLE="flask_sessions"

# === Script Start ===

echo "🔧 Starting PostgreSQL setup..."

# 1. Create PostgreSQL user if it doesn't exist
echo "🔹 Checking if user '$DB_USER' exists..."
USER_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'")

if [ "$USER_EXISTS" != "1" ]; then
  echo "✅ Creating PostgreSQL user '$DB_USER'..."
  sudo -u postgres createuser --createdb "$DB_USER"
else
  echo "✅ User '$DB_USER' already exists."
fi

# 2. Drop the existing database
echo "🔄 Dropping database '$DB_NAME' if it exists..."
sudo -u postgres dropdb --if-exists "$DB_NAME"

# 3. Create the database owned by $DB_USER
echo "🚀 Creating database '$DB_NAME' with owner '$DB_USER'..."
sudo -u postgres createdb "$DB_NAME" -O "$DB_USER"

echo "✅ Database '$DB_NAME' created and owned by '$DB_USER'."

# Optional: Inform about next steps
echo ""
echo "   IMPORTANT: Make sure your Flask app config contains:"
echo "    SQLALCHEMY_DATABASE_URI = 'postgresql://$DB_USER@localhost/$DB_NAME'"
echo ""
