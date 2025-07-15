#!/bin/bash

# ==============================================
# PostgreSQL Installation Script (Ubuntu/Debian)
# ==============================================

set -e # Exit on error

# Customizable variables
DB_NAME="rulezet"
# Current user and password
DB_USER=$(whoami)
DB_PASSWORD=default_password

echo "Checking if PostgreSQL is already installed..."
if ! command -v psql > /dev/null; then
    echo "Installing PostgreSQL..."
    sudo apt update
    sudo apt install -y postgresql postgresql-contrib
else
    echo "PostgreSQL is already installed."
fi

echo "Starting and enabling PostgreSQL service..."
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Create the user if it doesn't exist
echo "Creating user '$DB_USER' (if not exists)..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"

# Create the database if it doesn't exist
echo "Creating database '$DB_NAME' (if not exists)..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

# Optional: give user permission to create databases
sudo -u postgres psql -c "ALTER USER $DB_USER CREATEDB;"

# Result
echo "PostgreSQL successfully installed and configured!"
echo "Connection string (with password):psql postgresql://$DB_USER:$DB_PASSWORD@localhost/$DB_NAME or (with superUser): psql postgresql:///$DB_NAME"
