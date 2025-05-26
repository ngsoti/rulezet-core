#!/bin/bash

# Configuration variables
DB_USER="theo"
DB_PASSWORD="circl"
DB_NAME="rulezet"

echo "🔧 Updating packages and installing PostgreSQL..."
sudo apt update
sudo apt install -y postgresql postgresql-contrib

echo "👤 Creating PostgreSQL user if it doesn't exist..."
sudo -u postgres psql -c "DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
      CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
   END IF;
END
\$\$;"

echo "Creating the database..."
sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"

echo "Granting privileges to the user..."
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"


echo "/ PostgreSQL is now ready for your Flask app!"
echo "Use this in your Flask config:"
echo "   SQLALCHEMY_DATABASE_URI = 'postgresql://${DB_USER}:${DB_PASSWORD}@localhost/${DB_NAME}'"
