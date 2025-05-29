#!/bin/bash

echo "Starting application initialization..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:/opt/render/project/src"
export TRANSFORMERS_CACHE="/tmp/transformers_cache"
export TORCH_HOME="/tmp/torch_cache"

# Create database tables
echo "Creating database tables..."
python create_db.py

# Run database migrations
echo "Running database migrations..."
flask db upgrade

# Start the application with gunicorn
echo "Starting application..."
exec gunicorn app:app --log-level debug --timeout 120 --workers 2 --threads 2 --bind 0.0.0.0:$PORT 