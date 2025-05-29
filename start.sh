#!/bin/bash
set -e

echo "Starting application initialization..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:/app"
export TRANSFORMERS_CACHE="/tmp/transformers_cache"
export TORCH_HOME="/tmp/torch_cache"

# Create cache directories
mkdir -p "$TRANSFORMERS_CACHE"
mkdir -p "$TORCH_HOME"

# Wait for database to be ready
echo "Waiting for database..."
sleep 5

# Create database tables
echo "Creating database tables..."
python /app/create_db.py || echo "Database tables already exist"

# Initialize Flask-Migrate
echo "Initializing migrations..."
if [ ! -d "migrations" ]; then
    flask db init
fi

# Run database migrations
echo "Running database migrations..."
flask db migrate -m "Initial migration" || echo "No migrations needed"
flask db upgrade || echo "No upgrades needed"

# Start the application with gunicorn
echo "Starting application..."
exec gunicorn app:app \
    --log-level debug \
    --timeout 120 \
    --workers 2 \
    --threads 2 \
    --bind 0.0.0.0:$PORT \
    --access-logfile - \
    --error-logfile - 
