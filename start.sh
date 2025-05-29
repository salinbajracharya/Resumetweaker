#!/bin/bash
set -e

echo "🔧 Starting application initialization..."

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:/opt/render/project/src"
export TRANSFORMERS_CACHE="/tmp/transformers_cache"
export TORCH_HOME="/tmp/torch_cache"

# Create cache directories (safe even if already exist)
mkdir -p "$TRANSFORMERS_CACHE" "$TORCH_HOME"

# Wait for the database (optional delay)
echo "⏳ Waiting for database to initialize..."
sleep 5

# Run create_db script (optional fallback if tables don't exist)
echo "🗄️ Creating database tables (if not already created)..."
python create_db.py || echo "✔️ Tables likely already exist"

# Run migrations
echo "📦 Running Flask-Migrate upgrade..."
flask db upgrade || echo "✔️ No pending migrations"

# Launch the app
echo "🚀 Starting Gunicorn server..."
exec gunico
