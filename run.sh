#!/bin/bash
# Bell-LaPadula App — Setup & Run Script

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Bell-LaPadula Security Model — Setup    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required. Install from https://python.org"
    exit 1
fi
echo "✓ Python $(python3 --version)"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "→ Creating virtual environment..."
    python3 -m venv venv
fi

# Activate
source venv/bin/activate

# Install deps
echo "→ Installing dependencies..."
pip install -q -r requirements.txt

echo ""
echo "✓ Setup complete!"
echo ""
echo "→ Starting server at http://localhost:5000"
echo ""

python3 app.py
