# scripts/setup/initialize.sh

#!/bin/bash

# Initialize development environment
echo "Initializing Sentinel Optimization Toolkit..."

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up configuration
# Ensure config directory exists; copy examples if it's empty or specific files are missing.
# This is a more robust way to handle example configs.
if [ ! -d "config" ] || [ -z "$(ls -A config)" ]; then
    mkdir -p config
    echo "Copying example configurations..."
    cp config/examples/* config/
else
    echo "Config directory already exists and is not empty. Skipping example copy."
fi

# Set up logging
mkdir -p logs

echo "Setup complete!"