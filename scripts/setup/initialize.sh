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

# Ensure specific config files and directories are present
echo "Ensuring essential configurations and directories exist..."
mkdir -p config/queries
mkdir -p metrics

# Create default config files if they don't exist
# These are created after example copy, so user examples can take precedence
# but ensures the application has its needed files.

if [ ! -f "config/log_router.yaml" ]; then
    echo "Creating default config/log_router.yaml..."
    cat <<EOL > config/log_router.yaml
# Default Log Router Configuration
routes:
  - source: "DefaultSource"
    destination: "DefaultDestination"
    filters: []
    transformations: []
    retention: 30
    priority: 1
EOL
fi

if [ ! -f "config/queries/placeholder.kql" ]; then
    echo "Creating default config/queries/placeholder.kql..."
    cat <<EOL > config/queries/placeholder.kql
// Placeholder KQL Query
SecurityEvent
| where TimeGenerated > ago(1h)
| count
EOL
fi

if [ ! -f "config/hunting_queries.yaml" ]; then
    echo "Creating default config/hunting_queries.yaml..."
    cat <<EOL > config/hunting_queries.yaml
# Default Hunting Queries
hunts:
  - id: "default_hunt_001"
    name: "Default Example Hunt"
    query: |
      SecurityEvent | take 10
EOL
fi

if [ ! -f "config/detection_patterns.yaml" ]; then
    echo "Creating default config/detection_patterns.yaml..."
    cat <<EOL > config/detection_patterns.yaml
# Default Detection Patterns
patterns:
  - id: "default_pattern_001"
    name: "Default Example Pattern"
    value: "example_pattern"
EOL
fi
else
    echo "Config directory already exists and is not empty. Skipping example copy."
fi

# Set up logging
mkdir -p logs

echo "Setup complete!"