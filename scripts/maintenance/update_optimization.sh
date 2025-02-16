# scripts/maintenance/update_optimization.sh

#!/bin/bash

# Update Sentinel optimization configurations and rules
echo "Updating Sentinel optimization configurations..."

# Set environment variables
source .env

# Update retention policies
echo "Updating retention policies..."
pwsh src/powershell/Set-SentinelOptimization.ps1 \
    -WorkspaceId "$WORKSPACE_ID" \
    -SubscriptionId "$SUBSCRIPTION_ID" \
    -ConfigPath "config/sentinel_optimization.yaml"

# Update log routing rules
echo "Updating log routing rules..."
python src/python/log_router/update_routes.py \
    --config "config/log_router.yaml"

# Validate configurations
echo "Validating configurations..."
python src/python/utilities/config_validator.py \
    --config-dir "config" \
    --schema-dir "src/python/utilities/schemas"

echo "Update complete!"

# scripts/maintenance/cleanup_logs.sh

#!/bin/bash

# Cleanup old logs and metrics
echo "Starting log cleanup..."

# Set variables
RETENTION_DAYS=30
LOG_DIR="logs"
METRICS_DIR="metrics"
BACKUP_DIR="backups"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Backup old logs
echo "Backing up old logs..."
find "$LOG_DIR" -type f -mtime +$RETENTION_DAYS -exec tar -rf "$BACKUP_DIR/logs_$(date +%Y%m%d).tar" {} \;

# Backup old metrics
echo "Backing up old metrics..."
find "$METRICS_DIR" -type f -mtime +$RETENTION_DAYS -exec tar -rf "$BACKUP_DIR/metrics_$(date +%Y%m%d).tar" {} \;

# Compress backups
gzip "$BACKUP_DIR"/*.tar

# Remove old files
echo "Removing old files..."
find "$LOG_DIR" -type f -mtime +$RETENTION_DAYS -delete
find "$METRICS_DIR" -type f -mtime +$RETENTION_DAYS -delete

echo "Cleanup complete!"