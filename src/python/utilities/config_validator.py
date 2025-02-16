# src/python/utilities/config_validator.py

from typing import Dict, List, Optional
import yaml
import jsonschema
import logging
from pathlib import Path

class ConfigValidator:
    """
    Configuration validation utility for Sentinel optimization toolkit.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.schemas = self._load_schemas()

    def _load_schemas(self) -> Dict:
        """Load JSON schemas for configuration validation."""
        schema_path = Path(__file__).parent / 'schemas'
        schemas = {}

        for schema_file in schema_path.glob('*.json'):
            with open(schema_file, 'r') as f:
                schemas[schema_file.stem] = json.load(f)

        return schemas

    def validate_config(self, config_path: str, config_type: str) -> bool:
        """
        Validate configuration file against schema.
        
        Args:
            config_path (str): Path to configuration file
            config_type (str): Type of configuration to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        try:
            # Load configuration
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            # Get schema
            schema = self.schemas.get(config_type)
            if not schema:
                raise ValueError(f"No schema found for config type: {config_type}")

            # Validate
            jsonschema.validate(config, schema)
            self.logger.info(f"Configuration {config_path} is valid")
            return True

        except jsonschema.exceptions.ValidationError as e:
            self.logger.error(f"Configuration validation error: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Validation error: {str(e)}")
            return False

    def generate_config_template(self, config_type: str) -> str:
        """Generate configuration template from schema."""
        schema = self.schemas.get(config_type)
        if not schema:
            raise ValueError(f"No schema found for config type: {config_type}")

        template = self._schema_to_template(schema)
        return yaml.dump(template, default_flow_style=False)

    def _schema_to_template(self, schema: Dict) -> Dict:
        """Convert JSON schema to YAML template."""
        template = {}

        for prop, details in schema.get('properties', {}).items():
            if details.get('type') == 'object':
                template[prop] = self._schema_to_template(details)
            elif details.get('type') == 'array':
                template[prop] = [
                    self._schema_to_template(details['items'])
                ] if details['items'].get('type') == 'object' else []
            else:
                template[prop] = f"<{details.get('description', prop)}>"

        return template