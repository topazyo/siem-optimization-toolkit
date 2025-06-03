import yaml
import sys

def validate_yaml_file(filepath):
    try:
        with open(filepath, 'r') as f:
            yaml.safe_load(f)
        print(f"Validation successful: {filepath} is a valid YAML file.")
        return True
    except yaml.YAMLError as e:
        print(f"Validation failed: {filepath} is not a valid YAML file.")
        print(e)
        return False
    except FileNotFoundError:
        print(f"Error: File not found - {filepath}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
        # Default to config/detection_patterns.yaml if no argument is provided
        filepath = "config/detection_patterns.yaml"

    if not validate_yaml_file(filepath):
        sys.exit(1)
