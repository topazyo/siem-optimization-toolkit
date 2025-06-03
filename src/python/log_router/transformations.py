# src/python/log_router/transformations.py

from typing import Dict, Any, List, Optional # Any is already here
import re
import hashlib
import ipaddress
from datetime import datetime
import json
import base64
import zlib
from cryptography.fernet import Fernet
import logging # Added import

class AdvancedTransformations:
    """Advanced transformation handlers for log processing."""

    def __init__(self, config: Dict):
        """
        Initializes the AdvancedTransformations instance.

        This constructor stores the overall configuration, which might include
        settings for encryption, default behaviors for transformations, or
        credentials for external services used in transformations. It also
        loads an encryption key (if configured) and initializes a cache.

        Args:
            config (Dict): A dictionary containing overall configuration settings
                           relevant to various transformation operations. For example,
                           it might contain a path to an encryption key or default
                           parameters for certain transformations.

        Initializes key attributes:
        - `config` (Dict): Stores the provided overall configuration.
        - `encryption_key` (bytes, optional): The encryption key loaded via
                                             `_load_encryption_key()`, used by
                                             `transform_field_encrypt`. This might be None
                                             if no key is configured.
        - `cache` (Dict): A dictionary used for caching results of certain
                          transformations to improve performance (e.g., GeoIP lookups).
        """
        self.config = config
        self.logger = logging.getLogger(__name__) # Added logger initialization
        self.encryption_key = self._load_encryption_key()
        self.cache = {}

    # --- Stubs for private helper methods ---

    def _load_encryption_key(self) -> bytes:
        """Stub for loading the encryption key."""
        self.logger.warning("AdvancedTransformations._load_encryption_key is a stub and not yet implemented.")
        return Fernet.generate_key()

    def _get_nested_value(self, obj: Dict, path: str) -> Any:
        """Stub for getting a value from a nested dictionary using dot notation."""
        self.logger.warning("AdvancedTransformations._get_nested_value is a stub and not yet implemented.")
        return None

    def _set_nested_value(self, obj: Dict, path: str, value: Any) -> None:
        """Stub for setting a value in a nested dictionary using dot notation."""
        self.logger.warning("AdvancedTransformations._set_nested_value is a stub and not yet implemented.")
        pass

    # --- Existing public transform methods ---

    async def transform_json_flatten(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously flattens a nested JSON log entry into a single-level dictionary.

        Nested keys are combined using a dot ('.') separator. For arrays,
        the index is included in brackets (e.g., 'array[0].field').

        Args:
            log (Dict): The input log dictionary, potentially with nested structures.
            transform (Dict): Configuration for this transformation. Currently not used
                              by this specific transformation but included for consistency.
                              Example: {}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary with all nested fields flattened.
        """
        result = {}
        
        def flatten(obj: Any, prefix: str = ''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_prefix = f"{prefix}.{key}" if prefix else key
                    flatten(value, new_prefix)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_prefix = f"{prefix}[{i}]"
                    flatten(item, new_prefix)
            else:
                result[prefix] = obj

        flatten(log)
        return result

    async def transform_json_structure(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously restructures a JSON log entry based on a provided template.

        The template defines the desired output structure. Values from the input
        log are mapped to the new structure. Template values starting with '$'
        are treated as paths to values in the input log (e.g., "$UserData.Email").

        Args:
            log (Dict): The input log dictionary.
            transform (Dict): Configuration for this transformation.
                              Expected keys:
                              - 'template' (Dict): A dictionary defining the desired
                                                   output structure.
                              Example: {"template": {"user": {"id": "$Original.UserID", "status": "active"}}}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary restructured according to the template.
        """
        template = transform.get('template', {})
        result = {}

        def apply_template(template: Dict, data: Dict) -> Dict:
            output = {}
            for key, value in template.items():
                if isinstance(value, dict):
                    output[key] = apply_template(value, data)
                elif isinstance(value, str) and value.startswith('$'):
                    field_path = value[1:]
                    output[key] = self._get_nested_value(data, field_path)
                else:
                    output[key] = value
            return output

        return apply_template(template, log)

    async def transform_field_encrypt(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously encrypts specified fields in the log entry.

        Uses Fernet symmetric encryption. The encryption key should be loaded
        during class initialization. Encrypted values are Base64 encoded.

        Args:
            log (Dict): The input log dictionary.
            transform (Dict): Configuration for this transformation.
                              Expected keys:
                              - 'fields' (List[str]): A list of field paths (dot-notation
                                                      for nested fields) to encrypt.
                              Example: {"fields": ["UserData.SSN", "PaymentDetails.CardNumber"]}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary with specified fields encrypted. If a field
                  is not found or `self.encryption_key` is None, it's skipped.
        """
        result = log.copy()
        fields = transform.get('fields', [])
        
        if not self.encryption_key:
            # Consider logging a warning if encryption is attempted without a key
            return result

        f = Fernet(self.encryption_key)
        
        for field in fields:
            value = self._get_nested_value(result, field)
            if value is not None:
                try:
                    encrypted = f.encrypt(str(value).encode('utf-8'))
                    self._set_nested_value(
                        result,
                        field,
                        base64.b64encode(encrypted).decode('utf-8')
                    )
                except Exception: # Handle potential encryption errors
                    # Consider logging the error
                    pass # Keep original value or set to an error indicator
        
        return result

    async def transform_ip_anonymize(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously anonymizes IP addresses in specified fields.

        For IPv4, it masks the last octet (e.g., "192.168.1.123" -> "192.168.1.0").
        For IPv6, it aims to preserve network information by masking a portion
        (currently a simple mask of lower 64 bits, may need refinement for true privacy).

        Args:
            log (Dict): The input log dictionary.
            transform (Dict): Configuration for this transformation.
                              Expected keys:
                              - 'fields' (List[str]): A list of field paths containing IP addresses.
                              Example: {"fields": ["SourceIp", "DestinationIp"]}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary with specified IP fields anonymized.
                  Invalid IPs are skipped.
        """
        result = log.copy()
        fields = transform.get('fields', [])
        
        for field in fields:
            ip_str = self._get_nested_value(result, field)
            if ip_str:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.version == 4:
                        # Mask last octet for IPv4
                        masked_ip = ipaddress.ip_network(f"{str(ip_obj)}/24", strict=False).network_address
                        anonymized = str(masked_ip)
                    elif ip_obj.version == 6:
                        # Example: Mask the interface identifier part (last 64 bits)
                        # This is a basic example; real-world IPv6 anonymization can be complex.
                        masked_ip = ipaddress.ip_network(f"{str(ip_obj)}/64", strict=False).network_address
                        anonymized = str(masked_ip)
                    else:
                        anonymized = ip_str # Should not happen with ipaddress library
                    self._set_nested_value(result, field, anonymized)
                except ValueError: # Handles invalid IP strings
                    # Consider logging the invalid IP
                    continue
                    
        return result

    async def transform_field_aggregate(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously aggregates values from multiple fields into a single target field.

        Supported operations include concatenation, sum, and average.

        Args:
            log (Dict): The input log dictionary.
            transform (Dict): Configuration for this transformation.
                              Expected keys:
                              - 'fields' (List[str]): List of source field paths.
                              - 'target_field' (str): Path for the new aggregated field.
                              - 'operation' (str): 'concat', 'sum', or 'avg'. Defaults to 'concat'.
                              - 'separator' (str, optional): Separator for 'concat' (default: '').
                              Example: {"fields": ["Syslog.Hostname", "Syslog.ProcessName"],
                                        "target_field": "Event.SourceIdentifier", "operation": "concat", "separator": ":"}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary with the aggregated field added.
        """
        result = log.copy()
        source_fields = transform.get('fields', [])
        target_field = transform.get('target_field')
        operation = transform.get('operation', 'concat')
        
        if not target_field or not source_fields:
            return result # Or log a warning

        values = [
            self._get_nested_value(result, field)
            for field in source_fields
            if self._get_nested_value(result, field) is not None
        ]
        
        aggregated_value = None
        if values:
            if operation == 'concat':
                separator = transform.get('separator', '')
                aggregated_value = separator.join(map(str, values))
            elif operation == 'sum':
                try:
                    numeric_values = [float(v) for v in values]
                    aggregated_value = sum(numeric_values)
                except ValueError: # Handle non-numeric values for sum
                    # Consider logging a warning
                    pass
            elif operation == 'avg':
                try:
                    numeric_values = [float(v) for v in values]
                    if numeric_values:
                        aggregated_value = sum(numeric_values) / len(numeric_values)
                except ValueError: # Handle non-numeric values for avg
                    # Consider logging a warning
                    pass
                
        if aggregated_value is not None:
            self._set_nested_value(result, target_field, aggregated_value)

        return result

    async def transform_regex_extract_all(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously extracts all non-overlapping matches of a regex pattern
        from a source field and stores them as a list in a target field.

        Args:
            log (Dict): The input log dictionary.
            transform (Dict): Configuration for this transformation.
                              Expected keys:
                              - 'pattern' (str): The regex pattern to apply.
                              - 'source_field' (str): The field path to extract from.
                              - 'target_field' (str): The field path to store the list of matches.
                              Example: {"pattern": "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
                                        "source_field": "RawMessage", "target_field": "ExtractedIPs"}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary with the extracted matches in the target field.
                  If no matches, the target field is not added or is an empty list.
        """
        result = log.copy()
        pattern_str = transform.get('pattern')
        source_field = transform.get('source_field')
        target_field = transform.get('target_field')

        if not all([pattern_str, source_field, target_field]):
            # Consider logging a warning about missing configuration
            return result

        value_to_search = self._get_nested_value(result, source_field)
        if value_to_search is not None:
            try:
                compiled_pattern = re.compile(pattern_str)
                matches = compiled_pattern.findall(str(value_to_search))
                if matches: # Only add if there are matches
                    self._set_nested_value(result, target_field, matches)
            except re.error:
                # Consider logging a regex compilation error
                pass
                
        return result

    async def transform_timestamp_normalize(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """
        Asynchronously normalizes timestamps in specified fields to a standard ISO 8601 format.

        Attempts to parse timestamps from various common formats.

        Args:
            log (Dict): The input log dictionary.
            transform (Dict): Configuration for this transformation.
                              Expected keys:
                              - 'fields' (List[str]): List of field paths containing timestamps.
                              - 'output_format' (str, optional): Desired output format string
                                (strftime format). Defaults to '%Y-%m-%dT%H:%M:%S.%fZ'.
                              Example: {"fields": ["Event.Timestamp", "Header.ReceivedTime"],
                                        "output_format": "%Y-%m-%dT%H:%M:%S.%f%z"}
            context (Dict): Additional context for the transformation. Currently not used.

        Returns:
            Dict: A new dictionary with specified timestamp fields normalized.
                  Unparseable timestamps are left unchanged.
        """
        result = log.copy()
        fields_to_normalize = transform.get('fields', [])
        output_format = transform.get('output_format', '%Y-%m-%dT%H:%M:%S.%fZ')
        
        # Common input formats to try, ordered by likelihood or specificity
        common_input_formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO8601 with Z
            '%Y-%m-%dT%H:%M:%S.%f%z', # ISO8601 with timezone
            '%Y-%m-%dT%H:%M:%SZ',     # ISO8601 without milliseconds, with Z
            '%Y-%m-%dT%H:%M:%S%z',    # ISO8601 without milliseconds, with timezone
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S.%f',
            '%Y/%m/%d %H:%M:%S',
            '%m/%d/%Y %I:%M:%S %p',   # e.g., 12/31/2023 11:59:59 PM
            '%d/%b/%Y:%H:%M:%S',      # Common Apache log format part
            '%b %d %Y %H:%M:%S',      # e.g., Dec 31 2023 23:59:59
            # Add more formats as needed, or consider making input_formats configurable
        ]

        for field in fields_to_normalize:
            original_value = self._get_nested_value(result, field)
            if isinstance(original_value, str): # Only attempt to parse strings
                parsed_dt = None
                for fmt in common_input_formats:
                    try:
                        parsed_dt = datetime.strptime(original_value, fmt)
                        # If timezone is naive, assume UTC or make it configurable
                        if parsed_dt.tzinfo is None:
                             # parsed_dt = parsed_dt.replace(tzinfo=timezone.utc) # Requires import timezone
                             pass # Or leave as naive if output_format handles it
                        break
                    except ValueError:
                        continue # Try next format

                if parsed_dt:
                    try:
                        normalized_timestamp_str = parsed_dt.strftime(output_format)
                        self._set_nested_value(result, field, normalized_timestamp_str)
                    except Exception:
                        # Consider logging error during formatting
                        pass # Keep original if formatting fails
            # Consider handling numeric timestamps (e.g., Unix epoch) if necessary

        return result