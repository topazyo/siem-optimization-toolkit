# src/python/log_router/transformations.py

from typing import Dict, Any, List, Optional
import re
import hashlib
import ipaddress
from datetime import datetime
import json
import base64
import zlib
from cryptography.fernet import Fernet

class AdvancedTransformations:
    """Advanced transformation handlers for log processing."""

    def __init__(self, config: Dict):
        self.config = config
        self.encryption_key = self._load_encryption_key()
        self.cache = {}

    async def transform_json_flatten(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """Flatten nested JSON structures."""
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
        """Restructure JSON based on template."""
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
        """Encrypt sensitive fields."""
        result = log.copy()
        fields = transform.get('fields', [])
        
        f = Fernet(self.encryption_key)
        
        for field in fields:
            value = self._get_nested_value(result, field)
            if value is not None:
                encrypted = f.encrypt(str(value).encode())
                self._set_nested_value(
                    result,
                    field,
                    base64.b64encode(encrypted).decode()
                )
        
        return result

    async def transform_ip_anonymize(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """Anonymize IP addresses while preserving network information."""
        result = log.copy()
        fields = transform.get('fields', [])
        
        for field in fields:
            ip = self._get_nested_value(result, field)
            if ip:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.version == 4:
                        anonymized = str(ipaddress.IPv4Address(
                            int(ip_obj) & 0xFFFFFF00
                        ))
                    else:
                        anonymized = str(ipaddress.IPv6Address(
                            int(ip_obj) & (2**64 - 1)
                        ))
                    self._set_nested_value(result, field, anonymized)
                except:
                    continue
                    
        return result

    async def transform_field_aggregate(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """Aggregate multiple fields into a single value."""
        result = log.copy()
        fields = transform.get('fields', [])
        target_field = transform.get('target_field')
        operation = transform.get('operation', 'concat')
        
        values = [
            self._get_nested_value(result, field)
            for field in fields
            if self._get_nested_value(result, field) is not None
        ]
        
        if values:
            if operation == 'concat':
                aggregated = transform.get('separator', '').join(map(str, values))
            elif operation == 'sum':
                aggregated = sum(float(v) for v in values if str(v).replace('.', '').isdigit())
            elif operation == 'avg':
                valid_values = [float(v) for v in values if str(v).replace('.', '').isdigit()]
                aggregated = sum(valid_values) / len(valid_values) if valid_values else None
                
            if aggregated is not None:
                self._set_nested_value(result, target_field, aggregated)
                
        return result

    async def transform_regex_extract_all(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """Extract all regex matches from fields."""
        result = log.copy()
        pattern = transform.get('pattern')
        source_field = transform.get('source_field')
        target_field = transform.get('target_field')
        
        value = self._get_nested_value(result, source_field)
        if value:
            matches = re.findall(pattern, str(value))
            if matches:
                self._set_nested_value(result, target_field, matches)
                
        return result

    async def transform_timestamp_normalize(
        self,
        log: Dict,
        transform: Dict,
        context: Dict
    ) -> Dict:
        """Normalize timestamps to standard format."""
        result = log.copy()
        fields = transform.get('fields', [])
        output_format = transform.get('output_format', '%Y-%m-%dT%H:%M:%S.%fZ')
        
        for field in fields:
            value = self._get_nested_value(result, field)
            if value:
                try:
                    # Try multiple common formats
                    for fmt in [
                        '%Y-%m-%d %H:%M:%S',
                        '%Y/%m/%d %H:%M:%S',
                        '%d/%b/%Y:%H:%M:%S',
                        '%Y-%m-%dT%H:%M:%S.%fZ'
                    ]:
                        try:
                            dt = datetime.strptime(value, fmt)
                            normalized = dt.strftime(output_format)
                            self._set_nested_value(result, field, normalized)
                            break
                        except ValueError:
                            continue
                except:
                    continue
                    
        return result