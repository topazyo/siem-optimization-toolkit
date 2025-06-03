# Configuration Schemas and Templates

This document describes the structure and purpose of various configuration files used by the SIEM Optimization Toolkit.

## 1. Cost Analysis Configuration (`cost_analysis.json`)

This JSON schema (located at `src/python/utilities/schemas/cost_analysis.json`) defines the structure for a configuration file that would be used by the `SentinelCostAnalyzer` component (if it were to load its thresholds and rules from an external file instead of having them hardcoded or passed differently).

**Root Object:**

| Key                  | Type    | Required | Description                                                                 |
|----------------------|---------|----------|-----------------------------------------------------------------------------|
| `cost_thresholds`    | Object  | Yes      | Defines various cost-related thresholds for monitoring and alerts.        |
| `optimization_rules` | Array   | Yes      | A list of rules that define when and how to trigger cost optimizations. |

---

### 1.1. `cost_thresholds` Object

| Key                  | Type    | Required | Description                                      |
|----------------------|---------|----------|--------------------------------------------------|
| `daily_ingestion`    | Number  | Yes      | Maximum daily ingestion volume in GB.            |
| `query_execution`    | Number  | Yes      | Maximum daily query cost in USD.                 |
| `storage_tier`       | Object  | Yes      | Defines costs associated with different storage tiers. |

#### 1.1.1. `storage_tier` Object (within `cost_thresholds`)

| Key    | Type   | Required | Description                     |
|--------|--------|----------|---------------------------------|
| `hot`  | Number | Yes      | Cost per GB for hot storage.    |
| `warm` | Number | Yes      | Cost per GB for warm storage.   |
| `cold` | Number | Yes      | Cost per GB for cold storage.   |

---

### 1.2. `optimization_rules` Array

This is an array of objects, where each object defines a specific optimization rule.

| Key         | Type    | Required | Description                                                                |
|-------------|---------|----------|----------------------------------------------------------------------------|
| `type`      | String  | Yes      | The type of optimization. Enum: `"table"`, `"storage"`, `"query"`.         |
| `threshold` | Number  | Yes      | The threshold value that triggers this optimization rule. The unit depends on the `type`. |
| `actions`   | Array   | Yes      | A list of string identifiers for actions to take if the rule is triggered. |

**Example `optimization_rules` item:**
```json
{
  "type": "table",
  "threshold": 150, // e.g., if a table's daily cost exceeds 150 USD
  "actions": ["archive_table_data", "notify_admin"]
}
```

---
**Note on Usage:**
Currently, `SentinelCostAnalyzer` in `src/python/cost_analysis/cost_analyzer.py` loads its `cost_thresholds` directly within its `_load_cost_thresholds` method. The `optimization_rules` part of this schema is not explicitly used by the current `SentinelCostAnalyzer` stub, but it defines a potential structure for future enhancements where optimization rules could be configured externally. No example YAML/JSON file using this exact schema currently exists in `config/examples/`.

## 2. Log Routing Configuration (`routing_configs.yaml`)

This example YAML file (located at `config/examples/routing_configs.yaml`) demonstrates how to configure routing rules, likely for the `EnhancedLogRouter` or a similar component. It defines multiple routing "profiles" (e.g., `high_security`, `compliance`), each containing a list of rules.

**File Structure Overview:**

The root of the YAML is an object where each key represents a routing profile name (e.g., `high_security`). The value for each profile is an object that must contain a `rules` key.

```yaml
profile_name_1:
  rules:
    - # Rule 1 definition
    - # Rule 2 definition
profile_name_2:
  rules:
    - # Rule A definition
    # ...
```

---

### 2.1. Rule Definition (within a profile's `rules` list)

Each item in the `rules` list is an object defining a single routing rule. This structure is consistent with the `RoutingRule` dataclass defined in `src/python/log_router/enhanced_router.py`.

| Key               | Type         | Required | Description                                                                                                | Example Value                                                                 |
|-------------------|--------------|----------|------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| `name`            | String       | Yes      | A unique name for the rule within the profile.                                                               | `"critical_security_events"`                                                  |
| `priority`        | Integer      | Yes      | Numerical priority for the rule. Lower numbers usually mean higher priority.                                 | `1`                                                                           |
| `conditions`      | List         | Yes      | A list of condition objects that a log must satisfy to be processed by this rule. All conditions must pass. | `[{"field": "severity", "operator": "equals", "value": "critical"}]`           |
| `transformations` | List         | Yes      | A list of transformation objects to be applied to the log if conditions are met.                             | `[{"type": "field_encrypt", "fields": ["user.password"]}]`                    |
| `destination`     | Object       | Yes      | Defines the target destination for the processed log.                                                        | `{"type": "elasticsearch", "config": {"url": "...", "index": "..."}}`       |
| `enabled`         | Boolean      | No       | Whether the rule is active. Defaults to `True` if not specified (as per `RoutingRule` dataclass).             | `true` / `false`                                                              |
| `metadata`        | Object       | No       | Arbitrary key-value pairs for additional rule information. Defaults to empty dict.                           | `{"owner": "security_ops", "ticket": "SEC-123"}`                               |

---

#### 2.1.1. `conditions` Array Item

Each item in the `conditions` list defines a specific criterion.

| Key        | Type   | Required | Description                                                                 | Example Value         |
|------------|--------|----------|-----------------------------------------------------------------------------|-----------------------|
| `field`    | String | Yes      | The path to the field in the log to evaluate (dot notation for nested fields). | `"severity"`          |
| `operator` | String | Yes      | The comparison operator (e.g., `"equals"`, `"in"`, `"exists"`, `"contains"`). | `"equals"`            |
| `value`    | Any    | Yes      | The value to compare against the field's content.                             | `"critical"`          |

---

#### 2.1.2. `transformations` Array Item

Each item in the `transformations` list defines a data modification step. The `type` key determines the kind of transformation, and other keys provide parameters for that type.

| Key      | Type   | Required | Description                                                                | Example Value                                           |
|----------|--------|----------|----------------------------------------------------------------------------|---------------------------------------------------------|
| `type`   | String | Yes      | The type of transformation to apply (e.g., `"field_encrypt"`, `"ip_anonymize"`). | `"field_encrypt"`                                       |
| `fields` | List   | Varies   | List of field paths to apply the transformation to (common for many types).  | `["user.password", "credentials"]` (for field_encrypt) |
| `...`    | ...    | ...      | Other keys depend on the transformation `type`. Refer to `AdvancedTransformations` methods in `src/python/log_router/transformations.py` for specifics of each type (e.g., `template` for `json_structure`, `pattern` for `regex_extract`, `target_field` & `operation` for `field_aggregate`). |                                                         |

**Common Transformation Types Seen in Example:**
*   `field_encrypt`: Encrypts specified fields. Needs `fields` (list of field paths).
*   `ip_anonymize`: Anonymizes IP addresses in specified fields. Needs `fields` (list of field paths).
*   `timestamp_normalize`: Normalizes timestamp formats. Needs `fields` (list of field paths), optionally `output_format`.
*   `json_flatten`: Flattens nested JSON. No extra parameters typically needed beyond `type`.
*   `field_aggregate`: Aggregates multiple fields. Needs `fields` (list), `target_field` (string), `operation` (string, e.g., "concat"), optionally `separator` (string).
*   `json_structure`: Reshapes JSON. Needs `template` (object).

---

#### 2.1.3. `destination` Object

Defines where to send the transformed log.

| Key      | Type   | Required | Description                                                                    | Example Value                                |
|----------|--------|----------|--------------------------------------------------------------------------------|----------------------------------------------|
| `type`   | String | Yes      | The type of destination (e.g., `"elasticsearch"`, `"s3"`, `"kafka"`).          | `"elasticsearch"`                            |
| `config` | Object | Yes      | Destination-specific configuration (e.g., URL, index, bucket name, topic name). | `{"url": "...", "index": "..."}` (for ES) |

---
**Note on Usage:**
This `routing_configs.yaml` file is intended to be loaded by a component like `EnhancedLogRouter`. The `EnhancedLogRouter`'s `_load_config` method (currently stubbed) would parse this YAML. The `rules` array within each profile would then be used to instantiate `RoutingRule` objects. The specific transformation types and destination types mentioned would correspond to handlers registered within the router (e.g., methods in `AdvancedTransformations` and `DestinationHandlers`).
