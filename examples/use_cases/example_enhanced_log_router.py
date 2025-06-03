import asyncio
import json
from datetime import datetime

# Assuming correct import paths
from src.python.log_router.enhanced_router import EnhancedLogRouter, RoutingRule, TransformationContext

async def main():
    print("Starting Enhanced Log Router example...")

    # Initialize EnhancedLogRouter.
    # The __init__ method calls _load_config, _load_rules, _register_transformers,
    # _setup_destinations, and _initialize_monitoring, all of which are stubbed.
    # _load_config stub returns {'rules': []}, so router.rules will initially be empty.
    # _register_transformers populates self.transformers with stubs.
    try:
        router = EnhancedLogRouter(config_path="dummy_config/router_config.yaml") # Path won't be read by stub
        print("EnhancedLogRouter initialized.")
    except Exception as e:
        print(f"Error initializing EnhancedLogRouter: {e}")
        return

    # Manually add a routing rule for demonstration, as _load_rules is basic
    # and _validate_rule is a stub.
    # This rule attempts to use some of the (stubbed) transformation types.
    manual_rule = RoutingRule(
        name="ExampleRule-SyslogToArchive",
        conditions=[ # _apply_condition stub always returns True
            {"field": "hostname", "operator": "exists"},
            {"field": "severity", "operator": "equals", "value": "INFO"}
        ],
        transformations=[ # These will call the stubbed _transform_* methods
            {"type": "field_rename", "old_field": "hostname", "new_field": "device_id"},
            {"type": "field_mask", "field": "user_payload.sensitive_data"},
            {"type": "geoip_enrich", "ip_field": "source_ip"}, # Assumes _transform_geoip_enrich is present or stubbed
            {"type": "field_extract", "source_field": "message", "pattern": "id=(\w+)", "target_field": "extracted_id"},
            {"type": "timestamp_convert", "field": "event_time", "output_format": "ISO"}
        ],
        destination={"type": "ArchiveStorage", "details": "some_archive_path"}, # Destination type for grouping
        priority=1,
        enabled=True,
        metadata={"description": "Routes INFO syslog messages after transformation."}
    )
    router.rules.append(manual_rule) # Add directly to the rules list
    print(f"Manually added rule: {manual_rule.name}")

    # Ensure our manually added rule's transformation types are in the router's (stubbed) transformers map
    # The _register_transformers stub should have already populated these.
    # If not, we might need to add them manually to router.transformers for the example:
    # router.transformers['field_rename'] = router._transform_field_rename # (already done by _register_transformers stub)


    # Sample log messages
    sample_logs = [
        {
            "hostname": "server01.example.com",
            "severity": "INFO",
            "message": "User 'admin' logged in from 192.168.1.100, id=abc789",
            "user_payload": {"sensitive_data": "secret_value_123"},
            "source_ip": "192.168.1.100",
            "event_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        },
        {
            "hostname": "desktop05.local",
            "severity": "WARN", # This log should not match the "INFO" condition
            "message": "High CPU utilization detected.",
            "user_payload": {},
            "source_ip": "10.0.0.5",
            "event_time": datetime.now().strftime('%Y/%m/%d %H:%M:%S')
        },
        {
            # No hostname, so it might not match if "hostname exists" is strictly checked by a real _apply_condition
            "severity": "INFO",
            "message": "Service started successfully, id=def456",
            "user_payload": {"sensitive_data": "another_secret"},
            "source_ip": "203.0.113.45",
            "event_time": "2023-10-26T14:30:00Z"
        }
    ]

    print(f"\nRouting {len(sample_logs)} sample log messages...")
    try:
        # route_logs will use _find_matching_rule (which uses _evaluate_conditions -> _apply_condition stub)
        # and _apply_transformations (which uses the stubbed _transform_* methods).
        # _send_to_destinations is also stubbed.
        routed_logs_output = await router.route_logs(sample_logs)

        print("\n--- Routed Logs Output ---")
        if routed_logs_output:
            for destination_type, logs_for_dest in routed_logs_output.items():
                print(f"  Destination Type: {destination_type}")
                for log_item in logs_for_dest:
                    # The logs here will reflect changes from stubbed transformations (mostly returning original log)
                    # and enrichment from _enrich_log.
                    print(f"    - {json.dumps(log_item, indent=2)}")
        else:
            print("  No logs were routed (or routing output was empty). This might be due to stub behavior.")
            print("  (e.g., _apply_condition stub returning False, or no rules matching).")
            print(f"  Current router rules: {router.rules}")


        # Example of generating a metrics report (will use stubbed calculation methods)
        metrics_report = await router.generate_metrics_report()
        print("\n--- Metrics Report (from stubs) ---")
        print(json.dumps(metrics_report, indent=2))

    except Exception as e:
        print(f"\nAn error occurred during log routing: {e}")
        import traceback
        traceback.print_exc()

    print("\nEnhanced Log Router example finished.")

if __name__ == "__main__":
    asyncio.run(main())
