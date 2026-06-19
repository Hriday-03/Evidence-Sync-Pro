from evidence_sync_pro.parsers.prefetch_parser import PrefetchParser

parser = PrefetchParser(r"C:\Users\Hriday\Project\Refrences\sample_prefetch", "My_Computer")
events = parser.parse()
print("\n--- Pipeline Diagnostics ---")
print(f"Total Log Records Iterated: {parser.events_count}")
print(f"Successfully Normalized Events: {len(events)}")
print(f"Total Intercepted Anomalies / Drops: {len(parser.corruption_log)}")


if events:
    print(f"\n--- Sample Normalized Data Fields ---")
    # Show the first parsed event as a general sanity check
    print(f"First Event Record Overall:")
    print(f"  - Timestamp (UTC): {events[0].timestamp}")
    print(f"  - Local Timestamp: {events[0].local_timestamp}")
    print(f"  - Target User:     {events[0].user}")
    print(f"  - Event ID Type:   {events[0].event_type}")
    print(f"  - Extracted IPs:   {events[0].extracted_ips}")
    print(f"  - Forensic Level:  {events[0].forensic_priority}")
else:
    print('\n❌ Critical Error: Global event array is completely empty!')