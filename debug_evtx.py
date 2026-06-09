from evidence_sync_pro.parsers.evtx_parser import EvtxParser

# Initialize the updated parser instance
parser = EvtxParser(
    r'C:\Windows\System32\winevt\Logs\Security.evtx',
    r'C:\Windows\System32\config\SYSTEM'
)

print(f"--- Environment Initialization ---")
print(f"Detected System Timezone Offset: {parser.system_timezone}")
print(f"----------------------------------\n")

print("Executing localized parsing run...")
events = parser.parse()

print("\n--- Pipeline Diagnostics ---")
print(f"Total Log Records Iterated: {parser.events_count}")
print(f"Successfully Normalized Events: {len(events)}")
print(f"Total Intercepted Anomalies / Drops: {len(parser.corruption_log)}")

# Isolating the specific target records we were troubleshooting
target_ids = {3192917, 3192918, 3192919}
matched_targets = []

if parser.corruption_log:
    print(f"\n[!] Investigating Corruption Logs for Target IDs:")
    corruption_matches = [c for c in parser.corruption_log if c.get('event_record_id') in target_ids]
    if corruption_matches:
        for corr in corruption_matches:
            print(f"    ❌ Target Record dropped in stage '{corr.get('stage')}': {corr.get('error')}")
    else:
        print("    ✅ None of our target records failed or dropped into the corruption logs!")

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
# from evtx import PyEvtxParser

# raw_parser = PyEvtxParser(r'C:\Windows\System32\winevt\Logs\Security.evtx')
# target_record_id = 3192917

# for record in raw_parser.records():
#     if record.get('event_record_id') == target_record_id:
#         raw_data = record.get('data')
#         print(f"Type of raw_data: {type(raw_data)}")
#         print("\nRaw Content Snippet:")
#         print(str(raw_data)[:500])
#         break