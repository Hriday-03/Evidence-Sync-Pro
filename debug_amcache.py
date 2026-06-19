# from Registry import Registry
# from pathlib import Path

# # Load the hive
# hive_path = r"C:\Users\Hriday\Project\Refrences\sample_registry\Win10_10586_IE11+Edge_(CFReDS)\0x04_reference_hive\p1\Windows\appcompat\Programs\Amcache.hve"

# with open(hive_path, 'rb') as f:
#     hive = Registry.Registry(f)

# root = hive.root()

# print("\n" + "="*80)
# print("ROOT HIVE SUBKEYS (First level)")
# print("="*80)
# for i, subkey in enumerate(root.subkeys()):
#     print(f"{i}. {subkey.name()}")
#     if i >= 10:
#         print("... (truncated)")
#         break

# print("\n" + "="*80)
# print("TRYING TO ACCESS 'Root' SUBKEY")
# print("="*80)

# try:
#     root_key = root.subkey("Root")
#     if root_key:
#         print("✓ Found 'Root' subkey!")
#         print("\nROOT\ROOT SUBKEYS:")
#         for subkey in root_key.subkeys():
#             print(f"  - {subkey.name()}")
#     else:
#         print("✗ 'Root' subkey is None")
# except Exception as e:
#     print(f"✗ Error accessing Root: {e}")

# print("\n" + "="*80)
# print("LOOKING FOR PROGRAMS IN ROOT")
# print("="*80)

# try:
#     # Direct access attempt
#     programs_key = root.subkey("Programs")
#     if programs_key:
#         print("✓ Found 'Programs' directly under root!")
#         prog_count = 0
#         for prog in programs_key.subkeys():
#             prog_count += 1
#             if prog_count <= 3:
#                 print(f"\n  Program {prog_count}: {prog.name()}")
#                 print("    Values:")
#                 for val in prog.values():
#                     try:
#                         val_data = val.value()
#                         if isinstance(val_data, bytes):
#                             print(f"      - {val.name()}: <bytes len={len(val_data)}>")
#                         else:
#                             print(f"      - {val.name()}: {str(val_data)[:60]}")
#                     except:
#                         pass
#         print(f"\n  Total Programs: {prog_count}")
#     else:
#         print("✗ 'Programs' not found directly under root")
# except Exception as e:
#     print(f"✗ Error: {e}")

# print("\n" + "="*80)
# print("TRYING ROOT\ROOT\PROGRAMS")
# print("="*80)

# try:
#     root_sub = root.subkey("Root")
#     if root_sub:
#         programs_key = root_sub.subkey("Programs")
#         if programs_key:
#             print("✓ Found Programs under Root\Root!")
#             prog_count = sum(1 for _ in programs_key.subkeys())
#             print(f"Total Programs: {prog_count}")
#         else:
#             print("✗ Programs not found under Root\Root")
#             print(f"Available under Root\Root: {[s.name() for s in list(root_sub.subkeys())[:10]]}")
#     else:
#         print("✗ Root subkey not found")
# except Exception as e:
#     print(f"✗ Error: {e}")

# print("\n" + "="*80)
# print("LOOKING FOR ORPHAN SECTION")
# print("="*80)

# try:
#     # Try Orphan directly
#     orphan_key = root.subkey("Orphan")
#     if orphan_key:
#         print("✓ Found 'Orphan' directly under root!")
#         orphan_count = sum(1 for _ in orphan_key.subkeys())
#         print(f"Total Orphan entries: {orphan_count}")
#     else:
#         print("✗ Orphan not found directly")
        
#     # Try Root\Root\Orphan
#     root_sub = root.subkey("Root")
#     if root_sub:
#         orphan_key = root_sub.subkey("Orphan")
#         if orphan_key:
#             print("✓ Found 'Orphan' under Root\Root!")
#             orphan_count = sum(1 for _ in orphan_key.subkeys())
#             print(f"Total Orphan entries: {orphan_count}")
#         else:
#             print("✗ Orphan not found under Root\Root")
# except Exception as e:
#     print(f"✗ Error: {e}")

# print("\n" + "="*80)

from evidence_sync_pro.parsers.amcache_parser import AmcacheParser

parser = AmcacheParser(r"C:\Users\Hriday\Project\Refrences\sample_registry\Win10_10586_IE11+Edge_(CFReDS)\0x04_reference_hive\p1\Windows\appcompat\Programs\Amcache.hve"
, "My_Computer")
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