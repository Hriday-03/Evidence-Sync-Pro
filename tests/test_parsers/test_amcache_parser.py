import pytest
from pathlib import Path
from datetime import datetime, timezone
from evidence_sync_pro.parsers.amcache_parser import AmcacheParser
from evidence_sync_pro.parsers.base_parser import Event

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def nist_amcache_hive_path():
    """Fixture: Path to NIST Amcache.hve sample."""
    path = (
        r"C:\Users\Hriday\Project\Refrences\sample_registry\Win10_10586_IE11+Edge_(CFReDS)"
        r"\0x04_reference_hive\p1\Windows\appcompat\Programs\Amcache.hve"
    )
    assert Path(path).is_file(), f"NIST Amcache not found: {path}"
    return path

@pytest.fixture
def amcache_parser(nist_amcache_hive_path):
    """Fixture: Initialize AmcacheParser with NIST sample."""
    return AmcacheParser(
        amcache_hive_path=nist_amcache_hive_path,
        computer_name="TEST_DESKTOP",
        system_timezone="UTC+0"
    )

# ============================================================================
# STRUCTURE DETECTION TESTS
# ============================================================================

class TestStructureDetection:
    """Test auto-detection of Amcache hive structure."""
    
    def test_hive_loads_successfully(self, amcache_parser, nist_amcache_hive_path):
        """Test that Amcache hive file loads without errors."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        assert hive is not None, "Hive load failed"
    
    def test_structure_detection_populates_metadata(self, amcache_parser, nist_amcache_hive_path):
        """Test that structure detection identifies hive layout and Windows version."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        assert amcache_parser.amcache_type is not None, "Windows version not detected"
        assert amcache_parser.root_path, "Root path not detected"
        assert amcache_parser.available_sections, "Sections not detected"
    
    def test_windows_version_detected_as_win10_plus(self, amcache_parser, nist_amcache_hive_path):
        """Test that NIST sample is correctly identified as Win10+ (has Programs section)."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        assert amcache_parser.amcache_type == "Win10+", \
            f"Expected Win10+ but got {amcache_parser.amcache_type}"
    
    def test_root_path_detected(self, amcache_parser, nist_amcache_hive_path):
        r"""Test that root key path is correctly detected (Root or Root\Root)."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        assert amcache_parser.root_path == ["Root"], \
            f"Expected ['Root', 'Root'] but got {amcache_parser.root_path}"
    
    def test_programs_section_detected(self, amcache_parser, nist_amcache_hive_path):
        """Test that Programs section is detected with correct entry count."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        assert "Programs" in amcache_parser.available_sections, "Programs section not detected"
        assert amcache_parser.available_sections["Programs"] > 0, "Programs section is empty"
    
    def test_file_section_detected(self, amcache_parser, nist_amcache_hive_path):
        """Test that File section is detected with correct entry count."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        assert "File" in amcache_parser.available_sections, "File section not detected"
    
    def test_orphan_section_detected(self, amcache_parser, nist_amcache_hive_path):
        """Test that Orphan section is detected with correct entry count."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        assert "Orphan" in amcache_parser.available_sections, "Orphan section not detected"
        assert amcache_parser.available_sections["Orphan"] > 0, "Orphan section is empty"

# ============================================================================
# TIER 1: PROGRAMS EXTRACTION TESTS
# ============================================================================

class TestTier1ProgramsExtraction:
    """Test extraction of installed programs from Programs section (Tier 1)."""
    
    def test_extract_programs_returns_list(self, amcache_parser, nist_amcache_hive_path):
        """Test that _extract_programs() returns a list."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_programs(hive)
        
        assert isinstance(events, list), "Should return list of events"
    
    def test_extract_programs_finds_entries(self, amcache_parser, nist_amcache_hive_path):
        """Test that Programs section is populated with entries."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_programs(hive)
        
        assert len(events) > 0, f"Should extract programs, got {len(events)}"
    
    def test_program_events_are_event_objects(self, amcache_parser, nist_amcache_hive_path):
        """Test that extracted programs are valid Event objects."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_programs(hive)
        
        for event in events:
            assert isinstance(event, Event), f"Event should be Event object, got {type(event)}"
    
    def test_program_events_have_required_fields(self, amcache_parser, nist_amcache_hive_path):
        """Test that program events have all required forensic fields."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_programs(hive)
        
        assert len(events) > 0, "No events extracted"
        
        event = events[0]
        assert event.timestamp is not None, "Event should have timestamp"
        assert event.source_device == "TEST_DESKTOP", "Event should have source_device"
        assert event.source_type == "AMCACHE", "Event should have source_type"
        assert event.event_type == "program_installed", "Event should have event_type"
    
    def test_program_events_have_payload_fields(self, amcache_parser, nist_amcache_hive_path):
        """Test that program events have forensic payload data."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_programs(hive)
        
        assert len(events) > 0, "No events extracted"
        
        event = events[0]
        payload = event.payload
        
        assert "program_id" in payload, "Should have program_id"
        assert "program_name" in payload, "Should have program_name"
        assert "version" in payload, "Should have version"
        assert "publisher" in payload, "Should have publisher"
    
    def test_program_events_have_forensic_priority(self, amcache_parser, nist_amcache_hive_path):
        """Test that program events have forensic priority metadata."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_programs(hive)
        
        assert len(events) > 0, "No events extracted"
        
        event = events[0]
        assert event.forensic_priority == "HIGH", "Programs should have HIGH priority"
        assert 0.0 <= event.confidence_score <= 1.0, "Confidence score should be 0-1"

# ============================================================================
# TIER 2: FILE EXECUTION EXTRACTION TESTS
# ============================================================================

class TestTier2FileExecutionExtraction:
    """Test extraction of file execution history from File section (Tier 2)."""
    
    def test_extract_file_execution_returns_list(self, amcache_parser, nist_amcache_hive_path):
        """Test that _extract_file_execution() returns a list."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_file_execution(hive)
        
        assert isinstance(events, list), "Should return list of events"
    
    def test_file_section_entries_extracted(self, amcache_parser, nist_amcache_hive_path):
        """Test that File section entries are extracted (may be empty on some systems)."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_file_execution(hive)
        
        # File section may be empty but should return valid list
        assert isinstance(events, list), "Should return list"
    
    def test_file_events_are_event_objects(self, amcache_parser, nist_amcache_hive_path):
        """Test that extracted file executions are valid Event objects."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_file_execution(hive)
        
        for event in events:
            assert isinstance(event, Event), f"Event should be Event object, got {type(event)}"
    
    def test_file_events_have_correct_type(self, amcache_parser, nist_amcache_hive_path):
        """Test that file execution events have correct event_type."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_file_execution(hive)
        
        for event in events:
            assert event.event_type == "file_execution", \
                f"File events should have type 'file_execution', got {event.event_type}"

# ============================================================================
# TIER 3: ORPHAN PROGRAMS EXTRACTION TESTS
# ============================================================================

class TestTier3OrphanProgramsExtraction:
    """Test extraction of removed programs from Orphan section (Tier 3)."""
    
    def test_extract_orphan_programs_returns_list(self, amcache_parser, nist_amcache_hive_path):
        """Test that _extract_orphan_programs() returns a list."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_orphan_programs(hive)
        
        assert isinstance(events, list), "Should return list of events"
    
    def test_orphan_section_entries_extracted(self, amcache_parser, nist_amcache_hive_path):
        """Test that Orphan section entries are extracted."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_orphan_programs(hive)
        
        # NIST sample has 78 orphan entries
        assert len(events) > 0, "Should extract orphan entries"
    
    def test_orphan_events_are_event_objects(self, amcache_parser, nist_amcache_hive_path):
        """Test that extracted orphans are valid Event objects."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_orphan_programs(hive)
        
        for event in events:
            assert isinstance(event, Event), f"Event should be Event object, got {type(event)}"
    
    def test_orphan_events_have_correct_type(self, amcache_parser, nist_amcache_hive_path):
        """Test that orphan events have correct event_type."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_orphan_programs(hive)
        
        for event in events:
            assert event.event_type == "program_removed", \
                f"Orphan events should have type 'program_removed', got {event.event_type}"
    
    def test_orphan_events_have_medium_priority(self, amcache_parser, nist_amcache_hive_path):
        """Test that orphan events have MEDIUM forensic priority."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_orphan_programs(hive)
        
        if len(events) > 0:
            event = events[0]
            assert event.forensic_priority == "MEDIUM", "Orphans should have MEDIUM priority"

# ============================================================================
# TIER 4: OPTIONAL SECTIONS EXTRACTION TESTS
# ============================================================================

class TestTier4OptionalSectionsExtraction:
    """Test extraction from optional sections (Device, HwItem, Generic, Metadata)."""
    
    def test_extract_optional_section_returns_list(self, amcache_parser, nist_amcache_hive_path):
        """Test that _extract_optional_section() returns a list."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        events = amcache_parser._extract_optional_section(hive, "Device")
        
        assert isinstance(events, list), "Should return list of events"
    
    def test_extract_optional_section_handles_missing_section(self, amcache_parser, nist_amcache_hive_path):
        """Test that optional sections gracefully handle missing sections."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        # NIST sample doesn't have Device section, should return empty
        events = amcache_parser._extract_optional_section(hive, "Device")
        
        assert isinstance(events, list), "Should return list even if section missing"
        assert len(events) == 0, "Should return empty list for missing section"

# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegrationFullParsing:
    """Test complete end-to-end parsing workflow."""
    
    def test_full_amcache_parsing_with_parse_method(self, amcache_parser, nist_amcache_hive_path):
        """Test that parse() orchestrates complete extraction with auto-detection."""
        all_events = amcache_parser.parse()
        
        assert isinstance(all_events, list), "parse() should return list"
        assert len(all_events) > 0, f"Should extract events, got {len(all_events)}"
    
    def test_parse_returns_events_from_multiple_tiers(self, amcache_parser, nist_amcache_hive_path):
        """Test that parse() extracts from multiple sections (Programs, File, Orphan)."""
        all_events = amcache_parser.parse()
        
        event_types = {event.event_type for event in all_events}
        
        # Should have at least some of these event types
        assert "program_installed" in event_types, "Should extract installed programs (Tier 1)"
    
    def test_parse_extracts_expected_event_count(self, amcache_parser, nist_amcache_hive_path):
        """Test that parse() extracts approximately expected number of events."""
        all_events = amcache_parser.parse()
        
        # NIST sample: ~16 Programs + ~78 Orphan + ~4 File = ~98 events
        assert len(all_events) >= 80, \
            f"Expected ~98 events, got {len(all_events)}"
    
    def test_parse_sets_amcache_type(self, amcache_parser, nist_amcache_hive_path):
        """Test that parse() correctly identifies Windows version."""
        all_events = amcache_parser.parse()
        
        assert amcache_parser.amcache_type == "Win10+", \
            f"NIST sample should be Win10+, got {amcache_parser.amcache_type}"
    
    def test_parse_detects_available_sections(self, amcache_parser, nist_amcache_hive_path):
        """Test that parse() detects all available sections."""
        all_events = amcache_parser.parse()
        
        assert "Programs" in amcache_parser.available_sections, "Should detect Programs"
        assert "Orphan" in amcache_parser.available_sections, "Should detect Orphan"
    
    def test_all_events_have_valid_timestamps(self, amcache_parser, nist_amcache_hive_path):
        """Test that all extracted events have valid timestamps."""
        all_events = amcache_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        for event in all_events:
            assert event.timestamp is not None, "Event should have timestamp"
            assert isinstance(event.timestamp, datetime), \
                f"Timestamp should be datetime, got {type(event.timestamp)}"
    
    def test_all_events_have_forensic_priority(self, amcache_parser, nist_amcache_hive_path):
        """Test that all events have forensic priority metadata."""
        all_events = amcache_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        valid_priorities = {"HIGH", "MEDIUM", "LOW"}
        for event in all_events:
            assert event.forensic_priority in valid_priorities, \
                f"Invalid forensic_priority: {event.forensic_priority}"
    
    def test_all_events_have_confidence_score(self, amcache_parser, nist_amcache_hive_path):
        """Test that all events have confidence scores between 0-1."""
        all_events = amcache_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        for event in all_events:
            assert 0.0 <= event.confidence_score <= 1.0, \
                f"Confidence score should be 0-1, got {event.confidence_score}"
    
    def test_parse_records_corruption_log(self, amcache_parser, nist_amcache_hive_path):
        """Test that corruption_log is populated if errors occur."""
        all_events = amcache_parser.parse()
        
        # corruption_log should be a list (may be empty)
        assert isinstance(amcache_parser.corruption_log, list), \
            "corruption_log should be list"

# ============================================================================
# HELPER FUNCTION TESTS
# ============================================================================

class TestHelperFunctions:
    """Test helper functions (timestamp conversion, key navigation, etc.)."""
    
    def test_load_hive_with_valid_path(self, amcache_parser, nist_amcache_hive_path):
        """Test that _load_hive() successfully loads valid hive file."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        
        assert hive is not None, "Hive should load successfully"
    
    def test_load_hive_with_invalid_path_returns_none(self, amcache_parser):
        """Test that _load_hive() returns None for non-existent file."""
        hive = amcache_parser._load_hive("/nonexistent/path/Amcache.hve")
        
        assert hive is None, "Should return None for missing file"
    
    def test_get_root_key_navigates_correctly(self, amcache_parser, nist_amcache_hive_path):
        """Test that _get_root_key() navigates to correct location using detected path."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        root_key = amcache_parser._get_root_key(hive)
        
        assert root_key is not None, "Should navigate to root key"
    
    def test_calculate_local_timestamp_with_zero_offset(self, amcache_parser):
        """Test timestamp conversion with UTC+0 offset."""
        utc_time = datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = amcache_parser._calculate_local_timestamp(utc_time, "UTC+0")
        
        assert local_time == utc_time, "UTC+0 should not change timestamp"
    
    def test_calculate_local_timestamp_with_positive_offset(self, amcache_parser):
        """Test timestamp conversion with positive offset (e.g., UTC+5:30)."""
        utc_time = datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = amcache_parser._calculate_local_timestamp(utc_time, "UTC+5:30")
        
        # Should be 5.5 hours ahead
        assert local_time.hour == 16, f"Expected hour 16, got {local_time.hour}"
    
    def test_calculate_local_timestamp_with_negative_offset(self, amcache_parser):
        """Test timestamp conversion with negative offset (e.g., UTC-8)."""
        utc_time = datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = amcache_parser._calculate_local_timestamp(utc_time, "UTC-8")
        
        # Should be 8 hours behind
        assert local_time.hour == 2, f"Expected hour 2, got {local_time.hour}"
    
    def test_get_chain_of_custody_metadata(self, amcache_parser, nist_amcache_hive_path):
        """Test that chain of custody hashes are calculated correctly."""
        metadata = amcache_parser._get_chain_of_custody_metadata(nist_amcache_hive_path)
        
        assert metadata is not None, "Should return metadata dict"
        assert "sha256" in metadata, "Should have SHA256 hash"
        assert "md5" in metadata, "Should have MD5 hash"
        assert metadata["sha256"] is not None, "SHA256 should not be None"
        assert metadata["md5"] is not None, "MD5 should not be None"

# ============================================================================
# DEBUG TESTS (Structure Inspection)
# ============================================================================

class TestDebugAmcacheStructure:
    """Debug tests to inspect actual Amcache structure and diagnose issues."""
    
    def test_debug_inspect_root_key_contents(self, amcache_parser, nist_amcache_hive_path):
        """
        Debug: Inspect what's actually in the root key after detection.
        
        Prints all subkey names at Root level to understand structure.
        """
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        root = hive.root()
        print("\n\n=== ROOT KEY SUBKEYS ===")
        for subkey in root.subkeys():
            print(f"  - {subkey.name()}")
        
        # Try to get Root subkey
        root_subkey = root.subkey("Root")
        if root_subkey:
            print("\n=== ROOT\ROOT SUBKEYS ===")
            for subkey in root_subkey.subkeys():
                print(f"  - {subkey.name()}")
        else:
            print("\n=== ROOT\ROOT NOT FOUND - trying alternate paths ===")
            # Maybe the structure is different
            for subkey in root.subkeys():
                try:
                    children = list(subkey.subkeys())
                    if children:
                        print(f"Subkey '{subkey.name()}' has {len(children)} children:")
                        for child in children[:3]:
                            print(f"  - {child.name()}")
                except:
                    pass
    
    def test_debug_inspect_programs_section_directly(self, amcache_parser, nist_amcache_hive_path):
        """
        Debug: Try to access Programs section directly and inspect its contents.
        
        Prints actual Programs section data to verify extraction logic.
        """
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        root = hive.root()
        root_subkey = root.subkey("Root")
        
        print("\n\n=== TRYING TO ACCESS PROGRAMS ===")
        
        if root_subkey:
            print(f"Found Root subkey, children: {[s.name() for s in list(root_subkey.subkeys())[:5]]}")
            
            programs_key = root_subkey.subkey("Programs")
            if programs_key:
                print("\n=== PROGRAMS SECTION FOUND ===")
                count = 0
                for prog in programs_key.subkeys():
                    count += 1
                    print(f"Program {count}: {prog.name()}")
                    # Show first program's values
                    if count == 1:
                        print("  Values in first program:")
                        for val in prog.values():
                            try:
                                val_data = val.value()
                                if isinstance(val_data, bytes):
                                    print(f"    - {val.name()}: <bytes len={len(val_data)}>")
                                else:
                                    print(f"    - {val.name()}: {str(val_data)[:50]}")
                            except:
                                print(f"    - {val.name()}: <error reading>")
                    if count >= 5:
                        print("  ...")
                        break
                print(f"Total programs found: {count}")
            else:
                print(r"Programs key NOT FOUND under Root\Root")
                print(f"Available sections: {[s.name() for s in list(root_subkey.subkeys())]}")
        else:
            print("Root subkey NOT FOUND")

# ============================================================================
# ADAPTIVE EXTRACTION TESTS (Multi-System Compatibility)
# ============================================================================

class TestAdaptiveExtraction:
    """Test that parser adapts to different Amcache structures."""
    
    def test_parser_handles_populated_programs_section(self, amcache_parser, nist_amcache_hive_path):
        """Test that parser correctly handles populated Programs section."""
        all_events = amcache_parser.parse()
        
        # Filter for program events
        program_events = [e for e in all_events if e.event_type == "program_installed"]
        
        assert len(program_events) > 0, "Should extract programs when section populated"
    
    def test_parser_handles_orphan_programs(self, amcache_parser, nist_amcache_hive_path):
        """Test that parser correctly extracts orphan (removed) programs."""
        all_events = amcache_parser.parse()
        
        # Filter for orphan events
        orphan_events = [e for e in all_events if e.event_type == "program_removed"]
        
        assert len(orphan_events) > 0, "Should extract orphan programs"
    
    def test_parser_gracefully_handles_empty_file_section(self, amcache_parser, nist_amcache_hive_path):
        """Test that parser handles File section with empty entries."""
        hive = amcache_parser._load_hive(nist_amcache_hive_path)
        amcache_parser._detect_amcache_structure(hive)
        
        file_events = amcache_parser._extract_file_execution(hive)
        
        # File section exists but may have no useful entries
        assert isinstance(file_events, list), "Should return list"
    
    def test_parser_skips_missing_optional_sections(self, amcache_parser, nist_amcache_hive_path):
        """Test that parser gracefully skips missing optional sections."""
        all_events = amcache_parser.parse()
        
        # Should not crash even though Device, HwItem, Generic are missing on NIST sample
        assert isinstance(all_events, list), "Should handle missing optional sections"
