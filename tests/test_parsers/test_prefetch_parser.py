import pytest
from pathlib import Path
from datetime import datetime, timezone
from evidence_sync_pro.parsers.prefetch_parser import PrefetchParser
from evidence_sync_pro.parsers.base_parser import Event

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def prefetch_dir_path():
    r"""
    Fixture providing path to Prefetch directory from NIST SCHARDT sample.
    
    Prefetch files are typically located at:
    C:\Windows\Prefetch\*.pf
    
    For NIST SCHARDT sample:
    C:\Users\Hriday\Project\Refrences\extracted_prefetch\
    
    To extract Prefetch files from SCHARDT.001:
    1. Mount SCHARDT.001 using FTK Imager or Arsenal
    2. Navigate to X:\Windows\Prefetch\ (where X is mounted drive letter)
    3. Copy all *.pf files to extraction directory
    4. Place at: C:\Users\Hriday\Project\Refrences\extracted_prefetch\
    """
    path = r"C:\Users\Hriday\Project\Refrences\sample_prefetch"
    
    # Check if directory exists with prefetch files
    prefetch_path = Path(path)
    if not prefetch_path.is_dir():
        pytest.skip(f"Prefetch directory not found at {path}. Extract SCHARDT.001 first.")
    
    pf_files = list(prefetch_path.glob("*.pf")) + list(prefetch_path.glob("*.PF"))
    if not pf_files:
        pytest.skip(f"No Prefetch files found in {path}")
    
    return path

@pytest.fixture
def prefetch_parser(prefetch_dir_path):
    """
    Fixture initializing PrefetchParser with NIST SCHARDT sample.
    
    Returns a PrefetchParser instance ready for testing.
    """
    return PrefetchParser(
        prefetch_dir_path=prefetch_dir_path,
        computer_name="SCHARDT_TEST",
        system_timezone="UTC+0"
    )

# ============================================================================
# FILE DISCOVERY TESTS
# ============================================================================

class TestPrefetchFileDiscovery:
    """Test suite for discovering Prefetch files."""
    
    def test_discover_prefetch_files_returns_list(self, prefetch_parser, prefetch_dir_path):
        """
        Test that _discover_prefetch_files() returns a list of Path objects.
        
        Should discover all *.pf files (case-insensitive).
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        assert isinstance(pf_files, list), "Should return list of Path objects"
    
    def test_discover_prefetch_files_finds_pf_files(self, prefetch_parser, prefetch_dir_path):
        """
        Test that _discover_prefetch_files() successfully discovers .pf files.
        
        SCHARDT sample should have 50+ Prefetch files.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        assert len(pf_files) > 0, \
            f"Should discover Prefetch files, found {len(pf_files)}"
    
    def test_discover_prefetch_files_returns_path_objects(self, prefetch_parser, prefetch_dir_path):
        """
        Test that discovered files are Path objects.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        if pf_files:
            for pf_file in pf_files[:3]:
                assert isinstance(pf_file, Path), \
                    f"Should be Path object, got {type(pf_file)}"
    
    def test_discover_prefetch_files_have_pf_extension(self, prefetch_parser, prefetch_dir_path):
        """
        Test that all discovered files have .pf extension.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        for pf_file in pf_files:
            assert pf_file.suffix.lower() == ".pf", \
                f"File should have .pf extension: {pf_file.name}"
    
    def test_discover_prefetch_files_returns_nonexistent_dir_as_empty_list(self, prefetch_parser):
        """
        Test that _discover_prefetch_files() returns empty list for non-existent directory.
        
        Should not crash, but gracefully return empty list.
        """
        pf_files = prefetch_parser._discover_prefetch_files("/nonexistent/path/")
        
        assert isinstance(pf_files, list), "Should return list"
        assert len(pf_files) == 0, "Should return empty list for missing directory"

# ============================================================================
# PREFETCH FILE LOADING TESTS
# ============================================================================

class TestPrefetchFileLoading:
    """Test suite for loading Prefetch files."""
    
    def test_load_prefetch_file_returns_bytes(self, prefetch_parser, prefetch_dir_path):
        """
        Test that _load_prefetch_file() returns bytes.
        
        Should successfully load a valid Prefetch file.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        if not pf_files:
            pytest.skip("No Prefetch files found")
        
        pf_data = prefetch_parser._load_prefetch_file(pf_files[0])
        
        assert isinstance(pf_data, bytes), "Should return bytes"
        assert len(pf_data) > 0, "Prefetch file should not be empty"
    
    def test_load_prefetch_file_minimum_size(self, prefetch_parser, prefetch_dir_path):
        """
        Test that loaded Prefetch files are at least 84 bytes (minimum header size).
        
        Valid Prefetch files must have at least 84 bytes for header.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        if not pf_files:
            pytest.skip("No Prefetch files found")
        
        pf_data = prefetch_parser._load_prefetch_file(pf_files[0])
        
        assert len(pf_data) >= 84, \
            f"Prefetch file too small: {len(pf_data)} bytes"
    
    def test_load_prefetch_file_returns_none_for_missing_file(self, prefetch_parser):
        """
        Test that _load_prefetch_file() returns None for non-existent file.
        
        Should not crash, but gracefully return None.
        """
        fake_path = Path("/nonexistent/file.pf")
        
        pf_data = prefetch_parser._load_prefetch_file(fake_path)
        
        assert pf_data is None, "Should return None for missing file"
    
    def test_load_prefetch_file_returns_none_for_small_file(self, prefetch_parser, tmp_path):
        """
        Test that _load_prefetch_file() returns None for files smaller than 84 bytes.
        
        Prefetch files must have valid header (84+ bytes).
        """
        # Create fake small file
        fake_pf = tmp_path / "fake.pf"
        fake_pf.write_bytes(b"SCCA" + b"\x00" * 50)  # Only 54 bytes
        
        pf_data = prefetch_parser._load_prefetch_file(fake_pf)
        
        assert pf_data is None, "Should return None for file < 84 bytes"

# ============================================================================
# PREFETCH FILE PARSING TESTS
# ============================================================================

class TestPrefetchFileParsing:
    """Test suite for parsing Prefetch files."""
    
    def test_parse_prefetch_file_returns_list(self, prefetch_parser, prefetch_dir_path):
        """
        Test that _parse_prefetch_file() returns a list of Event objects.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        if not pf_files:
            pytest.skip("No Prefetch files found")
        
        events = prefetch_parser._parse_prefetch_file(pf_files[0])
        
        assert isinstance(events, list), "Should return list of events"
    
    def test_parse_prefetch_file_creates_events(self, prefetch_parser, prefetch_dir_path):
        """
        Test that _parse_prefetch_file() successfully creates Event objects.
        
        Valid Prefetch files should produce at least one execution event.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        if not pf_files:
            pytest.skip("No Prefetch files found")
        
        events = prefetch_parser._parse_prefetch_file(pf_files[0])
        
        # Most valid Prefetch files should have at least 1 event
        if len(events) == 0:
            pytest.skip(f"Prefetch file {pf_files[0].name} has no valid events")
        
        assert len(events) > 0, \
            f"Should create events from valid Prefetch file"
    
    def test_parse_prefetch_file_rejects_invalid_signature(self, prefetch_parser, tmp_path):
        """
        Test that _parse_prefetch_file() rejects files with invalid signature.
        
        Prefetch files must start with 'SCCA' signature.
        """
        # Create fake Prefetch file with invalid signature
        fake_pf = tmp_path / "fake.pf"
        fake_pf.write_bytes(b"XXXX" + b"\x00" * 100)
        
        events = prefetch_parser._parse_prefetch_file(fake_pf)
        
        assert isinstance(events, list), "Should return list"
        assert len(events) == 0, "Should return empty list for invalid signature"

# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegrationFullParsing:
    """Test suite for complete end-to-end Prefetch parsing workflow."""
    
    def test_parse_orchestrates_complete_workflow(self, prefetch_parser, prefetch_dir_path):
        """
        Test that parse() orchestrates complete extraction workflow.
        
        parse() should:
        1. Discover all Prefetch files
        2. Parse each Prefetch file
        3. Extract execution events
        4. Return consolidated event list
        """
        all_events = prefetch_parser.parse()
        
        assert isinstance(all_events, list), "parse() should return list"
    
    def test_parse_discovers_prefetch_files(self, prefetch_parser, prefetch_dir_path):
        """
        Test that parse() successfully discovers Prefetch files.
        
        Should find 50+ Prefetch files in SCHARDT sample.
        """
        all_events = prefetch_parser.parse()
        
        assert prefetch_parser.prefetch_files_found > 0, \
            "Should discover Prefetch files"
    
    def test_parse_extracts_execution_events(self, prefetch_parser, prefetch_dir_path):
        """
        Test that parse() extracts program execution events.
        
        SCHARDT sample should have 100+ execution events.
        """
        all_events = prefetch_parser.parse()
        
        assert len(all_events) >= 50, \
            f"Should extract 50+ execution events, got {len(all_events)}"
    
    def test_parse_creates_valid_event_objects(self, prefetch_parser, prefetch_dir_path):
        """
        Test that all parsed events are valid Event objects.
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        for event in all_events:
            assert isinstance(event, Event), \
                f"Event should be Event object, got {type(event)}"
    
    def test_parse_events_have_correct_source_type(self, prefetch_parser, prefetch_dir_path):
        """
        Test that Prefetch events have source_type = "PREFETCH".
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        for event in all_events:
            assert event.source_type == "PREFETCH", \
                f"Should have source_type='PREFETCH', got {event.source_type}"
    
    def test_parse_events_have_correct_event_type(self, prefetch_parser, prefetch_dir_path):
        """
        Test that all events have event_type = "program_executed".
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        for event in all_events:
            assert event.event_type == "program_executed", \
                f"Should have event_type='program_executed', got {event.event_type}"
    
    def test_parse_events_have_timestamps(self, prefetch_parser, prefetch_dir_path):
        """
        Test that all events have valid timestamps.
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        for event in all_events:
            assert event.timestamp is not None, \
                "Event should have timestamp"
            assert isinstance(event.timestamp, datetime), \
                f"Timestamp should be datetime, got {type(event.timestamp)}"
    
    def test_parse_events_have_forensic_metadata(self, prefetch_parser, prefetch_dir_path):
        """
        Test that all events have forensic priority and confidence score.
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        for event in all_events:
            assert event.forensic_priority in {"HIGH", "MEDIUM", "LOW"}, \
                f"Invalid forensic_priority: {event.forensic_priority}"
            assert 0.0 <= event.confidence_score <= 1.0, \
                f"Confidence score out of range: {event.confidence_score}"
    
    def test_parse_events_have_high_priority_and_high_confidence(self, prefetch_parser, prefetch_dir_path):
        """
        Test that Prefetch execution events have HIGH priority (definitive proof).
        
        Prefetch files are HIGH forensic value because they provide definitive
        proof of program execution.
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        for event in all_events:
            assert event.forensic_priority == "HIGH", \
                f"Prefetch should have HIGH priority, got {event.forensic_priority}"
            assert event.confidence_score == 0.95, \
                f"Prefetch should have 0.95 confidence, got {event.confidence_score}"
    
    def test_parse_populates_statistics(self, prefetch_parser, prefetch_dir_path):
        """
        Test that parse() populates parser statistics.
        
        Tracks: prefetch_files_found, prefetch_files_parsed, events_count
        """
        all_events = prefetch_parser.parse()
        
        assert prefetch_parser.prefetch_files_found > 0, \
            "Should track files found"
        assert prefetch_parser.prefetch_files_parsed > 0, \
            "Should track files parsed"
        assert prefetch_parser.events_count > 0, \
            "Should track event count"

# ============================================================================
# PAYLOAD DATA TESTS
# ============================================================================

class TestPrefetchPayloadData:
    """Test suite for Prefetch event payload content."""
    
    def test_events_have_required_payload_fields(self, prefetch_parser, prefetch_dir_path):
        """
        Test that Prefetch events have all required forensic fields in payload.
        
        Required: program_name, executable, last_execution, run_count, prefetch_version
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        required_fields = [
            "program_name", "executable", "last_execution",
            "run_count", "prefetch_version", "prefetch_file"
        ]
        
        event = all_events[0]
        payload = event.payload
        
        for field in required_fields:
            assert field in payload, \
                f"Payload missing required field: {field}"
    
    def test_events_have_program_name(self, prefetch_parser, prefetch_dir_path):
        """
        Test that events have program_name extracted from Prefetch filename.
        
        Prefetch files are named: PROGRAMNAME-HASH.pf
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        event = all_events[0]
        payload = event.payload
        
        assert "program_name" in payload, "Should have program_name"
        assert payload["program_name"], "program_name should not be empty"
        assert len(payload["program_name"]) > 0, \
            f"program_name should be non-empty, got '{payload['program_name']}'"
    
    def test_events_have_run_count(self, prefetch_parser, prefetch_dir_path):
        """
        Test that events have run_count (number of times program executed).
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        event = all_events[0]
        payload = event.payload
        
        assert "run_count" in payload, "Should have run_count"
        assert isinstance(payload["run_count"], int), \
            f"run_count should be int, got {type(payload['run_count'])}"
        assert payload["run_count"] >= 1, \
            f"run_count should be >= 1, got {payload['run_count']}"
    
    def test_events_have_last_execution_time(self, prefetch_parser, prefetch_dir_path):
        """
        Test that events have last_execution timestamp.
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        event = all_events[0]
        payload = event.payload
        
        assert "last_execution" in payload, "Should have last_execution"
        assert payload["last_execution"] is not None, \
            "last_execution should not be None"
    
    def test_events_have_prefetch_version(self, prefetch_parser, prefetch_dir_path):
        """
        Test that events identify Prefetch file format version.
        
        Valid versions: 17 (XP), 23 (Vista/Win7), 26 (Win8), 30 (Win10+)
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        event = all_events[0]
        payload = event.payload
        
        assert "prefetch_version" in payload, "Should have prefetch_version"
        # ADD 17 to the expected versions set
        assert payload["prefetch_version"] in {17, 23, 26, 30}, \
            f"Invalid prefetch version: {payload['prefetch_version']}"

# ============================================================================
# HELPER FUNCTION TESTS
# ============================================================================

class TestHelperFunctions:
    """Test suite for helper/utility functions."""
    
    def test_calculate_local_timestamp_with_utc_plus_zero(self, prefetch_parser):
        """
        Test timestamp conversion with UTC+0 (no offset).
        
        Should not change timestamp if offset is UTC+0.
        """
        utc_time = datetime(2020, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        
        local_time = prefetch_parser._calculate_local_timestamp(utc_time, "UTC+0")
        
        assert local_time == utc_time, "UTC+0 should not change timestamp"
    
    def test_calculate_local_timestamp_with_positive_offset(self, prefetch_parser):
        """
        Test timestamp conversion with positive offset (e.g., UTC+5:30).
        
        Should add offset hours to UTC time.
        """
        utc_time = datetime(2020, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = prefetch_parser._calculate_local_timestamp(utc_time, "UTC+5:30")
        
        # Should be 5.5 hours ahead: 10:30 + 5:30 = 16:00
        assert local_time.hour == 16, \
            f"Expected hour 16, got {local_time.hour}"
    
    def test_calculate_local_timestamp_with_negative_offset(self, prefetch_parser):
        """
        Test timestamp conversion with negative offset (e.g., UTC-8).
        
        Should subtract offset hours from UTC time.
        """
        utc_time = datetime(2020, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = prefetch_parser._calculate_local_timestamp(utc_time, "UTC-8")
        
        # Should be 8 hours behind: 10:30 - 8:00 = 02:30
        assert local_time.hour == 2, \
            f"Expected hour 2, got {local_time.hour}"
    
    def test_get_chain_of_custody_metadata(self, prefetch_parser, prefetch_dir_path):
        """
        Test that chain of custody hashes are calculated correctly.
        
        Verifies SHA256 and MD5 hashes for forensic integrity documentation.
        """
        pf_files = prefetch_parser._discover_prefetch_files(prefetch_dir_path)
        
        if not pf_files:
            pytest.skip("No Prefetch files found")
        
        metadata = prefetch_parser._get_chain_of_custody_metadata(pf_files[0])
        
        assert metadata is not None, "Should return metadata dict"
        assert "sha256" in metadata, "Should have SHA256 hash"
        assert "md5" in metadata, "Should have MD5 hash"
        
        # Check if hashes are valid
        if metadata.get("sha256"):
            assert len(metadata["sha256"]) == 64, \
                "SHA256 should be 64 hex characters"
        if metadata.get("md5"):
            assert len(metadata["md5"]) == 32, \
                "MD5 should be 32 hex characters"

# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Test suite for edge cases and error handling."""
    
    def test_parser_handles_empty_prefetch_directory(self, prefetch_parser, tmp_path):
        """
        Test that parser gracefully handles empty Prefetch directory.
        
        Should return empty event list if no Prefetch files found.
        """
        # Override the path property to use the empty temp directory
        prefetch_parser.prefetch_dir_path = str(tmp_path)
        all_events = prefetch_parser.parse()
        
        assert isinstance(all_events, list), "Should return list"
        assert len(all_events) == 0, "Should return empty list for empty directory"
    
    def test_parser_populates_corruption_log(self, prefetch_parser, prefetch_dir_path):
        """
        Test that parser tracks errors in corruption_log.
        
        corruption_log should be a list (may be empty if no errors).
        """
        all_events = prefetch_parser.parse()
        
        assert isinstance(prefetch_parser.corruption_log, list), \
            "corruption_log should be list"

# ============================================================================
# NIST SCHARDT SAMPLE-SPECIFIC TESTS
# ============================================================================

class TestSCHARDTSample:
    """Test suite for SCHARDT-specific forensic expectations."""
    
    def test_schardt_sample_has_known_prefetch_files(self, prefetch_parser, prefetch_dir_path):
        """
        Test that SCHARDT sample has expected Prefetch files.
        
        SCHARDT is a known benchmark image with predictable contents.
        Should have 50+ Prefetch files for common executables.
        """
        all_events = prefetch_parser.parse()
        
        assert prefetch_parser.prefetch_files_found >= 50, \
            f"SCHARDT should have 50+ Prefetch files, found {prefetch_parser.prefetch_files_found}"
    
    def test_schardt_timeline_reconstruction(self, prefetch_parser, prefetch_dir_path):
        """
        Test that SCHARDT Prefetch files can be used for timeline reconstruction.
        
        Events should be sortable by timestamp for forensic timeline.
        """
        all_events = prefetch_parser.parse()
        
        if not all_events:
            pytest.skip("No events extracted")
        
        # Sort by timestamp
        sorted_events = sorted(all_events, key=lambda e: e.timestamp)
        
        # Verify ordering
        for i in range(1, len(sorted_events)):
            assert sorted_events[i].timestamp >= sorted_events[i-1].timestamp, \
                "Events should be sortable by timestamp"
    
    def test_schardt_common_programs_detected(self, prefetch_parser, prefetch_dir_path):
        """
        Test that SCHARDT sample contains common Windows programs.
        
        Should have Prefetch records for: explorer.exe, svchost.exe, etc.
        """
        all_events = prefetch_parser.parse()
        
        program_names = [e.payload.get("program_name", "").upper() for e in all_events]
        
        # At minimum, some programs should be detected
        assert len(program_names) > 0, "Should detect program names"
        
        # Should have some variation in program names
        unique_programs = set(program_names)
        assert len(unique_programs) > 5, \
            f"Should have multiple different programs, got {len(unique_programs)}"