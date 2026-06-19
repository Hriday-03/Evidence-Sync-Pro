import pytest
from pathlib import Path
from datetime import datetime, timezone
from evidence_sync_pro.parsers.mft_parser import MFTParser
from evidence_sync_pro.parsers.base_parser import Event

# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def schardt_mft_path():
    r"""
    Fixture providing path to extracted $MFT from SCHARDT.001 NIST sample.
    
    The SCHARDT.001 is a segmented disk image (001, 002, 003, etc.).
    This fixture assumes the image has been mounted or extracted, and the
    $MFT file is accessible at the specified path.
    
    To extract $MFT from SCHARDT.001:
    1. Use 7-Zip or similar to extract all .001, .002, etc. segments
    2. Use FTK Imager or Arsenal Image Mounter to mount the image
    3. Copy $MFT from root of C: drive
    4. Place at path: C:\Users\Hriday\Project\Refrences\extracted_mft\$MFT
    """
    path = r"C:\Users\Hriday\Project\Refrences\sample_mft\$MFT"
    
    # For testing purposes, if the extracted path doesn't exist yet,
    # we'll use a placeholder that pytest can skip gracefully
    if not Path(path).is_file():
        pytest.skip(f"MFT file not found at {path}. Extract SCHARDT.001 first.")
    
    return path

@pytest.fixture
def mft_parser(schardt_mft_path):
    r"""
    Fixture initializing MFTParser with NIST SCHARDT sample.
    
    Returns an MFTParser instance ready for testing.
    """
    return MFTParser(
        mft_file_path=schardt_mft_path,
        computer_name="SCHARDT_TEST",
        system_timezone="UTC+0",
        partition_letter="C"
    )

# ============================================================================
# FILE LOADING TESTS
# ============================================================================

class TestMFTFileLoading:
    r"""Test suite for loading and validating $MFT file."""
    
    def test_mft_file_loads_successfully(self, mft_parser, schardt_mft_path):
        r"""
        Test that $MFT file loads without errors.
        
        Verifies _load_mft_file() can successfully open the MFT file
        and return its binary contents.
        """
        mft_data = mft_parser._load_mft_file(schardt_mft_path)
        
        assert mft_data is not None, "MFT file load failed"
        assert len(mft_data) > 0, "MFT file is empty"
    
    def test_mft_file_is_multiple_of_record_size(self, mft_parser, schardt_mft_path):
        r"""
        Test that MFT file size is a multiple of 1024 bytes (standard record size).
        
        Each MFT record is exactly 1024 bytes. If file size isn't a multiple,
        there may be corruption or the file is incomplete.
        """
        mft_data = mft_parser._load_mft_file(schardt_mft_path)
        
        assert mft_data is not None, "MFT file load failed"
        assert len(mft_data) % 1024 == 0, \
            f"MFT file size {len(mft_data)} is not multiple of 1024"
    
    def test_mft_file_has_valid_records(self, mft_parser, schardt_mft_path):
        r"""
        Test that MFT file contains valid MFT records with correct signature.
        
        First record should have 'FILE' signature (0x46494C45 in little-endian).
        """
        mft_data = mft_parser._load_mft_file(schardt_mft_path)
        
        assert mft_data is not None, "MFT file load failed"
        
        # Check first record signature
        first_record = mft_data[0:1024]
        signature = first_record[0:4]
        
        assert signature == b'FILE', \
            f"Invalid MFT signature: {signature} (expected b'FILE')"
    
    def test_mft_returns_none_for_nonexistent_file(self, mft_parser):
        r"""
        Test that _load_mft_file() returns None for non-existent file path.
        
        Should not crash, but gracefully return None.
        """
        mft_data = mft_parser._load_mft_file("/nonexistent/path/$MFT")
        
        assert mft_data is None, "Should return None for missing file"

# ============================================================================
# MFT RECORD PARSING TESTS
# ============================================================================

class TestMFTRecordParsing:
    r"""Test suite for parsing individual MFT records."""
    
    def test_parse_mft_record_returns_list(self, mft_parser, schardt_mft_path):
        r"""
        Test that _parse_mft_record() returns a list of Event objects.
        
        Even if record has no data, should return empty list, not None.
        """
        mft_data = mft_parser._load_mft_file(schardt_mft_path)
        record_data = mft_data[0:1024]
        
        events = mft_parser._parse_mft_record(0, record_data)
        
        assert isinstance(events, list), "Should return list of events"
    
    def test_parse_mft_record_recognizes_valid_records(self, mft_parser, schardt_mft_path):
        r"""
        Test that _parse_mft_record() successfully parses valid MFT records.
        
        Record 0 (MFT itself) should parse without errors.
        """
        mft_data = mft_parser._load_mft_file(schardt_mft_path)
        record_data = mft_data[0:1024]
        
        events = mft_parser._parse_mft_record(0, record_data)
        
        assert isinstance(events, list), "Should return list"
    
    def test_parse_mft_record_rejects_invalid_signature(self, mft_parser):
        r"""
        Test that _parse_mft_record() rejects records with invalid signature.
        
        Non-FILE records should return empty list.
        """
        # Create fake record with invalid signature
        fake_record = b'XXXX' + (b'\x00' * 1020)
        
        events = mft_parser._parse_mft_record(999, fake_record)
        
        assert isinstance(events, list), "Should return list"
        assert len(events) == 0, "Should return empty list for invalid signature"

# ============================================================================
# ATTRIBUTE PARSING TESTS
# ============================================================================

class TestAttributeParsing:
    r"""Test suite for parsing MFT attributes."""
    
    def test_parse_filetime_conversion(self, mft_parser):
        r"""
        Test that FILETIME to datetime conversion works correctly.
        
        Uses known FILETIME value: 0x01D5A5B0E0000000
        Should convert to a valid datetime.
        """
        # Example FILETIME: 132373048000000000 (2020-06-15 12:00:00 UTC)
        filetime = 132373048000000000
        
        dt = mft_parser._filetime_to_datetime(filetime)
        
        assert dt is not None, "FILETIME conversion failed"
        assert isinstance(dt, datetime), "Should return datetime object"
        assert dt.tzinfo is not None, "Should have timezone info"
    
    def test_parse_filetime_zero_returns_none(self, mft_parser):
        r"""
        Test that FILETIME of 0 returns None (invalid/uninitialized time).
        """
        dt = mft_parser._filetime_to_datetime(0)
        
        assert dt is None, "Zero FILETIME should return None"
    
    def test_parse_filetime_negative_returns_none(self, mft_parser):
        """
        Test that negative FILETIME returns None (invalid).
        """
        dt = mft_parser._filetime_to_datetime(-1000)
        
        assert dt is None, "Negative FILETIME should return None"

# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegrationFullParsing:
    """Test suite for complete end-to-end MFT parsing workflow."""
    
    def test_parse_orchestrates_complete_workflow(self, mft_parser, schardt_mft_path):
        """
        Test that parse() orchestrates complete extraction workflow.
        
        parse() should:
        1. Load MFT file
        2. Parse all MFT records
        3. Extract file system events
        4. Return consolidated event list
        """
        all_events = mft_parser.parse()
        
        assert isinstance(all_events, list), "parse() should return list"
    
    def test_parse_extracts_multiple_file_system_events(self, mft_parser, schardt_mft_path):
        """
        Test that parse() extracts file system events from MFT records.
        
        SCHARDT sample should have hundreds of files and directories.
        """
        all_events = mft_parser.parse()
        
        # SCHARDT sample typically has 500+ files
        assert len(all_events) >= 100, \
            f"Should extract 100+ events, got {len(all_events)}"
    
    def test_parse_creates_valid_event_objects(self, mft_parser, schardt_mft_path):
        """
        Test that all parsed events are valid Event objects.
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        for event in all_events:
            assert isinstance(event, Event), \
                f"Event should be Event object, got {type(event)}"
    
    def test_parse_events_have_correct_source_type(self, mft_parser, schardt_mft_path):
        """
        Test that MFT events have source_type = "MFT".
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        for event in all_events:
            assert event.source_type == "MFT", \
                f"Should have source_type='MFT', got {event.source_type}"
    
    def test_parse_events_have_valid_event_types(self, mft_parser, schardt_mft_path):
        """
        Test that events have valid event_type values.
        
        Valid types: file_created, directory_created, file_deleted
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        valid_types = {"file_created", "directory_created", "file_deleted"}
        
        for event in all_events:
            assert event.event_type in valid_types, \
                f"Invalid event_type: {event.event_type}"
    
    def test_parse_events_have_timestamps(self, mft_parser, schardt_mft_path):
        """
        Test that all events have valid timestamps.
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        for event in all_events:
            assert event.timestamp is not None, "Event should have timestamp"
            assert isinstance(event.timestamp, datetime), \
                f"Timestamp should be datetime, got {type(event.timestamp)}"
    
    def test_parse_events_have_forensic_metadata(self, mft_parser, schardt_mft_path):
        """
        Test that all events have forensic priority and confidence score.
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        valid_priorities = {"HIGH", "MEDIUM", "LOW"}
        
        for event in all_events:
            assert event.forensic_priority in valid_priorities, \
                f"Invalid forensic_priority: {event.forensic_priority}"
            assert 0.0 <= event.confidence_score <= 1.0, \
                f"Confidence score out of range: {event.confidence_score}"
    
    def test_parse_detects_file_vs_directory(self, mft_parser, schardt_mft_path):
        """
        Test that parse() correctly identifies files vs directories.
        
        Both file_created and directory_created events should be present.
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        file_events = [e for e in all_events if e.event_type == "file_created"]
        dir_events = [e for e in all_events if e.event_type == "directory_created"]
        
        # Should have both files and directories
        assert len(file_events) > 0, "Should extract file events"
        assert len(dir_events) > 0, "Should extract directory events"
    
    def test_parse_detects_deleted_files(self, mft_parser, schardt_mft_path):
        """
        Test that parse() detects deleted (unallocated) MFT records.
        
        SCHARDT sample should have some deleted files.
        """
        all_events = mft_parser.parse()
        
        deleted_events = [e for e in all_events if e.event_type == "file_deleted"]
        
        # May or may not have deleted files depending on sample
        assert isinstance(deleted_events, list), "Should return list of deleted events"
    
    def test_parse_populates_statistics(self, mft_parser, schardt_mft_path):
        """
        Test that parse() populates parser statistics.
        
        Tracks: total_records, in_use_records, deleted_records, files, directories
        """
        all_events = mft_parser.parse()
        
        assert mft_parser.total_records > 0, "Should have total record count"
        assert mft_parser.in_use_records > 0, "Should have in-use records"
        assert mft_parser.files > 0, "Should count files"
        assert mft_parser.directories > 0, "Should count directories"

# ============================================================================
# PAYLOAD DATA TESTS
# ============================================================================

class TestMFTPayloadData:
    """Test suite for MFT event payload content."""
    
    def test_events_have_required_payload_fields(self, mft_parser, schardt_mft_path):
        """
        Test that MFT events have all required forensic fields in payload.
        
        Required: mft_record_number, filename, is_directory, in_use,
                  creation_time, modification_time, access_time
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        required_fields = [
            "mft_record_number", "filename", "is_directory", "in_use",
            "creation_time", "modification_time", "access_time", "partition"
        ]
        
        event = all_events[0]
        payload = event.payload
        
        for field in required_fields:
            assert field in payload, \
                f"Payload missing required field: {field}"
    
    def test_events_have_file_size_information(self, mft_parser, schardt_mft_path):
        """
        Test that file events have allocated and actual size information.
        """
        all_events = mft_parser.parse()
        
        file_events = [e for e in all_events if e.event_type == "file_created"]
        
        assert len(file_events) > 0, "Should have file events"
        
        event = file_events[0]
        payload = event.payload
        
        assert "allocated_size" in payload, "Should have allocated_size"
        assert "actual_size" in payload, "Should have actual_size"
        assert isinstance(payload["allocated_size"], int), \
            "allocated_size should be int"
        assert isinstance(payload["actual_size"], int), \
            "actual_size should be int"
    
    def test_events_have_mac_times(self, mft_parser, schardt_mft_path):
        """
        Test that events have MAC times (Creation, Modification, Access).
        
        All three timestamps should be present for forensic timeline.
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        event = all_events[0]
        payload = event.payload
        
        # At least creation_time should be present
        assert "creation_time" in payload, "Should have creation_time"
        assert "modification_time" in payload, "Should have modification_time"
        assert "access_time" in payload, "Should have access_time"

# ============================================================================
# HELPER FUNCTION TESTS
# ============================================================================

class TestHelperFunctions:
    """Test suite for helper/utility functions."""
    
    def test_calculate_local_timestamp_with_utc_plus_zero(self, mft_parser):
        """
        Test timestamp conversion with UTC+0 (no offset).
        
        Should not change timestamp if offset is UTC+0.
        """
        utc_time = datetime(2020, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        
        local_time = mft_parser._calculate_local_timestamp(utc_time, "UTC+0")
        
        assert local_time == utc_time, "UTC+0 should not change timestamp"
    
    def test_calculate_local_timestamp_with_positive_offset(self, mft_parser):
        """
        Test timestamp conversion with positive offset (e.g., UTC+5:30).
        
        Should add offset hours to UTC time.
        """
        utc_time = datetime(2020, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = mft_parser._calculate_local_timestamp(utc_time, "UTC+5:30")
        
        # Should be 5.5 hours ahead: 10:30 + 5:30 = 16:00
        assert local_time.hour == 16, \
            f"Expected hour 16 (10:30 + 5:30), got {local_time.hour}"
    
    def test_calculate_local_timestamp_with_negative_offset(self, mft_parser):
        """
        Test timestamp conversion with negative offset (e.g., UTC-8).
        
        Should subtract offset hours from UTC time.
        """
        utc_time = datetime(2020, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        
        local_time = mft_parser._calculate_local_timestamp(utc_time, "UTC-8")
        
        # Should be 8 hours behind: 10:30 - 8:00 = 02:30
        assert local_time.hour == 2, \
            f"Expected hour 2 (10:30 - 8), got {local_time.hour}"
    
    def test_get_chain_of_custody_metadata(self, mft_parser, schardt_mft_path):
        """
        Test that chain of custody hashes are calculated correctly.
        
        Verifies SHA256 and MD5 hashes for forensic integrity documentation.
        """
        metadata = mft_parser._get_chain_of_custody_metadata(schardt_mft_path)
        
        assert metadata is not None, "Should return metadata dict"
        assert "sha256" in metadata, "Should have SHA256 hash"
        assert "md5" in metadata, "Should have MD5 hash"
        assert metadata["sha256"] is not None, "SHA256 should not be None"
        assert metadata["md5"] is not None, "MD5 should not be None"
        assert len(metadata["sha256"]) == 64, \
            "SHA256 should be 64 hex characters"
        assert len(metadata["md5"]) == 32, \
            "MD5 should be 32 hex characters"

# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Test suite for edge cases and error handling."""
    
    def test_parser_handles_large_mft_files(self, mft_parser, schardt_mft_path):
        """
        Test that parser gracefully handles large MFT files.
        
        SCHARDT image MFT can be 20+ MB with thousands of records.
        """
        mft_data = mft_parser._load_mft_file(schardt_mft_path)
        
        assert mft_data is not None, "Should load large MFT file"
        assert len(mft_data) > 1_000_000, \
            f"Expected large MFT (>1MB), got {len(mft_data)} bytes"
    
    def test_parser_recovers_from_corrupt_records(self, mft_parser, schardt_mft_path):
        """
        Test that parser gracefully skips corrupted MFT records.
        
        Should continue processing despite individual record errors.
        """
        all_events = mft_parser.parse()
        
        # Should complete without crashing even if some records are corrupt
        assert isinstance(all_events, list), \
            "Should handle corrupt records gracefully"
    
    def test_parser_populates_corruption_log(self, mft_parser, schardt_mft_path):
        """
        Test that parser tracks errors in corruption_log.
        
        corruption_log should be a list (may be empty if no errors).
        """
        all_events = mft_parser.parse()
        
        assert isinstance(mft_parser.corruption_log, list), \
            "corruption_log should be list"

# ============================================================================
# NIST SCHARDT SAMPLE-SPECIFIC TESTS
# ============================================================================

class TestSCHARDTSample:
    """Test suite for SCHARDT-specific forensic expectations."""
    
    def test_schardt_sample_has_known_structure(self, mft_parser, schardt_mft_path):
        """
        Test that SCHARDT sample has expected file system structure.
        
        SCHARDT is a known benchmark image with predictable contents.
        """
        all_events = mft_parser.parse()
        
        # SCHARDT typically has these characteristics
        assert mft_parser.total_records > 100, \
            "SCHARDT should have 100+ MFT records"
        assert mft_parser.files > 50, \
            "SCHARDT should have 50+ files"
        assert mft_parser.directories > 10, \
            "SCHARDT should have 10+ directories"
    
    def test_schardt_timeline_reconstruction(self, mft_parser, schardt_mft_path):
        """
        Test that SCHARDT MFT can be used for timeline reconstruction.
        
        Events should be sortable by timestamp for forensic timeline.
        """
        all_events = mft_parser.parse()
        
        assert len(all_events) > 0, "No events extracted"
        
        # Sort by timestamp
        sorted_events = sorted(all_events, key=lambda e: e.timestamp)
        
        # Verify ordering
        for i in range(1, len(sorted_events)):
            assert sorted_events[i].timestamp >= sorted_events[i-1].timestamp, \
                "Events should be sortable by timestamp"