"""
Unit tests for EVTX parser.

Tests verify:
- Valid EVTX file parsing
- Timezone detection from registry
- IP extraction and normalization
- Failure reason extraction
- Local timestamp calculation
- Forensic priority assignment
- Timestamp validation
- Error handling
"""

import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from evidence_sync_pro.parsers.evtx_parser import EvtxParser
from evidence_sync_pro.parsers.base_parser import Event


class TestEvtxParserInitialization:
    """Test EVTX parser initialization."""
    
    def test_parser_initialization(self):
        """Parser initializes with valid paths."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        if not Path(evtx_path).exists() or not Path(system_hive_path).exists():
            pytest.skip("EVTX or System hive not available on this system")
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        assert parser.artifact_path == evtx_path
        assert parser.system_hive_path == system_hive_path
        assert parser.events == []
        assert parser.corruption_log == []
        assert parser.events_count == 0
    
    def test_parser_initialization_with_missing_hive(self):
        """Parser initializes gracefully even if system hive not provided."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        
        if not Path(evtx_path).exists():
            pytest.skip("EVTX file not available on this system")
        
        parser = EvtxParser(evtx_path, "C:\\nonexistent\\path\\SYSTEM")
        
        # Should still initialize, defaulting timezone to UTC
        assert parser.system_timezone is not None


class TestEvtxParserParsing:
    """Test EVTX file parsing."""
    
    def test_parse_valid_evtx_file(self):
        """Parser successfully parses valid EVTX file."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        if not Path(evtx_path).exists():
            pytest.skip("Security.evtx not available on this system")
        
        parser = EvtxParser(evtx_path, system_hive_path)
        events = parser.parse()
        
        # Should parse at least some events
        assert isinstance(events, list)
        assert len(events) > 0, "Security.evtx should contain events"
    
    def test_parse_returns_event_objects(self):
        """Parser returns valid Event objects."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        if not Path(evtx_path).exists():
            pytest.skip("Security.evtx not available on this system")
        
        parser = EvtxParser(evtx_path, system_hive_path)
        events = parser.parse()
        
        if events:
            event = events[0]
            
            # Verify Event object structure
            assert isinstance(event, Event)
            assert event.timestamp is not None
            assert event.source_device is not None
            assert event.source_type == "EVTX"
            assert event.event_type is not None
            assert event.user is not None
    
    def test_parse_nonexistent_file(self):
        """Parser raises FileNotFoundError for missing EVTX file."""
        evtx_path = "C:\\nonexistent\\path\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        with pytest.raises(FileNotFoundError):
            parser.parse()


class TestTimezoneDetection:
    """Test system timezone detection from registry."""
    
    def test_timezone_detection_returns_string(self):
        """Timezone detection returns valid UTC offset string."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        if not Path(system_hive_path).exists():
            pytest.skip("System hive not available")
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        # Timezone should be a string like "UTC-5" or "UTC+5:30"
        assert isinstance(parser.system_timezone, str)
        assert parser.system_timezone.startswith("UTC")
    
    def test_timezone_detection_fallback(self):
        """Timezone detection falls back to UTC if hive not found."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\nonexistent\\path\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        # Should default to UTC or similar fallback
        assert parser.system_timezone is not None
        assert "UTC" in parser.system_timezone


class TestIPExtraction:
    """Test IP extraction and normalization."""
    
    def test_normalize_localhost_ip(self):
        """Localhost IPs are normalized correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        normalized = parser._normalize_ip("127.0.0.1")
        
        assert "127.0.0.1" in normalized
        assert "localhost" in normalized.lower()
    
    def test_normalize_private_192_ip(self):
        """Private 192.168.x.x IPs are normalized correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        normalized = parser._normalize_ip("192.168.1.100")
        
        assert "192.168.1.100" in normalized
        assert "Private" in normalized or "private" in normalized.lower()
    
    def test_normalize_private_10_ip(self):
        """Private 10.x.x.x IPs are normalized correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        normalized = parser._normalize_ip("10.0.0.50")
        
        assert "10.0.0.50" in normalized
        assert "Private" in normalized or "private" in normalized.lower()
    
    def test_normalize_private_172_ip(self):
        """Private 172.16-31.x.x IPs are normalized correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        normalized = parser._normalize_ip("172.20.5.100")
        
        assert "172.20.5.100" in normalized
        assert "Private" in normalized or "private" in normalized.lower()
    
    def test_normalize_apipa_ip(self):
        """APIPA IPs (169.254.x.x) are normalized correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        normalized = parser._normalize_ip("169.254.1.1")
        
        assert "169.254.1.1" in normalized
        assert "APIPA" in normalized
    
    def test_normalize_public_ip(self):
        """Public IPs are marked as such."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        normalized = parser._normalize_ip("8.8.8.8")
        
        assert "8.8.8.8" in normalized
        assert "Public" in normalized


class TestFailureReasonExtraction:
    """Test failure reason extraction for failed login events."""
    
    def test_extract_failure_reason_incorrect_password(self):
        """Failure reason 'Incorrect password' is extracted correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        event_data = {"Status": "0xC000006A"}
        reason = parser._extract_failure_reason(event_data)
        
        assert reason is not None
        assert "Incorrect password" in reason or "password" in reason.lower()
    
    def test_extract_failure_reason_no_such_user(self):
        """Failure reason 'No such user' is extracted correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        event_data = {"Status": "0xC000005E"}
        reason = parser._extract_failure_reason(event_data)
        
        assert reason is not None
        assert "No such user" in reason or "user" in reason.lower()
    
    def test_extract_failure_reason_account_locked(self):
        """Failure reason 'Account locked' is extracted correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        event_data = {"Status": "0xC0000234"}
        reason = parser._extract_failure_reason(event_data)
        
        assert reason is not None
        assert "locked" in reason.lower()
    
    def test_extract_failure_reason_unknown_code(self):
        """Unknown failure reason codes are handled gracefully."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        event_data = {"Status": "0xDEADBEEF"}
        reason = parser._extract_failure_reason(event_data)
        
        assert reason is not None
        assert "Unknown" in reason or "0xDEADBEEF" in reason


class TestLocalTimestampCalculation:
    """Test local timestamp calculation from UTC."""
    
    def test_calculate_local_timestamp_utc_minus_5(self):
        """Local timestamp is correctly calculated for UTC-5 timezone."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        utc_time = datetime(2026, 6, 8, 20, 0, 0, tzinfo=timezone.utc)
        local_time = parser._calculate_local_timestamp(utc_time, "UTC-5")
        
        # UTC-5 means local is 5 hours BEHIND UTC
        # So 20:00 UTC = 15:00 local
        expected = datetime(2026, 6, 8, 15, 0, 0)
        
        assert local_time.hour == expected.hour
        assert local_time.day == expected.day
    
    def test_calculate_local_timestamp_utc_plus_530(self):
        """Local timestamp is correctly calculated for UTC+5:30 timezone."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        utc_time = datetime(2026, 6, 8, 20, 0, 0, tzinfo=timezone.utc)
        local_time = parser._calculate_local_timestamp(utc_time, "UTC+5:30")
        
        # UTC+5:30 means local is 5 hours 30 minutes AHEAD of UTC
        # So 20:00 UTC = 01:30 next day local
        # 20:00 + 5:30 = 25:30 = 01:30 next day
        
        assert local_time.hour == 1
        assert local_time.minute == 30
        assert local_time.day == 9  # Next day
    
    def test_calculate_local_timestamp_invalid_format(self):
        """Invalid timezone format is handled gracefully."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        utc_time = datetime(2026, 6, 8, 20, 0, 0, tzinfo=timezone.utc)
        
        # Invalid timezone format should fallback to UTC
        local_time = parser._calculate_local_timestamp(utc_time, "INVALID")
        
        # Should return the UTC time as fallback
        assert local_time == utc_time


class TestTimestampValidation:
    """Test timestamp parsing and validation."""
    
    def test_validate_valid_iso8601_timestamp(self):
        """Valid ISO 8601 timestamps are parsed correctly."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        timestamp_str = "2026-06-08T20:30:57.2192047Z"
        validated = parser._validate_timestamp(timestamp_str)
        
        assert validated is not None
        assert isinstance(validated, datetime)
        assert validated.year == 2026
        assert validated.month == 6
        assert validated.day == 8
    
    def test_validate_future_timestamp(self):
        """Future timestamps are logged but returned."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        # Timestamp 10 days in future
        future_date = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat().replace('+00:00', 'Z')
        validated = parser._validate_timestamp(future_date)
        
        # Should still return timestamp but log warning
        assert validated is not None
    
    def test_validate_invalid_timestamp_format(self):
        """Invalid timestamp formats return None."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        invalid_timestamp = "not-a-timestamp"
        validated = parser._validate_timestamp(invalid_timestamp)
        
        assert validated is None


class TestForensicPriority:
    """Test forensic priority assignment."""
    
    def test_high_priority_event_4625(self):
        """Event 4625 (failed login) is assigned HIGH priority."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        priority = parser._calculate_forensic_priority(4625)
        
        assert priority == "HIGH"
    
    def test_high_priority_event_4624(self):
        """Event 4624 (successful login) is assigned HIGH priority."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        priority = parser._calculate_forensic_priority(4624)
        
        assert priority == "HIGH"
    
    def test_high_priority_event_4728(self):
        """Event 4728 (group membership changed) is assigned HIGH priority."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        priority = parser._calculate_forensic_priority(4728)
        
        assert priority == "HIGH"
    
    def test_medium_priority_event_4648(self):
        """Event 4648 (logon with explicit credentials) is assigned MEDIUM priority."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        priority = parser._calculate_forensic_priority(4648)
        
        assert priority == "MEDIUM"
    
    def test_low_priority_unknown_event(self):
        """Unknown event IDs are assigned LOW priority."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        parser = EvtxParser(evtx_path, system_hive_path)
        priority = parser._calculate_forensic_priority(9999)
        
        assert priority == "LOW"


class TestCorruptionDetection:
    """Test corruption detection and logging."""
    
    def test_corruption_log_initialized(self):
        """Corruption log is properly initialized."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        if not Path(evtx_path).exists():
            pytest.skip("EVTX file not available")
        
        parser = EvtxParser(evtx_path, system_hive_path)
        
        assert isinstance(parser.corruption_log, list)
        assert len(parser.corruption_log) == 0


class TestEventNormalization:
    """Test event normalization to standard Event schema."""
    
    def test_normalized_event_has_all_fields(self):
        """Normalized Event object has all required fields populated."""
        evtx_path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        system_hive_path = "C:\\Windows\\System32\\config\\SYSTEM"
        
        if not Path(evtx_path).exists():
            pytest.skip("EVTX file not available")
        
        parser = EvtxParser(evtx_path, system_hive_path)
        events = parser.parse()
        
        if events:
            event = events[0]
            
            # Check all fields are populated
            assert event.timestamp is not None
            assert event.source_device is not None
            assert event.source_type == "EVTX"
            assert event.event_type is not None
            assert event.user is not None
            assert event.payload is not None
            assert event.timezone_offset is not None
            assert event.forensic_priority in ["HIGH", "MEDIUM", "LOW"]
            assert event.confidence_score == 1.0
            assert event.corruption_detected == False