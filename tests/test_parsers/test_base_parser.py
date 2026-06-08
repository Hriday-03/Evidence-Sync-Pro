"""Tests for base parser class."""

import pytest
from datetime import datetime
from evidence_sync_pro.parsers.base_parser import Event, BaseParser


class TestEvent:
    """Test Event data model."""
    
    def test_event_creation(self, sample_event):
        """Event can be created with valid data."""
        assert sample_event.timestamp == datetime(2024, 1, 15, 14, 23, 45)
        assert sample_event.source_device == "DESKTOP-ABC123"
        assert sample_event.source_type == "EVTX"
    
    def test_event_missing_timestamp(self):
        """Event raises error if timestamp is None."""
        with pytest.raises(ValueError, match="Timestamp cannot be None"):
            Event(
                timestamp=None,
                source_device="DESKTOP-ABC123",
                source_type="EVTX",
                event_type="login",
                user="john.doe",
                payload={},
                timezone_offset="UTC-5"
            )
    
    def test_event_missing_source_device(self):
        """Event raises error if source_device is empty."""
        with pytest.raises(ValueError, match="Source device required"):
            Event(
                timestamp=datetime(2024, 1, 15, 14, 23, 45),
                source_device="",
                source_type="EVTX",
                event_type="login",
                user="john.doe",
                payload={},
                timezone_offset="UTC-5"
            )


class TestBaseParser:
    """Test abstract BaseParser class."""
    
    def test_base_parser_is_abstract(self):
        """BaseParser cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseParser("/fake/path")
    
    def test_event_validation(self, sample_event):
        """Test _validate_event method works correctly."""
        # Create a mock parser for testing (since BaseParser is abstract)
        class MockParser(BaseParser):
            def parse(self):
                return []
        
        parser = MockParser("/fake/path")
        assert parser._validate_event(sample_event) is True